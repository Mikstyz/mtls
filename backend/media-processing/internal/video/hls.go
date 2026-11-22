package video

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

const maxHLSSegments = 24*60*60/4 + 1

var errHLSLayout = errors.New("invalid fragmented MP4 layout")

type fragment struct {
	offset   int64
	size     int64
	duration time.Duration
}

type mp4Box struct {
	kind string
	size int64
}

func readMP4Box(file io.ReaderAt, offset, size int64) (mp4Box, error) {
	var header [8]byte
	if size-offset < int64(len(header)) {
		return mp4Box{}, errHLSLayout
	}
	if _, err := file.ReadAt(header[:], offset); err != nil {
		return mp4Box{}, err
	}

	length := int64(binary.BigEndian.Uint32(header[:4]))
	if length < 8 || length > size-offset {
		return mp4Box{}, errHLSLayout
	}

	return mp4Box{kind: string(header[4:]), size: length}, nil
}

// FFmpeg emits one version-1 SIDX per track for each moof/mdat pair.
func readFragmentIndex(file io.ReaderAt, offset int64, box mp4Box) (int64, int64, time.Duration, error) {
	var index [44]byte
	if box.size != 8+int64(len(index)) {
		return 0, 0, 0, errHLSLayout
	}

	if _, err := file.ReadAt(index[:], offset+8); err != nil {
		return 0, 0, 0, err
	}

	timescale := binary.BigEndian.Uint32(index[8:12])
	delta := binary.BigEndian.Uint64(index[20:28])
	length := binary.BigEndian.Uint32(index[32:36])
	ticks := binary.BigEndian.Uint32(index[36:40])
	if binary.BigEndian.Uint32(index[:4]) != 1<<24 || timescale == 0 || delta > 52 ||
		binary.BigEndian.Uint32(index[28:32]) != 1 || length == 0 || length>>31 != 0 || ticks == 0 ||
		binary.BigEndian.Uint32(index[40:44])>>31 != 1 {
		return 0, 0, 0, errHLSLayout
	}

	duration := time.Duration(ticks) * time.Second / time.Duration(timescale)
	if duration < time.Millisecond || duration > 6*time.Second {
		return 0, 0, 0, errHLSLayout
	}

	return offset + box.size + int64(delta), int64(length), duration, nil
}

func hlsFragments(file io.ReaderAt, size int64) (int64, []fragment, error) {
	var offset int64
	for _, kind := range []string{"ftyp", "moov"} {
		box, err := readMP4Box(file, offset, size)
		if err != nil || box.kind != kind {
			return 0, nil, errHLSLayout
		}
		offset += box.size
	}

	initialization := offset
	var fragments []fragment
	for offset < size {
		box, err := readMP4Box(file, offset, size)
		if err != nil {
			return 0, nil, err
		}
		if box.kind == "mfra" && offset+box.size == size {
			break
		}

		if box.kind != "sidx" || len(fragments) == maxHLSSegments {
			return 0, nil, errHLSLayout
		}

		start, length, duration, err := readFragmentIndex(file, offset, box)
		if err != nil {
			return 0, nil, err
		}
		offset += box.size

		if offset < start {
			audio, err := readMP4Box(file, offset, size)
			if err != nil || audio.kind != "sidx" {
				return 0, nil, errHLSLayout
			}
			audioStart, audioLength, _, err := readFragmentIndex(file, offset, audio)
			if err != nil || audioStart != start || audioLength != length {
				return 0, nil, errHLSLayout
			}
			offset += audio.size
		}

		if offset != start {
			return 0, nil, errHLSLayout
		}

		moof, err := readMP4Box(file, offset, size)
		if err != nil || moof.kind != "moof" {
			return 0, nil, errHLSLayout
		}
		mdat, err := readMP4Box(file, offset+moof.size, size)
		if err != nil || mdat.kind != "mdat" || moof.size+mdat.size != length {
			return 0, nil, errHLSLayout
		}

		fragments = append(fragments, fragment{offset: offset, size: length, duration: duration})
		offset += length
	}

	if len(fragments) == 0 {
		return 0, nil, errHLSLayout
	}

	return initialization, fragments, nil
}

func renditionPlaylist(file io.ReaderAt, size int64, name string) ([]byte, uint64, error) {
	initialization, fragments, err := hlsFragments(file, size)
	if err != nil {
		return nil, 0, err
	}

	var target time.Duration
	var bandwidth uint64
	for _, segment := range fragments {
		target = max(target, segment.duration)
		bandwidth = max(bandwidth, uint64(math.Ceil(float64(segment.size)*8/segment.duration.Seconds())))
	}

	var playlist strings.Builder
	playlist.Grow(256 + len(fragments)*64)
	playlist.WriteString("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-PLAYLIST-TYPE:VOD\n")
	fmt.Fprintf(&playlist, "#EXT-X-TARGETDURATION:%d\n", (target+time.Second-1)/time.Second)
	fmt.Fprintf(&playlist, "#EXT-X-MAP:URI=%q,BYTERANGE=%q\n", name, fmt.Sprintf("%d@0", initialization))
	for _, segment := range fragments {
		fmt.Fprintf(&playlist, "#EXTINF:%.6f,\n#EXT-X-BYTERANGE:%d@%d\n%s\n",
			segment.duration.Seconds(), segment.size, segment.offset, name)
	}
	playlist.WriteString("#EXT-X-ENDLIST\n")

	return []byte(playlist.String()), bandwidth, nil
}
