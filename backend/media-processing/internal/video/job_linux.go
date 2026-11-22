//go:build linux

package video

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"mtls/media-processing/internal/lifecycle"
	"mtls/media-processing/internal/quarantine"
	"mtls/media-processing/internal/storage"
)

type Job struct {
	Processor  *Processor
	Ledger     *lifecycle.Store
	Quarantine *quarantine.Store
	Prepared   *storage.Store
	Limits     ProbeLimits
	MaxInput   int64
	MaxOutput  int64
}

func (j *Job) Process(ctx context.Context, id, lease uuid.UUID) error {
	original, err := j.Quarantine.Read(id)
	if err != nil {
		return err
	}
	defer original.Close()

	info, err := original.Stat()
	if err != nil {
		return err
	}
	if info.Size() < 1 || info.Size() > j.MaxInput {
		return errors.New("invalid original video size")
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(original, 0, info.Size())); err != nil {
		return err
	}
	variant := lifecycle.Variant{Name: "original.mp4", Size: info.Size(), SHA256: [32]byte(hash.Sum(nil))}
	check := func(ctx context.Context) error { return j.Ledger.CheckVideoInput(ctx, id, lease, variant) }
	if err := check(ctx); err != nil {
		return err
	}

	source, err := j.Processor.Probe(ctx, original, j.Limits)
	if err != nil {
		return err
	}
	if len(source.Renditions) == 0 {
		if err := j.Processor.validateOriginal(ctx, original); err != nil {
			return err
		}
	}

	var variants []lifecycle.Variant
	var inputs []storage.InputFile
	var expected []storage.InstalledFile
	addVariant := func(variant lifecycle.Variant, reader io.Reader) {
		variants = append(variants, variant)
		inputs = append(inputs, storage.InputFile{Name: variant.Name, Reader: reader, MaxBytes: variant.Size})
		expected = append(expected, storage.InstalledFile{Name: variant.Name, Size: variant.Size, SHA256: variant.SHA256})
	}
	addVariant(variant, io.NewSectionReader(original, 0, variant.Size))

	poster, err := j.Processor.poster(ctx, original, j.MaxOutput, 0)
	if err != nil {
		return fmt.Errorf("prepare video poster: %w", err)
	}

	addVariant(lifecycle.Variant{Name: "poster.jpg", Size: int64(len(poster)), SHA256: sha256.Sum256(poster)}, bytes.NewReader(poster))
	remaining := j.MaxOutput - int64(len(poster))
	var streams []string
	for _, dimensions := range source.Renditions {
		out, release, err := j.Quarantine.NewPartial()
		if err != nil {
			return err
		}
		defer release()

		hash.Reset()
		if err := j.Processor.Transcode(ctx, original, io.MultiWriter(out, hash), remaining, source, dimensions); err != nil {
			return err
		}
		actual, err := j.Processor.Probe(ctx, out, j.Limits)
		if err != nil {
			return err
		}
		if actual.Dimensions != dimensions || actual.Rotation != 0 || actual.VideoCodec != "h264" ||
			(source.AudioCodec != "" && actual.AudioCodec != "aac") || (actual.Duration-source.Duration).Abs() > time.Second {
			return errors.New("invalid generated video rendition")
		}
		size, err := out.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}
		remaining -= size
		prefix := fmt.Sprintf("%dp", min(dimensions.Width, dimensions.Height))
		name := prefix + ".mp4"
		digest := [32]byte(hash.Sum(nil))
		addVariant(lifecycle.Variant{Name: name, Size: size, SHA256: digest}, io.NewSectionReader(out, 0, size))

		playlist, bandwidth, err := renditionPlaylist(out, size, name)
		if err != nil {
			return fmt.Errorf("index video rendition: %w", err)
		}

		if int64(len(playlist)) > remaining {
			return errors.New("video playlists exceed output budget")
		}
		remaining -= int64(len(playlist))
		addVariant(lifecycle.Variant{Name: prefix + ".m3u8", Size: int64(len(playlist)), SHA256: sha256.Sum256(playlist)}, bytes.NewReader(playlist))
		streams = append(streams, fmt.Sprintf("#EXT-X-STREAM-INF:BANDWIDTH=%d,RESOLUTION=%dx%d\n%s.m3u8\n",
			bandwidth, dimensions.Width, dimensions.Height, prefix))
	}

	if len(streams) > 0 {
		var master strings.Builder
		master.WriteString("#EXTM3U\n#EXT-X-VERSION:7\n")
		for i := len(streams) - 1; i >= 0; i-- {
			master.WriteString(streams[i])
		}

		playlist := []byte(master.String())
		if int64(len(playlist)) > remaining {
			return errors.New("video playlists exceed output budget")
		}
		remaining -= int64(len(playlist))
		addVariant(lifecycle.Variant{Name: "adaptive.m3u8", Size: int64(len(playlist)), SHA256: sha256.Sum256(playlist)}, bytes.NewReader(playlist))
	}
	if source.Duration >= 2*time.Second && remaining >= 2<<20 {
		for _, candidate := range []struct {
			name string
			at   time.Duration
		}{
			{name: "poster-25.jpg", at: source.Duration / 4},
			{name: "poster-60.jpg", at: source.Duration * 3 / 5},
		} {
			frame, err := j.Processor.poster(ctx, original, 1<<20, candidate.at)
			if errors.Is(err, errNoVideoOutput) {
				continue
			}
			if err != nil {
				return fmt.Errorf("prepare video poster %s: %w", candidate.name, err)
			}

			addVariant(lifecycle.Variant{Name: candidate.name, Size: int64(len(frame)), SHA256: sha256.Sum256(frame)}, bytes.NewReader(frame))
		}
	}

	return j.Prepared.InstallGuarded(ctx, id, inputs, expected, check, func(ctx context.Context) error {
		return j.Ledger.MarkVideoProcessed(ctx, id, lease, (source.Duration + time.Millisecond - 1).Milliseconds(), variants)
	})
}

func (p *Processor) validateOriginal(ctx context.Context, original *os.File) error {
	var progress bytes.Buffer
	args := []string{"ffmpeg", "-v", "error", "-nostdin", "-xerror", "-max_alloc", "268435456",
		"-threads", "2", "-err_detect", "explode", "-protocol_whitelist", "file,pipe", "-format_whitelist", "mov",
		"-codec_whitelist", "h264,hevc,av1,vp9,aac,mp3", "-i", "/input", "-map", "0:v:0", "-map", "0:a:0?",
		"-stats_period", "86400", "-progress", "pipe:1", "-f", "null", "-"}
	if err := p.run(ctx, original, &progress, 8192, args); err != nil {
		return err
	}
	if !bytes.HasSuffix(bytes.TrimSpace(progress.Bytes()), []byte("progress=end")) {
		return errors.New("incomplete video decode")
	}
	return nil
}
