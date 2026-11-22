//go:build linux

package video

import (
	"bytes"
	"context"
	"errors"
	"image/jpeg"
	"os"
	"strconv"
	"time"
)

func posterArgs(at time.Duration) []string {
	seconds := strconv.FormatFloat(at.Seconds(), 'f', 3, 64)
	return []string{
		"ffmpeg", "-v", "error", "-nostdin", "-xerror", "-max_alloc", "268435456",
		"-threads", "2", "-filter_threads", "1", "-err_detect", "explode", "-protocol_whitelist", "file,pipe",
		"-format_whitelist", "mov", "-codec_whitelist", "h264,hevc,av1,vp9,aac,mp3", "-ss", seconds, "-i", "/input",
		"-map", "0:v:0", "-frames:v", "1", "-map_metadata", "-1", "-map_chapters", "-1",
		"-vf", "scale=w='min(640,iw)':h='min(640,ih)':force_original_aspect_ratio=decrease,setsar=1",
		"-c:v", "mjpeg", "-threads:v", "1", "-pix_fmt", "yuvj444p", "-q:v", "4", "-f", "image2pipe", "pipe:1",
	}
}

func (p *Processor) poster(ctx context.Context, input *os.File, maxBytes int64, at time.Duration) ([]byte, error) {
	var output bytes.Buffer
	if err := p.run(ctx, input, &output, min(maxBytes, 1<<20), posterArgs(at)); err != nil {
		return nil, err
	}

	data := output.Bytes()
	config, err := jpeg.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width < 1 || config.Height < 1 || config.Width > 640 || config.Height > 640 ||
		!bytes.HasSuffix(data, []byte{0xff, 0xd9}) {
		return nil, errors.New("invalid video poster")
	}

	return data, nil
}
