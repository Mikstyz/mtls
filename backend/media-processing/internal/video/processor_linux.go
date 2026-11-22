//go:build linux

package video

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"mtls/media-processing/internal/sandbox"
)

type Processor struct {
	systemd    string
	supervisor string
	bwrap      string
	runtime    string
	timeout    time.Duration
	slots      chan struct{}
}

func NewProcessor(systemd, supervisor, bwrap, runtime string, concurrency int, timeout time.Duration) (*Processor, error) {
	if concurrency < 1 || concurrency > 16 || timeout < time.Second || timeout > 6*time.Hour ||
		!filepath.IsAbs(runtime) || filepath.Clean(runtime) == "/" {
		return nil, errors.New("invalid video processor settings")
	}

	for _, path := range []string{systemd, supervisor, bwrap} {
		if !filepath.IsAbs(path) {
			return nil, errors.New("video executables require absolute paths")
		}
		file, err := sandbox.OpenExecutable(path)
		if err != nil {
			return nil, err
		}
		_ = file.Close()
	}

	return &Processor{
		systemd: systemd, supervisor: supervisor, bwrap: bwrap, runtime: runtime,
		timeout: timeout, slots: make(chan struct{}, concurrency),
	}, nil
}

const probeEntries = "format=format_name,duration:format_tags=major_brand:" +
	"stream=codec_type,codec_name,width,height,sample_aspect_ratio,avg_frame_rate,r_frame_rate:" +
	"stream_disposition=attached_pic:stream_side_data=rotation"

func (p *Processor) Probe(ctx context.Context, input *os.File, limits ProbeLimits) (Source, error) {
	var output bytes.Buffer
	args := []string{
		"ffprobe", "-v", "error", "-max_alloc", "67108864", "-protocol_whitelist", "file",
		"-format_whitelist", "mov", "-show_entries", probeEntries, "-of", "json", "/input",
	}

	if err := p.run(ctx, input, &output, MaxProbeOutput, args); err != nil {
		return Source{}, err
	}

	return ParseMP4Probe(output.Bytes(), limits)
}

// Transcode writes a fragmented MP4 to private staging. Discard any partial
// output on error and validate the output before registering a rendition.
func (p *Processor) Transcode(ctx context.Context, input *os.File, out io.Writer, maxBytes int64, source Source, dimensions Dimensions) error {
	if !slices.Contains(source.Renditions, dimensions) || dimensions.Width < 2 || dimensions.Height < 2 ||
		dimensions.Width > 16384 || dimensions.Height > 16384 ||
		dimensions.Width%2 != 0 || dimensions.Height%2 != 0 || maxBytes < 1 || maxBytes > 1<<40 {
		return errors.New("invalid video rendition")
	}

	scale := "scale=" + strconv.Itoa(dimensions.Width) + ":" + strconv.Itoa(dimensions.Height) + ",setsar=1"
	args := []string{
		"ffmpeg", "-v", "error", "-nostdin", "-xerror", "-max_alloc", "268435456",
		"-threads", "2", "-filter_threads", "1", "-err_detect", "explode", "-protocol_whitelist", "file,pipe",
		"-format_whitelist", "mov", "-codec_whitelist", "h264,hevc,av1,vp9,aac,mp3", "-i", "/input",
		"-map", "0:v:0", "-map", "0:a:0?", "-map_metadata", "-1", "-map_chapters", "-1",
		"-vf", scale, "-c:v", "libx264", "-threads:v", "2", "-pix_fmt", "yuv420p", "-preset", "fast", "-crf", "23",
		"-g", "10000", "-sc_threshold", "0", "-forced-idr", "1", "-force_key_frames", "expr:gte(t,n_forced*4)",
		"-c:a", "aac", "-ac", "2", "-ar", "48000", "-movflags", "+dash+frag_keyframe+empty_moov+default_base_moof",
		"-f", "mp4", "pipe:1",
	}

	return p.run(ctx, input, out, maxBytes, args)
}

var errNoVideoOutput = errors.New("video processor produced no output")

func (p *Processor) run(ctx context.Context, input *os.File, output io.Writer, maxBytes int64, args []string) error {
	if ctx == nil || input == nil || output == nil {
		return errors.New("invalid video processing request")
	}
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return errors.New("invalid video input")
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		return errors.New("video processor is busy")
	}

	files := make([]*os.File, 0, 5)
	for _, path := range []string{p.systemd, p.supervisor, p.bwrap} {
		file, err := sandbox.OpenExecutable(path)
		if err != nil {
			return err
		}
		defer file.Close()
		files = append(files, file)
	}

	root, err := openRuntime(p.runtime)
	if err != nil {
		return err
	}
	defer root.Close()

	runCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	scope := []string{
		"--user", "--scope", "--quiet", "--collect", "--property=MemoryMax=2G", "--property=MemorySwapMax=0",
		"--property=TasksMax=64", "--property=CPUQuota=200%", "/proc/self/fd/4",
	}
	cmd := exec.CommandContext(runCtx, "/proc/self/fd/3", append(scope, args...)...)
	cmd.ExtraFiles = append(files, root, input)
	cmd.Stderr = io.Discard

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open video processor output: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start video processor: %w", err)
	}

	limited := &io.LimitedReader{R: stdout, N: maxBytes}
	n, copyErr := io.Copy(output, limited)
	if copyErr == nil && limited.N == 0 {
		var extra [1]byte
		if _, err := io.ReadFull(stdout, extra[:]); err != io.EOF {
			copyErr = errors.New("video processor output exceeds limit")
		}
	}
	if copyErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()

	if err := runCtx.Err(); err != nil {
		return err
	}
	if copyErr != nil {
		return fmt.Errorf("read video processor output: %w", copyErr)
	}
	if waitErr != nil {
		return errors.New("video processor failed")
	}
	if n == 0 {
		return errNoVideoOutput
	}

	return nil
}

func openRuntime(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("invalid video runtime directory")
	}

	root := os.NewFile(uintptr(fd), "video-runtime")
	info, err := root.Stat()
	if err != nil || info.Mode().Perm()&0022 != 0 {
		_ = root.Close()
		return nil, errors.New("unsafe video runtime directory")
	}

	return root, nil
}
