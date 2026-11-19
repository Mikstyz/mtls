//go:build linux

package photo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"mtls/media-processing/internal/imageprep"
	"mtls/media-processing/internal/sandbox"
)

var ErrProcessorBusy = errors.New("photo processor is busy")

type Processor struct {
	systemd    string
	supervisor string
	bwrap      string
	worker     string
	timeout    time.Duration
	slots      chan struct{}
}

// NewProcessor requires trusted, immutable executables; isolation failure is fatal.
func NewProcessor(systemd, supervisor, bwrap, worker string, concurrency int, timeout time.Duration) (*Processor, error) {
	if concurrency < 1 || concurrency > 64 || timeout < time.Second || timeout > 5*time.Minute {
		return nil, errors.New("invalid photo processor settings")
	}

	for _, path := range []string{systemd, supervisor, bwrap, worker} {
		if !filepath.IsAbs(path) {
			return nil, errors.New("photo executables require absolute paths")
		}

		file, err := sandbox.OpenExecutable(path)

		if err != nil {
			return nil, err
		}

		_ = file.Close()
	}

	return &Processor{
		systemd:    systemd,
		supervisor: supervisor,
		bwrap:      bwrap,
		worker:     worker,
		timeout:    timeout,
		slots:      make(chan struct{}, concurrency),
	}, nil
}

// Prepare uses a read-only sandbox without access to the host filesystem or network.
func (p *Processor) Prepare(ctx context.Context, input []byte, maxEdge int) ([]byte, error) {
	if ctx == nil || len(input) == 0 || len(input) > imageprep.MaxInputBytes || maxEdge < 1 || maxEdge > 2048 {
		return nil, errors.New("invalid image preparation request")
	}

	release, err := p.acquire(ctx)

	if err != nil {
		return nil, err
	}

	defer release()
	return p.prepareLocked(ctx, input, maxEdge)
}

func (p *Processor) acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	select {
	case p.slots <- struct{}{}:
		return func() { <-p.slots }, nil
	default:
		return nil, ErrProcessorBusy
	}
}

func (p *Processor) prepareLocked(ctx context.Context, input []byte, maxEdge int) ([]byte, error) {
	runCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	systemd, err := sandbox.OpenExecutable(p.systemd)

	if err != nil {
		return nil, err
	}

	defer systemd.Close()

	supervisor, err := sandbox.OpenExecutable(p.supervisor)

	if err != nil {
		return nil, err
	}

	defer supervisor.Close()

	bwrap, err := sandbox.OpenExecutable(p.bwrap)

	if err != nil {
		return nil, err
	}

	defer bwrap.Close()

	worker, err := sandbox.OpenExecutable(p.worker)

	if err != nil {
		return nil, err
	}

	defer worker.Close()

	cmd := exec.CommandContext(runCtx, "/proc/self/fd/3",
		"--user", "--scope", "--quiet", "--collect",
		"--property=MemoryMax=384M", "--property=MemorySwapMax=0",
		"--property=TasksMax=32", "--property=CPUQuota=100%",
		"/proc/self/fd/4", strconv.Itoa(maxEdge))
	cmd.ExtraFiles = []*os.File{systemd, supervisor, bwrap, worker}
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stderr = io.Discard

	stdout, err := cmd.StdoutPipe()

	if err != nil {
		return nil, errors.New("cannot initialize photo processor")
	}

	if err := cmd.Start(); err != nil {
		return nil, errors.New("cannot start photo processor")
	}

	output, readErr := io.ReadAll(io.LimitReader(stdout, imageprep.MaxOutputBytes+1))

	if readErr != nil || len(output) > imageprep.MaxOutputBytes {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		if err := runCtx.Err(); err != nil {
			return nil, err
		}

		return nil, errors.New("photo processor output invalid")
	}

	waitErr := cmd.Wait()

	if err := runCtx.Err(); err != nil {
		return nil, err
	}

	if waitErr != nil || len(output) == 0 {
		return nil, errors.New("photo processor failed")
	}

	return output, nil
}
