//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
	"mtls/media-processing/internal/sandbox"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "photo isolation unavailable")
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 2 {
		return errors.New("invalid arguments")
	}

	if err := sandbox.VerifyCgroup(sandbox.Limits{MemoryBytes: 384 << 20, Processes: 32, CPUs: 1}); err != nil {
		return err
	}

	if len(os.Args) == 1 {
		return nil
	}

	edge, err := strconv.Atoi(os.Args[1])

	if err != nil || edge < 1 || edge > 2048 {
		return errors.New("invalid preview size")
	}

	filterFD, err := sandbox.SeccompFile()

	if err != nil {
		return err
	}

	defer unix.Close(filterFD)
	args := []string{
		"bwrap", "--unshare-all", "--unshare-user", "--disable-userns", "--cap-drop", "ALL",
		"--die-with-parent", "--new-session", "--clearenv", "--seccomp", strconv.Itoa(filterFD),
		"--setenv", "GOMEMLIMIT", "256MiB", "--setenv", "GOMAXPROCS", "1",
		"--ro-bind-fd", "6", "/worker", "/worker", strconv.Itoa(edge),
	}

	return unix.Exec("/proc/self/fd/5", args, []string{})
}
