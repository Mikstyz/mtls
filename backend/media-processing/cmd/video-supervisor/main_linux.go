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
		fmt.Fprintln(os.Stderr, "video isolation unavailable")
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 || len(os.Args) > 96 || (os.Args[1] != "ffprobe" && os.Args[1] != "ffmpeg") {
		return errors.New("invalid video worker command")
	}

	if err := sandbox.VerifyCgroup(sandbox.Limits{MemoryBytes: 2 << 30, Processes: 64, CPUs: 2}); err != nil {
		return err
	}

	filter, err := sandbox.SeccompFile()
	if err != nil {
		return err
	}
	defer unix.Close(filter)

	args := []string{
		"bwrap", "--unshare-all", "--unshare-user", "--disable-userns", "--cap-drop", "ALL",
		"--die-with-parent", "--new-session", "--clearenv", "--seccomp", strconv.Itoa(filter),
		"--ro-bind-fd", "6", "/", "--ro-bind-fd", "7", "/input", "--chdir", "/",
		"/usr/bin/" + os.Args[1],
	}
	args = append(args, os.Args[2:]...)

	return unix.Exec("/proc/self/fd/5", args, []string{})
}
