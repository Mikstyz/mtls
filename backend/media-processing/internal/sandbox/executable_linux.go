//go:build linux

package sandbox

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func validExecutable(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&(os.ModeSetuid|os.ModeSetgid) == 0 &&
		info.Mode().Perm()&0111 != 0 && info.Mode().Perm()&0022 == 0
}

func OpenExecutable(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)

	if err != nil {
		return nil, errors.New("invalid sandbox executable")
	}

	file := os.NewFile(uintptr(fd), "sandbox-executable")

	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("invalid sandbox executable")
	}

	info, err := file.Stat()

	if err != nil || !validExecutable(info) {
		_ = file.Close()
		return nil, errors.New("invalid sandbox executable")
	}

	size, err := unix.Fgetxattr(fd, "security.capability", nil)

	if err != nil && !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		_ = file.Close()
		return nil, errors.New("cannot inspect sandbox executable capabilities")
	}

	if err == nil && size != 0 {
		_ = file.Close()
		return nil, errors.New("sandbox executable has file capabilities")
	}

	return file, nil
}
