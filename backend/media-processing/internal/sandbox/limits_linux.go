//go:build linux

package sandbox

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type Limits struct {
	MemoryBytes uint64
	Processes   uint64
	CPUs        uint64
}

func VerifyCgroup(limits Limits) error {
	var fs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &fs); err != nil || uint64(fs.Type) != uint64(unix.CGROUP2_SUPER_MAGIC) {
		return errors.New("cgroup v2 is required")
	}

	membership, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return errors.New("cannot inspect process cgroup")
	}

	group := ""
	for _, line := range strings.Split(string(membership), "\n") {
		if strings.HasPrefix(line, "0::/") {
			if group != "" {
				return errors.New("ambiguous cgroup")
			}
			group = strings.TrimPrefix(line, "0::")
		}
	}
	if group == "" || !filepath.IsAbs(group) || filepath.Clean(group) != group {
		return errors.New("invalid process cgroup")
	}

	return verifyLimits(filepath.Join("/sys/fs/cgroup", group), limits)
}

func verifyLimits(group string, limits Limits) error {
	read := func(name string) (string, error) {
		file, err := os.Open(filepath.Join(group, name))

		if err != nil {
			return "", errors.New("cannot read cgroup limits")
		}

		defer file.Close()
		value, err := io.ReadAll(io.LimitReader(file, 129))

		if err != nil || len(value) > 128 {
			return "", errors.New("invalid cgroup limits")
		}

		return strings.TrimSpace(string(value)), nil
	}

	for _, item := range []struct {
		name string
		max  uint64
	}{{"memory.max", limits.MemoryBytes}, {"memory.swap.max", 0}, {"pids.max", limits.Processes}} {
		value, err := read(item.name)

		if err != nil {
			return err
		}

		number, err := strconv.ParseUint(value, 10, 64)

		if err != nil || number > item.max || (item.name != "memory.swap.max" && number == 0) {
			return errors.New("unsafe cgroup limit")
		}
	}

	cpu, err := read("cpu.max")

	if err != nil {
		return err
	}

	parts := strings.Fields(cpu)

	if len(parts) != 2 {
		return errors.New("invalid cpu limit")
	}

	quota, quotaErr := strconv.ParseUint(parts[0], 10, 64)
	period, periodErr := strconv.ParseUint(parts[1], 10, 64)

	if quotaErr != nil || periodErr != nil || quota == 0 || period == 0 || (quota-1)/period >= limits.CPUs {
		return errors.New("unsafe cpu limit")
	}

	return nil
}
