//go:build linux

package sandbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// SeccompFile returns a filter FD for bubblewrap to install before exec.
func SeccompFile() (int, error) {
	var arch uint32

	switch runtime.GOARCH {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	default:
		return -1, errors.New("unsupported sandbox architecture")
	}

	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: arch},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	}

	if runtime.GOARCH == "amd64" {
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: 0x40000000},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		)
	}

	filter = append(filter,
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 4, K: unix.SYS_CLONE},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jt: 1, K: unix.CLONE_THREAD},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_CLONE3},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
	)

	blocked := []uint32{
		unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_BIND,
		unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4, unix.SYS_SENDTO,
		unix.SYS_SENDMSG, unix.SYS_RECVFROM, unix.SYS_RECVMSG,
		unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_SETNS,
		unix.SYS_UNSHARE, unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
		unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_KEYCTL, unix.SYS_ADD_KEY,
		unix.SYS_REQUEST_KEY, unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER,
		unix.SYS_IO_URING_REGISTER, unix.SYS_KEXEC_LOAD, unix.SYS_OPEN_BY_HANDLE_AT,
	}

	if runtime.GOARCH == "amd64" {
		blocked = append(blocked, 57, 58) // fork and vfork do not exist on arm64.
	}

	for _, number := range blocked {
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: number},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		)
	}

	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	data := make([]byte, len(filter)*8)

	for i, instruction := range filter {
		offset := i * 8
		binary.LittleEndian.PutUint16(data[offset:offset+2], instruction.Code)
		data[offset+2], data[offset+3] = instruction.Jt, instruction.Jf
		binary.LittleEndian.PutUint32(data[offset+4:offset+8], instruction.K)
	}

	fd, err := unix.MemfdCreate("media-filter", 0)

	if err != nil {
		return -1, fmt.Errorf("create seccomp filter: %w", err)
	}

	for len(data) > 0 {
		n, err := unix.Write(fd, data)

		if err != nil || n == 0 {
			_ = unix.Close(fd)
			return -1, errors.New("cannot write seccomp filter")
		}

		data = data[n:]
	}

	if _, err := unix.Seek(fd, 0, 0); err != nil {
		_ = unix.Close(fd)
		return -1, errors.New("cannot rewind seccomp filter")
	}

	return fd, nil
}
