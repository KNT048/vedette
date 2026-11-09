//go:build linux

package peer

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
)

// New returns the real checker: SO_PEERCRED uid == coreUID and the peer's cgroup contains unit.
func New(coreUID int, unit string) (Checker, error) {
	if _, err := Decide(Cred{UID: coreUID, PID: 1}, coreUID, unit, func(int) ([]byte, error) { return []byte("0::/" + unit + "\n"), nil }); err != nil {
		return nil, fmt.Errorf("peer: %w", err)
	}
	return func(conn net.Conn) (Info, error) {
		c, err := credentials(conn)
		if err != nil {
			return Info{}, fmt.Errorf("%w: %w", ErrNotAllowed, err)
		}
		return Decide(c, coreUID, unit, readCgroup)
	}, nil
}

func credentials(conn net.Conn) (Cred, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Cred{}, fmt.Errorf("connection is %T, not a unix socket", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Cred{}, err
	}
	var (
		ucred *syscall.Ucred
		gerr  error
	)
	if err := raw.Control(func(fd uintptr) {
		ucred, gerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Cred{}, err
	}
	if gerr != nil {
		return Cred{}, gerr
	}
	return Cred{UID: int(ucred.Uid), PID: int(ucred.Pid)}, nil
}

func readCgroup(pid int) ([]byte, error) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxCgroupFile+1))
}
