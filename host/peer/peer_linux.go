//go:build linux

package peer

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// userHZ is the unit of /proc/<pid>/stat starttime: USER_HZ is 100 on every Linux ABI we run on.
const userHZ = 100

// New returns the real checker: SO_PEERCRED uid == coreUID and the peer's cgroup is anchor or
// below it (anchor "" means /system.slice/<unit>). The pid read from SO_PEERCRED could be reused
// by another process before /proc is read; the check closes that window with SO_PEERPIDFD
// (Linux 6.5+): the pidfd pins the process, and fdinfo must still name the same pid after the
// cgroup was read. Older kernels fall back to refusing a process that started after the accept.
func New(coreUID int, unit, anchor string) (Checker, error) {
	want := anchor
	if want == "" {
		want = DefaultAnchor(unit)
	}
	fake := func(int) ([]byte, error) { return []byte("0::" + want + "\n"), nil }
	if _, err := Decide(Cred{UID: coreUID, PID: 1}, coreUID, unit, anchor, fake); err != nil {
		return nil, fmt.Errorf("peer: %w", err)
	}
	return func(conn net.Conn) (Info, error) {
		accepted := time.Now()
		c, pidfd, err := credentials(conn)
		if err != nil {
			return Info{}, fmt.Errorf("%w: %w", ErrNotAllowed, err)
		}
		if pidfd >= 0 {
			defer func() { _ = unix.Close(pidfd) }()
		}
		return Decide(c, coreUID, unit, anchor, func(pid int) ([]byte, error) {
			return readCgroupPinned(pid, pidfd, accepted)
		})
	}, nil
}

// credentials returns SO_PEERCRED and, when the kernel supports it, a pidfd for the peer (else -1).
func credentials(conn net.Conn) (Cred, int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Cred{}, -1, fmt.Errorf("connection is %T, not a unix socket", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Cred{}, -1, err
	}
	var (
		ucred *unix.Ucred
		gerr  error
		pidfd = -1
	)
	if err := raw.Control(func(fd uintptr) {
		ucred, gerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if gerr == nil {
			if v, e := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD); e == nil {
				pidfd = v
			}
		}
	}); err != nil {
		return Cred{}, -1, err
	}
	if gerr != nil {
		return Cred{}, -1, gerr
	}
	return Cred{UID: int(ucred.Uid), PID: int(ucred.Pid)}, pidfd, nil
}

// readCgroupPinned reads /proc/<pid>/cgroup and proves the pid still names the peer process.
func readCgroupPinned(pid, pidfd int, accepted time.Time) ([]byte, error) {
	if pidfd >= 0 {
		if err := pidfdNames(pidfd, pid); err != nil {
			return nil, err
		}
	} else if err := notStartedAfter(pid, accepted); err != nil {
		return nil, err
	}
	data, err := readProc(pid, "cgroup", maxCgroupFile+1)
	if err != nil {
		return nil, err
	}
	if pidfd >= 0 {
		if err := pidfdNames(pidfd, pid); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func pidfdNames(pidfd, pid int) error {
	b, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(pidfd))
	if err != nil {
		return err
	}
	got, err := PidFromFdinfo(b)
	if err != nil {
		return err
	}
	if got != pid {
		return fmt.Errorf("pidfd names pid %d, not %d", got, pid)
	}
	return nil
}

// notStartedAfter is the fallback for kernels without SO_PEERPIDFD: a process whose start time is
// after the accept cannot be the one that connected, so the pid was reused.
func notStartedAfter(pid int, accepted time.Time) error {
	stat, err := readProc(pid, "stat", 4096)
	if err != nil {
		return err
	}
	ticks, err := StartTicks(stat)
	if err != nil {
		return err
	}
	sys, err := readFile("/proc/stat", 1<<20)
	if err != nil {
		return err
	}
	var btime int64
	for line := range strings.SplitSeq(string(sys), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			btime, err = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return errors.New("bad btime")
			}
		}
	}
	if btime <= 0 {
		return errors.New("no btime")
	}
	if ticks > 1<<40 {
		return errors.New("implausible start time")
	}
	started := time.Unix(btime, 0).Add(time.Duration(int64(ticks)) * time.Second / userHZ)
	if started.After(accepted.Add(time.Second)) { // one second of tick and btime rounding
		return errors.New("the process started after the connection was accepted")
	}
	return nil
}

func readProc(pid int, name string, limit int64) ([]byte, error) {
	return readFile("/proc/"+strconv.Itoa(pid)+"/"+name, limit)
}

func readFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // fixed /proc paths built from a numeric pid
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit))
}
