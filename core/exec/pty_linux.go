//go:build linux

package exec

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openTerm opens a new pseudo-terminal (#830): its master end, which the Runner reads and drops while the child runs, and its peer,
// which becomes the child's stdin and controlling terminal. Neither becomes the controlling terminal of this process (O_NOCTTY).
// The peer is reached through the master (TIOCGPTPEER, Linux 4.13), never by a path under /dev/pts.
func openTerm(ptmx string) (master, peer *os.File, err error) {
	master, err = os.OpenFile(ptmx, os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0) //nolint:gosec // the Runner's fixed /dev/ptmx (a test points it elsewhere), never input
	if err != nil {
		return nil, nil, err
	}
	rc, err := master.SyscallConn() // not Fd(): it would put the master back in blocking mode, out of the poller
	if err != nil {
		_ = master.Close()
		return nil, nil, err
	}
	peerFD, opErr := -1, error(nil)
	if err := rc.Control(func(fd uintptr) {
		if opErr = unix.IoctlSetPointerInt(int(fd), unix.TIOCSPTLCK, 0); opErr != nil {
			opErr = fmt.Errorf("unlocking the terminal: %w", opErr)
			return
		}
		r, _, e := unix.Syscall(unix.SYS_IOCTL, fd, unix.TIOCGPTPEER, uintptr(unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC))
		if e != 0 {
			opErr = fmt.Errorf("opening the terminal's peer: %w", e)
			return
		}
		peerFD = int(r)
	}); err != nil {
		opErr = err
	}
	if opErr != nil {
		_ = master.Close()
		return nil, nil, opErr
	}
	return master, os.NewFile(uintptr(peerFD), "pty"), nil
}

// inTerminal makes the child the leader of a new session whose controlling terminal is its stdin (fd 0, the peer of openTerm), so it
// is the terminal's foreground process group: nmap's tty_init checks exactly that (tcgetpgrp of /dev/tty == getpgrp). A new
// session is a new process group too (its id is the child's pid), so killGroup still reaches every process of the run; Setpgid
// is cleared because a session leader cannot change its group.
func inTerminal(a *syscall.SysProcAttr) {
	a.Setpgid = false
	a.Setsid, a.Setctty, a.Ctty = true, true, 0
}
