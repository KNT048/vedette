package ops

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// dpkgLockFiles are the lock files apt and dpkg take with fcntl locks (relative to the root).
var dpkgLockFiles = []string{
	"var/lib/dpkg/lock-frontend",
	"var/lib/dpkg/lock",
	"var/lib/apt/lists/lock",
	"var/cache/apt/archives/lock",
}

// fcntlLockHeld asks the kernel whether another process holds a lock on path (F_GETLK), without
// taking one. A missing file means nobody holds it. A lock held by this very process is not
// reported (POSIX locks do not conflict with their owner), which cannot matter: the host never
// takes these locks itself, apt runs as a child.
func fcntlLockHeld(path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // fixed lock file path under the root
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("ops: open lock file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk); err != nil {
		return false, fmt.Errorf("ops: probe lock %s: %w", path, err)
	}
	return lk.Type != syscall.F_UNLCK, nil
}

// dpkgLocked reports whether any of the apt/dpkg lock files is held. A probe error counts as held:
// better to ask the caller to retry than to run apt into a lock.
func (o *Ops) dpkgLocked() bool {
	for _, rel := range dpkgLockFiles {
		held, err := o.d.LockHeld(o.path(rel))
		if err != nil {
			o.log.Warn("could not probe an apt lock; treating it as held", "file", rel)
			return true
		}
		if held {
			return true
		}
	}
	return false
}

const lockRetryS = 60

func lockedRefusal() error {
	return refuseRetry(409, "dpkg_locked", "Another apt or dpkg process (for example unattended-upgrades) holds the package lock. Try again in 60 seconds.", lockRetryS)
}
