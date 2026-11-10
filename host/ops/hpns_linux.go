//go:build linux

package ops

import (
	"os"

	"golang.org/x/sys/unix"
)

// isNetNS asks the descriptor what it is: on nsfs (a bind-mounted namespace), a network namespace by
// NS_GET_NSTYPE, and not the one this process runs in (a link to the host's own namespace would put
// decoys, and the egress ruleset, on the box itself).
func isNetNS(f *os.File) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return false, err
	}
	if int64(st.Type) != unix.NSFS_MAGIC { //nolint:unconvert // Statfs_t.Type is int32 or int64 by architecture
		return false, nil
	}
	typ, err := unix.IoctlGetInt(int(f.Fd()), unix.NS_GET_NSTYPE)
	if err != nil || typ != unix.CLONE_NEWNET {
		return false, err
	}
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return false, err
	}
	return !os.SameFile(fi, self), nil
}
