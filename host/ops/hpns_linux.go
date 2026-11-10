//go:build linux

package ops

import (
	"os"

	"golang.org/x/sys/unix"
)

// isNsfs asks the descriptor which filesystem it is on: a bind-mounted network namespace is on nsfs.
func isNsfs(f *os.File) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return false, err
	}
	return int64(st.Type) == unix.NSFS_MAGIC, nil //nolint:unconvert // Statfs_t.Type is int32 or int64 by architecture
}
