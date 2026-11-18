package store

import (
	"errors"
	"fmt"
	"syscall"
)

// DiskFree is the space an unprivileged writer may use on the filesystem of dir, in bytes.
func DiskFree(dir string) (int64, error) {
	if dir == "" {
		return 0, errors.New("no data directory configured")
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", dir, err)
	}
	return int64(st.Bavail) * int64(st.Bsize), nil //nolint:gosec,unconvert // block counts of a real filesystem fit; Bsize differs in type between Linux and macOS
}
