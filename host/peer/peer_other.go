//go:build !linux

package peer

// New has no real implementation off Linux: SO_PEERCRED and /proc/<pid>/cgroup do not exist.
// The caller must refuse to start.
func New(int, string, string) (Checker, error) { return nil, ErrUnsupportedOS }
