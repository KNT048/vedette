//go:build linux

package ops

import "syscall"

// unmountDetach lazily unmounts p (umount -l): the mount of an orphaned container that ended (orphans.go).
func unmountDetach(p string) error { return syscall.Unmount(p, syscall.MNT_DETACH) }
