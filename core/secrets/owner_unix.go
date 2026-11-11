//go:build unix

package secrets

import (
	"io/fs"
	"syscall"
)

// ownerOf reads the numeric owner and group of a file (Linux and macOS).
func ownerOf(info fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
