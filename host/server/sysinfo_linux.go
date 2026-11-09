//go:build linux

package server

import (
	"syscall"
	"time"
)

// systemInfo returns the kernel release and the boot time.
func systemInfo(now time.Time) (kernel string, booted time.Time) {
	kernel = "unknown"
	var u syscall.Utsname
	if syscall.Uname(&u) == nil {
		b := make([]byte, 0, len(u.Release))
		for _, c := range u.Release {
			if c == 0 {
				break
			}
			b = append(b, byte(c)) //nolint:gosec // Utsname is char data: int8 on amd64, uint8 elsewhere
		}
		if s := string(b); osTokenRE.MatchString(s) {
			kernel = s
		}
	}
	var si syscall.Sysinfo_t
	if syscall.Sysinfo(&si) == nil {
		booted = now.Add(-time.Duration(si.Uptime) * time.Second).UTC().Truncate(time.Second)
	}
	return kernel, booted
}
