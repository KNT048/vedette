//go:build linux

package server

import (
	"syscall"
	"time"

	"github.com/knt048/vedette/host/api"
)

// systemInfo returns the kernel release, the OS host name ("" when it fails api.ValidHostname) and the boot time. vedette-host
// shares the machine's UTS namespace (its unit may not set ProtectHostname=, deploy/systemd/unit_test.go), so the node name is the
// machine's.
func systemInfo(now time.Time) (kernel, hostname string, booted time.Time) {
	kernel = "unknown"
	var u syscall.Utsname
	if syscall.Uname(&u) == nil {
		if s := utsString(u.Release[:]); osTokenRE.MatchString(s) {
			kernel = s
		}
		if s := utsString(u.Nodename[:]); api.ValidHostname(s) {
			hostname = s
		}
	}
	var si syscall.Sysinfo_t
	if syscall.Sysinfo(&si) == nil {
		booted = now.Add(-time.Duration(si.Uptime) * time.Second).UTC().Truncate(time.Second)
	}
	return kernel, hostname, booted
}

// utsString is a NUL-terminated field of Utsname.
func utsString[T int8 | uint8](f []T) string {
	b := make([]byte, 0, len(f))
	for _, c := range f {
		if c == 0 {
			break
		}
		b = append(b, byte(c)) // Utsname is char data: int8 on amd64, uint8 elsewhere
	}
	return string(b)
}
