package api

import "regexp"

// MaxHostname is the longest host name either side passes on: Linux keeps at most 64 bytes (HOST_NAME_MAX).
const MaxHostname = 64

// hostnameRE is RFC 1123 (section 2.1): labels of letters, digits and inner hyphens, 1 to 63 characters, joined by single dots.
var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// ValidHostname reports whether s is a host name the box shows and sends on (Info.Hostname): RFC 1123 labels, at most
// MaxHostname bytes, no trailing dot, no space, underscore, control or non-ASCII character. The name is text set by whoever runs the
// machine and ends in a device row and in the HOSTNAME of a syslog record, so the host checks it before answering and core again
// when it reads it; anything else is not passed on.
func ValidHostname(s string) bool {
	return len(s) <= MaxHostname && hostnameRE.MatchString(s)
}
