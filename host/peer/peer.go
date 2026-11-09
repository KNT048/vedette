// Package peer authenticates the process on the other end of the host socket (spec section 3).
// Layer 1 (file permissions) is the server's; this package does layers 2 and 3:
//
//  2. SO_PEERCRED uid equals the configured core uid;
//  3. the peer pid's /proc/<pid>/cgroup places it inside the core unit's cgroup.
//
// A Checker is a function value so tests inject a fake peer. There is no real Checker off
// Linux: New returns ErrUnsupportedOS and the binary refuses to run (fail closed).
package peer

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Info identifies an allowed peer. Unit is the unit its cgroup matched.
type Info struct {
	UID  int
	PID  int
	Unit string
}

// Checker authenticates one accepted connection. It returns the peer or an error; any error means deny.
// On denial it may still return the credentials it read, for the audit line.
type Checker func(conn net.Conn) (Info, error)

var (
	// ErrNotAllowed means the peer failed a layer.
	ErrNotAllowed = errors.New("peer: not allowed")
	// ErrUnsupportedOS means there is no real check on this platform.
	ErrUnsupportedOS = errors.New("peer: unsupported operating system (SO_PEERCRED and /proc need Linux)")
)

// Cred is what SO_PEERCRED returns.
type Cred struct {
	UID int
	PID int
}

// maxCgroupFile bounds how much of /proc/<pid>/cgroup is read.
const maxCgroupFile = 64 << 10

var unitRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9:_.@-]{0,100}\.service$`)

// Decide applies layers 2 and 3 to credentials already read. readCgroup returns the contents of
// /proc/<pid>/cgroup. It is split out so it runs (and is tested) on every OS.
func Decide(c Cred, coreUID int, unit, anchor string, readCgroup func(pid int) ([]byte, error)) (Info, error) {
	info := Info{UID: c.UID, PID: c.PID}
	if anchor == "" {
		anchor = DefaultAnchor(unit)
	}
	switch {
	case coreUID <= 0 || !unitRE.MatchString(unit) || ValidAnchor(anchor) != nil:
		return info, fmt.Errorf("%w: checker is misconfigured", ErrNotAllowed)
	case c.UID != coreUID:
		return info, fmt.Errorf("%w: uid %d is not the core uid", ErrNotAllowed, c.UID)
	case c.PID <= 0:
		return info, fmt.Errorf("%w: no pid", ErrNotAllowed)
	}
	data, err := readCgroup(c.PID)
	if err != nil {
		return info, fmt.Errorf("%w: cgroup of pid %d unreadable: %w", ErrNotAllowed, c.PID, err)
	}
	if !InUnit(data, anchor) {
		return info, fmt.Errorf("%w: pid %d is not in %s", ErrNotAllowed, c.PID, unit)
	}
	info.Unit = unit
	return info, nil
}

// DefaultAnchor is where a system-level unit lives in the unified hierarchy.
func DefaultAnchor(unit string) string { return "/system.slice/" + unit }

// ValidAnchor accepts an absolute, clean cgroup path without control characters (the optional
// core_cgroup key of host.conf, for a core that runs as a user service under a user manager).
func ValidAnchor(p string) error {
	if len(p) < 2 || len(p) > 256 || p[0] != '/' || strings.HasSuffix(p, "/") || strings.Contains(p, "//") {
		return errors.New("cgroup path must be absolute and clean")
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] == 0x7f {
			return errors.New("cgroup path contains a space or control character")
		}
	}
	for comp := range strings.SplitSeq(p[1:], "/") {
		if comp == "." || comp == ".." {
			return errors.New("cgroup path must not contain '.' or '..' components")
		}
	}
	return nil
}

// InUnit reports whether the contents of a /proc/<pid>/cgroup file (cgroup v2) put the process
// inside the anchor cgroup: the file is exactly one line "0::<path>" and path equals anchor or
// lies below it (anchor + "/..."). Quadlet/Podman containers sit in a sub-cgroup of their unit.
// Anchoring (not "the unit name appears somewhere") is what stops a same-uid process from
// matching by creating a cgroup named like the unit under another parent. Pure and fail-closed:
// control characters (a cgroup directory name may hold a newline), more or fewer than one line,
// a v1 or hybrid layout, an oversized file or a "(deleted)" path all give false.
func InUnit(data []byte, anchor string) bool {
	if len(data) == 0 || len(data) > maxCgroupFile || ValidAnchor(anchor) != nil {
		return false
	}
	text := strings.TrimSuffix(string(data), "\n")
	for i := 0; i < len(text); i++ {
		if c := text[i]; c < 0x20 || c == 0x7f {
			return false // includes a second line: only exactly one line is accepted
		}
	}
	path, ok := strings.CutPrefix(text, "0::")
	if !ok || strings.HasSuffix(path, " (deleted)") {
		return false
	}
	return path == anchor || strings.HasPrefix(path, anchor+"/")
}

// PidFromFdinfo reads the "Pid:" line of /proc/self/fdinfo/<pidfd>: the pid the pidfd refers to
// in our pid namespace, or -1 once that process is gone (reported as an error).
func PidFromFdinfo(data []byte) (int, error) {
	for line := range strings.SplitSeq(string(data), "\n") {
		v, ok := strings.CutPrefix(line, "Pid:")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n <= 0 {
			return 0, errors.New("process is gone")
		}
		return n, nil
	}
	return 0, errors.New("no Pid line in fdinfo")
}

// StartTicks returns field 22 (starttime, in clock ticks since boot) of /proc/<pid>/stat. The
// command name (field 2) may contain spaces and parentheses, so parsing starts after the last ")".
func StartTicks(stat []byte) (uint64, error) {
	s := string(stat)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, errors.New("malformed stat")
	}
	fields := strings.Fields(s[i+1:])
	// After ")" the fields are 3..: state is field 3, starttime is field 22, so index 19.
	if len(fields) < 20 {
		return 0, errors.New("malformed stat")
	}
	n, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, errors.New("malformed stat")
	}
	return n, nil
}
