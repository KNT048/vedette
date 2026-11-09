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
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"
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
func Decide(c Cred, coreUID int, unit string, readCgroup func(pid int) ([]byte, error)) (Info, error) {
	info := Info{UID: c.UID, PID: c.PID}
	switch {
	case coreUID <= 0 || !unitRE.MatchString(unit):
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
	if !InUnit(data, unit) {
		return info, fmt.Errorf("%w: pid %d is not in %s", ErrNotAllowed, c.PID, unit)
	}
	info.Unit = unit
	return info, nil
}

// InUnit reports whether the contents of a /proc/<pid>/cgroup file (cgroup v2) put the process
// inside the cgroup of the systemd unit: some path component of the unified ("0::") line equals
// the unit name. Quadlet/Podman containers sit in a sub-cgroup of their unit, so a component
// match, not an exact path, is the right test. Pure and fail-closed: anything unexpected
// (no unified line, a second unified line, an oversized file, a "(deleted)" path) is false.
func InUnit(data []byte, unit string) bool {
	if len(data) == 0 || len(data) > maxCgroupFile || bytes.IndexByte(data, 0) >= 0 || !unitRE.MatchString(unit) {
		return false
	}
	var path string
	found := false
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		id, rest, ok := strings.Cut(line, ":")
		if !ok {
			return false
		}
		controllers, p, ok := strings.Cut(rest, ":")
		if !ok {
			return false
		}
		if id != "0" || controllers != "" {
			continue // a cgroup v1 or hybrid line: only the unified hierarchy decides
		}
		if found {
			return false
		}
		found, path = true, p
	}
	if !found || !strings.HasPrefix(path, "/") || strings.HasSuffix(path, " (deleted)") {
		return false
	}
	for comp := range strings.SplitSeq(path, "/") {
		if comp == ".." {
			return false
		}
		if comp == unit {
			return true
		}
	}
	return false
}
