//go:build !linux

package ops

import "errors"

// systemNeighDump: there is no netlink here. The host is a Linux program; this keeps the package building on a
// developer's Mac (state/net then reports no gateway MAC).
func systemNeighDump() ([]byte, error) {
	return nil, errors.New("ops: no neighbour table on this system")
}
