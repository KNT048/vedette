//go:build linux

package ops

import "syscall"

// systemNeighDump asks the kernel for its neighbour table (ARP and IPv6 neighbour discovery) with one netlink dump, the
// same kind of request the net package makes to list the interfaces. No program runs and no network socket opens (NET-1).
// ponytail: the whole dump is read (the kernel bounds it with gc_thresh3, 1024 entries per family by default); a
// one-entry RTM_GETNEIGH get needs a socket of our own, the upgrade if a box ever holds a huge table.
func systemNeighDump() ([]byte, error) {
	return syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_UNSPEC)
}

// systemAddrDump asks the kernel for every address with one netlink RTM_GETADDR dump: the net package drops the flag that says
// whether an address came from a lease (D-405). No program runs and no network socket opens (NET-1).
func systemAddrDump() ([]byte, error) {
	return syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
}
