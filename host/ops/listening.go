package ops

import (
	"cmp"
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/host/api"
)

// readPorts is GET /v1/state/ports (inventory INV-3, host INV-9b): the ports the box listens on at an address other than loopback,
// for its own device's Open services. The box is never scanned by its own sensor, and an agent-style list is what it can give of
// itself (Defender, runZero and Lansweeper list an agent's listening ports the same way). It reads the kernel's socket tables and,
// for the sockets it keeps, which processes hold them (the reading of D-455's port check): no program runs, no socket is opened.
// A TCP socket in LISTEN or a UDP socket with no peer counts when another machine of the network can reach it: bound to every
// address (0.0.0.0, ::) or to an address of one of the box's network cards (a device with a hardware parent, or the management
// interface). One bound to loopback, to a container bridge (Podman's aardvark-dns on 10.89.0.1:53, docker0) or to any other virtual
// link is not listed: only the box itself reaches it.
// A table that exists but cannot be read to its end, or no IPv4 TCP table, fails the read (core keeps what it has); the other tables
// say nothing when absent.
func (o *Ops) readPorts(ctx context.Context) (any, error) {
	socks, err := o.socketsWhole()
	if err != nil {
		return nil, err
	}
	type key struct {
		port uint16
		udp  bool
	}
	inodes := map[key][]uint64{}
	want := map[uint64]bool{}
	lan := o.cardAddrs()
	for _, s := range socks {
		if (!s.addr.IsUnspecified() && !lan[s.addr]) || (s.udp && s.peer) {
			continue
		}
		k := key{s.port, s.udp}
		inodes[k] = append(inodes[k], s.inode)
		want[s.inode] = true
	}
	owners := o.socketOwners(want, "")
	out := api.PortsState{Ports: make([]api.ListenPort, 0, len(inodes))}
	for k, list := range inodes {
		p := api.ListenPort{Port: int(k.port), Proto: api.ProtoTCP}
		if k.udp {
			p.Proto = api.ProtoUDP
		}
		p.Process = o.portOwner(list, owners)
		out.Ports = append(out.Ports, p)
	}
	slices.SortFunc(out.Ports, func(a, b api.ListenPort) int {
		return cmp.Or(cmp.Compare(a.Proto, b.Proto), cmp.Compare(a.Port, b.Port))
	})
	if len(out.Ports) > api.MaxPorts {
		o.log.WarnContext(ctx, "ports: the box listens on more ports than the list holds; the lowest are listed", "ports", len(out.Ports), "listed", api.MaxPorts)
		out.Ports = out.Ports[:api.MaxPorts]
	}
	return out, ctx.Err()
}

// cardAddrs are the addresses of the box's network cards: interfaces with a hardware parent (sysfs device link) and the management
// interface (netplan's, or the default route's before the host configured it); never loopback, bridges, veth or macvlan links. None
// when the interfaces cannot be listed: then only sockets bound to every address are listed.
func (o *Ops) cardAddrs() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	if o.d.Interfaces == nil {
		return out
	}
	ifaces, err := o.d.Interfaces()
	if err != nil {
		return out
	}
	mgmt := ""
	if cfg, managed := o.readNetplanConfig(); managed {
		mgmt = cfg.Mgmt.Iface
	} else if r := o.defaultRoute(); r != nil {
		mgmt = r.Iface
	}
	sys := openSysfs(o.d.Root)
	defer sys.close()
	for _, h := range ifaces {
		if h.Loopback || !validIfaceName(h.Name) || (h.Name != mgmt && !sys.physical(h.Name)) {
			continue
		}
		for _, p := range h.Addrs {
			if a := p.Addr().Unmap().WithZone(""); !a.IsLoopback() {
				out[a] = true
			}
		}
	}
	return out
}

// portOwner names what holds a port: the first named owner of its sockets in the order of the inodes (lowest pid first among the
// owners of one socket), "" when none was found.
func (o *Ops) portOwner(inodes []uint64, owners map[uint64][]sockOwner) string {
	for _, ino := range inodes {
		ow := slices.Clone(owners[ino])
		slices.SortFunc(ow, func(a, b sockOwner) int { return cmp.Compare(a.pid, b.pid) })
		for _, x := range ow {
			if n := o.processName(x); n != "" {
				return n
			}
		}
	}
	return ""
}

// processName is the name an owner is listed under: the systemd unit of a Vedette service ("vedette-core", from the cgroup the
// process runs in or below) or of any unit when the process is a container monitor (conmon keeps the host ports of a Podman
// container open, and "conmon" names nothing), else the process name.
func (o *Ops) processName(x sockOwner) string {
	unit := cgroupUnit(filepath.Join(o.path("proc"), strconv.Itoa(x.pid)))
	switch {
	case strings.HasPrefix(unit, "vedette-"), unit != "" && x.comm == "conmon":
		return unit
	}
	return x.comm
}

// cgroupUnit is the systemd service a process runs in, from /proc/<pid>/cgroup ("0::/system.slice/vedette-core.service/libpod-…"
// gives "vedette-core"), "" when it is in none. Only [A-Za-z0-9@._-] is kept (a unit name is the box's own, but the file is read
// as untrusted text all the same).
func cgroupUnit(dir string) string {
	b, err := readBounded(filepath.Join(dir, "cgroup"), maxCgroupBytes)
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		rest, ok := strings.CutPrefix(parts[2], "/system.slice/")
		if !ok {
			continue
		}
		seg, _, _ := strings.Cut(rest, "/")
		name, ok := strings.CutSuffix(seg, ".service")
		if !ok || name == "" || len(name) > 64 || strings.ContainsFunc(name, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '@' && r != '.' && r != '_' && r != '-'
		}) {
			continue
		}
		return name
	}
	return ""
}
