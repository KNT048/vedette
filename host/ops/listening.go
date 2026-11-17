package ops

import (
	"cmp"
	"context"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/host/api"
)

// heldByInit is whether pid 1 is the only process that holds the sockets of a port: a socket unit whose service has not started yet
// (or starts one process per connection, Accept=yes).
func (o *Ops) heldByInit(inodes []uint64, owners map[uint64][]sockOwner) bool {
	held := false
	for _, ino := range inodes {
		for _, x := range owners[ino] {
			if x.pid != 1 {
				return false
			}
			held = true
		}
	}
	return held
}

// socketKey is a port and its protocol (UDP for ListenDatagram=, TCP for ListenStream=).
type socketKey struct {
	port uint16
	udp  bool
}

// unitDirs are where systemd reads unit files and drop-ins, highest precedence first (systemd.unit(5)): a unit file of the same name
// in an earlier directory hides the later ones; so does a drop-in of the same name in the same <unit>.d.
var unitDirs = []string{"etc/systemd/system", "run/systemd/system", "run/systemd/generator", "usr/local/lib/systemd/system", "usr/lib/systemd/system", "lib/systemd/system"}

const (
	maxUnitFiles = 4096
	maxUnitBytes = 64 << 10
)

// socketUnits names, for each port a systemd socket unit listens on, the service it activates ("ssh" for ssh.socket, Service= when
// set; "foo" for a foo@.service of Accept=yes), read from the unit files and their drop-ins (Ubuntu's sshd-socket-generator writes
// ssh.socket.d/addresses.conf under /run/systemd/generator): no program runs. A port two socket units claim for different services
// names neither (never a guess). Unit names keep [A-Za-z0-9@._-] only (cgroupUnit's rule).
func (o *Ops) socketUnits() map[socketKey]string {
	files := map[string]string{}              // unit name -> its file, highest precedence
	dropins := map[string]map[string]string{} // unit name -> drop-in name -> file
	seen := 0
	for _, d := range unitDirs {
		dir := o.path(d)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if seen++; seen > maxUnitFiles {
				break
			}
			name := e.Name()
			if unit, ok := strings.CutSuffix(name, ".socket.d"); ok && e.IsDir() && validUnitName(unit) {
				confs, err := os.ReadDir(filepath.Join(dir, name))
				if err != nil {
					continue
				}
				for _, c := range confs {
					if !strings.HasSuffix(c.Name(), ".conf") || c.IsDir() {
						continue
					}
					if dropins[unit] == nil {
						dropins[unit] = map[string]string{}
					}
					if _, hidden := dropins[unit][c.Name()]; !hidden {
						dropins[unit][c.Name()] = filepath.Join(dir, name, c.Name())
					}
				}
				continue
			}
			if unit, ok := strings.CutSuffix(name, ".socket"); ok && !e.IsDir() && validUnitName(unit) {
				if _, hidden := files[unit]; !hidden {
					files[unit] = filepath.Join(dir, name)
				}
			}
		}
	}
	out := map[socketKey]string{}
	claimed := map[socketKey]bool{}
	for unit, file := range files {
		paths := []string{file}
		names := slices.Sorted(maps.Keys(dropins[unit])) // drop-ins apply in the order of their names, whatever their directory
		for _, n := range names {
			paths = append(paths, dropins[unit][n])
		}
		keys, service := parseSocketUnit(paths)
		if service == "" {
			service = unit
		}
		for _, k := range keys {
			switch {
			case !claimed[k]:
				claimed[k], out[k] = true, service
			case out[k] != service:
				out[k] = ""
			}
		}
	}
	return out
}

// parseSocketUnit reads a socket unit and its drop-ins in order: the ports of its ListenStream= and ListenDatagram= (an empty value
// resets the list, as systemd does) and the service of Service=, without ".service" or a trailing "@".
func parseSocketUnit(paths []string) ([]socketKey, string) {
	var stream, dgram []uint16
	service := ""
	for _, p := range paths {
		b, err := readBounded(p, maxUnitBytes)
		if err != nil {
			continue
		}
		section := ""
		for line := range strings.SplitSeq(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") {
				section = line
				continue
			}
			if section != "[Socket]" {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch k {
			case "ListenStream", "ListenDatagram":
				list := &stream
				if k == "ListenDatagram" {
					list = &dgram
				}
				if v == "" {
					*list = nil
				} else if port, ok := listenPort(v); ok {
					*list = append(*list, port)
				}
			case "Service":
				if name, ok := strings.CutSuffix(v, ".service"); ok && validUnitName(name) {
					service = name
				}
			}
		}
	}
	var keys []socketKey
	for _, p := range stream {
		keys = append(keys, socketKey{p, false})
	}
	for _, p := range dgram {
		keys = append(keys, socketKey{p, true})
	}
	return keys, strings.TrimSuffix(service, "@")
}

// listenPort is the port of a ListenStream=/ListenDatagram= value that names one: "22", "0.0.0.0:22", "[::]:22". A path, a vsock or
// netlink address, or a value with a specifier holds no port.
func listenPort(v string) (uint16, bool) {
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Port(), ap.Port() != 0
	}
	n, err := strconv.ParseUint(v, 10, 16)
	return uint16(n), err == nil && n != 0
}

// validUnitName keeps a unit name of [A-Za-z0-9@._-], 1 to 64 characters (cgroupUnit's rule).
func validUnitName(name string) bool {
	return name != "" && len(name) <= 64 && !strings.ContainsFunc(name, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '@' && r != '.' && r != '_' && r != '-'
	})
}

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
	inodes := map[socketKey][]uint64{}
	want := map[uint64]bool{}
	lan := o.cardAddrs()
	for _, s := range socks {
		if (!s.addr.IsUnspecified() && !lan[s.addr]) || (s.udp && s.peer) {
			continue
		}
		k := socketKey{s.port, s.udp}
		inodes[k] = append(inodes[k], s.inode)
		want[s.inode] = true
	}
	owners := o.socketOwners(want, "")
	var units map[socketKey]string // read once, only when systemd alone holds a port
	out := api.PortsState{Ports: make([]api.ListenPort, 0, len(inodes))}
	for k, list := range inodes {
		p := api.ListenPort{Port: int(k.port), Proto: api.ProtoTCP}
		if k.udp {
			p.Proto = api.ProtoUDP
		}
		p.Process = o.portOwner(list, owners)
		if p.Process == "systemd" && o.heldByInit(list, owners) {
			if units == nil {
				units = o.socketUnits()
			}
			if u := units[k]; u != "" {
				p.Process = u
			}
		}
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
// owners of one socket, systemd (pid 1) last: a socket-activated service such as Ubuntu's ssh.socket → sshd holds the socket systemd
// passed it, and is what serves the port), "" when none was found.
func (o *Ops) portOwner(inodes []uint64, owners map[uint64][]sockOwner) string {
	for _, ino := range inodes {
		ow := slices.Clone(owners[ino])
		slices.SortFunc(ow, func(a, b sockOwner) int {
			if (a.pid == 1) != (b.pid == 1) {
				return cmp.Compare(b.pid, a.pid) // pid 1 is the lower of the two: it goes after
			}
			return cmp.Compare(a.pid, b.pid)
		})
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
