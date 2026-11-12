package ops

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/host/api"
)

// Host ports a unit change adds (D-455). A unit that publishes a host port another program listens on does not start: Podman
// cannot reserve the port, the container exits, and for core that takes 8443 down with it. install.sh refuses a busy port on a
// fresh box, but an update in place never runs install.sh, so the host looks itself, before it writes a unit that publishes a port
// the unit it replaces did not (D-395 added 127.0.0.1:8765, D-214 6514): container.start and container.rollback refuse
// 412 port_in_use and leave the running release alone; the unit migration at start keeps the earlier unit (unit_migration_deferred)
// and tries again at the next start.
//
// It reads the kernel's socket tables (/proc/net/tcp, tcp6, udp, udp6) and, only for a listener it found, which processes hold that
// socket (/proc/<pid>/fd) and their name and cgroup: no program runs, no socket is opened. A socket held by a process of the service's
// own systemd unit (the container being replaced, its conmon) is not a conflict. A port the earlier unit already published is not
// looked at: the running container holds it, and judging its owner is what would go wrong (ponytail: a unit already rewritten on
// disk whose running container is still the earlier one is not covered; the migration that wrote it checked the port then).
// A table the host cannot read says nothing (logged): the check never blocks an update on its own misreading.

const (
	maxProcNetLines = 1 << 20 // listeners come first in the kernel's tables; a busy box has many connections after them
	maxCgroupBytes  = 64 << 10
	maxCommLen      = 15 // TASK_COMM_LEN - 1
)

// hostPort is a host port a unit publishes: the address it binds (the zero Addr for every address) and the protocol.
type hostPort struct {
	addr netip.Addr
	port uint16
	udp  bool
}

func (p hostPort) String() string {
	if p.udp {
		return strconv.Itoa(int(p.port)) + "/udp"
	}
	return strconv.Itoa(int(p.port)) + "/tcp"
}

// publishedPorts reads the PublishPort= lines of a unit the host wrote: [ip:]hostPort:containerPort[/proto], an IPv6 address in
// brackets. A line without a fixed host port, or with a range, is not one the host writes and is skipped (a test pins that every
// line of every template is read).
func publishedPorts(unit []byte) []hostPort {
	var out []hostPort
	for line := range strings.SplitSeq(string(unit), "\n") {
		v, ok := strings.CutPrefix(line, "PublishPort=")
		if !ok {
			continue
		}
		udp := false
		if s, ok := strings.CutSuffix(v, "/udp"); ok {
			v, udp = s, true
		} else {
			v = strings.TrimSuffix(v, "/tcp")
		}
		i := strings.LastIndexByte(v, ':')
		if i < 0 {
			continue
		}
		host := v[:i]
		var addr netip.Addr
		if j := strings.LastIndexByte(host, ':'); j >= 0 {
			a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host[:j], "["), "]"))
			if err != nil {
				continue
			}
			if !a.IsUnspecified() {
				addr = a.Unmap()
			}
			host = host[j+1:]
		}
		n, err := strconv.ParseUint(host, 10, 16)
		if err != nil || n == 0 {
			continue
		}
		out = append(out, hostPort{addr: addr, port: uint16(n), udp: udp})
	}
	return out
}

// addedPorts lists the host ports want publishes that old does not publish at all (same port and protocol, any address). A nil old
// (no unit yet) adds every port.
func addedPorts(old, want []byte) []hostPort {
	had := publishedPorts(old)
	var out []hostPort
	for _, p := range publishedPorts(want) {
		if !slices.ContainsFunc(had, func(h hostPort) bool { return h.port == p.port && h.udp == p.udp }) {
			out = append(out, p)
		}
	}
	return out
}

// sockEntry is one socket of the kernel's tables that holds a local port.
type sockEntry struct {
	addr  netip.Addr
	port  uint16
	udp   bool
	inode uint64
}

// parseProcNet reads /proc/net/tcp, tcp6, udp or udp6 text: TCP sockets in LISTEN (0A), every UDP socket (a bound one holds its port
// whether connected or not). Lines that do not parse are skipped; input is bounded by lines.
func parseProcNet(r io.Reader, udp bool) []sockEntry {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 512), 4096)
	var out []sockEntry
	for n := 0; sc.Scan() && n < maxProcNetLines; n++ {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || !strings.HasSuffix(f[0], ":") || (!udp && f[3] != "0A") {
			continue
		}
		h, p, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		addr, err := procNetAddr(h)
		port, perr := strconv.ParseUint(p, 16, 16)
		inode, ierr := strconv.ParseUint(f[9], 10, 64)
		if err != nil || perr != nil || ierr != nil || port == 0 {
			continue
		}
		out = append(out, sockEntry{addr: addr, port: uint16(port), udp: udp, inode: inode})
	}
	return out
}

// procNetAddr reads an address of /proc/net/{tcp,udp}{,6}: the kernel prints each 32-bit word it holds in network order as a
// hexadecimal number in host byte order (8 digits for IPv4, 4 words for IPv6). An IPv4-mapped IPv6 address is returned as IPv4.
func procNetAddr(h string) (netip.Addr, error) {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.Addr{}, errors.New("not an address")
	}
	out := make([]byte, len(b))
	for i := 0; i < len(b); i += 4 {
		binary.NativeEndian.PutUint32(out[i:], binary.BigEndian.Uint32(b[i:]))
	}
	if len(out) == 4 {
		return netip.AddrFrom4([4]byte(out)), nil
	}
	return netip.AddrFrom16([16]byte(out)).Unmap(), nil
}

// clashes says whether a socket keeps Podman from binding p: same port and protocol, and either side binds every address (an
// unspecified IPv6 listener counts for IPv4 too: dual stack is Linux's default, the table does not say IPV6_V6ONLY) or both the same one.
func clashes(p hostPort, s sockEntry) bool {
	return s.port == p.port && s.udp == p.udp && (!p.addr.IsValid() || s.addr.IsUnspecified() || s.addr == p.addr)
}

// sockets reads the four socket tables under the root. A table that is not there (no IPv6) has nothing; one that cannot be read
// is logged and has nothing.
func (o *Ops) sockets() []sockEntry {
	var out []sockEntry
	for _, t := range []struct {
		rel string
		udp bool
	}{{"proc/net/tcp", false}, {"proc/net/tcp6", false}, {"proc/net/udp", true}, {"proc/net/udp6", true}} {
		f, err := os.Open(o.path(t.rel))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				o.log.Warn("could not read a socket table; the port check goes on without it", "table", t.rel, "error", err.Error())
			}
			continue
		}
		out = append(out, parseProcNet(f, t.udp)...)
		_ = f.Close()
	}
	return out
}

// sockOwner is a process that holds a socket.
type sockOwner struct {
	pid  int
	comm string
	ours bool // the process is in the cgroup of the service's own systemd unit
}

// socketOwners finds the processes that hold the sockets of inodes (/proc/<pid>/fd links "socket:[inode]"), with their name and
// whether they run in the service's systemd unit. A process that ends while it is read is skipped.
func (o *Ops) socketOwners(inodes map[uint64]bool, service string) map[uint64][]sockOwner {
	out := map[uint64][]sockOwner{}
	procs, err := os.ReadDir(o.path("proc"))
	if err != nil {
		return out
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join(o.path("proc"), p.Name())
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		var owner *sockOwner
		for _, fd := range fds {
			l, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil {
				continue
			}
			s, ok := strings.CutPrefix(l, "socket:[")
			if !ok {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64)
			if err != nil || !inodes[ino] {
				continue
			}
			if owner == nil {
				owner = &sockOwner{pid: pid, comm: procComm(dir), ours: inUnitCgroup(dir, unitOf(service))}
			}
			if !slices.Contains(out[ino], *owner) {
				out[ino] = append(out[ino], *owner)
			}
		}
	}
	return out
}

// procComm is the process name of /proc/<pid>/comm, reduced to printable ASCII (a process sets its own name): "" when unreadable.
func procComm(dir string) string {
	b, err := readBounded(filepath.Join(dir, "comm"), 64)
	if err != nil {
		return ""
	}
	s := []byte(strings.TrimRight(string(b), "\n"))
	if len(s) > maxCommLen {
		s = s[:maxCommLen]
	}
	for i, c := range s {
		if c < 0x20 || c > 0x7e {
			s[i] = '?'
		}
	}
	return string(s)
}

// inUnitCgroup says whether /proc/<pid>/cgroup puts the process in the cgroup of a systemd unit or below it (a container of a
// Quadlet unit runs in a sub-cgroup of the unit's).
func inUnitCgroup(dir, unit string) bool {
	b, err := readBounded(filepath.Join(dir, "cgroup"), maxCgroupBytes)
	if err != nil {
		return false
	}
	want := "/system.slice/" + unit
	for line := range strings.SplitSeq(string(b), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && (parts[2] == want || strings.HasPrefix(parts[2], want+"/")) {
			return true
		}
	}
	return false
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // a fixed file of /proc/<pid> under the root
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit))
}

// busyPort is a port a new unit adds that another program listens on: the process when the host found it.
type busyPort struct {
	hostPort
	comm string
	pid  int
}

func (b busyPort) String() string {
	switch {
	case b.pid > 0 && b.comm != "":
		return b.hostPort.String() + " (" + b.comm + ", pid " + strconv.Itoa(b.pid) + ")"
	case b.pid > 0:
		return b.hostPort.String() + " (pid " + strconv.Itoa(b.pid) + ")"
	}
	return b.hostPort.String()
}

// busyPorts lists the ports want adds over old on which a program outside the service's own unit listens. Nothing is read when the
// change adds no port.
func (o *Ops) busyPorts(service string, old, want []byte) []busyPort {
	added := addedPorts(old, want)
	if len(added) == 0 {
		return nil
	}
	socks := o.sockets()
	inodes := map[uint64]bool{}
	for _, p := range added {
		for _, s := range socks {
			if clashes(p, s) {
				inodes[s.inode] = true
			}
		}
	}
	if len(inodes) == 0 {
		return nil
	}
	owners := o.socketOwners(inodes, service)
	var out []busyPort
	for _, p := range added {
		var hit *busyPort
		for _, s := range socks {
			if !clashes(p, s) {
				continue
			}
			ow := owners[s.inode]
			if slices.ContainsFunc(ow, func(x sockOwner) bool { return x.ours }) {
				continue // the service's own container (or its conmon) holds it
			}
			b := busyPort{hostPort: p}
			if len(ow) > 0 {
				b.comm, b.pid = ow[0].comm, ow[0].pid
			}
			if hit == nil || (hit.pid == 0 && b.pid > 0) {
				hit = &b
			}
		}
		if hit != nil {
			out = append(out, *hit)
		}
	}
	return out
}

func busyList(bs []busyPort) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = b.String()
	}
	return out
}

// portsFreeFor is portsFree for the unit the host would write for digest (Check, and container.rollback's plan).
func (o *Ops) portsFreeFor(service string, old []byte, digest string) error {
	want, err := o.renderUnitFor(service, digest)
	if err != nil {
		return err
	}
	return o.portsFree(service, old, want)
}

// portsFree refuses (412 port_in_use) a unit change that adds a port another program listens on, naming the ports and the
// processes; nothing has been changed when it does.
func (o *Ops) portsFree(service string, old, want []byte) error {
	busy := o.busyPorts(service, old, want)
	if len(busy) == 0 {
		return nil
	}
	list := busyList(busy)
	o.log.Warn("a port the new unit publishes is in use by another program; the unit is not changed", "service", service, "ports", strings.Join(list, ", "))
	what := "Port " + list[0] + " is"
	if len(list) > 1 {
		what = "Ports " + strings.Join(list, ", ") + " are"
	}
	return refuse412(api.CodePortInUse, what+" in use by another program on this machine. The new "+service+
		" unit publishes it, so "+service+" would not start. Stop that program or move it to another port, then try again. Nothing was changed.")
}
