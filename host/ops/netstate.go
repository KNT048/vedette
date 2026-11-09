package ops

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/host/api"
)

// GET /v1/state/net (host-api section 5, D-101). It reports what the host can read without
// looking at traffic: the cards with their kernel counters, the addresses on them, the default
// route and the configuration the host wrote itself. Nothing here runs a program or opens a socket.

const (
	maxNetIfaces   = 32
	maxIfaceAddrs  = 16
	maxRouteLines  = 4096
	maxRouteBytes  = 1 << 20
	maxSysfsFile   = 64
	iffPromisc     = 0x100
	rtfUp, rtfGate = 0x1, 0x2
	maxSpeedMbps   = 1_000_000
)

// HostIface is one interface as the system lists it (Deps.Interfaces replaces the answer in tests).
type HostIface struct {
	Name     string
	MAC      string
	Loopback bool
	Addrs    []netip.Prefix
}

// systemInterfaces lists the interfaces and their addresses through the net package.
func systemInterfaces() ([]HostIface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]HostIface, 0, len(all))
	for _, i := range all {
		h := HostIface{Name: i.Name, MAC: i.HardwareAddr.String(), Loopback: i.Flags&net.FlagLoopback != 0}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				if p, err := netip.ParsePrefix(a.String()); err == nil {
					h.Addrs = append(h.Addrs, p)
				}
			}
		}
		out = append(out, h)
	}
	return out, nil
}

// sysfs reads the small files of /sys/class/net through an os.Root opened at <root>/sys. Every
// path is resolved inside that root: /sys/class/net/<if> is itself a symlink into /sys/devices,
// and the root is /sys, not /sys/class/net, so the kernel's own links resolve while a link that
// leads out of /sys (a hostile or damaged entry) is refused by the root and read as "missing".
type sysfs struct{ root *os.Root }

func openSysfs(root string) *sysfs {
	r, err := os.OpenRoot(root + "/sys")
	if err != nil {
		return &sysfs{}
	}
	return &sysfs{root: r}
}

func (s *sysfs) close() {
	if s.root != nil {
		_ = s.root.Close()
	}
}

// read returns the trimmed text of class/net/<iface>/<rel>, "" when it is absent, a link out of
// the root, not a regular file or longer than maxSysfsFile bytes.
func (s *sysfs) read(iface, rel string) (string, bool) {
	if s.root == nil {
		return "", false
	}
	p := "class/net/" + iface + "/" + rel
	f, err := s.root.Open(p)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSysfsFile+1))
	if err != nil || len(b) > maxSysfsFile {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func (s *sysfs) uint(iface, rel string) uint64 {
	t, ok := s.read(iface, rel)
	if !ok {
		return 0
	}
	v, err := strconv.ParseUint(t, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// physical reports whether the interface has a hardware parent (class/net/<if>/device exists):
// a card, not a bridge, veth or macvlan link.
func (s *sysfs) physical(iface string) bool {
	if s.root == nil {
		return false
	}
	_, err := s.root.Lstat("class/net/" + iface + "/device")
	return err == nil
}

func (s *sysfs) counters(iface string) api.NetCounters {
	g := func(n string) uint64 { return s.uint(iface, "statistics/"+n) }
	return api.NetCounters{
		RxPackets: g("rx_packets"), TxPackets: g("tx_packets"), RxBytes: g("rx_bytes"), TxBytes: g("tx_bytes"),
		RxErrors: g("rx_errors"), TxErrors: g("tx_errors"), RxDropped: g("rx_dropped"), TxDropped: g("tx_dropped"),
	}
}

func (s *sysfs) state(iface string) string {
	t, _ := s.read(iface, "operstate")
	switch t {
	case "up", "dormant":
		return t
	case "down", "lowerlayerdown", "notpresent":
		return "down"
	}
	return "unknown"
}

func (s *sysfs) speed(iface string) *int {
	t, ok := s.read(iface, "speed")
	if !ok {
		return nil
	}
	v, err := strconv.Atoi(t)
	if err != nil || v <= 0 || v > maxSpeedMbps {
		return nil
	}
	return &v
}

func (s *sysfs) promisc(iface string) bool {
	t, ok := s.read(iface, "flags")
	if !ok {
		return false
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(t, "0x"), 16, 32)
	return err == nil && v&iffPromisc != 0
}

// parseDefaultRoute reads /proc/net/route text and returns the default route with the lowest
// metric: destination and mask 0, flags UP and GATEWAY, a unicast gateway on a valid interface
// name. Lines that do not parse are skipped; input and line count are bounded.
func parseDefaultRoute(r io.Reader) (*api.NetRoute, bool) {
	sc := bufio.NewScanner(io.LimitReader(r, maxRouteBytes))
	sc.Buffer(make([]byte, 0, 512), 4096)
	var best *api.NetRoute
	var bestMetric uint64
	for n := 0; sc.Scan() && n < maxRouteLines; n++ {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" || !validIfaceName(f[0]) {
			continue
		}
		flags, err1 := strconv.ParseUint(f[3], 16, 32)
		metric, err2 := strconv.ParseUint(f[6], 10, 32)
		g, err3 := routeAddr(f[2])
		if err1 != nil || err2 != nil || err3 != nil || flags&(rtfUp|rtfGate) != rtfUp|rtfGate || !unicast4(g) {
			continue
		}
		if best == nil || metric < bestMetric {
			best, bestMetric = &api.NetRoute{Iface: f[0], Gateway: g.String()}, metric
		}
	}
	return best, best != nil
}

// routeAddr reads an address of /proc/net/route: the kernel prints the u32 it holds in network
// order as one hexadecimal number in host byte order ("010AA8C0" is 192.168.10.1 on a little-endian machine).
func routeAddr(h string) (netip.Addr, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 4 {
		return netip.Addr{}, errors.New("not an address")
	}
	var a [4]byte
	binary.NativeEndian.PutUint32(a[:], binary.BigEndian.Uint32(b))
	return netip.AddrFrom4(a), nil
}

func (o *Ops) defaultRoute() *api.NetRoute {
	f, err := os.Open(o.path("proc/net/route"))
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	r, _ := parseDefaultRoute(f)
	return r
}

// readNetplanConfig returns what the host wrote: the overlay in /run when there is one (it is
// what netplan runs), else the file in /etc. Each is opened inside its directory with os.Root and
// must be a regular file the host would have rendered; anything else counts as "not written".
func (o *Ops) readNetplanConfig() (NetplanConfig, bool) {
	for _, dir := range []string{"run/netplan", "etc/netplan"} {
		if cfg, ok := o.readNetplanFile(dir); ok {
			return cfg, true
		}
	}
	return NetplanConfig{}, false
}

func (o *Ops) readNetplanFile(dir string) (NetplanConfig, bool) {
	r, err := os.OpenRoot(o.path(dir))
	if err != nil {
		return NetplanConfig{}, false
	}
	defer func() { _ = r.Close() }()
	if st, err := r.Lstat(netplanName); err != nil || !st.Mode().IsRegular() {
		return NetplanConfig{}, false
	}
	f, err := r.Open(netplanName)
	if err != nil {
		return NetplanConfig{}, false
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxNetplan+1))
	if err != nil {
		return NetplanConfig{}, false
	}
	cfg, err := parseNetplan(b)
	if err != nil {
		o.log.Debug("the host's netplan file is not one the host rendered; it is not reported", "dir", dir)
		return NetplanConfig{}, false
	}
	return cfg, true
}

func prefixStrings(ps []netip.Prefix) []string {
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().BitLen() - b.Addr().BitLen(); c != 0 {
			return c
		}
		return strings.Compare(a.String(), b.String())
	})
	out := make([]string, 0, min(len(ps), maxIfaceAddrs))
	for _, p := range ps {
		if len(out) == maxIfaceAddrs {
			break
		}
		out = append(out, p.String())
	}
	return out
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.String())
	}
	return out
}

// readNet is Readers.Net.
func (o *Ops) readNet(context.Context) (any, error) {
	ifaces, err := o.d.Interfaces()
	if err != nil {
		return nil, errors.New("ops: list the interfaces: " + err.Error())
	}
	cfg, managed := o.readNetplanConfig()
	route := o.defaultRoute()
	st := api.NetState{Interfaces: []api.NetInterface{}, DefaultRoute: route, Decoys: []api.NetDecoy{}}
	st.Config.NTP = []string{}
	mgmtName, spanName := "", ""
	if managed {
		mgmtName, spanName = cfg.Mgmt.Iface, cfg.SPAN
		m := &api.NetMgmt{Iface: cfg.Mgmt.Iface, Mode: cfg.Mgmt.Mode, DNS: addrStrings(cfg.Mgmt.DNS), Search: slices.Clone(cfg.Mgmt.Search)}
		if m.Search == nil {
			m.Search = []string{}
		}
		if cfg.Mgmt.Address.IsValid() {
			m.Address = cfg.Mgmt.Address.String()
		}
		if cfg.Mgmt.Gateway.IsValid() {
			m.Gateway = cfg.Mgmt.Gateway.String()
		}
		st.Config.Mgmt = m
		if spanName != "" {
			st.Config.SPAN = &spanName
		}
	} else if route != nil {
		mgmtName = route.Iface // the card the box reaches its network by, before the host has configured anything
	}

	sys := openSysfs(o.d.Root)
	defer sys.close()
	for _, h := range ifaces {
		if h.Loopback || !validIfaceName(h.Name) {
			continue
		}
		if !sys.physical(h.Name) && h.Name != mgmtName && h.Name != spanName {
			continue
		}
		if len(st.Interfaces) == maxNetIfaces {
			break
		}
		ni := api.NetInterface{
			Name: h.Name, State: sys.state(h.Name), SpeedMbps: sys.speed(h.Name), Promisc: sys.promisc(h.Name),
			Addresses: prefixStrings(h.Addrs), Counters: sys.counters(h.Name),
		}
		if mac, err := net.ParseMAC(h.MAC); err == nil && len(mac) == 6 {
			ni.MAC = mac.String()
		}
		switch h.Name {
		case mgmtName:
			ni.Role = api.NetRoleManagement
		case spanName:
			ni.Role = api.NetRoleSPAN
		}
		st.Interfaces = append(st.Interfaces, ni)
	}
	slices.SortFunc(st.Interfaces, func(a, b api.NetInterface) int { return strings.Compare(a.Name, b.Name) })
	return st, nil
}
