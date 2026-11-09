package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
)

// card writes a sysfs entry the way the kernel lays it out: the dev files under
// sys/devices/.../net/<name>, and class/net/<name> as a relative symlink to them.
func card(t *testing.T, root, name string, files map[string]string, physical bool) {
	t.Helper()
	dev := filepath.Join(root, "sys/devices/pci0000:00/0000:00:03.0/net", name)
	if err := os.MkdirAll(filepath.Join(dev, "statistics"), 0o750); err != nil {
		t.Fatal(err)
	}
	for k, v := range files {
		if err := os.WriteFile(filepath.Join(dev, k), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if physical {
		if err := os.Symlink("../../../0000:00:03.0", filepath.Join(dev, "device")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "sys/class/net"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../devices/pci0000:00/0000:00:03.0/net/"+name, filepath.Join(root, "sys/class/net", name)); err != nil {
		t.Fatal(err)
	}
}

func stats(rxb, txb string) map[string]string {
	return map[string]string{
		"statistics/rx_packets": "11", "statistics/tx_packets": "22", "statistics/rx_bytes": rxb, "statistics/tx_bytes": txb,
		"statistics/rx_errors": "1", "statistics/tx_errors": "2", "statistics/rx_dropped": "3", "statistics/tx_dropped": "4",
		"operstate": "up", "speed": "1000", "flags": "0x1003",
	}
}

func withIfaces(ifs ...HostIface) func(*Deps) {
	return func(d *Deps) { d.Interfaces = func() ([]HostIface, error) { return ifs, nil } }
}

func netOps(t *testing.T, mutate ...func(*Deps)) (*Ops, string) {
	t.Helper()
	o, root := newNetOps(t)
	for _, f := range mutate {
		f(&o.d)
	}
	return o, root
}

func readState(t *testing.T, o *Ops) api.NetState {
	t.Helper()
	v, err := o.readNet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	st, ok := v.(api.NetState)
	if !ok {
		t.Fatalf("%T", v)
	}
	return st
}

func pfx(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

const routeText = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"eth0\t00000000\t010AA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
	"eth0\t000AA8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"

func TestNetStateReadsCardsCountersAndTheDefaultRoute(t *testing.T) {
	t.Parallel()
	o, root := netOps(t, withIfaces(
		HostIface{Name: "lo", Loopback: true, Addrs: pfx("127.0.0.1/8")},
		HostIface{Name: "eth1", MAC: "02:00:00:00:00:02", Addrs: nil},
		HostIface{Name: "eth0", MAC: "02:00:00:00:00:01", Addrs: pfx("fe80::1/64", "192.168.10.250/24", "fd00::5/64")},
		HostIface{Name: "veth123", MAC: "02:00:00:00:00:03", Addrs: pfx("10.88.0.1/16")},
	))
	m := stats("1000", "2000")
	card(t, root, "eth0", m, true)
	s := stats("5", "6")
	s["flags"] = "0x1103" // IFF_PROMISC set
	s["operstate"] = "down"
	s["speed"] = "-1"
	card(t, root, "eth1", s, true)
	card(t, root, "veth123", stats("9", "9"), false) // no device link: a virtual link, listed because it holds an address
	card(t, root, "lo", stats("9", "9"), false)
	put(t, root, "proc/net/route", routeText)

	st := readState(t, o)
	// The management card first, then the physical cards, then any other link that holds an address.
	if len(st.Interfaces) != 3 || st.Interfaces[0].Name != "eth0" || st.Interfaces[1].Name != "eth1" || st.Interfaces[2].Name != "veth123" {
		t.Fatalf("interfaces: %+v", st.Interfaces)
	}
	e0, e1 := st.Interfaces[0], st.Interfaces[1]
	if e0.MAC != "02:00:00:00:00:01" || e0.State != "up" || e0.SpeedMbps == nil || *e0.SpeedMbps != 1000 || e0.Promisc || e0.Role != api.NetRoleManagement {
		t.Fatalf("eth0: %+v", e0)
	}
	if got, want := strings.Join(e0.Addresses, ","), "192.168.10.250/24,fd00::5/64,fe80::1/64"; got != want {
		t.Fatalf("addresses %s, want %s", got, want)
	}
	if e0.Counters != (api.NetCounters{RxPackets: 11, TxPackets: 22, RxBytes: 1000, TxBytes: 2000, RxErrors: 1, TxErrors: 2, RxDropped: 3, TxDropped: 4}) {
		t.Fatalf("counters %+v", e0.Counters)
	}
	if e1.State != "down" || e1.SpeedMbps != nil || !e1.Promisc || e1.Role != "" || e1.Counters.RxBytes != 5 {
		t.Fatalf("eth1: %+v", e1)
	}
	if st.DefaultRoute == nil || st.DefaultRoute.Iface != "eth0" || st.DefaultRoute.Gateway != "192.168.10.1" {
		t.Fatalf("default route: %+v", st.DefaultRoute)
	}
	if st.Config.Mgmt != nil || st.Config.SPAN != nil {
		t.Fatalf("config without a netplan file: %+v", st.Config)
	}
	if st.Pending != nil || len(st.Decoys) != 0 {
		t.Fatalf("pending %v decoys %v: not before slices 3-4 and 3-5", st.Pending, st.Decoys)
	}
	b, _ := json.Marshal(st)
	for _, nul := range []string{`"interfaces":null`, `"decoys":null`, `"ntp":null`, `"addresses":null`} {
		if strings.Contains(string(b), nul) {
			t.Errorf("%s in %s", nul, b)
		}
	}
	if strings.Contains(string(b), "other_macs") || strings.Contains(string(b), "last_packet") {
		t.Errorf("root reports traffic facts (D-101): %s", b)
	}
}

func TestNetStateMarksTheCardsOfTheHostsNetplanFile(t *testing.T) {
	t.Parallel()
	o, root := netOps(t, withIfaces(HostIface{Name: "eth0", MAC: "02:00:00:00:00:01"}, HostIface{Name: "eth1", MAC: "02:00:00:00:00:02"}, HostIface{Name: "eth2", MAC: "02:00:00:00:00:03"}))
	for _, n := range []string{"eth0", "eth1", "eth2"} {
		card(t, root, n, stats("1", "1"), true)
	}
	put(t, root, "proc/net/route", strings.ReplaceAll(routeText, "eth0", "eth2")) // the default route is on eth2, the file says eth0
	cfg := staticCfg()
	cfg.SPAN = "eth1"
	text, _ := renderNetplan(cfg)
	put(t, root, "etc/netplan/90-vedette.yaml", string(text))
	st := readState(t, o)
	roles := map[string]string{}
	for _, i := range st.Interfaces {
		roles[i.Name] = i.Role
	}
	if roles["eth0"] != "management" || roles["eth1"] != "span" || roles["eth2"] != "" {
		t.Fatalf("roles %v: the file decides, not the default route", roles)
	}
	m := st.Config.Mgmt
	if m == nil || m.Iface != "eth0" || m.Mode != "static" || m.Address != "192.168.10.250/24" || m.Gateway != "192.168.10.1" ||
		strings.Join(m.DNS, ",") != "192.168.10.1,1.1.1.1" || strings.Join(m.Search, ",") != "corp.example,lan" {
		t.Fatalf("mgmt %+v", m)
	}
	if st.Config.SPAN == nil || *st.Config.SPAN != "eth1" {
		t.Fatalf("span %v", st.Config.SPAN)
	}
}

func TestNetStateRunOverlayWinsAndForeignFilesAreNotReported(t *testing.T) {
	t.Parallel()
	o, root := netOps(t, withIfaces(HostIface{Name: "eth0"}, HostIface{Name: "eth1"}))
	card(t, root, "eth0", stats("1", "1"), true)
	card(t, root, "eth1", stats("1", "1"), true)
	etc, _ := renderNetplan(NetplanConfig{Mgmt: NetplanMgmt{Iface: "eth0", Mode: api.NetModeDHCP}})
	run, _ := renderNetplan(NetplanConfig{Mgmt: NetplanMgmt{Iface: "eth1", Mode: api.NetModeDHCP}})
	put(t, root, "etc/netplan/90-vedette.yaml", string(etc))
	if m := readState(t, o).Config.Mgmt; m == nil || m.Iface != "eth0" {
		t.Fatalf("etc only: %+v", m)
	}
	put(t, root, "run/netplan/90-vedette.yaml", string(run))
	if m := readState(t, o).Config.Mgmt; m == nil || m.Iface != "eth1" {
		t.Fatalf("the /run overlay hides /etc, as it does for netplan: %+v", m)
	}
	// netplan runs the /run file whatever it holds, so an overlay that is not the file the host renders makes the answer
	// "unknown": never the /etc file, whose card, mode and addresses are not the ones in force.
	cut := string(run[:len(run)-1]) // truncated by a crash in the middle of a write
	foreign := "network:\n  version: 2\n  ethernets:\n    eth1:\n      dhcp4: true\n      wakeonlan: true\n"
	for name, text := range map[string]string{"truncated": cut, "foreign": foreign, "empty": ""} {
		put(t, root, "run/netplan/90-vedette.yaml", text)
		st := readState(t, o)
		if st.Config.Mgmt != nil || st.Config.SPAN != nil {
			t.Fatalf("%s overlay: the /etc file was reported while netplan runs the /run one: %+v", name, st.Config)
		}
	}
	// A link or a directory at the overlay's name hides /etc as well, and is never followed.
	if err := os.Remove(filepath.Join(root, "run/netplan/90-vedette.yaml")); err != nil {
		t.Fatal(err)
	}
	put(t, root, "elsewhere/x.yaml", string(run))
	if err := os.Symlink(filepath.Join(root, "elsewhere/x.yaml"), filepath.Join(root, "run/netplan/90-vedette.yaml")); err != nil {
		t.Fatal(err)
	}
	if st := readState(t, o); st.Config.Mgmt != nil {
		t.Fatalf("a symlink at our name was followed or fell back to /etc: %+v", st.Config.Mgmt)
	}
	if err := os.Remove(filepath.Join(root, "run/netplan/90-vedette.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "run/netplan/90-vedette.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	if st := readState(t, o); st.Config.Mgmt != nil {
		t.Fatalf("a directory at our name fell back to /etc: %+v", st.Config.Mgmt)
	}
	// No overlay at all: /etc again.
	if err := os.Remove(filepath.Join(root, "run/netplan/90-vedette.yaml")); err != nil {
		t.Fatal(err)
	}
	if m := readState(t, o).Config.Mgmt; m == nil || m.Iface != "eth0" {
		t.Fatalf("without an overlay /etc is the configuration: %+v", m)
	}
}

// A FIFO at the file's name must not block the host (it is refused before it is opened, and opened without blocking if it is swapped in later).
func TestNetStateNeverBlocksOnAFIFOAtTheNetplanName(t *testing.T) {
	t.Parallel()
	o, root := netOps(t, withIfaces(HostIface{Name: "eth0"}))
	if err := os.MkdirAll(filepath.Join(root, "etc/netplan"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "etc/netplan", netplanName), 0o600); err != nil {
		t.Skip("no FIFOs here:", err)
	}
	done := make(chan struct{})
	go func() { defer close(done); readState(t, o) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("state/net blocked on a FIFO")
	}
	if _, st := o.readNetplanFile("etc/netplan"); st != netplanBroken {
		t.Fatalf("a FIFO is state %d, want broken", st)
	}
}

// /sys/class/net/<if> is a symlink into /sys/devices and the root is /sys, so those resolve; anything that leaves /sys does not.
func TestNetStateDoesNotFollowSymlinksOutOfSysfs(t *testing.T) {
	t.Parallel()
	o, root := netOps(t, withIfaces(HostIface{Name: "eth0"}, HostIface{Name: "evil1"}, HostIface{Name: "evil2"}, HostIface{Name: "evil3"}, HostIface{Name: "evil4"}))
	card(t, root, "eth0", stats("1000", "2000"), true)

	// outside holds a full set of statistics that must never be read.
	outside := filepath.Join(filepath.Dir(root), "outside")
	if err := os.MkdirAll(filepath.Join(outside, "statistics"), 0o750); err != nil {
		t.Fatal(err)
	}
	for k, v := range stats("999999", "999999") {
		if err := os.WriteFile(filepath.Join(outside, k), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../../device", filepath.Join(outside, "device")); err != nil { // would make it "physical"
		t.Fatal(err)
	}
	cls := filepath.Join(root, "sys/class/net")
	// 1: absolute link to a directory outside the root.
	if err := os.Symlink(outside, filepath.Join(cls, "evil1")); err != nil {
		t.Fatal(err)
	}
	// 2: relative link that climbs out of /sys.
	rel, _ := filepath.Rel(cls, outside)
	if err := os.Symlink(rel, filepath.Join(cls, "evil2")); err != nil {
		t.Fatal(err)
	}
	// 3: a dev directory whose files are links to outside files.
	if err := os.MkdirAll(filepath.Join(cls, "evil3/statistics"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"statistics/rx_bytes", "statistics/tx_bytes", "operstate", "speed", "flags"} {
		if err := os.Symlink(filepath.Join(outside, f), filepath.Join(cls, "evil3", f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(cls, "evil3/device")); err != nil {
		t.Fatal(err)
	}
	// 4: a statistics directory that is a link outside, inside a card that is otherwise fine.
	if err := os.MkdirAll(filepath.Join(cls, "evil4"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "statistics"), filepath.Join(cls, "evil4/statistics")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("x", filepath.Join(cls, "evil4/device")); err != nil {
		t.Fatal(err)
	}
	put(t, root, "proc/net/route", routeText)

	st := readState(t, o)
	got := map[string]api.NetInterface{}
	for _, i := range st.Interfaces {
		got[i.Name] = i
	}
	if got["eth0"].Counters.RxBytes != 1000 {
		t.Fatalf("the kernel's own link into /sys/devices did not resolve: %+v", got["eth0"])
	}
	for _, n := range []string{"evil1", "evil2"} {
		if _, listed := got[n]; listed {
			t.Errorf("%s: a card reached through a link out of /sys was listed", n)
		}
	}
	for _, n := range []string{"evil3", "evil4"} {
		i, listed := got[n]
		if listed && (i.Counters != (api.NetCounters{}) || i.State != "unknown" || i.SpeedMbps != nil || i.Promisc) {
			t.Errorf("%s: read through a link out of /sys: %+v", n, i)
		}
	}
	for n, i := range got {
		if n != "eth0" && (i.Counters.RxBytes == 999999 || i.Counters.TxBytes == 999999) {
			t.Errorf("%s: counters of the outside directory leaked: %+v", n, i.Counters)
		}
	}
}

func TestNetStateWithNoSysfsOrProcStillAnswers(t *testing.T) {
	t.Parallel()
	o, _ := netOps(t, withIfaces(HostIface{Name: "eth0", MAC: "02:00:00:00:00:01", Addrs: pfx("10.0.0.2/24")}))
	st := readState(t, o)
	// The address still counts as the box's; only the counters and the route are missing.
	if len(st.Interfaces) != 1 || st.Interfaces[0].Addresses[0] != "10.0.0.2/24" || st.Interfaces[0].Counters != (api.NetCounters{}) || st.DefaultRoute != nil {
		t.Fatalf("%+v", st)
	}
}

func TestNetStateSkipsUnsafeNamesAndCaps(t *testing.T) {
	t.Parallel()
	var ifs []HostIface
	for i := range 80 {
		ifs = append(ifs, HostIface{Name: fmt.Sprintf("en%02d", i)})
	}
	ifs = append(ifs, HostIface{Name: "bad name"}, HostIface{Name: "-x"}, HostIface{Name: "a/b"}, HostIface{Name: "abcdefghijklmnop"})
	var many []netip.Prefix
	for i := range 80 {
		many = append(many, netip.MustParsePrefix(fmt.Sprintf("10.0.%d.1/24", i)))
	}
	ifs[0].Addrs = many
	o, root := netOps(t, withIfaces(ifs...))
	for _, i := range ifs {
		if i.Name == "bad name" || i.Name == "-x" || i.Name == "a/b" || i.Name == "abcdefghijklmnop" {
			continue
		}
		card(t, root, i.Name, stats("1", "1"), true)
	}
	st := readState(t, o)
	if len(st.Interfaces) != maxNetIfaces {
		t.Fatalf("%d interfaces, cap is %d", len(st.Interfaces), maxNetIfaces)
	}
	if len(st.Interfaces[0].Addresses) != maxIfaceAddrs {
		t.Fatalf("%d addresses, cap is %d", len(st.Interfaces[0].Addresses), maxIfaceAddrs)
	}
	for _, i := range st.Interfaces {
		if !validIfaceName(i.Name) {
			t.Errorf("unsafe name %q was reported", i.Name)
		}
	}
}

func TestNetStateReportsAnInterfaceListFailureAsAnError(t *testing.T) {
	t.Parallel()
	o, _ := netOps(t, func(d *Deps) { d.Interfaces = func() ([]HostIface, error) { return nil, os.ErrPermission } })
	if _, err := o.readNet(context.Background()); err == nil {
		t.Fatal("no error")
	}
}

func TestSysfsOddValues(t *testing.T) {
	t.Parallel()
	_, root := netOps(t)
	card(t, root, "eth0", map[string]string{
		"statistics/rx_bytes": "-5", "statistics/tx_bytes": "99999999999999999999999", "statistics/rx_packets": strings.Repeat("9", 200),
		"operstate": "weird", "speed": "9999999999", "flags": "zz",
	}, true)
	s := openSysfs(root)
	defer s.close()
	if c := s.counters("eth0"); c != (api.NetCounters{}) {
		t.Fatalf("%+v", c)
	}
	if s.state("eth0") != "unknown" || s.speed("eth0") != nil || s.promisc("eth0") {
		t.Fatal("odd values were believed")
	}
	if s.state("nope") != "unknown" {
		t.Fatal("a missing card has no state")
	}
}

// --- /proc/net/route ----------------------------------------------------------------------------------

func TestParseDefaultRoute(t *testing.T) {
	t.Parallel()
	hdr := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	cases := []struct {
		name, text, iface, gw string
	}{
		{"one", routeText, "eth0", "192.168.10.1"},
		{"lowest metric wins", hdr + "eth0\t00000000\t010AA8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" + "eth1\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n", "eth1", "10.0.0.1"},
		{"first on a tie", hdr + "eth0\t00000000\t010AA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" + "eth1\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n", "eth0", "192.168.10.1"},
		{"down route skipped", hdr + "eth0\t00000000\t010AA8C0\t0002\t0\t0\t1\t00000000\t0\t0\t0\n" + "eth1\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n", "eth1", "10.0.0.1"},
		{"no gateway flag skipped", hdr + "eth0\t00000000\t00000000\t0001\t0\t0\t1\t00000000\t0\t0\t0\n", "", ""},
		{"not a default destination", hdr + "eth0\t000AA8C0\t010AA8C0\t0003\t0\t0\t1\t00FFFFFF\t0\t0\t0\n", "", ""},
		{"zero gateway", hdr + "eth0\t00000000\t00000000\t0003\t0\t0\t1\t00000000\t0\t0\t0\n", "", ""},
		{"loopback gateway", hdr + "eth0\t00000000\t0100007F\t0003\t0\t0\t1\t00000000\t0\t0\t0\n", "", ""},
		{"bad iface name", hdr + "e th0\t00000000\t010AA8C0\t0003\t0\t0\t1\t00000000\t0\t0\t0\n", "", ""},
		{"malformed lines", "garbage\n\x00\x01\x02\n\t\t\t\n" + "eth0\tZZ\t010AA8C0\t0003\t0\t0\t1\t00000000\n" + "eth0\t00000000\tXYZ\t0003\t0\t0\t1\t00000000\t0\n" + "eth0\t00000000\t010AA8C0\t0003\t0\t0\tnine\t00000000\n" + "eth0\t00000000\t010AA8C0\n", "", ""},
		{"valid after malformed", "junk junk\n" + routeText, "eth0", "192.168.10.1"},
		{"empty", "", "", ""},
		{"a very long line", strings.Repeat("x", 100000) + "\n" + routeText, "", ""}, // the scanner stops at an over-long line: fail closed
	}
	for _, c := range cases {
		r, ok := parseDefaultRoute(strings.NewReader(c.text))
		switch {
		case c.iface == "" && ok:
			t.Errorf("%s: got %+v", c.name, r)
		case c.iface != "" && (!ok || r.Iface != c.iface || r.Gateway != c.gw):
			t.Errorf("%s: got %+v, want %s via %s", c.name, r, c.iface, c.gw)
		}
	}
}

func TestParseDefaultRouteIsBounded(t *testing.T) {
	t.Parallel()
	junk := strings.Repeat("eth0\t0000000A\t010AA8C0\t0003\t0\t0\t1\t00000000\n", maxRouteLines+10)
	if r, ok := parseDefaultRoute(strings.NewReader(junk + routeText)); ok {
		t.Fatalf("read past the line limit: %+v", r)
	}
}

func FuzzParseDefaultRoute(f *testing.F) {
	f.Add(routeText)
	f.Add("")
	f.Add("eth0\t00000000\tFFFFFFFF\t0003\t0\t0\t0\t00000000\n")
	f.Fuzz(func(t *testing.T, s string) {
		r, ok := parseDefaultRoute(strings.NewReader(s))
		if !ok {
			return
		}
		if !validIfaceName(r.Iface) {
			t.Fatalf("interface %q", r.Iface)
		}
		if a, err := netip.ParseAddr(r.Gateway); err != nil || !unicast4(a) {
			t.Fatalf("gateway %q", r.Gateway)
		}
	})
}

// Every address of the box must reach core: a VLAN, a WireGuard link or a container bridge that holds one is listed, a virtual
// link without an address is not.
func TestNetStateListsEveryLinkThatHoldsAnAddress(t *testing.T) {
	t.Parallel()
	o, root := netOps(t, withIfaces(
		HostIface{Name: "eth0", MAC: "02:00:00:00:00:01", Addrs: pfx("192.168.10.250/24")},
		HostIface{Name: "eth0.20", MAC: "02:00:00:00:00:01", Addrs: pfx("10.20.0.5/24")},
		HostIface{Name: "wg0", Addrs: pfx("100.64.0.7/32")},
		HostIface{Name: "podman1", MAC: "02:00:00:00:00:09", Addrs: pfx("10.89.0.1/24", "fd00:89::1/64")},
		HostIface{Name: "veth9", MAC: "02:00:00:00:00:0a"}, // no address: nothing to report
	))
	card(t, root, "eth0", stats("1", "1"), true)
	card(t, root, "eth0.20", stats("1", "1"), false)
	card(t, root, "wg0", stats("1", "1"), false)
	card(t, root, "podman1", stats("1", "1"), false)
	card(t, root, "veth9", stats("1", "1"), false)
	put(t, root, "proc/net/route", routeText)
	st := readState(t, o)
	got := map[string]bool{}
	var names []string
	for _, i := range st.Interfaces {
		names = append(names, i.Name)
		for _, s := range i.Addresses {
			got[netip.MustParsePrefix(s).Addr().String()] = true
		}
	}
	for _, want := range []string{"192.168.10.250", "10.20.0.5", "100.64.0.7", "10.89.0.1", "fd00:89::1"} {
		if !got[want] {
			t.Errorf("the box's address %s is not in state/net, so core would not treat it as the box (interfaces %v)", want, names)
		}
	}
	if strings.Contains(strings.Join(names, ","), "veth9") {
		t.Errorf("a link with no address was listed: %v", names)
	}
	if names[0] != "eth0" {
		t.Errorf("the management card is not first: %v", names)
	}
}

// Under the cap a global address is never dropped while a link-local one is kept, whatever the text order of the addresses.
func TestNetStateKeepsGlobalAddressesBeforeLinkLocalUnderTheCap(t *testing.T) {
	t.Parallel()
	addrs := pfx("fe80::1/64", "fe80::2/64", "192.168.10.250/24", "169.254.1.1/16")
	var global []netip.Prefix
	for i := range maxIfaceAddrs - 1 { // 63 global IPv6 plus the IPv4 address: exactly the cap
		global = append(global, netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::5/64", i+1)))
	}
	addrs = append(addrs, global...)
	o, root := netOps(t, withIfaces(HostIface{Name: "eth0", MAC: "02:00:00:00:00:01", Addrs: addrs}))
	card(t, root, "eth0", stats("1", "1"), true)
	got := readState(t, o).Interfaces[0].Addresses
	if len(got) != maxIfaceAddrs {
		t.Fatalf("%d addresses, want the cap %d", len(got), maxIfaceAddrs)
	}
	for _, s := range got {
		if a := netip.MustParsePrefix(s).Addr(); a.IsLinkLocalUnicast() {
			t.Errorf("link-local %s kept while a global address was cut", a)
		}
	}
	if got[0] != "192.168.10.250/24" {
		t.Errorf("order %v: IPv4 first", got[:2])
	}
	// One more global address than the cap: the cut falls on the last global one, still never on a global one before a link-local one.
	extra := append(addrs, netip.MustParsePrefix("2001:db8:ffff::5/64"))
	o2, root2 := netOps(t, withIfaces(HostIface{Name: "eth0", Addrs: extra}))
	card(t, root2, "eth0", stats("1", "1"), true)
	for _, s := range readState(t, o2).Interfaces[0].Addresses {
		if netip.MustParsePrefix(s).Addr().IsLinkLocalUnicast() {
			t.Errorf("link-local %s kept over the cap", s)
		}
	}
}

// The management card is first and is never the one the interface cap drops, even when its name sorts last.
func TestNetStateManagementCardIsFirstAndNeverCut(t *testing.T) {
	t.Parallel()
	var ifs []HostIface
	for i := range maxNetIfaces + 10 {
		ifs = append(ifs, HostIface{Name: fmt.Sprintf("en%02d", i), Addrs: pfx(fmt.Sprintf("10.1.%d.1/24", i))})
	}
	ifs = append(ifs, HostIface{Name: "zz9", MAC: "02:00:00:00:00:01", Addrs: pfx("192.168.10.250/24")})
	o, root := netOps(t, withIfaces(ifs...))
	for _, i := range ifs {
		card(t, root, i.Name, stats("1", "1"), true)
	}
	put(t, root, "proc/net/route", strings.ReplaceAll(routeText, "eth0", "zz9"))
	st := readState(t, o)
	if len(st.Interfaces) != maxNetIfaces || st.Interfaces[0].Name != "zz9" || st.Interfaces[0].Role != api.NetRoleManagement {
		t.Fatalf("%d interfaces, first %q: the management card was cut or not first", len(st.Interfaces), st.Interfaces[0].Name)
	}
}
