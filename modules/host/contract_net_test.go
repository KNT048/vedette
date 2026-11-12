package host_test

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
)

// netCard lays out one sysfs card under the machine's root the way the kernel does (the files
// under sys/devices, class/net/<name> a relative link to them).
func netCard(t *testing.T, root, name string, rxBytes string) {
	t.Helper()
	dev := filepath.Join(root, "sys/devices/pci0000:00/net", name)
	for _, d := range []string{filepath.Join(dev, "statistics"), filepath.Join(root, "sys/class/net")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range map[string]string{"statistics/rx_bytes": rxBytes, "statistics/tx_bytes": "20", "operstate": "up", "speed": "1000", "flags": "0x1003"} {
		if err := os.WriteFile(filepath.Join(dev, k), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../..", filepath.Join(dev, "device")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../devices/pci0000:00/net/"+name, filepath.Join(root, "sys/class/net", name)); err != nil {
		t.Fatal(err)
	}
}

// GET /v1/state/net (D-101, spec 5): cards with counters read from sysfs through a root, the default route from
// /proc/net/route, no traffic facts, and the same body through the client and as raw JSON.
func TestContract_Net_StateNetReportsCardsCountersAndRoute(t *testing.T) {
	t.Parallel()
	e := startSys(t, func(_ *ops.Config, d *ops.Deps) {
		d.Interfaces = func() ([]ops.HostIface, error) {
			return []ops.HostIface{
				{Name: "lo", Loopback: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
				{Name: "eth0", MAC: "02:00:00:00:00:01", Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.10.250/24")}},
				{Name: "eth1", MAC: "02:00:00:00:00:02"},
			}, nil
		}
	})
	root := e.m.Root
	netCard(t, root, "eth0", "1234")
	netCard(t, root, "eth1", "5678")
	// A card whose link leaves /sys must read as absent.
	outside := filepath.Join(filepath.Dir(root), "outside-sys")
	if err := os.MkdirAll(filepath.Join(outside, "statistics"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "statistics/rx_bytes"), []byte("777\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "sys/class/net/eth9")); err != nil {
		t.Fatal(err)
	}
	e.m.WriteRoot("proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t010AA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
	// D-390: the IPv6 default route and the DNS servers a lease gave (systemd-resolved's list; /etc/resolv.conf is its stub).
	e.m.WriteRoot("proc/net/ipv6_route", "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003     eth0\n")
	e.m.WriteRoot("run/systemd/resolve/resolv.conf", "nameserver 192.168.10.53\n")
	e.m.WriteRoot("etc/resolv.conf", "nameserver 127.0.0.53\n")

	st, err := e.h.Client.StateNet(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.DefaultRoutes6) != 1 || st.DefaultRoutes6[0].Iface != "eth0" || st.DefaultRoutes6[0].Gateway != "fe80::1" || len(st.Resolvers) != 1 || st.Resolvers[0] != "192.168.10.53" {
		t.Fatalf("IPv6 routes %+v, resolvers %v", st.DefaultRoutes6, st.Resolvers)
	}
	if len(st.Interfaces) != 2 || st.Interfaces[0].Name != "eth0" || st.Interfaces[0].Counters.RxBytes != 1234 || st.Interfaces[0].Role != api.NetRoleManagement ||
		st.Interfaces[1].Counters.RxBytes != 5678 || st.Interfaces[0].Addresses[0] != "192.168.10.250/24" {
		t.Fatalf("%+v", st.Interfaces)
	}
	if st.DefaultRoute == nil || st.DefaultRoute.Gateway != "192.168.10.1" {
		t.Fatalf("route %+v", st.DefaultRoute)
	}
	code, body := rawGet(t, e.h, "/v1/state/net")
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"interfaces", "config", "default_route", "default_routes6", "pending", "decoys", "resolvers"} {
		if _, ok := m[k]; !ok {
			t.Errorf("the body has no %q: %s", k, body)
		}
	}
	if strings.Contains(string(body), "777") || strings.Contains(string(body), "other_macs") || strings.Contains(string(body), "last_packet") {
		t.Errorf("the body leaks a file outside /sys or reports traffic facts: %s", body)
	}
	if code, _ := rawGet(t, e.h, "/v1/state/net?x=1"); code != 400 {
		t.Errorf("a query string answered %d", code)
	}
}

// INV-18: the host never analyses captured traffic. The only raw socket in the host is the AF_PACKET one of
// arp_linux.go, bound to ARP; nothing under host/ or cmd/vedette-host reads packets through pcap or any other raw socket.
func TestContract_INV18_OnlyTheARPSocketTouchesTheWire(t *testing.T) {
	t.Parallel()
	forbidden := regexp.MustCompile(`AF_PACKET|SOCK_RAW|pcap|gopacket|syscall\.Socket\(|unix\.Socket\(|net\.ListenPacket\(|net\.DialIP\(|ListenIP\(`)
	var withSocket []string
	for _, root := range []string{"../../host", "../../cmd/vedette-host"} {
		err := filepathWalkGo(root, func(path string, src string) {
			if forbidden.MatchString(src) {
				withSocket = append(withSocket, filepath.ToSlash(strings.TrimPrefix(path, "../../")))
			}
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(withSocket) != 1 || withSocket[0] != "host/ops/arp_linux.go" {
		t.Fatalf("raw sockets or capture code outside arp_linux.go: %v", withSocket)
	}
	src, err := os.ReadFile("../../host/ops/arp_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	// The socket is created with protocol 0, so nothing is queued before bind sets the protocol and the card in one step (a SPAN card
	// mirrors a whole network's ARP), and every frame is checked again against the card's index.
	if strings.Count(s, "unix.Socket(") != 1 || !strings.Contains(s, "unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)") ||
		!strings.Contains(s, "Protocol: htons(unix.ETH_P_ARP), Ifindex: ifc.Index") {
		t.Fatal("arp_linux.go must open exactly one packet socket with protocol 0 and bind it to ETH_P_ARP and one interface")
	}
	recv := s[strings.Index(s, "func (s *packetARP) Recv"):]
	recv = recv[:strings.Index(recv, "\n}\n")]
	if !strings.Contains(recv, "arpFromCard(ll.Ifindex, s.index") {
		t.Fatal("Recv must drop every frame whose Ifindex is not the card's")
	}
	for _, bad := range []string{"SetsockoptPacketMreq", "PACKET_MR_PROMISC", "SO_ATTACH", "ETH_P_ALL"} {
		if strings.Contains(s, bad) {
			t.Errorf("arp_linux.go uses %s: root would see more than ARP", bad)
		}
	}
}

func filepathWalkGo(root string, f func(path, src string)) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // a source file of this repository
		if err != nil {
			return err
		}
		f(p, string(b))
		return nil
	})
}

// The grammar for netplan is "apply" and nothing else: "generate --root-dir" checks a string, so no production argv has it
// (TestProductionRunnerOnlyAppliesNetplan in host/ops). chronyc has two argv shapes (D-106).
func TestContract_Net_NetplanAndChronycArgvAreTheFixedGrammar(t *testing.T) {
	t.Parallel()
	if err := ops.ValidateNetplan([]string{"apply"}); err != nil {
		t.Fatal(err)
	}
	for _, a := range [][]string{{"generate", "--root-dir", "/tmp/x/y"}, {"try"}, {"generate"}, {"apply", "--debug"}, {"apply", "extra"}, {"get"}, {"set", "x=y"}, {"ip", "leases", "eth0"}, nil} {
		if err := ops.ValidateNetplan(a); err == nil {
			t.Errorf("%v was accepted", a)
		}
	}
	for _, a := range [][]string{{"reload", "sources"}, {"-N", "-" + "c", "sources"}} {
		if err := ops.ValidateChronyc(a); err != nil {
			t.Errorf("%v: %v", a, err)
		}
	}
	for _, a := range [][]string{nil, {"reload"}, {"reload", "sources", "x"}, {"add", "server", "x"}, {"makestep"}, {"sources"}, {"-N", "sources"}, {"-" + "c", "sources"}, {"waitsync"}, {"-a", "reload", "sources"}} {
		if err := ops.ValidateChronyc(a); err == nil {
			t.Errorf("%v was accepted", a)
		}
	}
}
