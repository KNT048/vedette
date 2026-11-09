package ops

// Independent security review of slice 3-3 (feat/host-net-read): state/net, the netplan argv grammar
// and the ARP prober. Each test fails while the defect it names is present.

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
)

// FINDING (Low, latent): the netplan argv grammar checks the --root-dir string only. A plain-looking
// path that is a symlink to "/" (or to a directory someone else controls) passes, and "netplan generate
// --root-dir <it>" then reads the real /etc/netplan and writes the real /run/systemd/network, which is
// exactly what the grammar's comment says it refuses. Not reachable today: no command runs binNetplan;
// only a CI test does, through its own runner. Before slice 3-4 gives it a caller, the directory must be
// created by the host itself (root-owned chain, O_NOFOLLOW, like D-87), or generate must leave the
// production runner.
func TestReviewNetplanArgvRefusesASymlinkToTheRealRoot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	link := filepath.Join(dir, "root")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	if err := validateNetplan([]string{"generate", "--root-dir", link}); err == nil {
		t.Fatalf("--root-dir %s (a symlink to /) was accepted: netplan generate would regenerate the real network configuration", link)
	}
}

// FINDING (Low): readNetplanConfig says the /run overlay wins "because it is what netplan runs", but a
// /run/netplan/90-vedette.yaml the host cannot read back (truncated by a crash mid-write, edited) is
// skipped and /etc's file is reported as the configuration. netplan itself still uses the /run file
// (same basename shadows /etc entirely), so state/net reports a management card, mode and addresses
// that are not the ones in force, and the roles follow the wrong file. When an overlay exists and is not
// ours the honest answer is "unknown" (config.mgmt null), not the /etc file.
func TestReviewForeignRunOverlayIsNotReportedAsTheEtcConfig(t *testing.T) {
	t.Parallel()
	o, root := netOps(t, withIfaces(HostIface{Name: "eth0"}, HostIface{Name: "eth1"}))
	card(t, root, "eth0", stats("1", "1"), true)
	card(t, root, "eth1", stats("1", "1"), true)
	etc, _ := renderNetplan(NetplanConfig{Mgmt: NetplanMgmt{Iface: "eth0", Mode: api.NetModeDHCP}})
	put(t, root, "etc/netplan/90-vedette.yaml", string(etc))
	// What netplan actually runs: an overlay that moves management to eth1 with a static address,
	// cut short (the last byte is missing), so the host cannot read it back.
	run, _ := renderNetplan(NetplanConfig{Mgmt: NetplanMgmt{Iface: "eth1", Mode: api.NetModeStatic, Address: netip.MustParsePrefix("10.0.0.5/24")}})
	put(t, root, "run/netplan/90-vedette.yaml", string(run[:len(run)-1]))
	st := readState(t, o)
	if st.Config.Mgmt != nil && st.Config.Mgmt.Iface == "eth0" {
		t.Fatalf("state/net reports /etc's eth0 DHCP as the configuration while netplan runs the /run overlay (eth1 static): %+v", st.Config.Mgmt)
	}
}

// FINDING (Low): core's hostNetSource treats state/net as "every address of the box", but readNet lists
// only cards with a hardware parent plus the management/SPAN card. Addresses the appliance holds on a
// VLAN sub-interface, a bond or bridge that is not the management card, a WireGuard link or a second
// podman bridge are never reported, so core/conn's "not the box" check (D-94) and the sweep's protected
// list do not know them. The 16-address cap per card, sorted as strings, drops global IPv6 addresses the
// same way (SLAAC from a router or a rogue RA can give a card more than 16).
func TestReviewEveryAddressOfTheBoxReachesCore(t *testing.T) {
	t.Parallel()
	t.Run("virtual links", func(t *testing.T) {
		t.Parallel()
		o, root := netOps(t, withIfaces(
			HostIface{Name: "eth0", MAC: "02:00:00:00:00:01", Addrs: pfx("192.168.10.250/24")},
			HostIface{Name: "eth0.20", MAC: "02:00:00:00:00:01", Addrs: pfx("10.20.0.5/24")},
			HostIface{Name: "wg0", Addrs: pfx("100.64.0.7/32")},
		))
		card(t, root, "eth0", stats("1", "1"), true)
		card(t, root, "eth0.20", stats("1", "1"), false)
		card(t, root, "wg0", stats("1", "1"), false)
		put(t, root, "proc/net/route", routeText)
		got := reviewAllAddrs(readState(t, o))
		for _, want := range []string{"10.20.0.5", "100.64.0.7"} {
			if !got[want] {
				t.Errorf("the box's address %s (on a virtual link) is not in state/net, so core does not treat it as the box", want)
			}
		}
	})
	t.Run("more than 16 addresses", func(t *testing.T) {
		t.Parallel()
		addrs := pfx("192.168.10.250/24", "fe80::1/64")
		for i := range 18 {
			addrs = append(addrs, netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::5/64", i+1)))
		}
		o, root := netOps(t, withIfaces(HostIface{Name: "eth0", MAC: "02:00:00:00:00:01", Addrs: addrs}))
		card(t, root, "eth0", stats("1", "1"), true)
		put(t, root, "proc/net/route", routeText)
		got := reviewAllAddrs(readState(t, o))
		for _, p := range addrs {
			if a := p.Addr(); !a.IsLinkLocalUnicast() && !got[a.String()] {
				t.Errorf("global address %s of the management card was cut by the per-card cap", a)
			}
		}
	})
}

func reviewAllAddrs(st api.NetState) map[string]bool {
	out := map[string]bool{}
	for _, i := range st.Interfaces {
		for _, s := range i.Addresses {
			if p, err := netip.ParsePrefix(s); err == nil {
				out[p.Addr().String()] = true
			}
		}
	}
	return out
}

// FINDING (Low): the packet socket is created with protocol ETH_P_ARP and only then bound to one
// ifindex. Between socket() and bind() the kernel already queues ARP frames from EVERY interface,
// including the SPAN card, which in promiscuous mode receives the mirrored network's ARP. Recv never
// checks sockaddr_ll.Ifindex, so those queued frames are read after bind as if they came from the
// probed card: a false conflict or a false "gateway answers", and root reads (ARP) frames of the SPAN
// mirror, against the "bound to one card" wording of INV-18. Fix: socket(AF_PACKET, SOCK_RAW, 0) and set
// the protocol in bind (nothing is queued before bind), or drop frames whose Ifindex is not s.index.
// (Source check: the package cannot open a real socket in tests, D-107.)
func TestReviewARPSocketOnlyEverReadsItsOwnCard(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("arp_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	sock := regexp.MustCompile(`(?m)unix\.Socket\(unix\.AF_PACKET,[^,]+,\s*(.*)\)\s*$`).FindStringSubmatch(src)
	if sock == nil {
		t.Fatal("no AF_PACKET socket call found")
	}
	protoAtCreate := strings.TrimSpace(sock[1]) != "0"
	recv := src[strings.Index(src, "func (s *packetARP) Recv"):]
	recv = recv[:strings.Index(recv, "\n}\n")]
	checksIfindex := strings.Contains(recv, "Ifindex")
	if protoAtCreate && !checksIfindex {
		t.Fatalf("socket opened with protocol %q before bind, and Recv does not check the frame's Ifindex: frames of other cards queued before bind are read", sock[1])
	}
}

// FINDING (Low): the reader refuses every frame longer than 60 bytes, so a conflicting host whose
// card or driver delivers a longer ARP frame (FCS kept with rx-fcs, vendor trailers) is never seen
// and the probe says "free" for an address in use: the check fails open. The padding is never read
// either way, so truncating any frame of 42 bytes or more to 42 adds no parsing surface.
func TestReviewProbeSeesAConflictInALongerFrame(t *testing.T) {
	t.Parallel()
	s := &fakeSock{mac: macA}
	s.push(append(reply(macB, probed, gwIP), make([]byte, 22)...)) // 64 bytes: 60 + FCS
	res, err := fastProber(s).Probe(context.Background(), "eth0", probed)
	if err != nil || !res.Conflict {
		t.Fatalf("a 64-byte ARP reply from the probed address was ignored: %+v %v (the address is in use)", res, err)
	}
}
