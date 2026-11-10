package host_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
)

// decoy_ip.add and decoy_ip.remove, the honeypot namespace and the re-apply (WP-07b part 3, slice
// 3-5; spec 6.6, D-102; host CONTRACT DECOY-1..DECOY-8). The machine is the fake of opstest with
// its stateful ip: it remembers links, addresses, rules and the nft ruleset, so the tests assert both
// the exact argv of every step and the effect.

const (
	decoyIP1 = "192.168.1.100"
	decoyIP2 = "192.168.1.101"
	// The kernel's /proc/net/route for a default route via 192.168.1.1 on eth0.
	routeVia1 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
)

type decoyEnv struct {
	*netEnv
}

// startDecoy starts a host whose box is 192.168.1.50/24 behind 192.168.1.1 (the default route; the
// host has not configured the network itself). before runs on the machine before Start.
func startDecoy(t *testing.T, before ...func(*opstest.Machine)) *decoyEnv {
	t.Helper()
	box, probe := &netBox{}, &fakeProber{}
	e := startSys(t, netMut(box, probe))
	box.m = e.m
	physicalCards(e.m)
	e.m.WriteRoot("proc/net/route", routeVia1)
	e.m.RuleText("chronyc", "-N", "^,*,203.0.113.7,2,6,377,12,0.0,0.0,0.0\n", 0, "", "")
	for _, f := range before {
		f(e.m)
	}
	e.o.Start(context.Background(), e.h.Server)
	t.Cleanup(e.o.Close)
	return &decoyEnv{&netEnv{sysEnv: e, box: box, probe: probe}}
}

func (d *decoyEnv) add(t *testing.T, ip string, oui ...string) api.Run {
	t.Helper()
	a := api.DecoyAddArgs{IP: ip}
	if len(oui) > 0 {
		a.OUI = oui[0]
	}
	return d.ok(t, "decoy_ip.add", a)
}

// refusedBy runs a command and returns the refusal code, whether the server refused it before the
// run (412) or the run ended refused.
func (d *decoyEnv) refusedBy(t *testing.T, command string, args any) string {
	t.Helper()
	r, err := d.call(t, command, args)
	var ce *client.Error
	switch {
	case errors.As(err, &ce):
		if ce.Status != http.StatusPreconditionFailed {
			t.Fatalf("%s: status %d code %s", command, ce.Status, ce.Code)
		}
		return ce.Code
	case err != nil:
		t.Fatal(err)
	case r.Status != api.StatusRefused || r.Error == nil:
		t.Fatalf("%s was not refused: %+v", command, r)
	default:
		return r.Error.Code
	}
	return ""
}

func (d *decoyEnv) ipCalls() []string {
	var out []string
	for _, c := range d.m.Calls(ops.BinIP) {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

// since returns the ip calls made after the first n.
func (d *decoyEnv) since(n int) []string { return d.ipCalls()[n:] }

func (d *decoyEnv) decoysFile() string {
	b, _ := os.ReadFile(filepath.Join(d.m.State, "hp", "decoys.json"))
	return string(b)
}

func (d *decoyEnv) auditCodes(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, a := range audit(t, d.h) {
		if a.Actor == "system" && a.Code != nil {
			out = append(out, a.Command+"/"+*a.Code)
		}
	}
	return out
}

// derived is the MAC the spec gives an IP under the key of the machine.
func (d *decoyEnv) derived(t *testing.T, ip string, oui string) string {
	t.Helper()
	key, err := os.ReadFile(filepath.Join(d.m.State, "hp", "mac.key"))
	if err != nil || len(key) != 32 {
		t.Fatalf("mac.key: %v", err)
	}
	a := netip.MustParseAddr(ip).As4()
	h := hmac.New(sha256.New, key)
	h.Write(a[:])
	s := h.Sum(nil)
	mac := make([]byte, 6)
	if oui == "" {
		copy(mac, s[:6])
		mac[0] = mac[0]&^0x01 | 0x02
	} else {
		for i := range 3 {
			mac[i] = hexByte(oui[2*i : 2*i+2])
		}
		copy(mac[3:], s[:3])
	}
	var b strings.Builder
	for i, x := range mac {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(string("0123456789abcdef"[x>>4]) + string("0123456789abcdef"[x&15]))
	}
	return b.String()
}

func hexByte(s string) byte {
	var v byte
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= byte(c - '0')
		default:
			v |= byte(c-'a') + 10
		}
	}
	return v
}

// --- the honeypot namespace at Start (D-102 (1), (3), (4)) -----------------------------------------

func TestContract_Decoy_StartMakesTheNamespaceSetsTheSysctlsLoadsTheRulesetAndChecksIt(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	want := []string{
		"netns add vedette-hp",
		"netns exec vedette-hp /usr/sbin/sysctl -w net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.arp_announce=2 net.ipv4.conf.all.rp_filter=2 net.ipv4.ip_unprivileged_port_start=0",
		"netns exec vedette-hp /usr/sbin/nft -f -",
		"netns exec vedette-hp /usr/sbin/nft list ruleset", // the effect check
		"-n vedette-hp -j addr show",                       // the start re-apply: no decoys, only leftovers are looked for
	}
	if got := d.ipCalls(); !slices.Equal(got, want) {
		t.Fatalf("ip calls at start:\n%q\nwant\n%q", got, want)
	}
	if rs := d.m.IPState("ruleset"); !strings.Contains(rs, "ct state new drop") || !strings.Contains(rs, "ct state established,related accept") || !strings.Contains(rs, "hook output") {
		t.Fatalf("ruleset sent to nft:\n%s", rs)
	}
	if !strings.Contains(d.m.IPState("ruleset.in"), "flush ruleset") {
		t.Fatal("the load does not replace what was there")
	}
	if got := d.auditCodes(t); len(got) != 0 {
		t.Fatalf("a healthy start wrote audit lines: %v", got)
	}
	for _, c := range d.m.Calls(ops.BinIP) {
		if err := ops.ValidateIP(c); err != nil {
			t.Errorf("an ip call outside the grammar: %q", c)
		}
	}
	assertEnvClean(t, d.m.Envs(ops.BinIP))
}

func TestContract_Decoy_ANamespaceThatIsMissingIsMadeAgainAtStart(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.add(t, decoyIP1)
	mac := d.state(t).Decoys[0].MAC
	// A reboot: /run is empty (no namespace, so the links and the ruleset in it are gone too).
	d.o.Close()
	shutdownHost(t, d)
	d.m.RemoveRoot("run/netns/vedette-hp")
	_ = os.RemoveAll(filepath.Join(d.m.Rec, ops.BinIP, "ns"))
	_ = os.Remove(filepath.Join(d.m.Rec, ops.BinIP, "ruleset"))
	_ = os.Remove(filepath.Join(d.m.Rec, ops.BinIP, "rules"))
	n := len(d.ipCalls())
	d2 := restartHost(t, d.netEnv)
	got := d2.ipCalls()[n:]
	if len(got) < 3 || got[0] != "netns add vedette-hp" || !strings.Contains(got[1], "sysctl -w") || got[2] != "netns exec vedette-hp /usr/sbin/nft -f -" {
		t.Fatalf("calls at the second start: %q", got)
	}
	if !strings.Contains(d2.m.IPState("ruleset"), "ct state new drop") {
		t.Fatal("the ruleset was not loaded into the new namespace")
	}
	// The decoy is back, with the same MAC, and state/net still lists it.
	l := d2.m.IPState("ns/vdhc0a80164")
	if !strings.Contains(l, "mac="+mac) || !strings.Contains(l, "up=1") || !strings.Contains(l, "addr=192.168.1.100/24") {
		t.Fatalf("link after the start:\n%s", l)
	}
	if st := d2.state(t); len(st.Decoys) != 1 || st.Decoys[0].MAC != mac {
		t.Fatalf("decoys %+v", st.Decoys)
	}
}

func TestContract_Decoy_AnEgressRulesetThatIsNotReallyLoadedFailsTheStartAndTheAdd(t *testing.T) {
	t.Parallel()
	d := startDecoy(t, func(m *opstest.Machine) { m.Mark("nft-noload", true) })
	// At Start the load silently did nothing: the effect check fails, the host still serves, and says so.
	if got := d.auditCodes(t); !slices.Contains(got, "decoy_ip/hp_namespace_failed") {
		t.Fatalf("audit: %v", got)
	}
	n := len(d.ipCalls())
	code := ""
	if r, err := d.call(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP1}); err != nil {
		t.Fatal(err)
	} else if r.Status != api.StatusFailed || r.Error == nil || r.Error.Code != api.CodeHPNamespaceUnavailable {
		t.Fatalf("add with an unproven ruleset: %+v", r)
	} else {
		code = r.Error.Code
	}
	for _, c := range d.since(n) {
		if strings.HasPrefix(c, "link add") || strings.HasPrefix(c, "link set") {
			t.Fatalf("a link was made although the egress drop is not proven (%s): %q", code, c)
		}
	}
	if d.decoysFile() != "" {
		t.Fatalf("decoys.json: %s", d.decoysFile())
	}
	// Once nft loads it, the next add works: the add loads the ruleset again when it finds it missing.
	d.m.Mark("nft-noload", false)
	d.add(t, decoyIP1)
}

// --- decoy_ip.add: the steps and the effect ---------------------------------------------------------

func TestContract_Decoy_AddBuildsTheLinkAndChecksTheEffect(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	n := len(d.ipCalls())
	run := d.add(t, decoyIP1)
	res := result[api.DecoyAddResult](t, run)
	mac := d.derived(t, decoyIP1, "")
	if res.IP != decoyIP1 || res.MAC != mac {
		t.Fatalf("result %+v, want mac %s", res, mac)
	}
	b, _ := hexBytes(res.MAC)
	if b[0]&0x02 == 0 || b[0]&0x01 != 0 {
		t.Fatalf("mac bits of %s", res.MAC)
	}
	want := []string{
		"netns exec vedette-hp /usr/sbin/nft list ruleset", // the namespace is still proven
		"-n vedette-hp -j addr show",
		"link add link eth0 name vdhc0a80164 address " + mac + " type macvlan mode bridge",
		"link set vdhc0a80164 netns vedette-hp",
		"-n vedette-hp addr add 192.168.1.100/24 dev vdhc0a80164",
		"-n vedette-hp link set vdhc0a80164 up",
		"-n vedette-hp route flush table 100",
		"-n vedette-hp route replace 192.168.1.0/24 dev vdhc0a80164 src 192.168.1.100 table 100",
		"-n vedette-hp route replace default via 192.168.1.1 dev vdhc0a80164 table 100",
		"-n vedette-hp rule del from 192.168.1.100 lookup 100",
		"-n vedette-hp rule add from 192.168.1.100 lookup 100",
		"-n vedette-hp -j addr show", // the effect check
	}
	if got := d.since(n); !slices.Equal(got, want) {
		t.Fatalf("ip calls:\n%q\nwant\n%q", got, want)
	}
	// The effect: the link is in the namespace with the MAC and the address, and not in the host's.
	if !slices.Equal(d.m.IPLinks("ns"), []string{"vdhc0a80164"}) || len(d.m.IPLinks("host")) != 0 {
		t.Fatalf("links: ns %v host %v", d.m.IPLinks("ns"), d.m.IPLinks("host"))
	}
	// The state file, 0600, and state/net.
	var f struct {
		Decoys []struct {
			IP, MAC, Iface string
			Table          int
		}
	}
	if err := json.Unmarshal([]byte(d.decoysFile()), &f); err != nil || len(f.Decoys) != 1 || f.Decoys[0].Table != 100 || f.Decoys[0].Iface != "eth0" {
		t.Fatalf("decoys.json %q: %v", d.decoysFile(), err)
	}
	if st, err := os.Stat(filepath.Join(d.m.State, "hp", "decoys.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", st, err)
	}
	if st, err := os.Stat(filepath.Join(d.m.State, "hp", "mac.key")); err != nil || st.Mode().Perm() != 0o600 || st.Size() != 32 {
		t.Fatalf("mac.key: %v %v", st, err)
	}
	if got := d.state(t).Decoys; len(got) != 1 || got[0].IP != decoyIP1 || got[0].MAC != mac {
		t.Fatalf("state/net decoys %+v", got)
	}
	// Every call is in the grammar.
	for _, c := range d.m.Calls(ops.BinIP) {
		if err := ops.ValidateIP(c); err != nil {
			t.Errorf("outside the grammar: %q", c)
		}
	}
	// A second decoy gets the next table and the next MAC.
	d.add(t, decoyIP2)
	if !strings.Contains(d.m.IPState("routes"), "table 101") {
		t.Fatalf("routes:\n%s", d.m.IPState("routes"))
	}
}

func hexBytes(mac string) ([]byte, error) {
	var out []byte
	for _, p := range strings.Split(mac, ":") {
		out = append(out, hexByte(p))
	}
	return out, nil
}

func TestContract_Decoy_AddWithAnOUIAndTheMACRules(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	res := result[api.DecoyAddResult](t, d.add(t, decoyIP1, "001A2B"))
	if !strings.HasPrefix(res.MAC, "00:1a:2b:") || res.MAC != d.derived(t, decoyIP1, "001a2b") {
		t.Fatalf("mac %s", res.MAC)
	}
	// Each bad oui is invalid_args and nothing runs.
	n := len(d.ipCalls())
	for _, oui := range []string{"01005E", "020000", "FE0000", "00:1A:2B", "001A2", "001A2B0", "GG1A2B", "0x1A2B", "-01A2B"} {
		_, err := d.call(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP2, OUI: oui})
		var ce *client.Error
		if !errors.As(err, &ce) || ce.Status != http.StatusBadRequest || ce.Code != api.CodeInvalidArgs {
			t.Errorf("oui %q: %v", oui, err)
		}
	}
	if got := d.since(n); len(got) != 0 {
		t.Fatalf("a bad oui reached ip: %q", got)
	}
}

func TestContract_Decoy_TheSameIPKeepsItsMACAcrossRestartsAndRemoval(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	first := result[api.DecoyAddResult](t, d.add(t, decoyIP1)).MAC
	d.ok(t, "decoy_ip.remove", api.DecoyRemoveArgs{IP: decoyIP1})
	d.o.Close()
	shutdownHost(t, d)
	d2 := restartHost(t, d.netEnv)
	if again := result[api.DecoyAddResult](t, d2.add(t, decoyIP1)).MAC; again != first {
		t.Fatalf("the MAC changed: %s then %s", first, again)
	}
	// Another installation (another key) gives the same IP another MAC.
	other := startDecoy(t)
	if m := result[api.DecoyAddResult](t, other.add(t, decoyIP1)).MAC; m == first {
		t.Fatalf("two installations gave %s", m)
	}
}

// --- decoy_ip.add: every refusal --------------------------------------------------------------------

func TestContract_Decoy_AddRefusals(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.add(t, decoyIP1) // one decoy, for duplicate_decoy
	baseline := len(d.ipCalls())
	state := d.decoysFile()
	cases := []struct {
		name string
		ip   string
		oui  string
		want string
	}{
		{"outside the subnet", "192.168.2.10", "", api.CodeIPNotInMgmtSubnet},
		{"another network", "10.1.2.3", "", api.CodeIPNotInMgmtSubnet},
		{"the network address", "192.168.1.0", "", api.CodeIPIsNetwork},
		{"the broadcast address", "192.168.1.255", "", api.CodeIPIsBroadcast},
		{"the gateway", "192.168.1.1", "", api.CodeIPIsGateway},
		{"the box itself", "192.168.1.50", "", api.CodeIPIsHost},
		{"a duplicate", decoyIP1, "", api.CodeDuplicateDecoy},
		{"a duplicate with another oui", decoyIP1, "001A2B", api.CodeDuplicateDecoy},
	}
	for _, c := range cases {
		if got := d.refusedBy(t, "decoy_ip.add", api.DecoyAddArgs{IP: c.ip, OUI: c.oui}); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	// Nothing was built, nothing was probed beyond the first add, and the state did not change.
	for _, call := range d.since(baseline) {
		if strings.HasPrefix(call, "link add") || strings.Contains(call, "addr add") {
			t.Errorf("a refused add built something: %q", call)
		}
	}
	if d.decoysFile() != state {
		t.Fatalf("decoys.json changed: %s", d.decoysFile())
	}
	if p := d.probe.probes(); len(p) != 1 {
		t.Fatalf("probes %v: only the one add that passed every check probes", p)
	}
	// Bad arguments are invalid_args (400), never refusals.
	for _, ip := range []string{"fd00::5", "::ffff:192.168.1.5", "192.168.1.300", "192.168.1.5/24", "192.168.1.05", "", "192.168.1.5 ", "-1", "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"} {
		_, err := d.call(t, "decoy_ip.add", api.DecoyAddArgs{IP: ip})
		var ce *client.Error
		if !errors.As(err, &ce) || ce.Status != http.StatusBadRequest || ce.Code != api.CodeInvalidArgs {
			t.Errorf("ip %q: %v", ip, err)
		}
	}
}

func TestContract_Decoy_NotApplianceComesBeforeAnyOtherCheck(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.m.OSRelease("debian", "11", "Debian 11")
	n := len(d.ipCalls())
	// 10.1.2.3 would also be outside the subnet: the order puts not_appliance first.
	if got := d.refusedBy(t, "decoy_ip.add", api.DecoyAddArgs{IP: "10.1.2.3"}); got != api.CodeNotAppliance {
		t.Fatalf("%s", got)
	}
	if len(d.since(n)) != 0 {
		t.Fatal("ip ran")
	}
}

func TestContract_Decoy_AnAddressAnotherDeviceAnswersForIsRefusedAfterTheProbe(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.probe.set(func(p *fakeProber) { p.conflict = true })
	n := len(d.ipCalls())
	if got := d.refusedBy(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP1}); got != api.CodeIPInUse {
		t.Fatalf("%s", got)
	}
	if p := d.probe.probes(); len(p) != 1 || p[0] != "eth0 192.168.1.100" {
		t.Fatalf("probes %v", p)
	}
	for _, c := range d.since(n) {
		if strings.HasPrefix(c, "link add") {
			t.Fatalf("built after a conflict: %q", c)
		}
	}
	// A probe that cannot run fails the run and builds nothing.
	d.probe.set(func(p *fakeProber) { p.conflict, p.probeErr = false, errors.New("no socket") })
	if r, err := d.call(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP1}); err != nil || r.Status != api.StatusFailed || r.Error.Code != api.CodeARPProbeFailed {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestContract_Decoy_TheLimitIs32(t *testing.T) {
	t.Parallel()
	d := startDecoy(t, func(m *opstest.Machine) {
		var parts []string
		for i := range 32 {
			parts = append(parts, `{"ip":"192.168.1.`+itoa3(110+i)+`","mac":"02:00:00:00:00:`+hex2d(i)+`","table":`+itoa3(100+i)+`,"iface":"eth0"}`)
		}
		if err := os.MkdirAll(filepath.Join(m.State, "hp"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(m.State, "hp", "decoys.json"), []byte(`{"decoys":[`+strings.Join(parts, ",")+`]}`), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if got := d.refusedBy(t, "decoy_ip.add", api.DecoyAddArgs{IP: "192.168.1.200"}); got != api.CodeLimitReached {
		t.Fatalf("%s", got)
	}
	// 32 is the limit, not 31: a decoy that is not new is still a duplicate, which comes first.
	if got := d.refusedBy(t, "decoy_ip.add", api.DecoyAddArgs{IP: "192.168.1.110"}); got != api.CodeDuplicateDecoy {
		t.Fatalf("%s", got)
	}
	if got := len(d.state(t).Decoys); got != 32 {
		t.Fatalf("%d decoys in state/net", got)
	}
}

func itoa3(i int) string {
	return string(rune('0'+i/100)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}
func hex2d(i int) string { return string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16]) }

func TestContract_Decoy_ALinkOfThatNameThatTheHostDidNotMakeIsNeverTouched(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	// The host has a link called vdhc0a80164 already (vdh + c0a80164 is 192.168.1.100).
	base := d.box.interfaces
	d.o.Close()
	shutdownHost(t, d)
	o2 := d.m.Ops(d.clock.Now, func(c *ops.Config, dp *ops.Deps) {
		netMut(d.box, d.probe)(c, dp)
		dp.Interfaces = func() ([]ops.HostIface, error) {
			l, err := base()
			return append(l, ops.HostIface{Name: "vdhc0a80164", MAC: "02:aa:aa:aa:aa:aa"}), err
		}
	})
	h2 := servertest.Start(t, o2.Commands(), func(so *server.Options) {
		so.StateDir, so.AuditPath, so.Readers, so.Now, so.WriteGate, so.Resume = d.m.State, d.h.AuditPath, o2.Readers(), d.clock.Now, o2.WriteGate, o2.Resume
	})
	o2.Start(context.Background(), h2.Server)
	t.Cleanup(o2.Close)
	d2 := &decoyEnv{&netEnv{sysEnv: &sysEnv{m: d.m, o: o2, h: h2, clock: d.clock, timers: d.timers}, box: d.box, probe: d.probe}}
	n := len(d2.ipCalls())
	if got := d2.refusedBy(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP1}); got != api.CodeLinkNameInUse {
		t.Fatalf("%s", got)
	}
	for _, c := range d2.since(n) {
		if strings.Contains(c, "vdhc0a80164") {
			t.Fatalf("the host touched the link it did not make: %q", c)
		}
	}
	if d2.decoysFile() != "" {
		t.Fatalf("state %s", d2.decoysFile())
	}
}

func TestContract_Decoy_TwoDecoysNeverShareAMAC(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	r1 := result[api.DecoyAddResult](t, d.add(t, decoyIP1, "001A2B"))
	// The state of another decoy that holds the MAC the second IP would get.
	_ = d.derived(t, decoyIP2, "001a2b")
	mac2 := d.derived(t, decoyIP2, "001a2b")
	stateFile := filepath.Join(d.m.State, "hp", "decoys.json")
	var f struct {
		Decoys []map[string]any `json:"decoys"`
	}
	if err := json.Unmarshal([]byte(d.decoysFile()), &f); err != nil {
		t.Fatal(err)
	}
	f.Decoys[0]["mac"] = mac2
	b, _ := json.Marshal(f)
	if err := os.WriteFile(stateFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := d.refusedBy(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP2, OUI: "001A2B"}); got != api.CodeMACInUse {
		t.Fatalf("%s", got)
	}
	_ = r1
}

func TestContract_Decoy_AMACKeyThatIsALinkOrWrongFailsTheAddAndInventsNothing(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	hp := filepath.Join(d.m.State, "hp")
	if err := os.MkdirAll(hp, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(d.m.State, "other.key")
	if err := os.WriteFile(target, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(hp, "mac.key")); err != nil {
		t.Fatal(err)
	}
	n := len(d.ipCalls())
	r, err := d.call(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP1})
	if err != nil || r.Status != api.StatusFailed || r.Error.Code != api.CodeMACKeyInvalid {
		t.Fatalf("%+v %v", r, err)
	}
	for _, c := range d.since(n) {
		if strings.HasPrefix(c, "link add") {
			t.Fatalf("built with no key: %q", c)
		}
	}
}

// --- failures leave nothing behind ------------------------------------------------------------------

func TestContract_Decoy_AFailedStepIsUndoneAndNothingIsRecorded(t *testing.T) {
	t.Parallel()
	for _, pattern := range []string{"link set vdhc0a80164 netns", "addr add", "route replace default", "rule add"} {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()
			d := startDecoy(t)
			d.m.Rule(ops.BinIP, pattern, "", 1, "", "")
			r, err := d.call(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP1})
			if err != nil || r.Status != api.StatusFailed || r.Error.Code != api.CodeDecoyFailed {
				t.Fatalf("%+v %v", r, err)
			}
			if len(d.m.IPLinks("ns")) != 0 || len(d.m.IPLinks("host")) != 0 {
				t.Fatalf("leftovers: ns %v host %v", d.m.IPLinks("ns"), d.m.IPLinks("host"))
			}
			if d.decoysFile() != "" || len(d.state(t).Decoys) != 0 {
				t.Fatalf("recorded: %s", d.decoysFile())
			}
		})
	}
}

func TestContract_Decoy_ALinkThatDoesNotShowWithTheRightMACFailsTheEffectCheck(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	// The address never shows in the listing: the add made it but cannot prove it.
	d.m.Rule(ops.BinIP, "addr add", "", 0, "", "")
	r, err := d.call(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP1})
	if err != nil || r.Status != api.StatusFailed || r.Error.Code != api.CodeDecoyFailed {
		t.Fatalf("%+v %v", r, err)
	}
	if len(d.m.IPLinks("ns")) != 0 {
		t.Fatalf("links %v", d.m.IPLinks("ns"))
	}
	if strings.Contains(d.decoysFile(), decoyIP1) || len(d.state(t).Decoys) != 0 {
		t.Fatalf("recorded: %s", d.decoysFile())
	}
}

// --- decoy_ip.remove --------------------------------------------------------------------------------

func TestContract_Decoy_RemoveDeletesTheRuleTheRoutesAndTheLinkAndIsIdempotent(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.add(t, decoyIP1)
	d.add(t, decoyIP2)
	n := len(d.ipCalls())
	res := result[api.DecoyRemoveResult](t, d.ok(t, "decoy_ip.remove", api.DecoyRemoveArgs{IP: decoyIP1}))
	if !res.Removed {
		t.Fatalf("%+v", res)
	}
	want := []string{
		"-n vedette-hp rule del from 192.168.1.100 lookup 100",
		"-n vedette-hp route flush table 100",
		"-n vedette-hp link del vdhc0a80164",
		"-n vedette-hp -j addr show",
	}
	if got := d.since(n); !slices.Equal(got, want) {
		t.Fatalf("calls:\n%q\nwant\n%q", got, want)
	}
	if !slices.Equal(d.m.IPLinks("ns"), []string{"vdhc0a80165"}) || strings.Contains(d.m.IPState("rules"), "192.168.1.100") {
		t.Fatalf("ns %v rules %s", d.m.IPLinks("ns"), d.m.IPState("rules"))
	}
	if got := d.state(t).Decoys; len(got) != 1 || got[0].IP != decoyIP2 {
		t.Fatalf("decoys %+v", got)
	}
	// A decoy that is not there: success, nothing changed, no ip call.
	n = len(d.ipCalls())
	again := result[api.DecoyRemoveResult](t, d.ok(t, "decoy_ip.remove", api.DecoyRemoveArgs{IP: decoyIP1}))
	if again.Removed || len(d.since(n)) != 0 {
		t.Fatalf("second remove: %+v, calls %q", again, d.since(n))
	}
	if r := result[api.DecoyRemoveResult](t, d.ok(t, "decoy_ip.remove", api.DecoyRemoveArgs{IP: "192.168.7.7"})); r.Removed {
		t.Fatal("an address that was never a decoy was removed")
	}
	// The freed table is the lowest free one for the next decoy.
	d.add(t, "192.168.1.102")
	if !strings.Contains(d.m.IPState("routes"), "192.168.1.102 table 100") {
		t.Fatalf("routes:\n%s", d.m.IPState("routes"))
	}
	// And bad arguments are refused.
	for _, ip := range []string{"nope", "fd00::1", ""} {
		_, err := d.call(t, "decoy_ip.remove", api.DecoyRemoveArgs{IP: ip})
		var ce *client.Error
		if !errors.As(err, &ce) || ce.Code != api.CodeInvalidArgs {
			t.Errorf("remove %q: %v", ip, err)
		}
	}
}

func TestContract_Decoy_ALinkThatStaysAfterARemoveFailsTheRun(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.add(t, decoyIP1)
	d.m.Rule(ops.BinIP, "link del vdhc0a80164", "", 1, "", "")
	r, err := d.call(t, "decoy_ip.remove", api.DecoyRemoveArgs{IP: decoyIP1})
	if err != nil || r.Status != api.StatusFailed || r.Error.Code != api.CodeDecoyFailed {
		t.Fatalf("%+v %v", r, err)
	}
	// The decoy is out of the list: a restart (or the next reconcile) removes the link nobody owns.
	if len(d.state(t).Decoys) != 0 {
		t.Fatal("still listed")
	}
	d.m.ClearRules(ops.BinIP)
	d.o.Close()
	shutdownHost(t, d)
	d2 := restartHost(t, d.netEnv)
	if len(d2.m.IPLinks("ns")) != 0 {
		t.Fatalf("a leftover link survived the start: %v", d2.m.IPLinks("ns"))
	}
}

// --- the re-apply after a network change (D-100, D-102 (6)) -----------------------------------------

func TestContract_Decoy_AfterANetApplyDecoysOutsideTheNewSubnetAreDroppedAndReported(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.add(t, decoyIP1)
	n := len(d.ipCalls())
	run := d.apply(t, staticArgs("10.0.0.5/24", "10.0.0.1"))
	// The re-apply ran after the new network was checked: the decoy is outside 10.0.0.0/24.
	got := d.since(n)
	if !slices.Contains(got, "-n vedette-hp link del vdhc0a80164") || !slices.Contains(got, "-n vedette-hp rule del from 192.168.1.100 lookup 100") {
		t.Fatalf("the decoy was not removed:\n%q", got)
	}
	if len(d.m.IPLinks("ns")) != 0 {
		t.Fatalf("links %v", d.m.IPLinks("ns"))
	}
	if st := d.state(t); len(st.Decoys) != 0 || st.Pending == nil {
		t.Fatalf("state/net %+v", st)
	}
	if strings.Contains(d.decoysFile(), decoyIP1) {
		t.Fatalf("decoys.json still has it: %s", d.decoysFile())
	}
	if codes := d.auditCodes(t); !slices.Contains(codes, "decoy_ip/decoy_dropped") {
		t.Fatalf("no audit line for the dropped decoy: %v", codes)
	}
	for _, a := range audit(t, d.h) {
		if a.Command == "decoy_ip" && a.Code != nil && *a.Code == "decoy_dropped" && !strings.Contains(string(a.ArgsRedacted), "ip_not_in_mgmt_subnet") {
			t.Fatalf("the audit line does not say why: %s", a.ArgsRedacted)
		}
	}
	d.ok(t, "net.confirm", api.NetRunArgs{RunID: run.RunID})
	waitStatus(t, d.h, run.RunID, api.StatusSucceeded)
	// New decoys are for the new subnet now.
	if got := d.refusedBy(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP1}); got != api.CodeIPNotInMgmtSubnet {
		t.Fatalf("%s", got)
	}
}

func TestContract_Decoy_AfterANetApplyInTheSameSubnetDecoysStayWithTheNewGateway(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.add(t, decoyIP1)
	d.add(t, "192.168.1.60") // the address the box will take: it must not stay a decoy
	var macBefore string
	for _, x := range d.state(t).Decoys {
		if x.IP == decoyIP1 {
			macBefore = x.MAC
		}
	}
	n := len(d.ipCalls())
	d.apply(t, staticArgs("192.168.1.60/24", "192.168.1.2"))
	got := d.since(n)
	// .100 stays (same link, same MAC): its table is rebuilt with the new gateway, no link delete.
	if !slices.Contains(got, "-n vedette-hp route replace default via 192.168.1.2 dev vdhc0a80164 table 100") {
		t.Fatalf("no new default route:\n%q", got)
	}
	if slices.Contains(got, "-n vedette-hp link del vdhc0a80164") {
		t.Fatalf("a decoy that still fits was rebuilt:\n%q", got)
	}
	// .60 is the box now.
	if !slices.Contains(got, "-n vedette-hp link del vdhc0a8013c") {
		t.Fatalf("the decoy on the box's own new address stayed:\n%q", got)
	}
	st := d.state(t)
	if len(st.Decoys) != 1 || st.Decoys[0].IP != decoyIP1 || st.Decoys[0].MAC != macBefore {
		t.Fatalf("decoys %+v", st.Decoys)
	}
}

func TestContract_Decoy_ARevertPutsTheDecoysBackInLineWithTheOldNetwork(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.add(t, decoyIP1)
	run := d.apply(t, staticArgs("192.168.1.60/24", "192.168.1.2"))
	n := len(d.ipCalls())
	d.ok(t, "net.revert", api.NetRunArgs{RunID: run.RunID})
	waitStatus(t, d.h, run.RunID, api.StatusReverted)
	// The old network again: the decoy that fits is configured with the old gateway.
	got := d.since(n)
	if !slices.Contains(got, "-n vedette-hp route replace default via 192.168.1.1 dev vdhc0a80164 table 100") {
		t.Fatalf("the old gateway did not come back:\n%q", got)
	}
	if st := d.state(t); len(st.Decoys) != 1 {
		t.Fatalf("%+v", st.Decoys)
	}
}

func TestContract_Decoy_ADecoyThatCannotBeRebuiltIsDroppedNotKept(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.add(t, decoyIP1)
	// The link is gone from the namespace (the parent card was recreated); the rebuild fails.
	_ = os.RemoveAll(filepath.Join(d.m.Rec, ops.BinIP, "ns"))
	d.m.Rule(ops.BinIP, "link add link", "", 1, "", "")
	d.o.Close()
	shutdownHost(t, d)
	d2 := restartHost(t, d.netEnv)
	if len(d2.state(t).Decoys) != 0 {
		t.Fatal("a decoy that is not in the namespace is still listed")
	}
	if codes := d2.auditCodes(t); !slices.Contains(codes, "decoy_ip/decoy_dropped") {
		t.Fatalf("%v", codes)
	}
}

func TestContract_Decoy_AHostileStateFileIsSetAsideAndLeftoverLinksAreRemoved(t *testing.T) {
	t.Parallel()
	d := startDecoy(t, func(m *opstest.Machine) {
		if err := os.MkdirAll(filepath.Join(m.State, "hp"), 0o700); err != nil {
			t.Fatal(err)
		}
		hostile := `{"decoys":[{"ip":"192.168.1.100 -x","mac":"02:00:00:00:00:01","table":100,"iface":"eth0"}]}`
		if err := os.WriteFile(filepath.Join(m.State, "hp", "decoys.json"), []byte(hostile), 0o600); err != nil {
			t.Fatal(err)
		}
		// a leftover link in the namespace, from before
		_ = os.MkdirAll(filepath.Join(m.Rec, ops.BinIP, "ns"), 0o755)
		_ = os.WriteFile(filepath.Join(m.Rec, ops.BinIP, "ns", "vdhc0a80164"), []byte("mac=02:00:00:00:00:01\nup=1\n"), 0o600)
	})
	if _, err := os.Stat(filepath.Join(d.m.State, "hp", "decoys.json.invalid")); err != nil {
		t.Fatalf("not set aside: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d.m.State, "hp", "decoys.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the hostile file is still the state: %v", err)
	}
	if len(d.state(t).Decoys) != 0 || len(d.m.IPLinks("ns")) != 0 {
		t.Fatalf("decoys %+v links %v", d.state(t).Decoys, d.m.IPLinks("ns"))
	}
	if codes := d.auditCodes(t); !slices.Contains(codes, "decoy_ip/decoys_state_invalid") {
		t.Fatalf("%v", codes)
	}
	for _, c := range d.m.Calls(ops.BinIP) {
		if strings.Contains(strings.Join(c, " "), "-x") {
			t.Fatalf("hostile text reached ip: %q", c)
		}
	}
	// The host works on from an empty state.
	d.add(t, decoyIP1)
}

func TestContract_Decoy_AStateFileThatIsALinkIsNotFollowed(t *testing.T) {
	t.Parallel()
	d := startDecoy(t, func(m *opstest.Machine) {
		_ = os.MkdirAll(filepath.Join(m.State, "hp"), 0o700)
		target := filepath.Join(m.State, "elsewhere.json")
		_ = os.WriteFile(target, []byte(`{"decoys":[{"ip":"192.168.1.100","mac":"02:00:00:00:00:01","table":100,"iface":"eth0"}]}`), 0o600)
		_ = os.Symlink(target, filepath.Join(m.State, "hp", "decoys.json"))
	})
	if len(d.state(t).Decoys) != 0 {
		t.Fatal("a state file that is a link was read")
	}
	if got := d.m.IPLinks("ns"); len(got) != 0 {
		t.Fatalf("a decoy was built from it: %v", got)
	}
}

func TestContract_Decoy_NoNetworkYetMeansNoSubnetToRefuseAgainst(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.m.RemoveRoot("proc/net/route")
	if got := d.refusedBy(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP1}); got != api.CodeIPNotInMgmtSubnet {
		t.Fatalf("%s", got)
	}
}

func TestContract_Decoy_TheDecoyCommandsAreWritesUnderTheSharedLock(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	run := d.apply(t, staticArgs("10.0.0.5/24", "10.0.0.1"))
	// While a network change waits, a decoy command is 409 pending_confirm like every write.
	ce := d.refusedWith(t, "decoy_ip.add", api.DecoyAddArgs{IP: "10.0.0.20"}, http.StatusConflict, api.CodePendingConfirm)
	if ce.RunID != run.RunID {
		t.Fatalf("%q", ce.RunID)
	}
	_ = d.refusedWith(t, "decoy_ip.remove", api.DecoyRemoveArgs{IP: "10.0.0.20"}, http.StatusConflict, api.CodePendingConfirm)
}

// helpers: stop and start the host again on the same machine ---------------------------------------

func shutdownHost(t *testing.T, d *decoyEnv) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.h.Server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

// restartHost starts a new host on the state, the root and the audit file of n (after shutdownHost).
func restartHost(t *testing.T, n *netEnv) *decoyEnv {
	t.Helper()
	timers := &fakeTimers{}
	o2 := n.m.Ops(n.clock.Now, func(c *ops.Config, d *ops.Deps) {
		netMut(n.box, n.probe)(c, d)
		d.AfterFunc = timers.after
		d.FreeBytes = func(string) (uint64, error) { return 100 << 30, nil }
	})
	h2 := servertest.Start(t, o2.Commands(), func(so *server.Options) {
		so.StateDir, so.AuditPath, so.Readers, so.Now, so.WriteGate, so.Resume = n.m.State, n.h.AuditPath, o2.Readers(), n.clock.Now, o2.WriteGate, o2.Resume
	})
	o2.Start(context.Background(), h2.Server)
	t.Cleanup(o2.Close)
	return &decoyEnv{&netEnv{sysEnv: &sysEnv{m: n.m, o: o2, h: h2, clock: n.clock, timers: timers}, box: n.box, probe: n.probe}}
}
