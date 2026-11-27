package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

var ipSvc = netip.MustParseAddr("192.168.10.20")

// servicesOf lists a device's services as "port/proto name product version source", in the order Detail gives them.
func servicesOf(d inventory.Detail) []string {
	out := []string{}
	for _, s := range d.Asset.Services {
		var p, v string
		if s.Product != nil {
			p = *s.Product
		}
		if s.Version != nil {
			v = *s.Version
		}
		out = append(out, strings.TrimSpace(fmt.Sprintf("%d/%s %s %s %s %s", s.Port, s.Proto, s.Name, p, v, s.Source)))
	}
	return out
}

// A list of open ports from one source replaces what that source reported before, and only that (INV-23, POST-2b).
func TestContract_INV23_ServicesReplacedPerSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := e.ctx()
	e.record(obs(ipSvc, macA, observe.MAC, macA, observe.Passive, 0.9))
	id := e.idByMAC(macA)
	hint := observe.AssetHint{IP: ipSvc}
	nmap := []observe.Service{
		{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "8.9p1", Confidence: 0.95},
		{Port: 80, Proto: "tcp", Name: "http", Confidence: 0.5},
		{Port: 22, Proto: "tcp", Name: "ssh-again", Confidence: 0.1}, // the same port twice: the first one counts
		{Port: 22, Proto: "udp", Name: "", Confidence: 0.3},          // another protocol is another service; the name may be empty
	}
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, observe.ServiceScope{}, nmap); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ReplaceServices(ctx, hint, observe.Agent, observe.ServiceScope{}, []observe.Service{{Port: 443, Proto: "tcp", Name: "https", Product: "nginx", Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	want := []string{"22/tcp ssh OpenSSH 8.9p1 nmap", "22/udp    nmap", "80/tcp http   nmap", "443/tcp https nginx  agent"}
	if got := servicesOf(e.detail(id)); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("services\n got %q\nwant %q", got, want)
	}
	// The next scan: 22 got a new version, 80 closed. The agent's row is not touched.
	e.tick(time.Hour)
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, observe.ServiceScope{}, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.6p1", Confidence: 0.95}}); err != nil {
		t.Fatal(err)
	}
	want = []string{"22/tcp ssh OpenSSH 9.6p1 nmap", "443/tcp https nginx  agent"}
	if got := servicesOf(e.detail(id)); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("after the second scan\n got %q\nwant %q", got, want)
	}
	if n := e.count(`SELECT count(*) FROM inv_service WHERE asset_id = ? AND source = 'nmap' AND seen_at = ?`, id, "2026-11-09T11:00:00.000Z"); n != 1 {
		t.Fatalf("the refreshed row's seen_at did not move (%d rows at the new time)", n)
	}
	// An empty list: that source saw nothing open.
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, observe.ServiceScope{}, nil); err != nil {
		t.Fatal(err)
	}
	if got := servicesOf(e.detail(id)); len(got) != 1 || got[0] != "443/tcp https nginx  agent" {
		t.Fatalf("after an empty nmap list: %q", got)
	}
	// "manual" is never a sensor's source.
	if err := e.svc.ReplaceServices(ctx, hint, observe.Manual, observe.ServiceScope{}, nil); !errors.Is(err, inventory.ErrInvalid) {
		t.Fatalf("manual source: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM inv_asset`); n != 1 {
		t.Fatalf("%d devices, want the one", n)
	}
}

// Everything in a list is untrusted (SYS-6): a bad item refuses the list before any write; an item with an invisible character is
// dropped alone (INV-22), and the harmless default-ignorable ones are stripped.
func TestContract_INV23_ServiceBounds(t *testing.T) {
	t.Parallel()
	ok := observe.Service{Port: 80, Proto: "tcp", Name: "http", Product: "Apache httpd", Version: "2.4.52", Confidence: 0.5}
	with := func(f func(*observe.Service)) []observe.Service { s := ok; f(&s); return []observe.Service{s} }
	bad := map[string][]observe.Service{
		"port 0":            with(func(s *observe.Service) { s.Port = 0 }),
		"port 65536":        with(func(s *observe.Service) { s.Port = 65536 }),
		"proto sctp":        with(func(s *observe.Service) { s.Proto = "sctp" }),
		"proto upper":       with(func(s *observe.Service) { s.Proto = "TCP" }),
		"confidence > 1":    with(func(s *observe.Service) { s.Confidence = 1.5 }),
		"confidence < 0":    with(func(s *observe.Service) { s.Confidence = -0.1 }),
		"confidence NaN":    with(func(s *observe.Service) { s.Confidence = math.NaN() }),
		"name 101":          with(func(s *observe.Service) { s.Name = strings.Repeat("n", 101) }),
		"product 201":       with(func(s *observe.Service) { s.Product = strings.Repeat("p", 201) }),
		"version 101":       with(func(s *observe.Service) { s.Version = strings.Repeat("1", 101) }),
		"control in name":   with(func(s *observe.Service) { s.Name = "ht\ntp" }),
		"bad utf-8 product": with(func(s *observe.Service) { s.Product = "\xff\xfe" }),
		"too many":          make([]observe.Service, 1001),
	}
	for i := range bad["too many"] {
		bad["too many"][i] = observe.Service{Port: i + 1, Proto: "tcp", Confidence: 0.5}
	}
	for name, items := range bad {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			if err := e.svc.ReplaceServices(e.ctx(), observe.AssetHint{IP: ipSvc}, observe.Nmap, observe.ServiceScope{}, items); !errors.Is(err, inventory.ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
			if n := e.count(`SELECT count(*) FROM inv_asset`) + e.count(`SELECT count(*) FROM inv_service`); n != 0 {
				t.Fatalf("a refused list wrote %d rows", n)
			}
		})
	}
	// The bounds themselves pass: 1000 items, port 65535, udp, a 100-character name, a 200-character product, a 100-character version.
	e := newEnv(t)
	full := make([]observe.Service, 1000)
	for i := range full {
		full[i] = observe.Service{Port: 65535 - i, Proto: "udp", Name: strings.Repeat("n", 100), Product: strings.Repeat("p", 200), Version: strings.Repeat("1", 100), Confidence: 1}
	}
	sightedBy(t.Context(), t, e.svc, observe.AssetHint{IP: ipSvc}, observe.Nmap)
	if err := e.svc.ReplaceServices(e.ctx(), observe.AssetHint{IP: ipSvc}, observe.Nmap, observe.ServiceScope{}, full); err != nil {
		t.Fatalf("the largest list: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM inv_service`); n != 1000 {
		t.Fatalf("%d rows, want 1000", n)
	}
	// One banner with a bidi override is dropped alone; a variation selector is stripped, the port kept.
	e2 := newEnv(t)
	items := []observe.Service{
		{Port: 22, Proto: "tcp", Name: "ssh", Product: "Open\u202eHSS", Confidence: 0.5},
		{Port: 80, Proto: "tcp", Name: "http\ufe0f", Confidence: 0.5},
	}
	sightedBy(t.Context(), t, e2.svc, observe.AssetHint{IP: ipSvc}, observe.Nmap)
	if err := e2.svc.ReplaceServices(e2.ctx(), observe.AssetHint{IP: ipSvc}, observe.Nmap, observe.ServiceScope{}, items); err != nil {
		t.Fatal(err)
	}
	if n := e2.count(`SELECT count(*) FROM inv_service WHERE port = 80 AND name = 'http'`) + e2.count(`SELECT count(*) FROM inv_service`); n != 2 {
		t.Fatalf("want only port 80 stored as http (got %d)", n)
	}
}

// Ports reported for an address the box owns (a decoy) make no device (INV-17), like observations and software.
func TestContract_INV23_ServicesOfABoxOwnedAddressAreDropped(t *testing.T) {
	t.Parallel()
	owned := netip.MustParseAddr("192.168.10.240")
	e := newEnv(t, func(c *inventory.Config) {
		c.BoxOwnedIPs = func(context.Context) []netip.Addr { return []netip.Addr{owned} }
	})
	if err := e.svc.ReplaceServices(e.ctx(), observe.AssetHint{IP: owned}, observe.Nmap, observe.ServiceScope{}, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.5}}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_asset`) + e.count(`SELECT count(*) FROM inv_service`); n != 0 || e.svc.BoxOwnedSkipped() != 1 {
		t.Fatalf("%d rows, %d skipped: the decoy address became a device", n, e.svc.BoxOwnedSkipped())
	}
}

// A service no source has reported for 90 days is removed by the housekeeping prune; a fresher one stays (INV-23).
func TestPruneServicesRemovesOnlyRowsNotSeenFor90Days(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := e.ctx()
	other := netip.MustParseAddr("192.168.10.21")
	sightedBy(t.Context(), t, e.svc, observe.AssetHint{IP: ipSvc}, observe.Nmap)
	if err := e.svc.ReplaceServices(ctx, observe.AssetHint{IP: ipSvc}, observe.Nmap, observe.ServiceScope{}, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.5}}); err != nil {
		t.Fatal(err)
	}
	e.tick(60 * 24 * time.Hour)
	sightedBy(t.Context(), t, e.svc, observe.AssetHint{IP: other}, observe.Nmap)
	if err := e.svc.ReplaceServices(ctx, observe.AssetHint{IP: other}, observe.Nmap, observe.ServiceScope{}, []observe.Service{{Port: 80, Proto: "tcp", Name: "http", Confidence: 0.5}}); err != nil {
		t.Fatal(err)
	}
	e.tick(30 * 24 * time.Hour) // the first row is exactly 90 days old: kept
	if n, err := e.svc.PruneServices(ctx); err != nil || n != 0 {
		t.Fatalf("at 90 days: pruned %d, %v", n, err)
	}
	e.tick(time.Minute)
	if n, err := e.svc.PruneServices(ctx); err != nil || n != 1 {
		t.Fatalf("past 90 days: pruned %d, %v; want 1", n, err)
	}
	if n := e.count(`SELECT count(*) FROM inv_service WHERE port = 80`) + e.count(`SELECT count(*) FROM inv_service`); n != 2 {
		t.Fatal("the fresh row went too, or the old one stayed")
	}
	if n := e.count(`SELECT count(*) FROM inv_asset`); n != 2 {
		t.Fatalf("the prune removed a device: %d left", n)
	}
	if got := e.auditActions(); !has(got, "inventory.services_pruned") {
		t.Fatalf("no audit row of the prune: %v", got)
	}
	n := 0
	for _, a := range e.auditActions() {
		if a == "inventory.services_pruned" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d prune audit rows, want one (the prune that removed nothing writes none)", n)
	}
}

// A partial look (a gentle scan) adds the ports it saw and keeps what a full scan of the same source said: nothing is removed,
// and a port already listed keeps its name, product, version and confidence; only seen_at moves (INV-23).
func TestContract_INV23_AddServicesKeepsTheFullList(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := e.ctx()
	hint := observe.AssetHint{IP: ipSvc}
	full := []observe.Service{
		{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "8.9p1", Confidence: 0.95},
		{Port: 8080, Proto: "tcp", Name: "http-proxy", Product: "Squid http proxy", Version: "5.7", Confidence: 0.76},
	}
	sightedBy(t.Context(), t, e.svc, hint, observe.Nmap)
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, observe.ServiceScope{}, full); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Hour)
	gentle := []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.29}, {Port: 9100, Proto: "tcp", Name: "jetdirect", Confidence: 0.29}}
	sightedBy(t.Context(), t, e.svc, hint, observe.Nmap)
	if err := e.svc.AddServices(ctx, hint, observe.Nmap, gentle); err != nil {
		t.Fatal(err)
	}
	l, err := e.svc.Devices(ctx)
	if err != nil || len(l.Items) != 1 {
		t.Fatalf("devices: %v %v", l.Items, err)
	}
	want := []string{"22/tcp ssh OpenSSH 8.9p1 nmap", "8080/tcp http-proxy Squid http proxy 5.7 nmap", "9100/tcp jetdirect   nmap"}
	if got := servicesOf(e.detail(l.Items[0].ID)); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("services\n got %q\nwant %q", got, want)
	}
	if n := e.count(`SELECT count(*) FROM inv_service WHERE port = 22 AND confidence = 0.95 AND seen_at = ?`, "2026-11-09T11:00:00.000Z"); n != 1 {
		t.Fatal("port 22 lost its confidence, or its seen_at did not move")
	}
	if n := e.count(`SELECT count(*) FROM inv_service WHERE port = 8080 AND seen_at = ?`, "2026-11-09T10:00:00.000Z"); n != 1 {
		t.Fatal("port 8080, not in the partial look, was touched")
	}
	// A partial look that read the product of a port (the weekly -sV follow-up) updates it; a version changes
	sightedBy(t.Context(), t, e.svc, hint, observe.Nmap)
	if err := e.svc.AddServices(ctx, hint, observe.Nmap, []observe.Service{{Port: 8080, Proto: "tcp", Name: "http-proxy", Product: "Squid http proxy", Version: "6.10", Confidence: 0.8}}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_service WHERE port = 8080 AND version = '6.10' AND confidence = 0.8`); n != 1 {
		t.Fatal("a partial look with a product did not update the port's version")
	}
	if n := e.count(`SELECT count(*) FROM inv_service WHERE port = 22 AND product = 'OpenSSH' AND version = '8.9p1'`); n != 1 {
		t.Fatal("a partial look without a product changed port 22")
	}
}

// A scan of a few ports replaces the rows of those ports and leaves the device's other services (the scoped ReplaceServices).
func TestScopedReplaceServicesKeepsThePortsItDidNotScan(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := e.ctx()
	e.record(obs(ipSvc, macA, observe.MAC, macA, observe.Passive, 0.9))
	id := e.idByMAC(macA)
	hint := observe.AssetHint{IP: ipSvc}
	full := []observe.Service{
		{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "8.9p1", Confidence: 0.95},
		{Port: 80, Proto: "tcp", Name: "http", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
		{Port: 40000, Proto: "tcp", Name: "http", Product: "Acme admin", Version: "1.0", Confidence: 0.8},
	}
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, observe.ServiceScope{}, full); err != nil {
		t.Fatal(err)
	}
	// a scan of ports 1-1000: 22 has a new version, 80 closed; 40000 was not looked at
	scope := observe.ServiceScope{Ports: []observe.PortRange{{From: 1, To: 1000}}}
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, scope, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.6p1", Confidence: 0.95}}); err != nil {
		t.Fatal(err)
	}
	want := []string{"22/tcp ssh OpenSSH 9.6p1 nmap", "40000/tcp http Acme admin 1.0 nmap"}
	if got := servicesOf(e.detail(id)); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("after a scan of ports 1-1000\n got %q\nwant %q", got, want)
	}
	// a scan that only found which ports are open leaves what a fuller scan said about a port
	disc := observe.ServiceScope{Ports: []observe.PortRange{{From: 1, To: 65535}}, NoVersions: true}
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, disc, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.5}, {Port: 8443, Proto: "tcp", Name: "https-alt", Confidence: 0.5}}); err != nil {
		t.Fatal(err)
	}
	want = []string{"22/tcp ssh OpenSSH 9.6p1 nmap", "8443/tcp https-alt   nmap"}
	if got := servicesOf(e.detail(id)); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("after a discovery of every port\n got %q\nwant %q", got, want)
	}
}

// A service outside the scope, or not TCP, makes a scoped list invalid; so does a bad range.
func TestScopedReplaceServicesRefusesWhatIsOutsideTheScope(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	hint := observe.AssetHint{IP: ipSvc}
	scope := observe.ServiceScope{Ports: []observe.PortRange{{From: 1, To: 1000}}}
	for name, c := range map[string]struct {
		scope observe.ServiceScope
		items []observe.Service
	}{
		"port outside":     {scope, []observe.Service{{Port: 8080, Proto: "tcp", Confidence: 1}}},
		"udp in a scope":   {scope, []observe.Service{{Port: 53, Proto: "udp", Confidence: 1}}},
		"backwards range":  {observe.ServiceScope{Ports: []observe.PortRange{{From: 90, To: 80}}}, nil},
		"range over 65535": {observe.ServiceScope{Ports: []observe.PortRange{{From: 1, To: 70000}}}, nil},
		"negative keep":    {observe.ServiceScope{Ports: []observe.PortRange{{From: 1, To: 10}}, KeepFor: -time.Hour}, nil},
	} {
		if err := e.svc.ReplaceServices(e.ctx(), hint, observe.Nmap, c.scope, c.items); !errors.Is(err, inventory.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

// A row outside the scope that the source has not seen for scope.KeepFor goes with the scan; a younger one stays. A port that
// goes takes the software the source read on it (observe.PortInstance).
func TestScopedReplaceServicesAgesOutOthersAndTheirSoftware(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := e.ctx()
	e.record(obs(ipSvc, macA, observe.MAC, macA, observe.Passive, 0.9))
	id := e.idByMAC(macA)
	hint := observe.AssetHint{IP: ipSvc}
	sv := func(p int) observe.Service {
		return observe.Service{Port: p, Proto: "tcp", Name: "http", Confidence: 0.8}
	}
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, observe.ServiceScope{}, []observe.Service{sv(40000)}); err != nil {
		t.Fatal(err)
	}
	read := observe.Software{Display: "Acme admin 1.0", Vendor: "acme", Product: "admin", Version: "1.0", Instance: observe.PortInstance(40000), Confidence: 0.8}
	if err := e.svc.ReplaceSoftware(ctx, hint, observe.Nmap, []string{read.Instance}, []observe.Software{read}); err != nil {
		t.Fatal(err)
	}
	e.tick(13 * 24 * time.Hour)
	scope := observe.ServiceScope{Ports: []observe.PortRange{{From: 1, To: 1000}}, KeepFor: 14 * 24 * time.Hour}
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, scope, []observe.Service{sv(80)}); err != nil {
		t.Fatal(err)
	}
	if got := servicesOf(e.detail(id)); len(got) != 2 {
		t.Fatalf("13 days after the port was seen: %q", got)
	}
	readings := func() int {
		return e.count(`SELECT count(*) FROM inv_software_reading r JOIN inv_software s ON s.id = r.software_id WHERE s.asset_id = ? AND r.instance = ?`, id, read.Instance)
	}
	if readings() != 1 {
		t.Fatal("the reading of port 40000 is missing")
	}
	e.tick(2 * 24 * time.Hour)
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, scope, []observe.Service{sv(80)}); err != nil {
		t.Fatal(err)
	}
	if got := servicesOf(e.detail(id)); len(got) != 1 || got[0] != "80/tcp http   nmap" {
		t.Fatalf("15 days after the port was seen: %q", got)
	}
	if readings() != 0 {
		t.Fatal("the software read on the port that went is still there")
	}
}

// read_at (INV-23) is when the source last read a port's name, product and version: a list that read versions sets it on every port
// it lists (one that named no product too), a scan that only found open ports leaves it, and a port that names a product in such a
// scan or in an added list sets it. PortReadTimes gives it by port. The 90 days of PruneServices still count from seen_at.
func TestContract_INV23_ReadAtMovesOnlyOnAVersionRead(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := e.ctx()
	e.record(obs(ipSvc, macA, observe.MAC, macA, observe.Passive, 0.9))
	id := e.idByMAC(macA)
	hint := observe.AssetHint{IP: ipSvc}
	reads := func() map[int]time.Time {
		t.Helper()
		m, err := e.svc.PortReadTimes(ctx, id, observe.Nmap)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	same := func(got, want map[int]time.Time) bool {
		if len(got) != len(want) {
			return false
		}
		for p, w := range want {
			if !got[p].Equal(w) {
				return false
			}
		}
		return true
	}
	t0 := e.now
	normal := observe.ServiceScope{Ports: []observe.PortRange{{From: 1, To: 1000}}}
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, normal, []observe.Service{
		{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.6p1", Confidence: 0.95},
		{Port: 23, Proto: "tcp", Name: "tcpwrapped", Confidence: 0.5}, // read, named nothing
	}); err != nil {
		t.Fatal(err)
	}
	if got := reads(); !same(got, map[int]time.Time{22: t0, 23: t0}) {
		t.Fatalf("after a scan with versions: %v", got)
	}
	// the weekly discovery of every port reads no versions: it keeps the read times and adds 40000 unread
	e.tick(24 * time.Hour)
	disc := observe.ServiceScope{Ports: []observe.PortRange{{From: 1, To: 65535}}, NoVersions: true}
	found := []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.5}, {Port: 23, Proto: "tcp", Name: "telnet", Confidence: 0.5}, {Port: 40000, Proto: "tcp", Name: "unknown", Confidence: 0.5}}
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, disc, found); err != nil {
		t.Fatal(err)
	}
	if got := reads(); !same(got, map[int]time.Time{22: t0, 23: t0}) {
		t.Fatalf("after a discovery: %v", got)
	}
	// its follow-up reads 40000 and 23 with versions: both move, the one that names nothing too, and 22 keeps its time
	e.tick(time.Hour)
	t1 := e.now
	follow := observe.ServiceScope{Ports: []observe.PortRange{{From: 23, To: 23}, {From: 40000, To: 40000}}}
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, follow, []observe.Service{
		{Port: 23, Proto: "tcp", Name: "tcpwrapped", Confidence: 0.5},
		{Port: 40000, Proto: "tcp", Name: "http", Product: "Acme admin", Version: "1.0", Confidence: 0.8},
	}); err != nil {
		t.Fatal(err)
	}
	if got := reads(); !same(got, map[int]time.Time{22: t0, 23: t1, 40000: t1}) {
		t.Fatalf("after the follow-up: %v", got)
	}
	// a gentle look names no product and moves nothing; a discovery whose port names a product moves that port
	e.tick(time.Hour)
	t2 := e.now
	if err := e.svc.AddServices(ctx, hint, observe.Nmap, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.3}}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, disc, []observe.Service{found[0], found[1], {Port: 40000, Proto: "tcp", Name: "http", Product: "Acme admin", Version: "1.1", Confidence: 0.8}}); err != nil {
		t.Fatal(err)
	}
	if got := reads(); !same(got, map[int]time.Time{22: t0, 23: t1, 40000: t2}) {
		t.Fatalf("after a gentle look and a discovery that named a product: %v", got)
	}
	// a port that closes takes its read time with it; the other source's rows and an unknown device have none
	e.tick(time.Hour)
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, disc, found[:2]); err != nil {
		t.Fatal(err)
	}
	if got := reads(); !same(got, map[int]time.Time{22: t0, 23: t1}) {
		t.Fatalf("after 40000 closed: %v", got)
	}
	if m, err := e.svc.PortReadTimes(ctx, id, observe.Agent); err != nil || len(m) != 0 {
		t.Fatalf("agent read times %v, %v", m, err)
	}
	if m, err := e.svc.PortReadTimes(ctx, "no-such-device", observe.Nmap); err != nil || len(m) != 0 {
		t.Fatalf("unknown device: %v, %v", m, err)
	}
	// 91 days after 22 was read but a day after a discovery saw it, the prune keeps it: it counts from seen_at
	e.tick(89 * 24 * time.Hour)
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, disc, found[:2]); err != nil {
		t.Fatal(err)
	}
	e.tick(24 * time.Hour)
	if n, err := e.svc.PruneServices(ctx); err != nil || n != 0 {
		t.Fatalf("prune removed %d (%v), want 0", n, err)
	}
	if got := reads(); !same(got, map[int]time.Time{22: t0, 23: t1}) {
		t.Fatalf("after the prune: %v", got)
	}
}
