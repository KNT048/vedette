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
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, nmap); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ReplaceServices(ctx, hint, observe.Agent, []observe.Service{{Port: 443, Proto: "tcp", Name: "https", Product: "nginx", Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	want := []string{"22/tcp ssh OpenSSH 8.9p1 nmap", "22/udp    nmap", "80/tcp http   nmap", "443/tcp https nginx  agent"}
	if got := servicesOf(e.detail(id)); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("services\n got %q\nwant %q", got, want)
	}
	// The next scan: 22 got a new version, 80 closed. The agent's row is not touched.
	e.tick(time.Hour)
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.6p1", Confidence: 0.95}}); err != nil {
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
	if err := e.svc.ReplaceServices(ctx, hint, observe.Nmap, nil); err != nil {
		t.Fatal(err)
	}
	if got := servicesOf(e.detail(id)); len(got) != 1 || got[0] != "443/tcp https nginx  agent" {
		t.Fatalf("after an empty nmap list: %q", got)
	}
	// "manual" is never a sensor's source.
	if err := e.svc.ReplaceServices(ctx, hint, observe.Manual, nil); !errors.Is(err, inventory.ErrInvalid) {
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
			if err := e.svc.ReplaceServices(e.ctx(), observe.AssetHint{IP: ipSvc}, observe.Nmap, items); !errors.Is(err, inventory.ErrInvalid) {
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
	if err := e.svc.ReplaceServices(e.ctx(), observe.AssetHint{IP: ipSvc}, observe.Nmap, full); err != nil {
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
	if err := e2.svc.ReplaceServices(e2.ctx(), observe.AssetHint{IP: ipSvc}, observe.Nmap, items); err != nil {
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
	if err := e.svc.ReplaceServices(e.ctx(), observe.AssetHint{IP: owned}, observe.Nmap, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.5}}); err != nil {
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
	if err := e.svc.ReplaceServices(ctx, observe.AssetHint{IP: ipSvc}, observe.Nmap, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.5}}); err != nil {
		t.Fatal(err)
	}
	e.tick(60 * 24 * time.Hour)
	if err := e.svc.ReplaceServices(ctx, observe.AssetHint{IP: other}, observe.Nmap, []observe.Service{{Port: 80, Proto: "tcp", Name: "http", Confidence: 0.5}}); err != nil {
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
}
