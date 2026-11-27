package inventory_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// INV-46: the manual source's time is when a person last entered or changed something on the device. A device added long ago
// whose software row was entered or edited today reads today; one nobody changed since reads the time it was added (its typed
// details and product); a sensor's report never moves it, and a device no person touched has none.
func TestINV46_ManualTimeIsTheLastPersonEdit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	const who = "op@example.com"
	at := func(id string) string {
		t.Helper()
		d := e.detail(id)
		if d.ManualAt == nil {
			return ""
		}
		return *d.ManualAt
	}
	ts := func() string { return e.now.UTC().Format("2006-01-02T15:04:05.000Z") }

	// Added by hand and not changed since: the time it was added.
	hand := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Name: "fw-01", IP: "192.168.40.1"})
	added := ts()
	if got, first := at(hand), e.detail(hand).Asset.FirstSeen; got != added || first != added {
		t.Fatalf("a device added by hand and not changed since: manual_at = %q, want the time it was added %q (first_seen %q)", got, added, first)
	}

	// Two days later a person enters more software it runs: that time, not the day it was added.
	e.tick(48 * time.Hour)
	if _, err := e.svc.AddSoftware(e.ctx(), who, hand, inventory.AddInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6"}); err != nil {
		t.Fatal(err)
	}
	entered := ts()
	if got := at(hand); got != entered {
		t.Fatalf("a software row entered after the device was added: manual_at = %q, want %q", got, entered)
	}

	// An hour later the version is edited: the edit's time.
	e.tick(time.Hour)
	var sid string
	for _, s := range e.detail(hand).Asset.Software {
		if s.Product == "OpenSSH" {
			sid = s.ID
		}
	}
	if err := e.svc.EditSoftware(e.ctx(), who, hand, sid, inventory.SoftwareEdit{Version: ptr("9.7")}); err != nil {
		t.Fatal(err)
	}
	if got := at(hand); got != ts() {
		t.Fatalf("a software row edited: manual_at = %q, want %q", got, ts())
	}

	// A type set later counts as well.
	e.tick(time.Hour)
	kind := "router"
	if err := e.svc.PatchDevice(e.ctx(), who, hand, inventory.Patch{Kind: &kind}); err != nil {
		t.Fatal(err)
	}
	if got := at(hand); got != ts() {
		t.Fatalf("a type set by a person: manual_at = %q, want %q", got, ts())
	}

	// An OS set later too (the person's OS replaces the previous one; its row carries the new time).
	e.tick(time.Hour)
	osv := "FortiOS 7.2.14"
	if err := e.svc.PatchDevice(e.ctx(), who, hand, inventory.Patch{OS: &osv}); err != nil {
		t.Fatal(err)
	}
	if got := at(hand); got != ts() {
		t.Fatalf("an OS set by a person: manual_at = %q, want %q", got, ts())
	}

	// A device a sensor found: none until a person says a reported row is not installed, then that time; a later report keeps it.
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.168.40.20")}
	report := func(version string) {
		t.Helper()
		sightedBy(t.Context(), t, e.svc, hint, observe.Nmap)
		if err := e.svc.ReplaceSoftware(e.ctx(), hint, observe.Nmap, nil, []observe.Software{
			{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: version, CPE: "cpe:/a:openbsd:openssh:" + version, Confidence: 0.9},
		}); err != nil {
			t.Fatal(err)
		}
	}
	report("10.2")
	found := deviceAt(t, e, hint.IP)
	if d := e.detail(found); d.ManualAt != nil {
		t.Fatalf("a device no person touched: manual_at = %q, want none", *d.ManualAt)
	}
	e.tick(time.Hour)
	scanned, _ := swViews(t, e, found)
	if err := e.svc.EditSoftware(e.ctx(), who, found, scanned.ID, inventory.SoftwareEdit{NotInstalled: true}); err != nil {
		t.Fatal(err)
	}
	marked := ts()
	e.tick(time.Hour)
	report("10.2")
	if got := at(found); got != marked {
		t.Fatalf("marked not installed, then reported again: manual_at = %q, want the person's time %q", got, marked)
	}
}
