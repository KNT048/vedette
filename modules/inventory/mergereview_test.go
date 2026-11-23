package inventory_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// hpMAC is the card of a server a scan finds running VMware ESXi; esxiBanner is what its web service states.
const (
	hpMAC      = "94:57:a5:00:00:67"
	esxiBanner = "VMware ESXi 8.0 Update 3 (build 24022510)"
)

// esxiHost records a server found on the network at ip that states VMware ESXi 8.0 Update 3, build 24022510: its card, the maker of
// the card, the OS the scan read and the ESXi line of that banner. It returns the device id.
func esxiHost(e *env, ip string) string {
	e.t.Helper()
	h := observe.AssetHint{MAC: hpMAC, IP: netip.MustParseAddr(ip)}
	e.record(append(dhcp(hpMAC, ip, ""),
		observe.Observation{AssetHint: h, Field: observe.Vendor, Value: "Hewlett Packard", Source: observe.Passive, Confidence: 0.4},
		observe.Observation{AssetHint: h, Field: observe.OS, Value: esxiBanner, Source: observe.Nmap, Confidence: 0.95})...)
	sw := []observe.Software{{Display: esxiBanner, Vendor: "vmware", Product: "esxi", Version: "8.0", CPE: "cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*", Confidence: 0.9, Instance: "tcp/443"}}
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr(ip)}, observe.Nmap, nil, sw); err != nil {
		e.t.Fatal(err)
	}
	return e.idOf(ip)
}

// The merge review lists every field a person picks where the devices differ: a type only one of them states (the other's type the
// identification rules guess, or none) and an OS only one of them states are rows too, with the devices that have none, so "Pick the
// name, type and operating system" always has the type and OS to pick from. A guessed type may be picked; one none of them has may not.
func TestMergeReview_TypeAndOSRowsWhenOnlyOneDeviceStatesThem(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	hand := e.addDevice(inventory.AddInput{Vendor: "VMware", Product: "ESXi", Version: "8.0.3 build 24022510", Name: "esxi-01"})
	e.tick(time.Minute)
	host := esxiHost(e, "192.0.2.67")
	p, err := e.svc.MergePreview(e.ctx(), hand, []string{host})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]inventory.MergeField{}
	for _, f := range p.Differs {
		fields[f.Field] = f
	}
	kind, ok := fields["kind"]
	if !ok || !kind.Choosable {
		t.Fatalf("no type row: %+v", p.Differs)
	}
	os, ok := fields["os"]
	if !ok || !os.Choosable || !slices.Equal(os.Missing, []string{hand}) || len(os.Values) != 1 || os.Values[0].Device != host || os.Kept != esxiBanner {
		t.Fatalf("OS row: %+v", os)
	}
	guessed := ""
	for _, v := range kind.Values {
		if v.Device == host && v.Guess {
			guessed = v.Value
		}
	}
	if guessed != "" { // a guessed type is one a person may pick for the merged device
		if err := e.svc.MergeMany(e.ctx(), admin, hand, []string{host}, inventory.MergeChoice{Kind: &guessed}); err != nil {
			t.Fatalf("merge with the guessed type %q: %v", guessed, err)
		}
		if d := e.device(hand); d.Kind != guessed {
			t.Errorf("type after the merge = %q, want %q", d.Kind, guessed)
		}
		return
	}
	if len(kind.Missing) != 1 || kind.Missing[0] != host {
		t.Errorf("type row without a guess: %+v", kind)
	}
}

// A device added by hand with no address and a device the scan found that run the same OS at the same release are offered as
// possibly one machine (same_os), on both device pages and in the list of pairs; an OS of another release, a second hand-added row,
// or a found device that states another model are not.
func TestSameDevice_AHandAddedRowWithoutAnAddressAndAFoundDeviceOfOneOS(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	hand := e.addDevice(inventory.AddInput{Vendor: "VMware", Product: "ESXi", Version: "8.0.3 build 24022510", Name: "esxi-01"})
	other := e.addDevice(inventory.AddInput{Vendor: "VMware", Product: "ESXi", Version: "7.0.3 build 21930508", Name: "esxi-02"})
	twin := e.addDevice(inventory.AddInput{Vendor: "VMware", Product: "ESXi", Version: "8.0.3 build 24022510", Name: "esxi-03", IP: "192.0.2.90"})
	e.tick(time.Minute)
	host := esxiHost(e, "192.0.2.67")
	got := e.sameAs(host)
	ids := []string{}
	for _, p := range got {
		ids = append(ids, p.ID)
		// the release is named once, as the banner states it, not again as the version the line was filed under
		if want := "Both run " + esxiBanner + ", and esxi-01 was added by hand without an address: it may be this device."; p.Reason != inventory.ReasonSameOS || p.Why != want {
			t.Errorf("offer %+v", p)
		}
	}
	if !slices.Equal(ids, []string{hand}) {
		t.Fatalf("offered for the found host: %v, want only %s (not %s, %s)", ids, hand, other, twin)
	}
	if back := e.sameAs(hand); len(back) != 1 || back[0].ID != host || back[0].Reason != inventory.ReasonSameOS {
		t.Errorf("offered for the hand-added row: %+v", back)
	}
	pairs, err := e.svc.PossibleSamePairs(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range pairs.Items {
		if p.Reason == inventory.ReasonSameOS {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d same-OS pairs in the list, want 1: %+v", n, pairs.Items)
	}
	if err := e.svc.KeepSeparate(e.ctx(), admin, host, hand); err != nil {
		t.Fatal(err)
	}
	if again := e.sameAs(host); len(again) != 0 {
		t.Errorf("offered again after Keep separate: %+v", again)
	}
}
