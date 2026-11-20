package main

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// #905: the device a finding is about is shown running its operating system, else its kind, never its first software by name
// ("Microsoft Edge" under WINLAB01's Windows findings). DeviceRef.Display keeps the first row for notify's and audit's names.
func TestWiringFindingAssetDisplayIsTheOSNotTheFirstSoftware(t *testing.T) {
	s := newStack(t)
	ctx := t.Context()
	winlab := observe.AssetHint{IP: netip.MustParseAddr("192.168.10.50")}
	bare := observe.AssetHint{IP: netip.MustParseAddr("192.168.10.51")}
	if err := s.d.Inventory.Record(ctx, []observe.Observation{
		{AssetHint: winlab, Field: observe.Hostname, Value: "WINLAB01", Source: observe.Agent, Confidence: 1},
		{AssetHint: winlab, Field: observe.OS, Value: "Microsoft Windows Server 2025 10.0.26100.1742", Source: observe.Agent, Confidence: 1},
		{AssetHint: winlab, Field: observe.Kind, Value: "server", Source: observe.Agent, Confidence: 1},
		{AssetHint: bare, Field: observe.Kind, Value: "nas", Source: observe.Nmap, Confidence: 0.9},
	}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []observe.AssetHint{winlab, bare} {
		if err := s.d.Inventory.ReplaceSoftware(ctx, h, observe.Osquery, nil, []observe.Software{
			{Display: "Windows Server 2025", Vendor: "Microsoft", Product: "Windows", Version: "10.0.26100.1742", KevKeys: []string{"microsoft|windows"}, Confidence: 1},
			{Display: "Microsoft Edge", Vendor: "Microsoft", Product: "Edge", Version: "131.0.2903.70", KevKeys: []string{"microsoft|edge"}, Confidence: 1},
		}); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := s.d.Inventory.AssetIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := s.d.Inventory.DeviceRefs(ctx, ids)
	if err != nil {
		t.Fatal(err)
	}
	byIP := map[string]string{}
	for id, r := range refs {
		byIP[r.IP] = id
	}
	win, nas := byIP["192.168.10.50"], byIP["192.168.10.51"]
	if win == "" || nas == "" {
		t.Fatalf("devices: %v", byIP)
	}
	if refs[win].Display != "Microsoft Edge" || refs[win].OS != "Microsoft Windows Server 2025 10.0.26100.1742" || refs[nas].OS != "" {
		t.Fatalf("DeviceRef: display %q os %q; bare os %q", refs[win].Display, refs[win].OS, refs[nas].OS)
	}
	got, err := (findingsInventory{s.d.Inventory}).Assets(ctx, []string{win, nas})
	if err != nil {
		t.Fatal(err)
	}
	if d := got[win].Display; d != "Microsoft Windows Server 2025 10.0.26100.1742" {
		t.Errorf("WINLAB01 shown running %q, want its OS", d)
	}
	if d := got[nas].Display; d != got[nas].Kind || d == "" {
		t.Errorf("a device without an OS shown running %q, want its kind %q", d, got[nas].Kind)
	}
}
