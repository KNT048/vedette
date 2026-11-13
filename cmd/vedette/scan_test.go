package main

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/modules/inventory"
)

// fakeScanInv counts reads: the adapter must take Careful and the IP from the decision, not re-read the device.
type fakeScanInv struct {
	policy, devices, settings int
	batches                   [][]string
}

func (f *fakeScanInv) Settings(context.Context) (inventory.Settings, error) {
	f.settings++
	return inventory.Settings{}, nil
}
func (f *fakeScanInv) Devices(context.Context) (inventory.DeviceList, error) {
	f.devices++
	return inventory.DeviceList{}, nil
}
func (f *fakeScanInv) VulnScanPolicy(context.Context, string, bool) (inventory.ScanDecision, error) {
	f.policy++
	return inventory.ScanDecision{Allowed: true, Rate: 12, Reason: inventory.ReasonOK, Careful: true, IP: netip.MustParseAddr("192.168.10.20")}, nil
}

func (f *fakeScanInv) VulnScanPolicies(_ context.Context, ids []string, _ bool) (map[string]inventory.ScanDecision, error) {
	f.batches = append(f.batches, ids)
	out := map[string]inventory.ScanDecision{}
	for _, id := range ids {
		if id != "a-gone" {
			out[id] = inventory.ScanDecision{Allowed: true, Rate: 12, Reason: inventory.ReasonOK, Careful: true, IP: netip.MustParseAddr("192.168.10.20")}
		}
	}
	return out, nil
}

// D-472: the adapter reads the policy of a whole list in chunks of inventory.MaxPolicyBatch, never one read per device;
// a device deleted since the list was read is absent, and Careful and the IP come with each decision.
func TestScanAdapterVulnScanPoliciesBatches(t *testing.T) {
	f := &fakeScanInv{}
	ids := make([]string, inventory.MaxPolicyBatch+3)
	for i := range ids {
		ids[i] = fmt.Sprintf("a-%d", i)
	}
	ids[5] = "a-gone"
	m, err := scanInventory{inv: f}.VulnScanPolicies(t.Context(), ids, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.batches) != 2 || len(f.batches[0]) != inventory.MaxPolicyBatch || len(f.batches[1]) != 3 || f.policy != 0 {
		t.Fatalf("batches %d (first %d), single reads %d; want 2 (%d, 3), 0", len(f.batches), len(f.batches[0]), f.policy, inventory.MaxPolicyBatch)
	}
	if _, ok := m["a-gone"]; ok || len(m) != len(ids)-1 {
		t.Errorf("got %d decisions, gone present %v; want %d without a-gone", len(m), ok, len(ids)-1)
	}
	if d := m["a-7"]; !d.Allowed || !d.Careful || d.IP != "192.168.10.20" {
		t.Errorf("a-7: %+v", d)
	}
}

// Beta item 27: a device is never named "—" in the scan list.
func TestScanLabel(t *testing.T) {
	host, ip := "NAS-1", "192.168.10.20"
	dev := func(h *string, ip string, sw []inventory.Software, vendor string) inventory.Device {
		d := inventory.Device{AssetCore: inventory.AssetCore{Hostname: h, IP: ip}, Software: sw}
		if vendor != "" {
			d.Vendor = &inventory.Observed{Value: vendor}
		}
		return d
	}
	for want, d := range map[string]inventory.Device{
		"NAS-1":                            dev(&host, ip, nil, ""),
		"192.168.10.20":                    dev(nil, ip, nil, ""),
		"Microsoft Office (no device)":     dev(nil, "—", []inventory.Software{{Display: "Microsoft Office"}}, "Microsoft"),
		"Apple (no device)":                dev(nil, "—", nil, "Apple"),
		"Device without a name or address": dev(nil, "—", nil, ""),
	} {
		if got := scanLabel(d); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestScanAdapterVulnScanPolicyIsOneRead(t *testing.T) {
	f := &fakeScanInv{}
	d, err := scanInventory{inv: f}.VulnScanPolicy(t.Context(), "a-1", true)
	if err != nil || !d.Allowed || !d.Careful || d.IP != "192.168.10.20" {
		t.Fatalf("%+v, %v", d, err)
	}
	if f.policy != 1 || f.devices != 0 || f.settings != 0 {
		t.Errorf("reads: policy %d, devices %d, settings %d; want 1, 0, 0", f.policy, f.devices, f.settings)
	}
}
