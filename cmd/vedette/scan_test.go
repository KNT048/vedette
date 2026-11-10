package main

import (
	"context"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/modules/inventory"
)

// fakeScanInv counts reads: the adapter must take Careful and the IP from the decision, not re-read the device.
type fakeScanInv struct{ policy, devices, settings int }

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
