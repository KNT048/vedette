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

// Scan INV-14 (review M1 of #933): ports an agent or the box listed are not nuclei targets; a port the scan also found is one target
// with the scan's service name; UDP is not a target.
func TestScanPortsAreTheScansOnly(t *testing.T) {
	t.Parallel()
	rows := []inventory.ServiceRow{
		{Port: 22, Proto: "tcp", Name: "sshd", Source: "agent"},
		{Port: 22, Proto: "tcp", Name: "ssh", Source: "nmap"},
		{Port: 53, Proto: "udp", Name: "domain", Source: "nmap"},
		{Port: 443, Proto: "tcp", Name: "nginx", Source: "agent"},
		{Port: 8443, Proto: "tcp", Name: "ssl/http", Source: "nmap"},
		{Port: 8443, Proto: "tcp", Name: "https", Source: "scan"},
	}
	got := scanPorts(rows)
	if fmt.Sprint(got) != "[{22 ssh} {8443 ssl/http}]" {
		t.Fatalf("scan ports %v", got)
	}
	if got := scanPorts(rows[3:4]); len(got) != 0 { // agent-only: no target, so nuclei keeps its 80/443 fallback
		t.Fatalf("an agent-only port became a target: %v", got)
	}
}
