package inventory_test

import (
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// An ignored device is the same device when it is seen again, by its MAC alone (a passive LLDP frame), by MAC and address, or at
// another address: it stays ignored, is never announced as new, never reaches To review, and no second row appears. A removed
// device, by contrast, is a new device in To review.
func TestContract_INV51_IgnoredDeviceStaysIgnoredWhenSeenAgain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(dhcp(burnt1, "10.142.0.205", "switch")...)
	id := e.idOf("10.142.0.205")
	if err := e.svc.SetIgnored(e.ctx(), "user-a", id, true); err != nil {
		t.Fatal(err)
	}
	e.ev.reset()
	seen := []observe.Observation{
		{AssetHint: observe.AssetHint{MAC: burnt1}, Field: observe.Model, Value: "EX4200-48T", Source: observe.Passive, Confidence: 0.5},
		{AssetHint: observe.AssetHint{MAC: burnt1}, Field: observe.OS, Value: "JUNOS 15.1R7.9", Source: observe.Passive, Confidence: 0.5},
	}
	e.record(seen...)
	e.tick(2 * 3600 * 1e9)
	e.record(dhcp(burnt1, "10.142.0.77", "switch")...) // the same machine at another address
	if n := e.devices(); n != 1 {
		t.Fatalf("%d devices after the ignored one was seen again, want 1", n)
	}
	if got := e.list("true", ""); len(got.Items) != 1 || got.Items[0].ID != id {
		t.Fatalf("the ignored list: %+v", got.Items)
	}
	if got := e.review(); len(got.Items) != 0 {
		t.Fatalf("an ignored device came back to To review: %d", len(got.Items))
	}
	if n := len(e.ev.named(inventory.EventAssetDiscovered)); n != 0 {
		t.Fatalf("an ignored device was announced as discovered %d times", n)
	}
	if _, ok, _ := e.svc.MatchInput(e.ctx(), id); ok {
		t.Fatal("an ignored device is matched")
	}
}

// A phone that changes its private address under the same host name is folded into the row a person ignored: still one device,
// still ignored, nothing new in To review.
func TestContract_INV51_IgnoredDeviceFoldsAPrivateAddressChange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(dhcp(privMac1, "10.142.0.137", "studio-mac.local")...)
	id := e.idOf("10.142.0.137")
	if err := e.svc.SetIgnored(e.ctx(), "user-a", id, true); err != nil {
		t.Fatal(err)
	}
	e.tick(3 * 3600 * 1e9)
	e.record(dhcp(privMac2, "10.142.0.138", "studio-mac.local")...)
	if n := e.devices(); n != 1 {
		t.Fatalf("%d devices, want the ignored one only", n)
	}
	if got := e.review(); len(got.Items) != 0 {
		t.Fatalf("To review has %d devices", len(got.Items))
	}
	if got := e.list("true", ""); len(got.Items) != 1 {
		t.Fatalf("ignored list: %d", len(got.Items))
	}
}

// An ignored device is not approved by Approve (Approve all in another tab, a stale page): Stop ignoring comes first.
func TestContract_INV51_ApproveRefusesAnIgnoredDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(dhcp(burnt1, "10.142.0.205", "switch")...)
	id := e.idOf("10.142.0.205")
	if err := e.svc.SetIgnored(e.ctx(), "user-a", id, true); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Approve(e.ctx(), "user-a", id); err == nil {
		t.Fatal("an ignored device was approved")
	}
}
