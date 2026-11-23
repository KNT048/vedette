package inventory_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
)

// Two virtual cards of one host, each seen with the maker its MAC names; the second also states a host name.
const (
	vmCard1 = "52:54:00:76:6d:02"
	vmCard2 = "52:54:00:76:6d:03"
)

func vmCard(mac, ip, host string) []observe.Observation {
	h := observe.AssetHint{MAC: mac, IP: netip.MustParseAddr(ip)}
	return append(dhcp(mac, ip, host), observe.Observation{AssetHint: h, Field: observe.Vendor, Value: "QEMU virtual NIC", Source: observe.Passive, Confidence: 0.4})
}

// Split off is the undo of a person's merge: splitting off the address a merged device brought gives that device back as it was, with
// its id (its old links work again), its name in Vedette and what was known of it (the maker both cards state, the host name only it
// stated), and the kept device loses what it held only through the merge. A split of an address no merge brought makes a new device.
func TestSplit_GivesBackTheMergedDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(vmCard(vmCard1, "192.0.2.131", "")...)
	e.tick(time.Minute)
	e.record(vmCard(vmCard2, "192.0.2.130", "vm-b")...)
	kept, gone := e.idOf("192.0.2.131"), e.idOf("192.0.2.130")
	if err := e.rename(gone, "Build VM"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Merge(e.ctx(), admin, kept, gone); err != nil {
		t.Fatal(err)
	}
	if e.nameOf(kept) != "Build VM" {
		t.Fatalf("the kept device took the name of the merged one: %q", e.nameOf(kept))
	}
	nw, err := e.svc.Split(e.ctx(), admin, kept, "192.0.2.130")
	if err != nil {
		t.Fatal(err)
	}
	if nw != gone {
		t.Fatalf("split gave a new id %s, want the merged device's own %s", nw, gone)
	}
	back := e.device(nw)
	if back.Vendor == nil || back.Vendor.Value != "QEMU virtual NIC" || back.Hostname == nil || *back.Hostname != "vm-b" || back.UserName == nil || *back.UserName != "Build VM" {
		t.Errorf("device given back: vendor %v host %v name %v", back.Vendor, back.Hostname, back.UserName)
	}
	k := e.device(kept)
	if k.Vendor == nil || k.Vendor.Value != "QEMU virtual NIC" || k.Hostname != nil || k.UserName != nil {
		t.Errorf("kept device after the split: vendor %v host %v name %v", k.Vendor, k.Hostname, k.UserName)
	}
	if n := e.count(`SELECT count(*) FROM inv_merged_from`); n != 0 {
		t.Errorf("%d merge records left after the split", n)
	}
	// merged again and split again: the same device comes back again
	if err := e.svc.Merge(e.ctx(), admin, kept, gone); err != nil {
		t.Fatal(err)
	}
	if nw, err := e.svc.Split(e.ctx(), admin, kept, vmCard2); err != nil || nw != gone {
		t.Errorf("second split by MAC: %s %v, want %s", nw, err, gone)
	}
}

// A device that took another in a merge and then joins a third keeps both merges apart: its main interface may be the card the
// first merge brought (the card seen last becomes the main one), yet splitting off each card gives back the device that had it,
// with its own id and name.
func TestSplit_AfterTwoMergesGivesBackEachDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(vmCard("52:54:00:76:6d:01", "192.0.2.132", "")...)
	e.tick(time.Minute)
	e.record(vmCard(vmCard1, "192.0.2.131", "")...)
	e.tick(time.Minute)
	e.record(vmCard(vmCard2, "192.0.2.130", "vm-b")...)
	third, kept, gone := e.idOf("192.0.2.132"), e.idOf("192.0.2.131"), e.idOf("192.0.2.130")
	for id, name := range map[string]string{kept: "Kept VM", gone: "Build VM"} {
		if err := e.rename(id, name); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.svc.Merge(e.ctx(), admin, kept, gone); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Merge(e.ctx(), admin, third, kept); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ addr, id, name string }{{"192.0.2.130", gone, "Build VM"}, {"192.0.2.131", kept, "Kept VM"}} {
		nw, err := e.svc.Split(e.ctx(), admin, third, c.addr)
		if err != nil {
			t.Fatal(err)
		}
		if nw != c.id || e.nameOf(nw) != c.name {
			t.Errorf("split of %s gave %s named %q, want %s named %q", c.addr, nw, e.nameOf(nw), c.id, c.name)
		}
	}
	if n := e.count(`SELECT count(*) FROM inv_merged_from`); n != 0 {
		t.Errorf("%d merge records left after both splits", n)
	}
}
