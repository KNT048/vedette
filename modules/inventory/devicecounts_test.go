package inventory_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// DeviceCounts (Home's device tile through findings GET /findings/overview) is the "All" and "To review" counts of the device list,
// without the list.
func TestDeviceCountsAreTheListCounts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if total, pending, err := e.svc.DeviceCounts(e.ctx()); err != nil || total != 0 || pending != 0 {
		t.Fatalf("empty: %d, %d, %v", total, pending, err)
	}
	e.record(obs(netip.MustParseAddr("192.168.10.77"), "", observe.Hostname, "laptop", observe.Passive, 0.7))
	e.record(obs(netip.MustParseAddr("192.168.10.78"), "", observe.Hostname, "printer", observe.Passive, 0.7))
	l, err := e.svc.Devices(e.ctx())
	if err != nil || len(l.Items) != 2 {
		t.Fatalf("list = %+v, %v", l, err)
	}
	if err := e.svc.Approve(e.ctx(), "it@acme.example", l.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	if l, err = e.svc.Devices(e.ctx()); err != nil {
		t.Fatal(err)
	}
	total, pending, err := e.svc.DeviceCounts(e.ctx())
	if err != nil || total != l.Counts.All || pending != l.Counts.Pending || total != 2 || pending != 1 {
		t.Fatalf("DeviceCounts = %d, %d, %v; list counts %+v", total, pending, err, l.Counts)
	}
	// ToReviewIDs (findings' grouped card of the devices not added yet) is the devices of To review
	review, err := e.svc.ToReviewIDs(e.ctx())
	if err != nil || len(review) != pending || slices.Contains(review, l.Items[0].ID) {
		t.Fatalf("ToReviewIDs = %v, %v; want the %d device(s) not approved", review, err, pending)
	}
}
