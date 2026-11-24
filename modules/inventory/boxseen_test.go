package inventory_test

import (
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
)

// The box is the machine running Vedette: it is just seen on its page as on the Devices list, never "last seen 7 minutes ago" on one
// and "now" on the other.
func TestBoxLastSeen_OneRuleOnEveryRead(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	box, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette", IP: "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	e.tick(7 * time.Minute)
	now := store.FormatTS(e.now)
	d, err := e.svc.Device(e.ctx(), box)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := e.svc.DetailPage(e.ctx(), box)
	if err != nil {
		t.Fatal(err)
	}
	l, err := e.svc.Devices(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	listed := ""
	for _, x := range l.Items {
		if x.ID == box {
			listed = x.LastSeen
		}
	}
	if d.LastSeen != now || detail.Asset.LastSeen != now || listed != now {
		t.Fatalf("box last seen: device %s, page %s, list %s; want %s on each", d.LastSeen, detail.Asset.LastSeen, listed, now)
	}
}

// The box's main address on its page (Addresses) follows the same rule: just seen, never the stored time of the last write.
func TestBoxLastSeen_TheMainAddressToo(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	box, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette", IP: "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	e.tick(7 * time.Minute)
	detail, err := e.svc.DetailPage(e.ctx(), box)
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Addresses) == 0 || !detail.Addresses[0].Main {
		t.Fatalf("box addresses: %+v, want the main one first", detail.Addresses)
	}
	if now := store.FormatTS(e.now); detail.Addresses[0].LastSeen != now {
		t.Fatalf("box main address last seen %s, want %s (the page header's)", detail.Addresses[0].LastSeen, now)
	}
}
