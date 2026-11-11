package inventory_test

import (
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
)

type gate struct {
	mu sync.Mutex
	on map[string]bool
}

func (g *gate) Enabled(id string) bool { g.mu.Lock(); defer g.mu.Unlock(); return g.on[id] }
func (g *gate) set(id string, on bool) { g.mu.Lock(); g.on[id] = on; g.mu.Unlock() }

// D-327 (deferred sweep item 9): observed services not seen for 90 days and agent software not reported for 30 days are deleted; manual rows
// and other sources stay; the time counts only while the job runs unbroken, and for agent software only while agent-intake is on.
func TestD327_RetentionOfServicesAndAgentSoftware(t *testing.T) {
	g := &gate{on: map[string]bool{"agent-intake": true}}
	e := newEnv(t, func(c *inventory.Config) { c.Modules = g })
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.30")}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(e.svc.ReplaceSoftware(e.ctx(), hint, observe.Agent, []observe.Software{{Display: "htop", Vendor: "htop", Product: "htop", Version: "3.3.0", Confidence: 0.95}}))
	must(e.svc.ReplaceSoftware(e.ctx(), hint, observe.Nmap, []observe.Software{{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6", Confidence: 0.6}}))
	var asset string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM inv_asset LIMIT 1`).Scan(&asset); err != nil {
		t.Fatal(err)
	}
	seen := store.FormatTS(e.now)
	for i, src := range []string{"passive", "manual"} {
		e.exec(`INSERT INTO inv_service (id, asset_id, port, proto, name, source, confidence, seen_at) VALUES (?, ?, ?, 'tcp', 'ssh', ?, 0.8, ?)`,
			"svc-"+src, asset, 22+i, src, seen)
	}
	run := func(d time.Duration) { // the job every hour for d
		t.Helper()
		for end := e.now.Add(d); e.now.Before(end); e.tick(time.Hour) {
			must(e.svc.Prune(e.ctx()))
		}
	}

	run(31 * 24 * time.Hour)
	if e.count(`SELECT count(*) FROM inv_software WHERE source = 'agent'`) != 0 {
		t.Fatal("agent software not reported for 31 days was kept")
	}
	if e.count(`SELECT count(*) FROM inv_software WHERE source = 'nmap'`) != 1 || e.count(`SELECT count(*) FROM inv_service`) != 2 {
		t.Fatal("rows of other sources, or services younger than 90 days, were deleted")
	}
	if !slices.Contains(e.auditActions(), "inventory.software_expired") || len(e.ev.named(inventory.EventSoftwareChanged)) == 0 {
		t.Fatal("the prune of agent software left no audit row or no software-changed event")
	}
	run(60 * 24 * time.Hour)
	if e.count(`SELECT count(*) FROM inv_service WHERE source = 'passive'`) != 0 || e.count(`SELECT count(*) FROM inv_service WHERE source = 'manual'`) != 1 {
		t.Fatal("a service not seen for 90 days was kept, or a declared service was deleted")
	}
}

func TestD327_TimeCountsOnlyWhileTheModulesAreOn(t *testing.T) {
	g := &gate{on: map[string]bool{"agent-intake": false}}
	e := newEnv(t, func(c *inventory.Config) { c.Modules = g })
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.31")}
	if err := e.svc.ReplaceSoftware(e.ctx(), hint, observe.Agent, []observe.Software{{Display: "htop", Vendor: "htop", Product: "htop", Version: "3.3.0", Confidence: 0.95}}); err != nil {
		t.Fatal(err)
	}
	// agent-intake off for 40 days while the inventory runs: what it delivered is kept (its CONTRACT: off keeps the data)
	for range 40 * 24 {
		if err := e.svc.Prune(e.ctx()); err != nil {
			t.Fatal(err)
		}
		e.tick(time.Hour)
	}
	if e.count(`SELECT count(*) FROM inv_software WHERE source = 'agent'`) != 1 {
		t.Fatal("agent software was pruned while agent-intake was off")
	}
	// agent-intake on again: the 30 days start now; a gap (the inventory off, or a restart) starts them again
	g.set("agent-intake", true)
	for range 20 * 24 {
		_ = e.svc.Prune(e.ctx())
		e.tick(time.Hour)
	}
	e.tick(5 * time.Hour) // the job did not run for 5 hours
	for range 20 * 24 {
		_ = e.svc.Prune(e.ctx())
		e.tick(time.Hour)
	}
	if e.count(`SELECT count(*) FROM inv_software WHERE source = 'agent'`) != 1 {
		t.Fatal("the 30 days did not start again after a gap")
	}
	for range 11 * 24 {
		_ = e.svc.Prune(e.ctx())
		e.tick(time.Hour)
	}
	if e.count(`SELECT count(*) FROM inv_software WHERE source = 'agent'`) != 0 {
		t.Fatal("agent software was kept after 31 unbroken days with agent-intake on")
	}
}

