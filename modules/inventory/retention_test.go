package inventory_test

import (
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

type gate struct {
	mu sync.Mutex
	on map[string]bool
}

func (g *gate) Enabled(id string) bool { g.mu.Lock(); defer g.mu.Unlock(); return g.on[id] }
func (g *gate) set(id string, on bool) { g.mu.Lock(); g.on[id] = on; g.mu.Unlock() }

// D-327 (deferred sweep item 9): agent software not reported for 30 days is deleted with an audit row and a software-changed event; rows of
// other sources stay; the time counts only while the job runs unbroken and agent-intake is on. (Services: PruneServices, INV-23.)
func TestD327_RetentionOfAgentSoftware(t *testing.T) {
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
	for end := e.now.Add(29 * 24 * time.Hour); e.now.Before(end); e.tick(time.Hour) { // the job every hour
		must(e.svc.PruneAgentSoftware(e.ctx()))
	}
	if e.count(`SELECT count(*) FROM inv_software WHERE source = 'agent'`) != 1 {
		t.Fatal("agent software was pruned before 30 days")
	}
	for end := e.now.Add(2 * 24 * time.Hour); e.now.Before(end); e.tick(time.Hour) {
		must(e.svc.PruneAgentSoftware(e.ctx()))
	}
	if e.count(`SELECT count(*) FROM inv_software WHERE source = 'agent'`) != 0 {
		t.Fatal("agent software not reported for 31 days was kept")
	}
	if e.count(`SELECT count(*) FROM inv_software WHERE source = 'nmap'`) != 1 {
		t.Fatal("rows of another source were deleted")
	}
	if !slices.Contains(e.auditActions(), "inventory.software_expired") || len(e.ev.named(inventory.EventSoftwareChanged)) == 0 {
		t.Fatal("the prune of agent software left no audit row or no software-changed event")
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
		if err := e.svc.PruneAgentSoftware(e.ctx()); err != nil {
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
		_ = e.svc.PruneAgentSoftware(e.ctx())
		e.tick(time.Hour)
	}
	e.tick(5 * time.Hour) // the job did not run for 5 hours
	for range 20 * 24 {
		_ = e.svc.PruneAgentSoftware(e.ctx())
		e.tick(time.Hour)
	}
	if e.count(`SELECT count(*) FROM inv_software WHERE source = 'agent'`) != 1 {
		t.Fatal("the 30 days did not start again after a gap")
	}
	for range 11 * 24 {
		_ = e.svc.PruneAgentSoftware(e.ctx())
		e.tick(time.Hour)
	}
	if e.count(`SELECT count(*) FROM inv_software WHERE source = 'agent'`) != 0 {
		t.Fatal("agent software was kept after 31 unbroken days with agent-intake on")
	}
}

// D-327 review: an agent that keeps reporting keeps its list (seen_at is refreshed by every report, even an unchanged one).
func TestD327_ReportedSoftwareStays(t *testing.T) {
	g := &gate{on: map[string]bool{"agent-intake": true}}
	e := newEnv(t, func(c *inventory.Config) { c.Modules = g })
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.32")}
	list := []observe.Software{{Display: "htop", Vendor: "htop", Product: "htop", Version: "3.3.0", Confidence: 0.95}}
	for h := range 100 * 24 {
		if h%(24*7) == 0 { // the agent reports the same list once a week
			if err := e.svc.ReplaceSoftware(e.ctx(), hint, observe.Agent, list); err != nil {
				t.Fatal(err)
			}
		}
		if err := e.svc.PruneAgentSoftware(e.ctx()); err != nil {
			t.Fatal(err)
		}
		e.tick(time.Hour)
	}
	if e.count(`SELECT count(*) FROM inv_software WHERE source = 'agent'`) != 1 {
		t.Fatal("software an agent keeps reporting was pruned")
	}
}
