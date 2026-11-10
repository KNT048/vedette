package notify_test

import (
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/notify"
)

// gate is a module switch that tells its subscribers, like core/modreg.Registry.
type gate struct {
	mu   sync.Mutex
	on   bool
	subs []func(id string, enabled bool)
}

func (g *gate) Enabled(string) bool { g.mu.Lock(); defer g.mu.Unlock(); return g.on }
func (g *gate) OnChange(fn func(string, bool)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.subs = append(g.subs, fn)
}
func (g *gate) set(on bool) {
	g.mu.Lock()
	g.on = on
	subs := append([]func(string, bool){}, g.subs...)
	g.mu.Unlock()
	for _, f := range subs {
		f(notify.ModuleID, on)
	}
}

// D-86 (7): turning notify on again drops the queued notices that are older than 24 hours (measured from when they
// were queued) and audits the count; younger ones are sent.
func TestEnableDropsQueuedNoticesOlderThan24h(t *testing.T) {
	t.Parallel()
	g := &gate{on: true}
	e := newEnv(t, func(c *notify.Config) { c.Modules = g })
	e.telegram(notify.Low)
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("old1", "QNAP Photo Station", "CVE-2026-6001", notify.High, "NAS")); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("old2", "WordPress", "CVE-2026-6002", notify.High, "WEB01")); err != nil {
		t.Fatal(err)
	}
	g.set(false)
	e.clock.Add(25 * time.Hour)
	g.set(true)
	e.clock.Add(-2 * time.Hour) // the next one is queued 23 h before the next run, 25 h after the first two
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("young", "Microsoft Windows Server", "CVE-2026-6003", notify.High, "DC01")); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(2 * time.Hour)
	e.flush()
	if n := e.count(`SELECT COUNT(*) FROM notify_send WHERE kind = 'vuln'`); n != 1 {
		t.Fatalf("%d notices were sent, want only the young one", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_pending`); n != 0 {
		t.Fatalf("%d rows left in the queue", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.stale_dropped' AND detail LIKE '2 %'`); n != 1 {
		t.Fatalf("audit entries with the dropped count: %d, want 1", n)
	}
	e.flush() // the drop happens once per enable
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.stale_dropped'`); n != 1 {
		t.Fatalf("a second run audited again: %d", n)
	}
}

func TestEnableKeepsRowsAt23hAndAuditsNothingWhenNothingIsOld(t *testing.T) {
	t.Parallel()
	g := &gate{on: true}
	e := newEnv(t, func(c *notify.Config) { c.Modules = g })
	e.telegram(notify.Low)
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("a1", "QNAP Photo Station", "CVE-2026-6004", notify.High, "NAS")); err != nil {
		t.Fatal(err)
	}
	g.set(false)
	e.clock.Add(23 * time.Hour)
	g.set(true)
	e.flush()
	if n := e.count(`SELECT COUNT(*) FROM notify_send WHERE kind = 'vuln'`); n != 1 {
		t.Fatalf("a 23 h old notice: %d sent, want 1", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.stale_dropped'`); n != 0 {
		t.Fatalf("nothing was old, but %d audit entries were written", n)
	}
}

// A run without an enable in between never drops: a backlog while the module stays on is delivered as before.
func TestNoDropWithoutEnable(t *testing.T) {
	t.Parallel()
	g := &gate{on: true}
	e := newEnv(t, func(c *notify.Config) { c.Modules = g })
	e.telegram(notify.Low)
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("b1", "QNAP Photo Station", "CVE-2026-6005", notify.High, "NAS")); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(30 * time.Hour)
	e.flush()
	if n := e.count(`SELECT COUNT(*) FROM notify_send WHERE kind = 'vuln'`); n != 1 {
		t.Fatalf("%d sent, want 1", n)
	}
}
