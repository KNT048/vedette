package notify_test

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/notify"
)

// ---- D-78: the re-match after the first CISA pull is silent, by a marker on the context ----

func baselineEnv(t *testing.T) (*env, func(context.Context, string, any)) {
	t.Helper()
	m := map[string]notify.FindingInfo{}
	for i := range 5 {
		m[fmt.Sprintf("f-%d", i)] = notify.FindingInfo{CVE: fmt.Sprintf("CVE-2026-50%d", i), Product: fmt.Sprintf("Product%d", i), Severity: notify.Critical, Title: "is being exploited", What: "w", Action: "a", Devices: []string{"NAS-01"}}
	}
	m["f-new"] = notify.FindingInfo{CVE: "CVE-2026-900", Product: "Fresh", Severity: notify.Critical, Title: "is being exploited", What: "w", Action: "a", Devices: []string{"NAS-01"}}
	e := newEnv(t, func(c *notify.Config) { c.Findings = fakeFindings{m} })
	e.telegram(notify.Low)
	e.plain()
	e.svc.Subscribe(e.bus)
	return e, func(ctx context.Context, name string, data any) {
		t.Helper()
		if err := e.bus.Publish(ctx, events.Event{Name: name, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
}

func created(id, cve string) findings.CreatedEvent {
	return findings.CreatedEvent{FindingID: id, AssetID: "a-1", CVE: cve, Severity: findings.SeverityCritical, Basis: findings.BasisProduct}
}

// A finding created under the baseline marker (what inventory's re-match does after the first pull) queues nothing,
// so nothing can leak after a restart, a quiet-hours end or a slow job. The same event without the marker is one notice.
func TestBaselineContextSendsNothingAndQueuesNothing(t *testing.T) {
	e, pub := baselineEnv(t)
	marked := notify.WithBaseline(e.ctx())
	for i := range 5 {
		pub(marked, notify.EventFindingCreated, created(fmt.Sprintf("f-%d", i), fmt.Sprintf("CVE-2026-50%d", i)))
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_pending`); n != 0 {
		t.Fatalf("the baseline left %d queued rows", n)
	}
	e.clock.Add(time.Hour)
	e.flush()
	if e.net.total() != 0 || e.count(`SELECT COUNT(*) FROM notify_send`) != 0 {
		t.Fatalf("the baseline sent %d messages", e.net.total())
	}
	if h, _ := e.svc.History(e.ctx()); h.Suppressed.Count != 0 {
		t.Fatalf("a baseline is not new: suppressed = %d", h.Suppressed.Count)
	}
}

func TestFindingCreatedWithoutTheMarkerIsOneNotice(t *testing.T) {
	e, pub := baselineEnv(t)
	pub(e.ctx(), notify.EventFindingCreated, created("f-new", "CVE-2026-900"))
	e.flush() // no settle time any more: it goes out at once
	if n := len(e.net.to("api.telegram.org")); n != 1 {
		t.Fatalf("a finding without the marker sent %d messages, want 1", n)
	}
}

// The first pull, its re-match and a later real finding, in order: only the later one is sent.
func TestBaselineThenARealFinding(t *testing.T) {
	e, pub := baselineEnv(t)
	pub(e.ctx(), feeds.EventSyncBaseline, feeds.SyncBaselineEvent{Source: "cisa-kev", Count: 1200}) // notify may see it directly
	pub(notify.WithBaseline(e.ctx()), notify.EventFindingCreated, created("f-0", "CVE-2026-500"))
	e.flush()
	if e.net.total() != 0 || e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
		t.Fatalf("the baseline sent %d messages", e.net.total())
	}
	pub(e.ctx(), notify.EventFindingCreated, created("f-new", "CVE-2026-900")) // right after: not silenced
	e.flush()
	if n := len(e.net.to("api.telegram.org")); n != 1 {
		t.Fatalf("the real finding sent %d messages, want 1", n)
	}
}

func TestIsBaseline(t *testing.T) {
	ctx := t.Context()
	if notify.IsBaseline(ctx) {
		t.Fatal("a plain context is not a baseline")
	}
	m := notify.WithBaseline(ctx)
	type k struct{}
	derived, cancel := context.WithTimeout(context.WithValue(context.WithoutCancel(m), k{}, 1), time.Minute)
	defer cancel()
	if !notify.IsBaseline(m) || !notify.IsBaseline(derived) {
		t.Fatal("the marker must survive the contexts the chain derives")
	}
	if notify.IsBaseline(context.WithValue(ctx, k{}, 1)) {
		t.Fatal("an unrelated value is not the marker")
	}
}

// The marker reaches every handler of an event, whichever subscribed first, and an unmarked publish reaches none.
func TestIsBaselineInEitherHandlerOrder(t *testing.T) {
	bus := events.NewBus(slog.New(slog.DiscardHandler))
	var before, after []bool
	bus.Subscribe("findings.finding.created", func(ctx context.Context, _ events.Event) error { before = append(before, notify.IsBaseline(ctx)); return nil })
	// the notify handler sits in the middle
	e := newEnv(t, func(c *notify.Config) { c.Bus = bus })
	e.svc.Subscribe(bus)
	bus.Subscribe("findings.finding.created", func(ctx context.Context, _ events.Event) error { after = append(after, notify.IsBaseline(ctx)); return nil })
	for _, c := range []context.Context{notify.WithBaseline(t.Context()), t.Context()} {
		if err := bus.Publish(c, events.Event{Name: "findings.finding.created", Data: created("f-x", "CVE-2026-1")}); err != nil {
			t.Fatal(err)
		}
	}
	if fmt.Sprint(before) != "[true false]" || fmt.Sprint(after) != "[true false]" {
		t.Fatalf("before %v, after %v", before, after)
	}
}
