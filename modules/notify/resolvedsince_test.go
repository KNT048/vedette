package notify_test

import (
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/notify"
)

// A producer that holds back repeats of an incident key asks ResolvedSince before holding one back. The answer mirrors OpenIncident:
// true only when no incident the event would count on is open and one was resolved at or after the producer's announcement, so the
// repeat opens a new incident and is sent. Every producer event that opens an incident is covered.
func TestResolvedSinceSaysWhenARepeatIsANewIncident(t *testing.T) {
	t.Parallel()
	hit := map[string]any{"id": "hit-1", "ts": "2026-11-09T09:59:00Z", "kind": "service", "service": "smb", "src_ip": "10.0.0.7", "label": "FILESRV-OLD"}
	bad := map[string]any{"source": "logs", "target": "ioc:bad.example", "title": "nas-01 connected to bad.example", "what": "w", "action": "a", "severity": "high"}
	auth := map[string]any{"source": "fw-edge", "target": "auth:192.0.2.7", "title": "A login from 192.0.2.7 was ACCEPTED", "what": "w", "action": "a", "severity": "high"} // high: not held by the first-run summary
	for _, c := range []struct {
		name, event string
		data        map[string]any
	}{
		{"intrusion", notify.EventIntrusion, intrusion("medium", "198.51.100.9 fired Log4j at app-01", "/detection/alerts/ida-1")},
		{"trap", notify.EventHoneypotHit, hit},
		{"bad address", notify.EventLogBadAddress, bad},
		{"failed logins", notify.EventLogAnomaly, auth},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.telegram(notify.Low)
			e.plain()
			defer e.svc.Subscribe(e.bus)()
			ask := func(since time.Time) bool {
				t.Helper()
				ok, err := e.svc.ResolvedSince(e.ctx(), c.event, c.data, since)
				if err != nil {
					t.Fatal(err)
				}
				return ok
			}
			pub := func() {
				t.Helper()
				if err := e.bus.Publish(e.ctx(), events.Event{Name: c.event, Data: c.data}); err != nil {
					t.Fatal(err)
				}
				e.flush()
			}
			announced := e.clock.Now()
			if ask(announced) {
				t.Fatal("no incident yet: a producer's own budget held it, nothing to let through")
			}
			pub()
			if ask(announced) {
				t.Fatal("the incident is open: a repeat only counts")
			}
			l, err := e.svc.Incidents(e.ctx())
			if err != nil || len(l) != 1 {
				t.Fatalf("incidents %v %+v", err, l)
			}
			e.clock.Add(5 * time.Second)
			if _, err := e.svc.HandleIncident(e.ctx(), "u-op", l[0].ID, notify.StatusResolved, ""); err != nil {
				t.Fatal(err)
			}
			if !ask(announced) {
				t.Fatal("resolved after the announcement: the repeat is a new incident")
			}
			if ask(e.clock.Now().Add(time.Second)) {
				t.Fatal("resolved before the producer's announcement: the producer's own hold applies")
			}
			e.clock.Add(5 * time.Second)
			pub()
			if ask(announced) {
				t.Fatal("the repeat opened a new incident: open again")
			}
			if n := e.count(`SELECT count(*) FROM notify_incident`); n != 2 {
				t.Fatalf("%d incidents, want the resolved one and a new one", n)
			}
			if n := e.count(`SELECT count(*) FROM notify_send WHERE kind = 'incident' AND ok = 1`); n != 2 {
				t.Fatalf("%d sends, want one per incident", n)
			}
		})
	}
}

// A blocked attempt counts on the open connection incident of the same address before one of its own: once that connection incident
// is resolved, a blocked repeat is let through too (OpenIncident opens an attempt incident for it).
func TestResolvedSinceFollowsTheAttemptMergeRule(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	defer e.svc.Subscribe(e.bus)()
	conn := map[string]any{"source": "logs", "target": "ioc:bad.example", "title": "nas-01 connected to bad.example", "what": "w", "action": "a", "severity": "high"}
	blocked := map[string]any{"source": "logs", "target": "ioc:bad.example", "title": "nas-01 tried to reach bad.example", "what": "w", "action": "a", "severity": "high", "blocked": true}
	since := e.clock.Now()
	if err := e.bus.Publish(e.ctx(), events.Event{Name: notify.EventLogBadAddress, Data: conn}); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.svc.ResolvedSince(e.ctx(), notify.EventLogBadAddress, blocked, since); err != nil || ok {
		t.Fatalf("an attempt while the connection incident is open counts on it: %v %v", ok, err)
	}
	l, _ := e.svc.Incidents(e.ctx())
	e.clock.Add(time.Second)
	if _, err := e.svc.HandleIncident(e.ctx(), "u-op", l[0].ID, notify.StatusResolved, ""); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.svc.ResolvedSince(e.ctx(), notify.EventLogBadAddress, blocked, since); err != nil || !ok {
		t.Fatalf("the connection incident it counted on was resolved: %v %v", ok, err)
	}
	if ok, err := e.svc.ResolvedSince(e.ctx(), "inventory.asset.discovered", map[string]any{}, since); err != nil || ok {
		t.Fatalf("an event that opens no incident: %v %v", ok, err)
	}
}
