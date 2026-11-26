package notify_test

import (
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/notify"
)

func badAddress(severity, what string) map[string]any {
	return map[string]any{"source": "192.0.2.15", "target": "198.51.100.47", "title": "pc-sales-02 (192.0.2.15) connected to 198.51.100.47",
		"what": what, "action": "a", "severity": severity, "devices": []map[string]string{{"id": "a-pc", "name": "pc-sales-02"}}}
}

func (e *env) pubBadAddress(data any) {
	e.t.Helper()
	if err := e.bus.Publish(e.ctx(), events.Event{Name: notify.EventLogBadAddress, Data: data}); err != nil {
		e.t.Fatal(err)
	}
}

// A bad-address incident opened at medium (below the default trigger's minimum, so not sent) is raised by a repeat at a higher
// severity (a feed that rates the address higher lists it now) and the raise is sent: the open incident must not swallow the news.
func TestBadAddressRepeatAtAHigherSeverityRaisesTheIncidentAndSendsIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.firstRunAt(e.clock.Now().AddDate(0, -1, 0)) // not a fresh box: nothing is held for the first-run summary
	e.telegram(notify.Low)
	e.plain()
	defer e.svc.Subscribe(e.bus)()
	e.pubBadAddress(badAddress("medium", "Confidence 20%"))
	e.flush()
	before := e.count(`SELECT count(*) FROM notify_send WHERE kind = 'incident' AND ok = 1`)
	e.pubBadAddress(badAddress("high", "Confidence 85%"))
	e.flush()
	l, err := e.svc.Incidents(e.ctx())
	if err != nil || len(l) != 1 {
		t.Fatalf("incidents %v %+v", err, l)
	}
	i := l[0]
	if i.Severity != notify.High || i.What != "Confidence 85%" || i.Count != 2 {
		t.Fatalf("incident %+v", i)
	}
	if n := e.count(`SELECT count(*) FROM notify_send WHERE kind = 'incident' AND ref_id = ? AND ok = 1`, i.ID); n != before+1 {
		t.Fatalf("%d sends filed under the incident, want %d (one more: the raise)", n, before+1)
	}
	// a repeat at the same level sends nothing more
	e.pubBadAddress(badAddress("high", "Confidence 85%"))
	e.flush()
	if n := e.count(`SELECT count(*) FROM notify_send WHERE ref_id = ?`, i.ID); n != before+1 {
		t.Fatalf("%d sends after a repeat at the same level", n)
	}
}
