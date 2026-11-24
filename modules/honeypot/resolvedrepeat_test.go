package honeypot_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/honeypot"
)

// fakeIncidents answers Config.Incidents as notify does: the incident of every hit is open, except for the sources a test resolved
// (at that time).
type fakeIncidents struct {
	mu       sync.Mutex
	resolved map[string]time.Time
}

func (f *fakeIncidents) resolve(src string, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resolved == nil {
		f.resolved = map[string]time.Time{}
	}
	f.resolved[src] = at
}

func (f *fakeIncidents) since(_ context.Context, event string, data any, since time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := data.(honeypot.HitEventData)
	if event != honeypot.EventHitCreated || !ok {
		return false, nil
	}
	at, ok := f.resolved[d.SrcIP]
	return ok && !at.Before(since), nil
}

// INV-17 with a resolve: a person resolved the trap incident of a hit and the source connects again in the same 10-minute window. The
// connection starts a new hit (a new row and a new honeypot.hit.created: notify opens a new incident), once; the later connections of
// the window go to that new hit, and while its incident is open they add no row.
func TestAConnectionAfterTheHitsIncidentWasResolvedIsANewHit(t *testing.T) {
	t.Parallel()
	inc := &fakeIncidents{}
	e := newEnv(t, func(e *env) { e.cfg.Incidents = inc.since })
	e.setup()
	e.appendLog(sshNew("192.168.10.157", 1000, t0).json(), sshNew("192.168.10.157", 1001, t0.Add(time.Second)).json())
	e.poll()
	if n := e.hitCount(); n != 1 || len(e.pub.all()) != 1 {
		t.Fatalf("%d hits, %d events while the incident is open, want 1", n, len(e.pub.all()))
	}
	e.now = t0.Add(2 * time.Minute)
	inc.resolve("192.168.10.157", e.now)
	e.now = t0.Add(3 * time.Minute)
	e.appendLog(sshNew("192.168.10.157", 1002, e.now).json(), sshNew("192.168.10.157", 1003, e.now.Add(time.Second)).json())
	e.poll()
	if n := e.hitCount(); n != 2 || len(e.pub.all()) != 2 {
		t.Fatalf("%d hits, %d events after the resolve, want a second hit", n, len(e.pub.all()))
	}
	if n := e.count(`SELECT conn_count FROM hp_hits WHERE id = ?`, e.pub.all()[1].Data.(honeypot.HitEventData).ID); n != 2 {
		t.Fatalf("the new hit has %d connections, want both of its batch", n)
	}
	e.now = t0.Add(4 * time.Minute)
	e.appendLog(sshNew("192.168.10.157", 1004, e.now).json())
	e.poll()
	if n := e.hitCount(); n != 2 || len(e.pub.all()) != 2 {
		t.Fatalf("%d hits, %d events while the new incident is open, want 2", n, len(e.pub.all()))
	}
	if n := e.count(`SELECT conn_count FROM hp_hits WHERE id = ?`, e.pub.all()[1].Data.(honeypot.HitEventData).ID); n != 3 {
		t.Fatalf("the new hit has %d connections, want the later one of the window too", n)
	}
}
