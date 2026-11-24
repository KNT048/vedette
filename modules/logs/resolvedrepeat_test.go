package logs

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeIncidents answers Config.Incidents as notify does: every incident key is open, except the targets a test resolved (at that time).
type fakeIncidents struct {
	mu       sync.Mutex
	resolved map[string]time.Time
	asked    int
}

func (f *fakeIncidents) resolve(target string, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resolved == nil {
		f.resolved = map[string]time.Time{}
	}
	f.resolved[target] = at
}

func (f *fakeIncidents) since(_ context.Context, event string, data any, since time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked++
	var target string
	switch ev := data.(type) {
	case AnomalyEvent:
		target = ev.Target
	case BadAddressEvent:
		target = ev.Target
	default:
		return false, fmt.Errorf("unexpected %s data %T", event, data)
	}
	at, ok := f.resolved[target]
	return ok && !at.Before(since), nil
}

// A person resolved the failed-login incident while the guessing goes on inside the dedupe time: the next failure past the threshold
// opens a new incident, once; while that one is open the failures only count. The same holds for the incident of an accepted login.
func TestAuthFail_ARepeatAfterTheIncidentWasResolvedOpensANewOne(t *testing.T) {
	t.Parallel()
	e, src, p := authEnv(t)
	inc := &fakeIncidents{}
	e.svc.cfg.Incidents = inc.since
	for range AuthFailThreshold {
		e.ingest(src, failedPassword("root", attacker))
	}
	e.advance(time.Second)
	e.ingest(src, failedPassword("root", attacker))
	if len(p.summaries) != 1 {
		t.Fatalf("%d incidents while the first is open, want 1", len(p.summaries))
	}
	e.advance(time.Second)
	inc.resolve("auth:"+attacker, *e.clock)
	e.advance(time.Second)
	e.ingest(src, failedPassword("root", attacker), failedPassword("admin", attacker))
	if len(p.summaries) != 2 || p.summaries[1].Target != "auth:"+attacker {
		t.Fatalf("after the resolve: %+v, want a second incident of the same address", p.summaries)
	}
	e.advance(time.Second)
	e.ingest(src, failedPassword("root", attacker))
	if len(p.summaries) != 2 {
		t.Fatalf("%d incidents while the new one is open, want 2", len(p.summaries))
	}

	accepted := "Nov  9 10:01:00 web1 sshd[9]: Accepted password for root from " + attacker + " port 5 ssh2"
	e.ingest(src, accepted)
	e.advance(time.Second)
	e.ingest(src, accepted)
	if len(p.summaries) != 3 || p.summaries[2].Target != "auth:"+attacker+" accepted" {
		t.Fatalf("accepted logins: %+v, want one incident of the acceptance", p.summaries)
	}
	e.advance(time.Second)
	inc.resolve("auth:"+attacker+" accepted", *e.clock)
	e.advance(time.Second)
	e.ingest(src, accepted)
	if len(p.summaries) != 4 || p.summaries[3].Target != "auth:"+attacker+" accepted" || p.summaries[3].Severity != "high" {
		t.Fatalf("an accepted login after its incident was resolved: %+v", p.summaries)
	}
}

// A device meets a listed address again inside the 24-hour dedupe after a person resolved the bad-connection incident: the connection is
// a new hit (stored, announced: notify opens a new incident), once; while that incident is open the connections are repeats again.
// Without a resolve nothing more is stored for 24 hours.
func TestIOCARepeatAfterTheIncidentWasResolvedIsANewHit(t *testing.T) {
	t.Parallel()
	e, src, _, p := iocEnv(t)
	inc := &fakeIncidents{}
	e.svc.cfg.Incidents = inc.since
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	e.advance(time.Hour)
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	if h, b := p.counts(); hitCount(t, e) != 1 || h != 1 || b != 1 {
		t.Fatalf("while the incident is open: rows %d events %d %d", hitCount(t, e), h, b)
	}
	target := p.bad[0].Target
	inc.resolve(target, *e.clock)
	e.advance(time.Hour)
	e.feedAll(src, repeat(traffic(lanDevice, badIP), 3))
	if h, b := p.counts(); hitCount(t, e) != 2 || h != 2 || b != 2 || p.bad[1].Target != target {
		t.Fatalf("after the resolve: rows %d events %d %d, want a second hit", hitCount(t, e), h, b)
	}
	e.advance(time.Hour)
	e.feedAll(src, []string{traffic(lanDevice, badIP)})
	if h, _ := p.counts(); hitCount(t, e) != 2 || h != 2 {
		t.Fatalf("while the new incident is open: rows %d events %d", hitCount(t, e), h)
	}
}

// The hourly budget holds after a resolve: once IocEventsPerHour hits were announced, the hits past it are said by one summary an hour.
// A person who resolves that summary while the hour still runs over is told again (a new incident), once per resolve.
func TestIOCAResolvedHourlySummaryComesBackWhileTheBudgetIsOut(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	inc := &fakeIncidents{}
	e.svc.cfg.Incidents = inc.since
	batch := func(k int) {
		t.Helper()
		var texts []string
		for i := range MaxIocHitsPerBatch {
			d := fmt.Sprintf("46.%d.%d.9", k, i+1)
			ff.listed["ip:"+d] = Listing{Feeds: []string{"flood"}, Confidence: 0.5}
			texts = append(texts, traffic(lanDevice, d))
		}
		e.feedAll(src, texts)
	}
	for k := 1; k <= 3; k++ {
		batch(k)
	}
	if h, _ := p.counts(); h != IocEventsPerHour || len(p.summaries) != 1 {
		t.Fatalf("%d events, %d summaries: want the budget and one summary", h, len(p.summaries))
	}
	batch(4)
	if len(p.summaries) != 1 {
		t.Fatalf("%d summaries while the summary is open, want 1", len(p.summaries))
	}
	e.advance(time.Second)
	inc.resolve(p.summaries[0].Target, *e.clock)
	e.advance(time.Second)
	batch(5)
	if h, _ := p.counts(); h != IocEventsPerHour || len(p.summaries) != 2 || p.summaries[1].Target != p.summaries[0].Target {
		t.Fatalf("after the resolve: %d events, summaries %+v: want the summary again and no hit past the budget", h, p.summaries)
	}
	batch(6)
	if len(p.summaries) != 2 {
		t.Fatalf("%d summaries while the new summary is open, want 2", len(p.summaries))
	}
}
