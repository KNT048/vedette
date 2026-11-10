package scan

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

// fakeKEVFeed is feeds' record of announced KEV entries (KEVFeed): list is sorted by (At, CVE) like the real read.
type fakeKEVFeed struct {
	mu   sync.Mutex
	list []AnnouncedKEV
	asks []kevAsk
	err  error
}

type kevAsk struct {
	at    time.Time
	cve   string
	limit int
}

func (f *fakeKEVFeed) NewKEVSince(_ context.Context, at time.Time, cve string, limit int) ([]AnnouncedKEV, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asks = append(f.asks, kevAsk{at, cve, limit})
	if f.err != nil {
		return nil, f.err
	}
	var out []AnnouncedKEV
	for _, k := range f.list {
		if (k.At.After(at) || (k.At.Equal(at) && k.CVE > cve)) && len(out) < limit {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeKEVFeed) asked() []kevAsk {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.asks)
}

func newCatchUpEnv(t *testing.T, feed *fakeKEVFeed) *runEnv {
	t.Helper()
	r := newRunEnv(t)
	cfg := r.svc.cfg
	cfg.KEV = feed
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	return r
}

func announced(cve string, at time.Time, template bool) AnnouncedKEV {
	return AnnouncedKEV{NewKEV: NewKEV{CVE: cve, Vendor: "Palo Alto Networks", Product: "PAN-OS", HasTemplate: template}, At: at}
}

// INV-9, D-144 (S4b): a new KEV entry feeds announced while scan was off or the process was down (the bus is
// best-effort) is found in feeds' record and rescanned like one that came on the bus. The event keeps the time feeds
// announced it, so the latency is honest; an entry without a template is not queued; the next pass asks from the last
// entry read; the same entry from the bus too is one event.
func TestContract_INV9_CatchUpRecordsAMissedKEV(t *testing.T) {
	t.Parallel()
	feed := &fakeKEVFeed{list: []AnnouncedKEV{
		announced("CVE-2023-46805", t0.Add(-8*24*time.Hour), true), // older than the 7 days an event may wait: passed over
		announced("CVE-2024-3400", t0.Add(-3*time.Hour), true),
		announced("CVE-2020-0001", t0.Add(-2*time.Hour), false),
	}}
	r := newCatchUpEnv(t, feed)
	r.eng.reply = lines("CVE-2024-3400")
	r.tick() // the catch-up records it and the rescan starts: it was announced 3 hours ago
	r.tick() // the run is over
	evs := r.events()
	if len(evs) != 1 || evs[0].CVE != "CVE-2024-3400" || evs[0].Result != "matched" || evs[0].TS != "2026-11-10T07:00:00.000Z" ||
		evs[0].LatencyMin == nil || *evs[0].LatencyMin != 180 || !slices.Equal(evs[0].Devices, []string{"WEB01"}) {
		t.Fatalf("events: %+v", evs)
	}
	if r.count(`SELECT count(*) FROM scan_event WHERE cve = 'CVE-2020-0001'`) != 0 {
		t.Fatal("an entry without a scan template was queued")
	}
	if r.count(`SELECT count(*) FROM scan_event WHERE cve = 'CVE-2023-46805'`) != 0 {
		t.Fatal("an entry announced 8 days ago was queued")
	}
	asks := feed.asked()
	if len(asks) < 2 || !asks[0].at.IsZero() || asks[0].cve != "" || asks[0].limit != 100 {
		t.Fatalf("first ask: %+v", asks)
	}
	if last := asks[len(asks)-1]; !last.at.Equal(t0.Add(-2*time.Hour)) || last.cve != "CVE-2020-0001" {
		t.Fatalf("the next pass does not ask from the last entry read: %+v", last)
	}
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2024-3400")); err != nil {
		t.Fatal(err)
	}
	r.tick()
	if n := r.count(`SELECT count(*) FROM scan_event`); n != 1 {
		t.Fatalf("%d events for one entry that came both ways", n)
	}
}

// S4b: one pass reads at most a page from feeds; a long backlog is read over several passes, each entry once.
func TestCatchUp_ReadsAPagePerPass(t *testing.T) {
	t.Parallel()
	var list []AnnouncedKEV
	for i := range 250 {
		list = append(list, announced(fmt.Sprintf("CVE-2020-1%04d", i), t0.Add(-time.Hour), true)) // one pull: one time
	}
	feed := &fakeKEVFeed{list: list}
	r := newCatchUpEnv(t, feed)
	if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", Patch{AutoRescan: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	pass := func() {
		t.Helper()
		if err := r.svc.RunRescans(r.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	pass()
	if n := r.count(`SELECT count(*) FROM scan_event`); n != 100 {
		t.Fatalf("one pass recorded %d entries, want a page of 100", n)
	}
	pass()
	pass()
	pass()
	if n := r.count(`SELECT count(*) FROM scan_event`); n != 250 {
		t.Fatalf("%d entries after four passes, want 250", n)
	}
	for _, a := range feed.asked() {
		if a.limit != 100 {
			t.Fatalf("asked for %d", a.limit)
		}
	}
}

// S4b: a backlog is not rescanned one CVE at a time: the entries ready together go into one run, each device with
// the templates of its own CVEs, and each event closes with its own result and devices.
func TestContract_INV9_ABacklogIsScannedInOneRun(t *testing.T) {
	t.Parallel()
	feed := &fakeKEVFeed{list: []AnnouncedKEV{
		announced("CVE-2024-3400", t0.Add(-3*time.Hour), true),
		announced("CVE-2023-46805", t0.Add(-3*time.Hour+time.Second), true),
	}}
	r := newCatchUpEnv(t, feed)
	r.findings.mu.Lock()
	r.findings.list = append(r.findings.list, FindingRef{ID: "f-4", AssetID: "a-srv", CVE: "CVE-2023-46805", Status: "suspected"})
	r.findings.mu.Unlock()
	r.eng.reply = lines("CVE-2024-3400")
	r.tick()
	if n := r.count(`SELECT count(*) FROM scan_run`); n != 1 {
		t.Fatalf("%d runs for a backlog of two entries, want one", n)
	}
	if r.count(`SELECT count(DISTINCT run_id) FROM scan_event`) != 1 || r.count(`SELECT count(*) FROM scan_event WHERE run_id IS NULL`) != 0 {
		t.Fatal("the two events are not linked to the one run")
	}
	jobs := r.eng.sent()
	if len(jobs) != 2 || jobs[0].Targets[0].Host != "192.168.10.12" || !slices.Equal(jobs[0].Templates, []string{"http/cves/2024/CVE-2024-3400.yaml"}) ||
		jobs[1].Targets[0].Host != "192.168.10.10" || !slices.Equal(jobs[1].Templates, []string{"http/cves/2023/CVE-2023-46805.yaml"}) {
		t.Fatalf("jobs: %+v", jobs)
	}
	var note string
	if err := r.db.Reader().QueryRowContext(r.ctx(), `SELECT trigger_note FROM scan_run`).Scan(&note); err != nil {
		t.Fatal(err)
	}
	if note != "New KEV entries with a scan template: CVE-2024-3400, CVE-2023-46805" {
		t.Errorf("note %q", note)
	}
	r.tick()
	got := map[string]EventView{}
	for _, e := range r.events() {
		got[e.CVE] = e
	}
	if a, b := got["CVE-2024-3400"], got["CVE-2023-46805"]; a.Result != "matched" || !slices.Equal(a.Devices, []string{"WEB01"}) ||
		b.Result != "clear" || !slices.Equal(b.Devices, []string{"SRV-AD"}) {
		t.Fatalf("events: %+v", got)
	}
}

// S4b: when feeds cannot be read the queue still moves (the bus events are there); the catch-up tries again.
func TestCatchUp_AFeedErrorDoesNotStopTheQueue(t *testing.T) {
	t.Parallel()
	feed := &fakeKEVFeed{err: errors.New("feeds is not readable")}
	r := newCatchUpEnv(t, feed)
	if err := r.svc.OnNewKEV(r.ctx(), kev("CVE-2024-3400")); err != nil {
		t.Fatal(err)
	}
	r.advance(2 * time.Minute)
	r.tick()
	if n := r.count(`SELECT count(*) FROM scan_run`); n != 1 || len(feed.asked()) != 1 {
		t.Fatalf("%d runs, %d asks", n, len(feed.asked()))
	}
}
