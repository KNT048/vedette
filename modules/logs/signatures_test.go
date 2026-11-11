package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	logsdata "github.com/knt048/vedette/content/logs"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
)

// fw is a FortiGate traffic line with the log id n; its signature is sigFor(n). The port and the destination are not part of it.
func fw(n int, dst string) string {
	return fmt.Sprintf(`type="traffic" subtype="forward" logid="%010d" srcip=45.9.148.20 dstip=%s dstport=443 action="deny"`, n, dst)
}

func sigFor(n int) string {
	return fmt.Sprintf("type=traffic subtype=forward logid=%010d action=deny", n)
}

// feed ingests n copies of text from src at the clock's time.
func (e *env) feed(src Source, text string, n int) {
	e.t.Helper()
	for n > 0 {
		k := min(n, MaxBatch)
		batch := make([]Line, k)
		for i := range batch {
			batch[i] = Line{SourceID: src.ID, At: e.svc.now(), Text: text}
		}
		if _, err := e.svc.Ingest(e.t.Context(), batch); err != nil {
			e.t.Fatal(err)
		}
		n -= k
	}
}

func (e *env) digest() Digest {
	e.t.Helper()
	d, err := e.svc.Digest(e.t.Context())
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

// history gives src one signature (port 22) of 10 lines at 10:00 on each of the days 0..days after t0, and leaves the clock on
// the last of them.
func (e *env) history(src Source, days int) {
	e.t.Helper()
	for k := 0; k <= days; k++ {
		*e.clock = t0.Add(time.Duration(k) * 24 * time.Hour)
		e.feed(src, fw(22, "10.0.0.1"), 10)
	}
}

func newItems(d Digest) []string {
	var out []string
	for _, n := range d.New {
		out = append(out, n.Signature)
	}
	return out
}

// INV-6: "new" is a signature that was not in the baseline, counted from the end of the source's 24 h warm-up; the first day of
// a source is silent (the D-78 lesson: the first pull must not raise a flood).
func TestContract_INV6_WarmUpIsSilent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	e.feed(src, fw(22, "10.0.0.1"), 10) // 10:00, the source's first lines
	e.advance(time.Hour)
	e.feed(src, fw(23, "10.0.0.1"), 5) // a signature never seen, in the first day
	e.advance(12 * time.Hour)
	e.feed(src, fw(24, "10.0.0.1"), 5)
	if d := e.digest(); len(d.New) != 0 || len(d.Spikes) != 0 {
		t.Fatalf("the warm-up must be silent: %+v", d)
	}
	*e.clock = t0.Add(24*time.Hour + 30*time.Minute) // the warm-up ended at 10:00
	e.feed(src, fw(25, "10.0.0.1"), 3)
	e.feed(src, fw(23, "10.0.0.1"), 2) // seen again after the warm-up: it was in the baseline, not new
	d := e.digest()
	if got := newItems(d); len(got) != 1 || got[0] != sigFor(25) {
		t.Fatalf("new after the warm-up = %v, want only %q", got, sigFor(25))
	}
	n := d.New[0]
	if n.Count != 3 || n.SourceID != src.ID || n.SourceName != "FW-HQ" || !n.FirstSeen.Equal(*e.clock) || !strings.Contains(n.Sample, `logid="0000000025"`) || !strings.HasPrefix(n.ID, "n-") {
		t.Fatalf("%+v", n)
	}
}

// INV-6: a spike is at least max(20, 5 x baseline_per_day) in 24 h; the baseline is the 7 full days before yesterday.
func TestContract_INV6_SpikeMaths(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		extra int // lines added on day 3 to the 10 that the history put there
		spike bool
	}{
		{"below 5x baseline", 30, false}, // today 40 + 5.8 of yesterday < 50
		{"above 5x baseline", 50, true},  // today 60 + 5.8 of yesterday >= 50
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			src := e.add("FW-HQ", "192.168.10.1")
			e.history(src, 3)
			e.feed(src, fw(22, "10.0.0.1"), c.extra)
			d := e.digest()
			if (len(d.Spikes) == 1) != c.spike || len(d.New) != 0 {
				t.Fatalf("spikes %+v new %+v", d.Spikes, d.New)
			}
			if c.spike {
				s := d.Spikes[0]
				if s.BaselinePerDay != 10 || s.Count < 65 || s.Count > 67 || s.Signature != sigFor(22) || !strings.HasPrefix(s.ID, "s-") || s.Sample == "" {
					t.Fatalf("%+v", s)
				}
			}
		})
	}
	t.Run("the floor of 20", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		src := e.add("FW-HQ", "192.168.10.1")
		for k := 0; k <= 3; k++ { // one line a day: a baseline of 1, so 5x is 5 and the floor of 20 is what counts
			*e.clock = t0.Add(time.Duration(k) * 24 * time.Hour)
			e.feed(src, fw(22, "10.0.0.1"), 1)
		}
		e.feed(src, fw(22, "10.0.0.1"), 14) // today 15, with yesterday's share: under 20
		if d := e.digest(); len(d.Spikes) != 0 {
			t.Fatalf("15 lines is under the floor: %+v", d.Spikes)
		}
		e.feed(src, fw(22, "10.0.0.1"), 6) // today 21
		if d := e.digest(); len(d.Spikes) != 1 || d.Spikes[0].BaselinePerDay != 1 {
			t.Fatalf("21 lines is over the floor: %+v", d.Spikes)
		}
	})
	t.Run("no spike before there is a full day of baseline", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		src := e.add("FW-HQ", "192.168.10.1")
		e.feed(src, fw(22, "10.0.0.1"), 10)
		*e.clock = t0.Add(26 * time.Hour) // warmed up, but the source has no full day behind yesterday
		e.feed(src, fw(22, "10.0.0.1"), 500)
		if d := e.digest(); len(d.Spikes) != 0 || len(d.New) != 0 {
			t.Fatalf("%+v", d)
		}
	})
}

// INV-6 over ten days of fake time (testing/synctest): the warm-up, a spike against a baseline that is a full week, a new kind of line.
func TestContract_INV6_BaselineOverTenFakeDays(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t)
		e.svc.now = time.Now // the bubble's clock starts at midnight UTC and moves only when everything sleeps
		src := e.add("FW-HQ", "192.168.10.1")
		e.feed(src, fw(22, "10.0.0.1"), 10)
		<-time.After(time.Hour)
		e.feed(src, fw(23, "10.0.0.1"), 5)
		if d := e.digest(); len(d.New)+len(d.Spikes) != 0 {
			t.Fatalf("the first day is silent: %+v", d)
		}
		for range 9 { // days 1..9: ten lines of "22" a day, none of "23"
			<-time.After(24 * time.Hour)
			e.feed(src, fw(22, "10.0.0.1"), 10)
		}
		<-time.After(time.Hour)
		e.feed(src, fw(22, "10.0.0.1"), 49) // today 59 + yesterday's share: over 5 x 10
		e.feed(src, fw(24, "10.0.0.1"), 2)  // never seen
		e.feed(src, fw(23, "10.0.0.1"), 1)  // last seen on day 0: more than the 8 days the counters read go back, so it is new again
		d := e.digest()
		if got := newItems(d); len(got) != 2 {
			t.Fatalf("new %v", got)
		}
		if len(d.Spikes) != 1 || d.Spikes[0].Signature != sigFor(22) || d.Spikes[0].BaselinePerDay != 10 {
			t.Fatalf("spikes %+v", d.Spikes)
		}
	})
}

// INV-6: a signature that was not seen for the whole baseline is new again; one seen inside it is not.
func TestContract_INV6_BaselineIsSevenDays(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	e.history(src, 1)
	*e.clock = t0.Add(48*time.Hour + time.Hour)
	e.feed(src, fw(9999, "10.0.0.1"), 2) // new, on day 2
	if got := newItems(e.digest()); len(got) != 1 {
		t.Fatalf("%v", got)
	}
	*e.clock = t0.Add(48*time.Hour + 26*time.Hour) // a day later it has left the 24 h window of "new"
	if got := newItems(e.digest()); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	*e.clock = t0.Add(40 * 24 * time.Hour) // and 40 days later, with the old rows purged by retention, a quiet signature is new again
	if _, err := e.svc.Purge(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.feed(src, fw(22, "10.0.0.1"), 3)
	if got := newItems(e.digest()); len(got) != 0 { // the source itself is "warming up" again: its counters are gone
		t.Fatalf("%v", got)
	}
}

// INV-6: a clean install has an empty digest, and the lists are JSON arrays (the GUI maps over them).
func TestContract_INV6_CleanInstallEmptyDigest(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	d := e.digest()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"new":[]`, `"spikes":[]`, `"bad_connections":[]`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("%s missing in %s", key, b)
		}
	}
	e.add("FW-HQ", "192.168.10.1")
	if d := e.digest(); len(d.New) != 0 || len(d.Spikes) != 0 {
		t.Fatalf("a source with no line: %+v", d)
	}
}

// INV-1 (SYS-6): a flood of identical lines is one row, however many lines.
func TestContract_INV1_FloodOfIdenticalLinesIsOneRow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	kinds := map[string]string{src.ID: "fortigate"}
	batch := make([]Line, 5000)
	for i := range batch {
		batch[i] = Line{SourceID: src.ID, At: t0, Text: fw(22, "10.0.0.1")}
	}
	for range 200 { // 1,000,000 lines
		b := e.svc.tally(kinds, batch)
		if err := e.svc.cfg.Volume.Write(t.Context(), func(tx *sql.Tx) error { return e.svc.storeSignatures(t.Context(), tx, b) }); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily`); n != 1 {
		t.Fatalf("%d rows", n)
	}
	if n := count(t, e.vol, `SELECT count FROM logs_signature_daily`); n != 1_000_000 {
		t.Fatalf("count %d", n)
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_buckets`); n != 1 {
		t.Fatalf("%d bucket rows", n)
	}
}

// INV-1: a device that sends a different line every time cannot make the table grow without bound: past the quota of the miner the
// lines of a day are counted under one row "(other)", and no line is lost from the count.
func TestContract_INV1_DistinctSignaturesAreCapped(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	total := MaxMinedPerDay + 300
	for i := 0; i < total; i += MaxBatch {
		batch := make([]Line, 0, MaxBatch)
		for j := i; j < min(i+MaxBatch, total); j++ {
			batch = append(batch, Line{SourceID: src.ID, At: t0, Text: fmt.Sprintf("word%s some text", letters(j))})
		}
		if _, err := e.svc.Ingest(t.Context(), batch); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily`); n != MaxMinedPerDay+1 {
		t.Fatalf("%d rows, want %d", n, MaxMinedPerDay+1)
	}
	if n := count(t, e.vol, `SELECT sum(count) FROM logs_signature_daily`); n != total {
		t.Fatalf("counted %d lines of %d", n, total)
	}
	if n := count(t, e.vol, `SELECT count FROM logs_signature_daily WHERE signature = ?`, OtherSignature); n != 300 {
		t.Fatalf("(other) has %d", n)
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_buckets`); n > MaxMinedPerBucket+1 {
		t.Fatalf("%d bucket rows", n)
	}
}

// letters writes n in letters only, so that the miner (which masks digits) sees a different word each time.
func letters(n int) string {
	var b strings.Builder
	for ; n >= 0; n = n/26 - 1 {
		b.WriteByte(byte('a' + n%26))
	}
	return b.String()
}

// Ingest keeps what the digest needs and nothing more: the count, the first time, one clipped sample, and the latest destination.
func TestIngestCountsSignatures(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	e.feed(src, fw(3389, "192.168.10.1"), 3)
	e.advance(time.Minute)
	e.feed(src, fw(3389, "192.168.10.1"), 2)
	e.feed(src, fw(3389, "192.168.10.9"), 1)
	var n, mined int
	var first, sample, dest string
	if err := e.vol.Reader().QueryRowContext(t.Context(), `SELECT count, first_seen, sample, dest, mined FROM logs_signature_daily WHERE signature = ?`, sigFor(3389)).Scan(&n, &first, &sample, &dest, &mined); err != nil {
		t.Fatal(err)
	}
	if n != 6 || first != "2026-11-09T10:00:00.000Z" || !strings.Contains(sample, "dstip=192.168.10.1 ") || len(sample) > MaxSampleBytes || dest != "192.168.10.9" || mined != 0 {
		t.Fatalf("%d %s %q %s %d", n, first, sample, dest, mined)
	}
	if c := count(t, e.vol, `SELECT sum(count) FROM logs_signature_buckets WHERE signature = ?`, sigFor(3389)); c != 6 {
		t.Fatalf("buckets %d", c)
	}
	// a line of a source that is not declared leaves no counter
	if _, err := e.svc.Ingest(t.Context(), lines("ls-nobody", e.svc.now(), fw(1, "1.1.1.1"))); err != nil {
		t.Fatal(err)
	}
	if c := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily WHERE source_id = 'ls-nobody'`); c != 0 {
		t.Fatal("counted a line of an undeclared source")
	}
}

// Counts is the read port of response's log_threshold: lines of one signature of one source in a window of 5 minutes to 24 hours.
func TestCounts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	e.feed(src, fw(22, "10.0.0.1"), 3)
	e.advance(10 * time.Minute)
	e.feed(src, fw(22, "10.0.0.1"), 2)
	e.feed(src, fw(23, "10.0.0.1"), 7)
	for _, c := range []struct {
		sig    string
		window time.Duration
		want   int
	}{
		{sigFor(22), 5 * time.Minute, 2},
		{sigFor(22), 30 * time.Minute, 5},
		{sigFor(23), time.Hour, 7},
		{"something never seen", time.Hour, 0},
	} {
		got, err := e.svc.Counts(t.Context(), src.ID, c.sig, c.window)
		if err != nil || got != c.want {
			t.Errorf("%q %v: %d, %v; want %d", c.sig, c.window, got, err, c.want)
		}
	}
	for _, w := range []time.Duration{0, time.Minute, 25 * time.Hour} {
		if _, err := e.svc.Counts(t.Context(), src.ID, sigFor(22), w); err == nil {
			t.Errorf("window %v accepted", w)
		}
	}
}

type pubs struct {
	mu  sync.Mutex
	got []AnomalyEvent
}

func (p *pubs) Publish(_ context.Context, e events.Event) error {
	if e.Name != EventAnomalyDetected {
		return fmt.Errorf("unexpected event %s", e.Name)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.got = append(p.got, e.Data.(AnomalyEvent))
	return nil
}

func (p *pubs) events() []AnomalyEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]AnomalyEvent(nil), p.got...)
}

func (e *env) detect() {
	e.t.Helper()
	if err := e.svc.detect(e.t.Context()); err != nil {
		e.t.Fatal(err)
	}
}

// A new signature after the warm-up is announced once, with the payload notify reads; the warm-up announces nothing.
func TestContract_Events_NewSignatureIsAnnouncedOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := &pubs{}
	e.svc.cfg.Events = p
	src := e.add("FW-HQ", "192.168.10.1")
	e.feed(src, fw(22, "10.0.0.1"), 10)
	e.feed(src, fw(23, "10.0.0.1"), 10) // new, but inside the warm-up
	e.detect()
	if got := p.events(); len(got) != 0 {
		t.Fatalf("the warm-up announced %+v", got)
	}
	*e.clock = t0.Add(25 * time.Hour)
	e.feed(src, fw(3389, "192.168.10.1"), 4)
	e.detect()
	e.detect() // the same anomaly is not announced twice
	got := p.events()
	if len(got) != 1 {
		t.Fatalf("%d events: %+v", len(got), got)
	}
	ev := got[0]
	if ev.Source != "FW-HQ" || ev.Target != "192.168.10.1" || ev.Severity != "low" || ev.Title == "" || len([]rune(ev.Title)) > 200 || ev.What == "" || ev.Action == "" {
		t.Fatalf("%+v", ev)
	}
	if len(ev.Devices) != 1 || ev.Devices[0].ID != "a-fw" || ev.Devices[0].Name != "FW-HQ" {
		t.Fatalf("devices %+v", ev.Devices)
	}
	if b, _ := json.Marshal(ev); !strings.Contains(string(b), `"devices":[{"id":"a-fw","name":"FW-HQ"}]`) {
		t.Fatalf("the JSON notify reads: %s", b)
	}
}

// Events are grouped by source and target, and at most 20 an hour leave one source; what was held back goes out when the hour has passed.
func TestContract_Events_GroupingAndRateLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := &pubs{}
	e.svc.cfg.Events = p
	a := e.add("FW-HQ", "192.168.10.1")
	b := e.add("FW-2", "192.168.10.2")
	e.history(a, 1)
	*e.clock = t0
	e.history(b, 1)
	*e.clock = t0.Add(25 * time.Hour)
	for port := 100; port < 103; port++ { // three new signatures that aim at one address: one event
		e.feed(a, fw(port, "203.0.113.7"), 2)
	}
	e.detect()
	if got := p.events(); len(got) != 1 || got[0].Target != "203.0.113.7" || !strings.Contains(got[0].Title, "3") {
		t.Fatalf("grouping: %+v", got)
	}
	for i := 0; i < 25; i++ { // 25 more targets: the hourly cap lets 19 more through (20 in all)
		e.feed(a, fw(200+i, fmt.Sprintf("198.51.100.%d", i+1)), 2)
	}
	e.feed(b, fw(300, "198.51.100.200"), 2) // another source has its own allowance
	e.detect()
	perSource := map[string]int{}
	for _, ev := range p.events() {
		perSource[ev.Source]++
	}
	if perSource["FW-HQ"] != 20 || perSource["FW-2"] != 1 {
		t.Fatalf("%v", perSource)
	}
	e.detect()
	if len(p.events()) != 21 {
		t.Fatalf("a second pass in the same hour sent more: %d", len(p.events()))
	}
	e.advance(61 * time.Minute)
	e.detect()
	perSource = map[string]int{}
	for _, ev := range p.events() {
		perSource[ev.Source]++
	}
	if perSource["FW-HQ"] != 26 { // 1 + 25 targets: the 6 held back are sent now
		t.Fatalf("after the hour: %v", perSource)
	}
}

// A spike is announced too, as medium.
func TestContract_Events_SpikeIsMedium(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := &pubs{}
	e.svc.cfg.Events = p
	src := e.add("FW-HQ", "192.168.10.1")
	e.history(src, 3)
	e.feed(src, fw(22, "10.0.0.1"), 60)
	e.detect()
	got := p.events()
	if len(got) != 1 || got[0].Severity != "medium" || got[0].Target != "10.0.0.1" {
		t.Fatalf("%+v", got)
	}
}

// SYS-5: with the module off no job runs, so nothing is detected and nothing is published; turning it on starts the job.
func TestContract_SYS5_NoEventsWhileTheModuleIsOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := &pubs{}
	e.svc.cfg.Events = p
	src := e.add("FW-HQ", "192.168.10.1")
	e.feed(src, fw(22, "10.0.0.1"), 10)
	*e.clock = t0.Add(25 * time.Hour)
	e.feed(src, fw(3389, "192.168.10.1"), 4)
	gate := &toggleGate{}
	sched := jobs.New(slog.New(slog.DiscardHandler), gate, nil)
	found := false
	for _, j := range Jobs(e.svc) {
		if j.Name == "anomaly" {
			found = true
			if j.Housekeeping {
				t.Fatal("the anomaly job is housekeeping: it would announce with the module off")
			}
			if err := sched.Add(j); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found {
		t.Fatal("no anomaly job")
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); sched.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitUntil(t, "the scheduler to have asked the gate", func() bool { return gate.calls.Load() > 0 })
	if n := len(p.events()); n != 0 {
		t.Fatalf("%d events while the module is off", n)
	}
	gate.set(true)
	sched.ModuleChanged(ModuleID, true)
	waitUntil(t, "the event after the module was turned on", func() bool { return len(p.events()) == 1 })
}

// The signature counters are kept for exactly BaselineDays+2 days whatever the retention; a sample goes with the line it copies,
// by time and not by day; the 5-minute counters go after 48 hours and the announcements after 3 days.
func TestPurgeDropsOldSignatureCounters(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	put := func(hours int) {
		t.Helper()
		at := t0.Add(-time.Duration(hours) * time.Hour)
		ts := at.Format("2006-01-02T15:04:05.000Z")
		if err := e.svc.cfg.Volume.Write(t.Context(), func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO logs_signature_daily (day, source_id, signature, dest, count, first_seen, sample, mined) VALUES (?, ?, 'sig', '', 1, ?, 'a line', 0)`, at.Format("2006-01-02"), src.ID, ts); err != nil {
				return err
			}
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO logs_signature_buckets (source_id, bucket, signature, count, mined) VALUES (?, ?, 'sig', 1, 0)`, src.ID, at.Unix()/300); err != nil {
				return err
			}
			_, err := tx.ExecContext(t.Context(), `INSERT INTO logs_anomaly_sent (source_id, kind, signature, ref, target, sent_at) VALUES (?, 'new', 'sig', ?, 't', ?)`, src.ID, ts, ts)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range []int{0, 24, 7*24 + 1, 8*24 + 1, 10 * 24, 12 * 24} { // t0 is 10:00, so 10 days is day -10
		put(h)
	}
	for _, days := range []int{180, 7} { // the long retention first: it keeps every sample
		if _, err := e.svc.SetRetention(t.Context(), "admin@acme.example", days); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Purge(t.Context()); err != nil {
			t.Fatal(err)
		}
		// kept: days -0, -1, -7, -8 (BaselineDays+2 = 9 days back is the oldest day kept, -9 at 10:00 is not here); gone: -10 and -12
		if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily`); n != 4 {
			t.Fatalf("retention %d: %d rows, want 4 (exactly 9 days, whatever the retention)", days, n)
		}
		want := 4
		if days == 7 { // the order matters: the samples are blanked once and stay blank
			want = 2 // first_seen 7 days and 1 hour ago and older: the sample is gone, the row stays for the baseline
		}
		if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily WHERE sample <> ''`); n != want {
			t.Fatalf("retention %d: %d samples, want %d", days, n, want)
		}
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_buckets`); n != 2 {
		t.Fatalf("5-minute counters older than 48 h are dropped: %d", n)
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_anomaly_sent`); n != 2 { // 0 and 24 h stay; 169 h is over 72 h
		t.Fatalf("announcements older than 3 days are dropped: %d", n)
	}
}

// The catalog says "parsed" only for a kind that has a profile (honesty: the GUI shows it), and every profile is for a known kind.
func TestCatalogReadsMatchProfiles(t *testing.T) {
	t.Parallel()
	var list []struct{ ID, Reads string }
	if err := json.Unmarshal(logsdata.Kinds, &list); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	parsed := map[string]bool{}
	for _, k := range list {
		if k.Reads == "parsed" {
			parsed[k.ID] = true
		}
		if parsed[k.ID] != e.svc.sigs.HasProfile(k.ID) {
			t.Errorf("%s: kinds.json says %q, profiles say has=%v", k.ID, k.Reads, e.svc.sigs.HasProfile(k.ID))
		}
	}
	for _, id := range e.svc.sigs.Kinds() {
		if _, ok := kinds[id]; !ok {
			t.Errorf("a profile is for %q, which is not a source kind", id)
		}
	}
}

// fwDeny is a FortiGate deny with the same log id whatever the port: a scan of the Internet is one signature, not one per port.
func fwDeny(port int) string {
	return fmt.Sprintf(`type="traffic" subtype="forward" logid="0000000013" srcip=45.9.148.20 dstip=203.0.113.1 dstport=%d action="deny"`, port)
}

const adminLoginFailed = `logid="0100032001" type="event" subtype="system" msg="Administrator admin login failed from https(10.0.0.9) because of invalid password"`

func hasSignature(d Digest, part string) bool {
	for _, n := range d.New {
		if strings.Contains(n.Signature, part) {
			return true
		}
	}
	return false
}

// H1: ordinary traffic must not fill the quota and hide what is new. 2,100 denied ports are one signature, and an administrator
// login failure that comes after them is in the digest (the probe of the review: it was missing, with "(other)" on top).
func TestContract_INV6_ManyPortsDoNotBlindNew(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	e.history(src, 3)
	*e.clock = t0.Add(3*24*time.Hour + 2*time.Hour)
	for port := 1; port <= 2100; port += 100 {
		batch := make([]Line, 0, 100)
		for p := port; p < port+100; p++ {
			batch = append(batch, Line{SourceID: src.ID, At: e.svc.now(), Text: fwDeny(p)})
		}
		if _, err := e.svc.Ingest(t.Context(), batch); err != nil {
			t.Fatal(err)
		}
	}
	e.advance(time.Hour)
	e.feed(src, adminLoginFailed, 1)
	d := e.digest()
	if !hasSignature(d, "login failed") {
		t.Fatalf("the administrator login failure is not in the digest: %+v", d.New)
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily WHERE day = '2026-11-12'`); n > 3 {
		t.Fatalf("%d rows for one deny signature and one event", n)
	}
}

// H1: a flood of lines the miner cannot make alike fills the quota of the miner only: a signature of a profile still counts, and is
// still new, and "(other)" is never shown as news.
func TestContract_INV1_MinerFloodCannotPushOutAProfileSignature(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	e.history(src, 1)
	*e.clock = t0.Add(25 * time.Hour)
	total := MaxMinedPerDay + 400
	for i := 0; i < total; i += MaxBatch {
		batch := make([]Line, 0, MaxBatch)
		for j := i; j < min(i+MaxBatch, total); j++ {
			batch = append(batch, Line{SourceID: src.ID, At: e.svc.now(), Text: fmt.Sprintf("word%s some text", letters(j))})
		}
		if _, err := e.svc.Ingest(t.Context(), batch); err != nil {
			t.Fatal(err)
		}
	}
	e.feed(src, fw(77, "10.0.0.1"), 2)
	d := e.digest()
	if !hasSignature(d, "logid=0000000077") {
		t.Fatalf("a profile signature was pushed out by the miner flood: %+v", d.New)
	}
	for _, n := range d.New {
		if n.Signature == OtherSignature {
			t.Fatal(`"(other)" is shown as a new kind of line`)
		}
	}
	for _, s := range d.Spikes {
		if s.Signature == OtherSignature {
			t.Fatal(`"(other)" is shown as a spike`)
		}
	}
	if c := count(t, e.vol, `SELECT count FROM logs_signature_daily WHERE signature = ?`, OtherSignature); c != 400 {
		t.Fatalf("(other) counted %d lines, want 400", c)
	}
}

// H1: a list of user names is not a list of signatures: 500 names make at most a few.
func TestContract_INV1_UserNameBruteForceIsAFewSignatures(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s, err := e.svc.AddSource(t.Context(), "admin@acme.example", Input{Kind: "linux-rsyslog", Name: "SRV-LNX", SenderIP: "192.168.10.30", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	var batch []Line
	flush := func() {
		if _, err := e.svc.Ingest(t.Context(), batch); err != nil {
			t.Fatal(err)
		}
		batch = batch[:0]
	}
	for i := 0; i < 500; i++ {
		if len(batch) >= MaxBatch {
			flush()
		}
		batch = append(batch, Line{SourceID: s.ID, At: t0, Text: fmt.Sprintf("<38>Nov  9 10:00:00 srv sshd[%d]: Invalid user %s from 45.9.148.%d port %d", 1000+i, "u"+letters(i), i%250+1, 40000+i)})
		batch = append(batch, Line{SourceID: s.ID, At: t0, Text: fmt.Sprintf("<38>Nov  9 10:00:00 srv sshd[%d]: Failed password for invalid user %s from 45.9.148.%d port %d ssh2", 2000+i, letters(i), i%250+1, 41000+i)})
	}
	flush()
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily WHERE source_id = ?`, s.ID); n > 3 {
		t.Fatalf("%d signatures for 1,000 lines of a user name list", n)
	}
}

// H2: the event passes what notify accepts. notify refuses what and action over 1,000 characters, source and target and title over
// 200, a device id over 96 bytes or a name over 253 (modules/notify/incidents.go, IncidentInput.validate), and the bus swallows the
// refusal, so an event that is too long is an incident that never exists. The limits are mirrored here on purpose: logs does not
// import notify.
func notifyAccepts(t *testing.T, ev AnomalyEvent) {
	t.Helper()
	n := func(s string) int { return len([]rune(s)) }
	switch {
	case strings.TrimSpace(ev.Title) == "" || n(ev.Title) > 200:
		t.Errorf("title of %d characters", n(ev.Title))
	case n(ev.What) > 1000 || n(ev.Action) > 1000:
		t.Errorf("what %d action %d characters", n(ev.What), n(ev.Action))
	case n(ev.Source) > 200 || n(ev.Target) > 200 || ev.Source == "":
		t.Errorf("source %d target %d characters", n(ev.Source), n(ev.Target))
	case len(ev.Devices) > 20:
		t.Errorf("%d devices", len(ev.Devices))
	}
	switch ev.Severity {
	case "critical", "high", "medium", "low", "info":
	default:
		t.Errorf("severity %q", ev.Severity)
	}
	for _, d := range ev.Devices {
		if d.ID == "" || len(d.ID) > 96 || strings.TrimSpace(d.Name) == "" || n(d.Name) > 253 {
			t.Errorf("device %+v", d)
		}
	}
}

func TestContract_Events_PayloadFitsWhatNotifyAccepts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := &pubs{}
	e.svc.cfg.Events = p
	src := e.add("FW-HQ", "192.168.10.1")
	e.feed(src, fw(22, "10.0.0.1"), 10)
	*e.clock = t0.Add(25 * time.Hour)
	long := strings.Repeat("x", 30)
	for i := 0; i < 3; i++ { // three long new signatures that aim at one address: the probe of the review made 1,082 characters
		msg := strings.Repeat(fmt.Sprintf("word%c%s ", 'a'+i, long), 10)
		e.feed(src, fmt.Sprintf(`logid="0100032001" type="event" subtype="system" dstip=203.0.113.7 msg=%q pad=%s`, msg, strings.Repeat("y", 200)), 2)
	}
	e.feed(src, strings.Repeat("a", 30)+" "+strings.Repeat("z", 1900), 1)
	e.detect()
	got := p.events()
	if len(got) == 0 {
		t.Fatal("no event")
	}
	for _, ev := range got {
		notifyAccepts(t, ev)
	}
	if w := got[0].What; len([]rune(w)) < 400 {
		t.Fatalf("clipped too much: %d characters", len([]rune(w)))
	}
}

// M1: the baseline is 7 days: the 7 full days before yesterday, also for a source that is older than the counters read (the start of
// the source comes from the oldest day that is kept, not from the first baseline day). One day with 70 more lines gives (80+60)/7.
func TestContract_INV6_BaselineIsSevenFullDays(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	e.history(src, 10) // days 0..10
	*e.clock = t0.Add(2 * 24 * time.Hour)
	e.feed(src, fw(22, "10.0.0.1"), 70) // the first day of the baseline of day 10
	*e.clock = t0.Add(10 * 24 * time.Hour)
	e.feed(src, fw(22, "10.0.0.1"), 200)
	d := e.digest()
	if len(d.Spikes) != 1 || d.Spikes[0].BaselinePerDay != 20 {
		t.Fatalf("%+v", d.Spikes)
	}
}

// L2: a source whose kind or sender address changes is a different source for the baseline: its warm-up starts again, and nothing is
// announced during it.
func TestContract_INV6_ChangingKindOrSenderRestartsTheWarmUp(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		in   Input
	}{
		{"kind", Input{Kind: "mikrotik", Name: "FW-HQ", SenderIP: "192.168.10.1", Proto: "udp", Port: 514}},
		{"sender", Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "192.168.10.77", Proto: "udp", Port: 514}},
		{"name only", Input{Kind: "fortigate", Name: "FW-NEW", SenderIP: "192.168.10.1", Proto: "udp", Port: 514}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			p := &pubs{}
			e.svc.cfg.Events = p
			src := e.add("FW-HQ", "192.168.10.1")
			e.history(src, 3) // warm, with a baseline
			if _, err := e.svc.UpdateSource(t.Context(), "admin@acme.example", src.ID, c.in); err != nil {
				t.Fatal(err)
			}
			e.advance(time.Hour)
			e.feed(src, fw(4444, "10.0.0.1"), 5) // would be new
			e.feed(src, fw(22, "10.0.0.1"), 300) // would be a spike
			e.detect()
			d := e.digest()
			restarted := c.name != "name only"
			if restarted && (len(d.New) != 0 || len(d.Spikes) != 0 || len(p.events()) != 0) {
				t.Fatalf("the warm-up did not restart: %+v events %d", d, len(p.events()))
			}
			if !restarted && (len(d.New) != 1 || len(d.Spikes) != 1) {
				t.Fatalf("a rename must not restart it: %+v", d)
			}
			if restarted { // and it ends 24 hours after the change
				e.advance(25 * time.Hour)
				e.feed(src, "a brand new message about something else", 2) // not the same words as the lines of the warm-up
				if d := e.digest(); len(d.New) != 1 {
					t.Fatalf("after the warm-up: %+v now %v", d.New, e.svc.now())
				}
			}
		})
	}
}

// A spike that is still there at midnight is still a spike (yesterday's share is carried over), and the day boundary splits the rows.
func TestContract_INV6_MidnightKeepsTheSpike(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	e.history(src, 3)
	*e.clock = time.Date(2026, 11, 12, 23, 59, 30, 0, time.UTC)
	e.feed(src, fw(22, "10.0.0.1"), 60)
	if d := e.digest(); len(d.Spikes) != 1 {
		t.Fatalf("before midnight: %+v", d.Spikes)
	}
	*e.clock = time.Date(2026, 11, 13, 0, 0, 30, 0, time.UTC)
	e.feed(src, fw(22, "10.0.0.1"), 1)
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily WHERE signature = ? AND day IN ('2026-11-12', '2026-11-13')`, sigFor(22)); n != 2 {
		t.Fatalf("%d day rows", n)
	}
	if d := e.digest(); len(d.Spikes) != 1 {
		t.Fatalf("after midnight: %+v", d.Spikes)
	}
}

// The 5-minute counters have the same quotas, and "(other)" keeps the count.
func TestContract_INV1_BucketQuotaCountsTheRestUnderOther(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	total := MaxMinedPerBucket + 200
	batch := make([]Line, 0, total)
	for j := 0; j < total; j++ {
		batch = append(batch, Line{SourceID: src.ID, At: t0, Text: fmt.Sprintf("word%s some text", letters(j))})
	}
	for i := 0; i < total; i += MaxBatch {
		if _, err := e.svc.Ingest(t.Context(), batch[i:min(i+MaxBatch, total)]); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_buckets`); n != MaxMinedPerBucket+1 {
		t.Fatalf("%d bucket rows", n)
	}
	if n := count(t, e.vol, `SELECT count FROM logs_signature_buckets WHERE signature = ?`, OtherSignature); n != 200 {
		t.Fatalf("(other) %d", n)
	}
	if n, err := e.svc.Counts(t.Context(), src.ID, OtherSignature, 5*time.Minute); err != nil || n != 200 {
		t.Fatalf("%d %v", n, err)
	}
}

// INV-1 through the whole path: a flood of identical lines, batched as the listener batches them, is one row. (Under -race every batch is slow, so
// the million-line version stays in the unit above; this one proves Ingest itself.)
func TestContract_INV1_FloodThroughIngestIsOneRow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	batch := make([]Line, MaxBatch)
	for i := range batch {
		batch[i] = Line{SourceID: src.ID, At: t0, Text: fw(22, "10.0.0.1")}
	}
	start := time.Now()
	for range 40 { // 20,000 lines
		if _, err := e.svc.Ingest(t.Context(), batch); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("20,000 identical lines through Ingest: %v", time.Since(start))
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily`); n != 1 {
		t.Fatalf("%d rows", n)
	}
	if n := count(t, e.vol, `SELECT count FROM logs_signature_daily`); n != 20_000 {
		t.Fatalf("count %d", n)
	}
}

// M3: the reads of one source use the index, and a digest and a detect over 10 sources with every quota full for the 10 days that are
// kept are measured (the numbers go to D-206).
func TestMeasureDigestCost(t *testing.T) {
	t.Parallel()
	t.Run("a busy box", func(t *testing.T) { measureDigest(t, 300) })
	t.Run("every quota full", func(t *testing.T) { // 270,000 rows: seconds to build, so only when asked (VEDETTE_MEASURE=1)
		if os.Getenv("VEDETTE_MEASURE") == "" {
			t.Skip("set VEDETTE_MEASURE=1 to measure the worst case")
		}
		measureDigest(t, MaxMinedPerDay+MaxProfilePerDay)
	})
}

func measureDigest(t *testing.T, perDay int) {
	t.Helper()
	e := newEnv(t)
	var srcs []Source
	for i := 0; i < 10; i++ {
		srcs = append(srcs, e.add(fmt.Sprintf("S%d", i), fmt.Sprintf("192.168.20.%d", i+1)))
	}
	now := t0.Add(9 * 24 * time.Hour)
	if err := e.svc.cfg.Volume.Write(t.Context(), func(tx *sql.Tx) error {
		st, err := tx.PrepareContext(t.Context(), `INSERT INTO logs_signature_daily (day, source_id, signature, dest, count, first_seen, sample, mined) VALUES (?, ?, ?, '10.0.0.1', 1, ?, ?, ?)`)
		if err != nil {
			return err
		}
		for d := 0; d <= BaselineDays+1; d++ {
			at := now.Add(-time.Duration(d) * 24 * time.Hour).Truncate(24 * time.Hour).Add(time.Minute)
			for _, s := range srcs {
				for k := 0; k < perDay; k++ {
					if _, err := st.ExecContext(t.Context(), at.Format("2006-01-02"), s.ID, fmt.Sprintf("sig %d %d", d, k), at.Format("2006-01-02T15:04:05.000Z"), strings.Repeat("s", MaxSampleBytes), k%2); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	*e.clock = now
	p := &pubs{}
	e.svc.cfg.Events = p
	rows := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily`)
	start := time.Now()
	d := e.digest()
	dt := time.Since(start)
	start = time.Now()
	e.detect()
	t.Logf("%d rows: digest %v (new %d), detect %v (events %d)", rows, dt, len(d.New), time.Since(start), len(p.events()))
	var plan strings.Builder
	r, err := e.vol.Reader().QueryContext(t.Context(), `EXPLAIN QUERY PLAN SELECT dest, sample FROM logs_signature_daily WHERE source_id = ? AND signature = ? AND day >= ? ORDER BY day`, srcs[0].ID, "sig 1 1", "2026-11-01")
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
		var a, b, c int
		var s string
		_ = r.Scan(&a, &b, &c, &s)
		plan.WriteString(s + "; ")
	}
	_ = r.Close()
	if !strings.Contains(plan.String(), "logs_signature_daily_source") {
		t.Fatalf("the read of one signature of a source does not use the index: %s", plan.String())
	}
}

// L1: the cost of one Ingest batch of 500 lines (the numbers go to D-206): identical lines, distinct lines under the quota, distinct lines with the quota full.
func TestMeasureIngestCost(t *testing.T) {
	t.Parallel()
	if os.Getenv("VEDETTE_MEASURE") == "" {
		t.Skip("set VEDETTE_MEASURE=1 to measure")
	}
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	mk := func(distinct bool, off int) []Line {
		b := make([]Line, MaxBatch)
		for i := range b {
			txt := fw(22, "10.0.0.1")
			if distinct {
				txt = fmt.Sprintf("word%s some text from 10.0.0.1", letters(off+i))
			}
			b[i] = Line{SourceID: src.ID, At: e.svc.now(), Text: txt}
		}
		return b
	}
	run := func(name string, distinct bool, n, off int) {
		start := time.Now()
		for k := 0; k < n; k++ {
			if _, err := e.svc.Ingest(t.Context(), mk(distinct, off+k*MaxBatch)); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("%s: %v per batch of 500", name, time.Since(start)/time.Duration(n))
	}
	run("identical", false, 20, 0)
	run("distinct under quota", true, 2, 0)
	run("distinct at quota", true, 20, 100000)
}
