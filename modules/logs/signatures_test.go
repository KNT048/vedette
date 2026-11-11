package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	logsdata "github.com/knt048/vedette/content/logs"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
)

// fw is a FortiGate traffic line; its signature is sigFor(port).
func fw(port int, dst string) string {
	return fmt.Sprintf(`type="traffic" subtype="forward" logid="0000000013" srcip=45.9.148.20 dstip=%s dstport=%d action="deny"`, dst, port)
}

func sigFor(port int) string {
	return fmt.Sprintf("type=traffic subtype=forward logid=0000000013 action=deny dstport=%d", port)
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
	if n.Count != 3 || n.SourceID != src.ID || n.SourceName != "FW-HQ" || !n.FirstSeen.Equal(*e.clock) || !strings.Contains(n.Sample, "dstport=25") || !strings.HasPrefix(n.ID, "n-") {
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

// INV-1: a device that sends a different line every time cannot make the table grow without bound: past the cap the lines of a
// day are counted under one row "(other)", and no line is lost from the count.
func TestContract_INV1_DistinctSignaturesAreCapped(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	total := MaxSignaturesPerDay + 300
	for i := 0; i < total; i += MaxBatch {
		batch := make([]Line, 0, MaxBatch)
		for j := i; j < min(i+MaxBatch, total); j++ {
			batch = append(batch, Line{SourceID: src.ID, At: t0, Text: fmt.Sprintf("word%s some text", letters(j))})
		}
		if _, err := e.svc.Ingest(t.Context(), batch); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily`); n != MaxSignaturesPerDay+1 {
		t.Fatalf("%d rows, want %d", n, MaxSignaturesPerDay+1)
	}
	if n := count(t, e.vol, `SELECT sum(count) FROM logs_signature_daily`); n != total {
		t.Fatalf("counted %d lines of %d", n, total)
	}
	if n := count(t, e.vol, `SELECT count FROM logs_signature_daily WHERE signature = ?`, OtherSignature); n != 300 {
		t.Fatalf("(other) has %d", n)
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_buckets`); n > MaxSignaturesPerBucket+1 {
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

// Ingest keeps what the digest needs and nothing more: the count, the first time, one clipped sample, and the destination.
func TestIngestCountsSignatures(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	e.feed(src, fw(3389, "192.168.10.1"), 3)
	e.advance(time.Minute)
	e.feed(src, fw(3389, "192.168.10.1"), 2)
	e.feed(src, fw(3389, "192.168.10.9"), 1)
	var n int
	var first, sample, dest string
	if err := e.vol.Reader().QueryRowContext(t.Context(), `SELECT count, first_seen, sample FROM logs_signature_daily WHERE signature = ? AND dest = '192.168.10.1'`, sigFor(3389)).Scan(&n, &first, &sample); err != nil {
		t.Fatal(err)
	}
	if n != 5 || first != "2026-11-09T10:00:00.000Z" || !strings.Contains(sample, "dstport=3389") || len(sample) > MaxSampleBytes {
		t.Fatalf("%d %s %q", n, first, sample)
	}
	if err := e.vol.Reader().QueryRowContext(t.Context(), `SELECT dest FROM logs_signature_daily WHERE dest = '192.168.10.9'`).Scan(&dest); err != nil {
		t.Fatal(err)
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

// The counters follow the retention (and never less than the 9 days the baseline reads); the sample goes with the lines.
func TestPurgeDropsOldSignatureCounters(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	src := e.add("FW-HQ", "192.168.10.1")
	if _, err := e.svc.SetRetention(t.Context(), "admin@acme.example", 7); err != nil {
		t.Fatal(err)
	}
	put := func(days int) {
		t.Helper()
		at := t0.Add(-time.Duration(days) * 24 * time.Hour)
		ts := at.Format("2006-01-02T15:04:05.000Z")
		if err := e.svc.cfg.Volume.Write(t.Context(), func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO logs_signature_daily (day, source_id, signature, dest, count, first_seen, sample) VALUES (?, ?, 'sig', '', 1, ?, 'a line')`, at.Format("2006-01-02"), src.ID, ts); err != nil {
				return err
			}
			_, err := tx.ExecContext(t.Context(), `INSERT INTO logs_signature_buckets (source_id, bucket, signature, count) VALUES (?, ?, 'sig', 1)`, src.ID, at.Unix()/300)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []int{0, 1, 8, 10} {
		put(d)
	}
	if _, err := e.svc.Purge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily`); n != 3 {
		t.Fatalf("retention 7: %d rows, want 3 (the 10-day-old one is gone, the 8-day-old one stays for the baseline)", n)
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily WHERE sample <> ''`); n != 2 {
		t.Fatalf("the sample of a row older than the retention must be dropped: %d samples", n)
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_buckets`); n != 2 {
		t.Fatalf("5-minute counters older than 48 h are dropped: %d", n)
	}
	if _, err := e.svc.SetRetention(t.Context(), "admin@acme.example", 30); err != nil {
		t.Fatal(err)
	}
	put(10)
	if _, err := e.svc.Purge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e.vol, `SELECT count(*) FROM logs_signature_daily WHERE sample <> ''`); n != 3 {
		t.Fatalf("retention 30 keeps the samples: %d", n)
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
