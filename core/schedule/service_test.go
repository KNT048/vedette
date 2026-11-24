package schedule_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/schedule"
	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

const coreMigrations = "../../modules/core/migrations/sqlite"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = utc(s)
}

type gate struct {
	mu  sync.Mutex
	off map[string]bool
}

func (g *gate) Enabled(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.off[id]
}

func (g *gate) set(id string, on bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.off == nil {
		g.off = map[string]bool{}
	}
	g.off[id] = !on
}

// box is a database with a run manager, a schedule service and two owners: the vulnerability checks (one schedule, a run each
// time) and exposure targets (one schedule per target).
type box struct {
	t      *testing.T
	db     *store.DB
	clock  *clock
	gate   *gate
	runs   *run.Manager
	svc    *schedule.Service
	window *schedule.Window // the scan window; nil = always open
	fail   error            // the next Start of scan.vuln returns it
	starts []schedule.Fire
}

func newBox(t *testing.T, org string) *box {
	t.Helper()
	b := &box{t: t, db: storetest.NewMigrated(t, "core", coreMigrations), clock: &clock{t: utc("2026-11-20T03:00:00Z")}, gate: &gate{}}
	if org != "" {
		b.exec(`INSERT INTO core_org (id, name, timezone, install_id) VALUES (1, 'Example', ?, 'ins-test')`, org)
	}
	var err error
	if b.runs, err = run.New(run.Config{DB: b.db, Clock: b.clock.Now}); err != nil {
		t.Fatal(err)
	}
	noop := func(context.Context, *run.Exec) (run.Result, error) { return run.Result{}, nil }
	for _, k := range []run.Kind{{Module: "scan", Name: "vuln_check", Lane: "nuclei", Run: noop}, {Module: "exposure", Name: "exposure_scan", Lane: "exposure", Run: noop}} {
		if err := b.runs.Register(k); err != nil {
			t.Fatal(err)
		}
	}
	cfg := schedule.Config{DB: b.db, Clock: b.clock.Now, Gate: b.gate, ScanWindow: func(context.Context) (schedule.Window, error) {
		if b.window == nil {
			return schedule.Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "00:00", To: "00:00"}, nil
		}
		return *b.window, nil
	}}
	if b.svc, err = schedule.New(cfg); err != nil {
		t.Fatal(err)
	}
	startRun := func(module, kind string) func(ctx context.Context, tx *sql.Tx, f schedule.Fire) (string, error) {
		return func(ctx context.Context, tx *sql.Tx, f schedule.Fire) (string, error) {
			b.starts = append(b.starts, f)
			if _, err := tx.ExecContext(ctx, `INSERT INTO core_setting (key, value, updated_at, updated_by) VALUES ('test.started', '1', ?, 'test')
				ON CONFLICT (key) DO UPDATE SET value = value + 1`, store.FormatTS(b.clock.Now())); err != nil {
				return "", err
			}
			if b.fail != nil {
				err := b.fail
				b.fail = nil
				return "", err
			}
			return b.runs.CreateTx(ctx, tx, run.Spec{Module: module, Kind: kind, Title: "Scheduled work", Trigger: f.Trigger, RequestedBy: f.By, ScheduleID: f.ScheduleID})
		}
	}
	must(t, b.svc.Register(schedule.Owner{Module: "scan", Key: "scan.vuln", Default: schedule.DailyAt("02:00").InWindow(), DefaultOn: true, Start: startRun("scan", "vuln_check")}))
	must(t, b.svc.Register(schedule.Owner{
		Module: "exposure", Key: "exposure.target", PerSubject: true, Default: schedule.WeeklyAt("02:30", 1).InWindow(),
		Subject: func(_ context.Context, id string) (bool, error) { return id != "gone", nil },
		Start:   startRun("exposure", "exposure_scan"),
	}))
	must(t, b.svc.Register(schedule.Owner{
		Module: "feeds", Key: "feeds.source", PerSubject: true, AdminOnly: true, Default: schedule.Every(60),
		Limits: schedule.Limits{Freqs: []schedule.Freq{schedule.Interval}, MinEveryMinutes: 60, Reason: "Sources ask clients not to poll more often."},
		Start:  func(context.Context, *sql.Tx, schedule.Fire) (string, error) { return "", nil },
	}))
	return b
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (b *box) exec(q string, args ...any) {
	b.t.Helper()
	if err := b.db.Write(b.t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(b.t.Context(), q, args...); return err }); err != nil {
		b.t.Fatal(err)
	}
}

func (b *box) get(key string) schedule.View {
	b.t.Helper()
	v, err := b.svc.Get(b.t.Context(), key)
	if err != nil {
		b.t.Fatal(err)
	}
	return v
}

func (b *box) save(key string, st schedule.Setting) schedule.View {
	b.t.Helper()
	v, err := b.svc.Save(b.t.Context(), key, st, "ann@example.com")
	if err != nil {
		b.t.Fatal(err)
	}
	return v
}

func (b *box) tick(want int) {
	b.t.Helper()
	n, err := b.svc.Tick(b.t.Context())
	if err != nil {
		b.t.Fatal(err)
	}
	if n != want {
		b.t.Fatalf("tick handled %d schedules, want %d", n, want)
	}
}

// holds checks the stored next due times against Next (the self-check's rule) and the other registered rules of the table.
func (b *box) holds() {
	b.t.Helper()
	for _, inv := range selfcheck.Registered() {
		if !strings.HasPrefix(inv.Name, "schedules.") {
			continue
		}
		res := selfcheck.Run(b.t.Context(), b.db.Reader(), []selfcheck.Invariant{inv})[0]
		if res.Failed() {
			b.t.Fatalf("%s: %d rows break it (%v)", res.Name, res.Count, res.Err)
		}
	}
}

func (b *box) runStatus(id string) (run.Trigger, run.Status, string) {
	b.t.Helper()
	var tr, st string
	var sid sql.NullString
	if err := b.db.Reader().QueryRowContext(b.t.Context(), `SELECT trigger, status, schedule_id FROM core_run WHERE id = ?`, id).Scan(&tr, &st, &sid); err != nil {
		b.t.Fatal(err)
	}
	return run.Trigger(tr), run.Status(st), sid.String
}

func at(ts ...time.Time) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.UTC().Format(time.RFC3339)
	}
	return out
}

func eq(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}

// The preview gives the next three starts of every kind of rule, read in a zone that is not UTC (the organization's, Berlin, or
// the rule's own).
func TestPreviewOfEveryRuleKindInAZone(t *testing.T) {
	b := newBox(t, "Europe/Berlin")
	b.clock.Set("2026-11-20T09:00:00Z") // Friday 10:00 in Berlin
	ny := "America/New_York"
	for _, c := range []struct {
		name string
		rule schedule.Rule
		zone string
		want []string
	}{
		{"every 6 hours", schedule.Every(360), "Europe/Berlin", []string{"2026-11-20T15:00:00Z", "2026-11-20T21:00:00Z", "2026-11-21T03:00:00Z"}},
		{"every 3 days at 02:30", everyDaysAt230(3), "Europe/Berlin", []string{"2026-11-23T01:30:00Z", "2026-11-26T01:30:00Z", "2026-11-29T01:30:00Z"}},
		{"daily at 02:30", schedule.DailyAt("02:30"), "Europe/Berlin", []string{"2026-11-21T01:30:00Z", "2026-11-22T01:30:00Z", "2026-11-23T01:30:00Z"}},
		{"weekly Monday and Thursday at 08:00", schedule.WeeklyAt("08:00", 1, 4), "Europe/Berlin", []string{"2026-11-23T07:00:00Z", "2026-11-26T07:00:00Z", "2026-11-30T07:00:00Z"}},
		{"monthly on the 31st", schedule.MonthlyAt("08:00", 31), "Europe/Berlin", []string{"2026-11-30T07:00:00Z", "2026-12-31T07:00:00Z", "2027-01-31T07:00:00Z"}},
		{"once", once("2026-12-24T18:00:00Z"), "Europe/Berlin", []string{"2026-12-24T18:00:00Z"}},
		{"daily in its own zone", func() schedule.Rule { r := schedule.DailyAt("02:30"); r.TZ = ny; return r }(), ny, []string{"2026-11-21T07:30:00Z", "2026-11-22T07:30:00Z", "2026-11-23T07:30:00Z"}},
		{"every 3 days at 02:30 in a Monday to Friday window", custom(everyDaysAt230(3), "00:00", "00:00", 1, 2, 3, 4, 5), "Europe/Berlin", []string{"2026-11-23T01:30:00Z", "2026-11-26T01:30:00Z", "2026-11-29T23:00:00Z"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, zone, err := b.svc.Preview(t.Context(), "", c.rule, nil)
			if err != nil {
				t.Fatal(err)
			}
			if zone != c.zone {
				t.Errorf("zone %s, want %s", zone, c.zone)
			}
			eq(t, "upcoming", at(got...), c.want)
		})
	}
	// A pause moves the first start past its end.
	got, _, err := b.svc.Preview(t.Context(), "", schedule.DailyAt("02:30"), ptr(utc("2026-11-25T00:00:00Z")))
	must(t, err)
	eq(t, "upcoming after a pause", at(got...), []string{"2026-11-25T01:30:00Z", "2026-11-26T01:30:00Z", "2026-11-27T01:30:00Z"})
	// The scan window moves a start into it.
	b.window = &schedule.Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "22:00", To: "05:00"}
	got, _, err = b.svc.Preview(t.Context(), "", schedule.DailyAt("12:00").InWindow(), nil)
	must(t, err)
	eq(t, "upcoming in the scan window", at(got...), []string{"2026-11-20T21:00:00Z", "2026-11-21T21:00:00Z", "2026-11-22T21:00:00Z"})
	// An owner's limits apply to a preview with its key, with its reason.
	_, _, err = b.svc.Preview(t.Context(), "feeds.source:nvd", schedule.Every(10), nil)
	var re *schedule.RuleError
	if !errors.As(err, &re) || !strings.Contains(re.Message, "Sources ask clients not to poll more often.") {
		t.Fatalf("limited preview: %v", err)
	}
}

// A saved schedule comes due, starts a run in the same transaction, and counts its next due time from the due time.
func TestADueScheduleStartsARun(t *testing.T) {
	b := newBox(t, "")                  // the organization's zone before setup: Ho Chi Minh City
	b.clock.Set("2026-11-20T03:00:00Z") // Friday 10:00 there
	v := b.save("exposure.target:tgt-1", schedule.Setting{Enabled: true, Rule: schedule.DailyAt("23:00")})
	if !v.Saved || v.Zone != "Asia/Ho_Chi_Minh" || v.NextDueAt == nil || !v.NextDueAt.Equal(utc("2026-11-20T16:00:00Z")) {
		t.Fatalf("saved %+v", v)
	}
	eq(t, "upcoming", at(v.Upcoming...), []string{"2026-11-20T16:00:00Z", "2026-11-21T16:00:00Z", "2026-11-22T16:00:00Z"})
	b.holds()
	b.tick(0)
	b.clock.Set("2026-11-20T16:00:20Z")
	b.tick(1)
	v = b.get("exposure.target:tgt-1")
	if v.LastRunID == nil || v.LastSkipReason != nil || !v.LastDueAt.Equal(utc("2026-11-20T16:00:00Z")) || !v.NextDueAt.Equal(utc("2026-11-21T16:00:00Z")) {
		t.Fatalf("after the due time %+v", v)
	}
	tr, st, sid := b.runStatus(*v.LastRunID)
	if tr != run.Schedule || st != run.Queued || sid == "" {
		t.Fatalf("run %s %s %q", tr, st, sid)
	}
	if f := b.starts[0]; f.Subject != "tgt-1" || f.By != run.System || !f.DueAt.Equal(utc("2026-11-20T16:00:00Z")) {
		t.Fatalf("fire %+v", f)
	}
	b.holds()

	// The next day the run has not ended: the due time is skipped with the reason, and the schedule goes on.
	b.clock.Set("2026-11-21T16:00:05Z")
	b.tick(1)
	v = b.get("exposure.target:tgt-1")
	if v.LastSkipReason == nil || !strings.Contains(*v.LastSkipReason, "had not ended") || !v.NextDueAt.Equal(utc("2026-11-22T16:00:00Z")) || len(b.starts) != 1 {
		t.Fatalf("skipped %+v", v)
	}
	b.holds()

	// Once the run ended, the next due time starts a new one and clears the reason.
	b.exec(`UPDATE core_run SET status = 'done', ended_at = started_at WHERE id = ?`, *v.LastRunID)
	b.exec(`UPDATE core_run SET started_at = queued_at, ended_at = queued_at WHERE id = ?`, *v.LastRunID)
	b.clock.Set("2026-11-22T16:00:00Z")
	b.tick(1)
	v = b.get("exposure.target:tgt-1")
	if v.LastSkipReason != nil || len(b.starts) != 2 {
		t.Fatalf("after the run ended %+v", v)
	}
	b.holds()
}

// A box that was off for days starts the missed schedule once; the next run is the next asked time (the hour), not an hour after
// the late start.
func TestMissedDueTimesStartOneRun(t *testing.T) {
	b := newBox(t, "")
	b.save("scan.vuln", schedule.Setting{Enabled: true, Rule: schedule.Every(60)}) // due 04:00
	b.clock.Set("2026-11-23T07:12:00Z")
	b.tick(1)
	b.tick(0)
	v := b.get("scan.vuln")
	if !v.LastDueAt.Equal(utc("2026-11-23T07:12:00Z")) || !v.NextDueAt.Equal(utc("2026-11-23T08:00:00Z")) || len(b.starts) != 1 {
		t.Fatalf("after the missed due times %+v (starts %d)", v, len(b.starts))
	}
	b.holds()
}

// A schedule in the scan window is held while it is closed and starts when it opens; the view says what it waits for.
func TestTheScanWindowHoldsADueSchedule(t *testing.T) {
	b := newBox(t, "")
	b.window = &schedule.Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "22:00", To: "05:00"}
	b.save("scan.vuln", schedule.Setting{Enabled: true, Rule: schedule.DailyAt("12:00").InWindow()}) // due Friday 12:00 local = 05:00Z
	b.clock.Set("2026-11-20T05:00:00Z")
	b.tick(0)
	v := b.get("scan.vuln")
	if v.WaitingFor == nil || len(v.Upcoming) != 3 || !v.Upcoming[0].Equal(utc("2026-11-20T15:00:00Z")) {
		t.Fatalf("held %+v", v)
	}
	b.clock.Set("2026-11-20T15:00:10Z") // 22:00:10 local: the window opened
	b.tick(1)
	v = b.get("scan.vuln")
	if v.WaitingFor != nil || !v.LastDueAt.Equal(utc("2026-11-20T15:00:10Z")) || !v.NextDueAt.Equal(utc("2026-11-21T05:00:00Z")) {
		t.Fatalf("started in the window %+v", v)
	}
	b.holds()
}

// A schedule of a module that is off skips its due time; an owner's Skip and a failed start are recorded, and a failed start
// leaves none of its writes.
func TestSkippedDueTimesSayWhy(t *testing.T) {
	b := newBox(t, "")
	b.save("scan.vuln", schedule.Setting{Enabled: true, Rule: schedule.Every(60)})
	b.gate.set("scan", false)
	b.clock.Set("2026-11-20T04:00:00Z")
	b.tick(1)
	if v := b.get("scan.vuln"); v.LastSkipReason == nil || *v.LastSkipReason != "Its module is off." || len(b.starts) != 0 {
		t.Fatalf("module off %+v", v)
	}
	b.gate.set("scan", true)

	b.fail = schedule.Skip("Scanning is off.")
	b.clock.Set("2026-11-20T05:00:00Z")
	b.tick(1)
	if v := b.get("scan.vuln"); v.LastSkipReason == nil || *v.LastSkipReason != "Scanning is off." {
		t.Fatalf("owner skip %+v", v)
	}

	b.fail = errors.New("disk full")
	b.clock.Set("2026-11-20T06:00:00Z")
	b.tick(1)
	if v := b.get("scan.vuln"); v.LastSkipReason == nil || !strings.Contains(*v.LastSkipReason, "could not start") {
		t.Fatalf("failed start %+v", v)
	}
	var n int
	if err := b.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM core_setting WHERE key = 'test.started'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the failed starts left their writes: %d %v", n, err)
	}
	b.holds()
}

// Run once now starts the work with the person as who asked, and leaves the next due time alone; a second one while the first
// has not ended is refused.
func TestRunOnceNow(t *testing.T) {
	b := newBox(t, "")
	v := b.save("exposure.target:tgt-1", schedule.Setting{Enabled: true, Rule: schedule.WeeklyAt("02:30", 1)})
	id, err := b.svc.RunNow(t.Context(), "exposure.target:tgt-1", "ann@example.com")
	must(t, err)
	tr, st, _ := b.runStatus(id)
	after := b.get("exposure.target:tgt-1")
	if tr != run.Manual || st != run.Queued || after.LastRunID == nil || *after.LastRunID != id || !after.NextDueAt.Equal(*v.NextDueAt) || after.LastDueAt != nil {
		t.Fatalf("run once: %s %s %+v", tr, st, after)
	}
	if b.starts[0].By != "ann@example.com" {
		t.Fatalf("by %q", b.starts[0].By)
	}
	if _, err := b.svc.RunNow(t.Context(), "exposure.target:tgt-1", "ann@example.com"); !errors.Is(err, schedule.ErrBusy) {
		t.Fatalf("second run once: %v", err)
	}
	b.gate.set("feeds", false)
	var sk *schedule.SkipError
	if _, err := b.svc.RunNow(t.Context(), "feeds.source:nvd", "ann@example.com"); !errors.As(err, &sk) {
		t.Fatalf("module off: %v", err)
	}
	b.holds()
}

// Pause, off and a change of the rule: the next due time follows each, and the stored value always equals Next.
func TestPauseOffAndChanges(t *testing.T) {
	b := newBox(t, "")
	key := "exposure.target:tgt-1"
	v := b.save(key, schedule.Setting{Enabled: true, PausedUntil: ptr(utc("2026-11-25T00:00:00Z")), Rule: schedule.DailyAt("02:30")})
	if !v.NextDueAt.Equal(utc("2026-11-25T19:30:00Z")) || v.PausedUntil == nil {
		t.Fatalf("paused %+v", v)
	}
	b.holds()
	v = b.save(key, schedule.Setting{Enabled: false, Rule: schedule.DailyAt("02:30")})
	if v.NextDueAt != nil || len(v.Upcoming) != 0 {
		t.Fatalf("off %+v", v)
	}
	b.holds()
	b.clock.Set("2026-11-21T00:00:00Z")
	v = b.save(key, schedule.Setting{Enabled: true, PausedUntil: ptr(utc("2026-11-20T00:00:00Z")), Rule: schedule.Every(120)})
	if v.PausedUntil != nil || !v.NextDueAt.Equal(utc("2026-11-21T02:00:00Z")) {
		t.Fatalf("a pause in the past is no pause %+v", v)
	}
	b.holds()
	// A broken row is found by the self-check.
	b.exec(`UPDATE core_schedule SET next_due_at = '2026-11-21T02:00:01.000Z'`)
	if n, err := schedule.NextDueMismatches(t.Context(), b.db.Reader()); err != nil || n != 1 {
		t.Fatalf("mismatches %d %v", n, err)
	}
}

// The organization's zone changes: the rules in tz "org" move with it once Recompute runs in the same transaction.
func TestAZoneChangeMovesTheOrgRules(t *testing.T) {
	b := newBox(t, "Asia/Ho_Chi_Minh")
	b.save("scan.vuln", schedule.Setting{Enabled: true, Rule: schedule.DailyAt("02:30")})
	own := schedule.DailyAt("02:30")
	own.TZ = "Asia/Ho_Chi_Minh"
	b.save("exposure.target:tgt-1", schedule.Setting{Enabled: true, Rule: own})
	b.exec(`UPDATE core_org SET timezone = 'Europe/Berlin'`)
	if n, _ := schedule.NextDueMismatches(t.Context(), b.db.Reader()); n != 1 {
		t.Fatalf("before recompute: %d mismatches, want 1 (the org rule)", n)
	}
	must(t, b.db.Write(t.Context(), func(tx *sql.Tx) error { _, err := schedule.Recompute(t.Context(), tx); return err }))
	b.holds()
	if v := b.get("scan.vuln"); v.Zone != "Europe/Berlin" || !v.NextDueAt.Equal(utc("2026-11-21T01:30:00Z")) {
		t.Fatalf("after the change %+v", v)
	}
}

func TestOwnersKeysAndLimits(t *testing.T) {
	b := newBox(t, "")
	for _, key := range []string{"scan.unknown", "exposure.target", "exposure.target:gone", "scan.vuln:x", "Exposure.target:x", "exposure.target:a b"} {
		if _, err := b.svc.Get(t.Context(), key); !errors.Is(err, schedule.ErrUnknownOwner) {
			t.Errorf("%s: %v", key, err)
		}
	}
	// Before anyone saves one: the owner's default, not saved.
	v := b.get("exposure.target:tgt-9")
	if v.Saved || v.Enabled || v.Rule.Freq != schedule.Weekly || v.Rule.Window != schedule.WindowGlobal || v.EditRole != "operator" {
		t.Fatalf("default %+v", v)
	}
	if v := b.get("feeds.source:nvd"); v.EditRole != "admin" || v.Limits.MinEveryMinutes != 60 || len(v.Limits.Freqs) != 1 {
		t.Fatalf("limits %+v", v)
	}
	_, err := b.svc.Save(t.Context(), "feeds.source:nvd", schedule.Setting{Enabled: true, Rule: schedule.Every(10)}, "ann@example.com")
	var re *schedule.RuleError
	if !errors.As(err, &re) || re.Field != "every_minutes" {
		t.Fatalf("limited save: %v", err)
	}
	// Start saves the defaults that are on, once.
	must(t, b.svc.Start(t.Context()))
	defer b.svc.Close()
	if v := b.get("scan.vuln"); !v.Saved || !v.Enabled || v.UpdatedBy == nil || *v.UpdatedBy != run.System {
		t.Fatalf("default saved at start %+v", v)
	}
	b.holds()
	// The owner deletes its subject: the schedule goes, its runs stay.
	b.save("exposure.target:tgt-1", schedule.Setting{Enabled: true, Rule: schedule.Every(60)})
	id, err := b.svc.RunNow(t.Context(), "exposure.target:tgt-1", "ann@example.com")
	must(t, err)
	must(t, b.db.Write(t.Context(), func(tx *sql.Tx) error { return schedule.DeleteTx(t.Context(), tx, "exposure.target:tgt-1") }))
	if v := b.get("exposure.target:tgt-1"); v.Saved {
		t.Fatalf("still saved %+v", v)
	}
	b.runStatus(id)
}

// Review cases: a late start gives way to a regular time just after it; a paused interval starts at the end of the pause; a
// once time in the past is refused; a pause that has ended is not shown.
func TestLateStartsPausesAndPastOnceTimes(t *testing.T) {
	b := newBox(t, "")
	// Daily 02:00 (19:00Z), missed: the box comes back at 01:59 the next night.
	b.save("scan.vuln", schedule.Setting{Enabled: true, Rule: schedule.DailyAt("02:00")}) // due 2026-11-20T19:00Z
	b.clock.Set("2026-11-21T18:59:00Z")
	b.tick(1)
	v := b.get("scan.vuln")
	if len(b.starts) != 0 || v.LastSkipReason != nil || !v.NextDueAt.Equal(utc("2026-11-21T19:00:00Z")) {
		t.Fatalf("late start merged %+v (starts %d)", v, len(b.starts))
	}
	b.holds()
	b.clock.Set("2026-11-21T19:00:00Z")
	b.tick(1)
	if len(b.starts) != 1 {
		t.Fatalf("starts %d, want 1", len(b.starts))
	}
	b.holds()

	// Every 7 days, paused until Monday 00:00 local (Sunday 17:00Z): the first run is at the end of the pause.
	v = b.save("exposure.target:tgt-1", schedule.Setting{Enabled: true, PausedUntil: ptr(utc("2026-11-22T17:00:00Z")), Rule: schedule.Every(7 * schedule.MinuteOfDay)})
	if !v.NextDueAt.Equal(utc("2026-11-22T17:00:00Z")) {
		t.Fatalf("paused interval %+v", v)
	}
	b.holds()
	b.clock.Set("2026-11-22T17:00:30Z")
	b.tick(1)
	v = b.get("exposure.target:tgt-1")
	if v.PausedUntil != nil || !v.NextDueAt.Equal(utc("2026-11-29T17:00:00Z")) {
		t.Fatalf("after the pause %+v", v)
	}
	b.holds()

	// A once time in the past is refused, saved on or previewed.
	past := schedule.Rule{Freq: schedule.Once, OnceAt: ptr(utc("2026-11-01T00:00:00Z"))}
	var re *schedule.RuleError
	if _, err := b.svc.Save(t.Context(), "exposure.target:tgt-2", schedule.Setting{Enabled: true, Rule: past}, "ann@example.com"); !errors.As(err, &re) || re.Field != "once_at" {
		t.Fatalf("past once saved: %v", err)
	}
	if _, _, err := b.svc.Preview(t.Context(), "", past, nil); !errors.As(err, &re) || re.Field != "once_at" {
		t.Fatalf("past once previewed: %v", err)
	}
}
