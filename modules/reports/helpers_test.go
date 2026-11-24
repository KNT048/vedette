package reports

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// 2026-11-11 is a Wednesday.
var t0 = time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)

type fakeInv struct{ devs []Device }

func (f *fakeInv) Devices(context.Context) ([]Device, error) { return f.devs, nil }

type fakeFindings struct {
	fs  []Finding
	err error
}

func (f *fakeFindings) All(context.Context) ([]Finding, error) { return f.fs, f.err }

type fakeViews struct {
	vs      []FindingView
	reasons map[string][]Reason
	err     error
	asked   []string
}

func (f *fakeViews) Views(context.Context) ([]FindingView, error) { return f.vs, f.err }
func (f *fakeViews) Reasons(_ context.Context, ids []string) (map[string][]Reason, error) {
	f.asked = append(f.asked, ids...)
	out := map[string][]Reason{}
	for _, id := range ids {
		if r, ok := f.reasons[id]; ok {
			out[id] = r
		}
	}
	return out, nil
}

type fakeKEV struct{ es []KEVEntry }

func (f *fakeKEV) Entries(context.Context) ([]KEVEntry, error) { return f.es, nil }

type fakeExposure struct {
	ts       []ExposureTarget
	from, to time.Time
}

func (f *fakeExposure) Targets(_ context.Context, from, to time.Time) ([]ExposureTarget, error) {
	f.from, f.to = from, to
	return f.ts, nil
}

type fakeDetections struct {
	counts []DetectionCount
	top    []Detection
}

func (f *fakeDetections) Period(context.Context, time.Time, time.Time, int) ([]DetectionCount, []Detection, error) {
	return f.counts, f.top, nil
}

type fakeFeeds struct{ hs []FeedHealth }

func (f *fakeFeeds) Health(context.Context) ([]FeedHealth, error) { return f.hs, nil }

type fakeMail struct {
	mu    sync.Mutex
	ready bool
	err   error
	sent  []sentMail
}
type sentMail struct {
	to []string
	m  Mail
}

func (f *fakeMail) Ready(context.Context) (bool, string) { return f.ready, "not ready" }
func (f *fakeMail) Send(_ context.Context, to []string, m Mail) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, sentMail{append([]string(nil), to...), m})
	return nil
}
func (f *fakeMail) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.sent) }

type fakeAI struct {
	on    bool
	err   error
	calls []string
	data  [][]Block
}

func (f *fakeAI) Available(string) bool { return f.on }
func (f *fakeAI) Summarize(_ context.Context, _, job, _ string, data []Block) (Summary, error) {
	f.calls = append(f.calls, job)
	f.data = append(f.data, data)
	if f.err != nil {
		return Summary{}, f.err
	}
	return Summary{Paragraphs: []string{"Commentary."}, Model: "m", Profile: "p", TokensIn: 10, TokensOut: 5}, nil
}

type fakeMods map[string]bool

func (f fakeMods) Enabled(id string) bool { return f[id] }

type clockT struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clockT) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clockT) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type env struct {
	t     *testing.T
	db    *store.DB
	svc   *Service
	clock *clockT
	every string // how often the schedule sends the report while it is on; "" off
	inv   *fakeInv
	fnd   *fakeFindings
	views *fakeViews
	kev   *fakeKEV
	exp   *fakeExposure
	det   *fakeDetections
	feeds *fakeFeeds
	mail  *fakeMail
	ai    *fakeAI
	mods  fakeMods
}

func newDB(t *testing.T) *store.DB {
	t.Helper()
	db := storetest.New(t)
	for _, m := range []storetest.Migration{{Module: "core", FS: core.Migrations}, {Module: "reports", FS: Migrations}} {
		if err := store.Migrate(t.Context(), db, m.Module, m.FS); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// allModules is every module the report reads, on.
func allModules() fakeMods {
	return fakeMods{"feeds": true, "notify": true, "exposure": true, "honeypot": true, "logs": true, "sensor-passive": true, "sensor-active": true,
		"agent-intake": true, "ids": false, "scan": true}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, db: newDB(t), clock: &clockT{now: t0}, inv: &fakeInv{}, fnd: &fakeFindings{}, views: &fakeViews{}, kev: &fakeKEV{},
		exp: &fakeExposure{}, det: &fakeDetections{}, feeds: &fakeFeeds{}, mail: &fakeMail{ready: true}, ai: &fakeAI{on: true}, mods: allModules()}
	svc, err := NewService(Config{DB: e.db, Audit: audit.New(e.clock.Now), Inventory: e.inv, Findings: e.fnd, Views: e.views, KEV: e.kev,
		Exposure: e.exp, Detections: e.det, Feeds: e.feeds, Mail: e.mail, AI: e.ai, Modules: e.mods,
		OrgName: func(context.Context) (string, error) { return "Acme Ltd", nil }, Zone: func(context.Context) string { return "UTC" },
		Every: func(context.Context) string { return e.every },
		Log:   slog.New(slog.DiscardHandler), Clock: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

// seed fills every port with the fixtures: the network of the golden report and the PDPL sample.
func (e *env) seed() {
	f := fixture()
	e.inv.devs, e.views.vs, e.views.reasons = f.devices, f.views, f.reasons
	e.exp.ts, e.det.counts, e.det.top, e.feeds.hs = f.targets, f.counts, f.top, f.feeds
	p := pdplSample()
	e.fnd.fs, e.kev.es = p.findings, p.kev
}

func (e *env) ctx() context.Context { return e.t.Context() }

func (e *env) count(query string) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.ctx(), query).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) auditActions() []string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT action FROM core_audit ORDER BY seq`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

// saveRecipients saves the definition with these recipients and the other fields as they are.
func (e *env) saveRecipients(to ...string) {
	e.t.Helper()
	d, err := e.svc.Definition(e.ctx())
	mustNoErr(e.t, err)
	_, err = e.svc.SaveDefinition(e.ctx(), "admin@acme.example", DefinitionInput{Name: d.Name, Options: d.Options, Recipients: to})
	mustNoErr(e.t, err)
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

var errBoom = errors.New("boom")
