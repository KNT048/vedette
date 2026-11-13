package findings

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

type fakeInv struct {
	mu     sync.Mutex
	assets map[string]AssetView
	match  map[string]Asset
	idsErr error
}

func (f *fakeInv) Assets(_ context.Context, ids []string) (map[string]AssetView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]AssetView{}
	for _, id := range ids {
		if a, ok := f.assets[id]; ok {
			out[id] = a
		}
	}
	return out, nil
}

func (f *fakeInv) MatchInput(_ context.Context, id string) (Asset, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.match[id]
	return a, ok, nil
}

// AssetIDs lists the devices that exist: the ones the matcher can read. idsErr makes the read fail.
func (f *fakeInv) AssetIDs(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.idsErr != nil {
		return nil, f.idsErr
	}
	return slices.Sorted(maps.Keys(f.match)), nil
}

type fakeFeeds struct {
	kev   map[string]KevInfo
	vulns []Vuln
}

func (f *fakeFeeds) KevInfo(_ context.Context, cves []string) (map[string]KevInfo, error) {
	out := map[string]KevInfo{}
	for _, c := range cves {
		if k, ok := f.kev[c]; ok {
			out[c] = k
		}
	}
	return out, nil
}

func (f *fakeFeeds) Vulns(context.Context) ([]Vuln, error) { return f.vulns, nil }

type published struct {
	Name    string
	Payload any
}

type fakePub struct {
	mu     sync.Mutex
	events []published
}

func (p *fakePub) Publish(_ context.Context, name string, payload any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, published{name, payload})
	return nil
}

func (p *fakePub) take() []published {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.events
	p.events = nil
	return out
}

// env is a real database with core and findings migrated, the service on it and fakes for the rest.
type env struct {
	t     *testing.T
	db    *store.DB
	svc   *Service
	inv   *fakeInv
	feeds *fakeFeeds
	pub   *fakePub
	clock *time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := storetest.New(t)
	for _, m := range []storetest.Migration{{Module: "core", FS: core.Migrations}, {Module: "findings", FS: Migrations}} {
		if err := store.Migrate(t.Context(), db, m.Module, m.FS); err != nil {
			t.Fatal(err)
		}
	}
	e := &env{t: t, db: db, pub: &fakePub{}, clock: new(time.Time)}
	*e.clock = t0
	e.inv = &fakeInv{
		assets: map[string]AssetView{"a-1": {ID: "a-1", Hostname: ptr("nas01"), IP: "192.168.10.21", Kind: "nas", Display: "Photo Station"}},
		match:  map[string]Asset{"a-1": nas("6.1.1")},
	}
	e.feeds = &fakeFeeds{
		kev:   map[string]KevInfo{"CVE-2022-27593": {Name: "QNAP Photo Station External Reference", Vendor: "QNAP", Product: "Photo Station", RequiredAction: "Apply updates.", Links: []string{"https://example.test/a"}, DateAdded: "2022-09-01", Ransomware: true}},
		vulns: []Vuln{qnapVuln()},
	}
	svc, err := NewService(ServiceConfig{DB: db, Audit: audit.New(func() time.Time { return *e.clock }), Publisher: e.pub, Inventory: e.inv, Feeds: e.feeds, Log: slog.New(slog.DiscardHandler), Clock: func() time.Time { return *e.clock }})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

func ptr[T any](v T) *T { return &v }

func (e *env) advance(d time.Duration) { *e.clock = e.clock.Add(d) }

func (e *env) count(query string) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.t.Context(), query).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) auditActions() []string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.t.Context(), `SELECT action FROM core_audit ORDER BY seq`)
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

// seed matches the default device once and returns the id of the one finding.
func (e *env) seed() string {
	e.t.Helper()
	res, err := e.svc.OnMatchChanged(e.t.Context(), "a-1")
	if err != nil || len(res.Created) != 1 {
		e.t.Fatalf("seed: %+v %v", res, err)
	}
	e.pub.take()
	return res.Created[0]
}

func TestContract_POST1_UpsertCreatesFindingWithHistoryAuditAndEvent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	res, err := e.svc.OnMatchChanged(t.Context(), "a-1")
	if err != nil || len(res.Created) != 1 || res.Touched != 0 {
		t.Fatalf("result = %+v err=%v", res, err)
	}
	r, err := e.svc.Get(t.Context(), res.Created[0])
	if err != nil {
		t.Fatal(err)
	}
	if r.AssetID != "a-1" || r.CVE != "CVE-2022-27593" || r.Status != StatusSuspected || r.Basis != BasisProduct || r.Confidence != 0.5 || r.Severity != SeverityMedium {
		t.Fatalf("finding = %+v", r)
	}
	if !r.FirstSeen.Equal(t0) || !r.LastSeen.Equal(t0) || len(r.History) != 1 || r.History[0].Action != "created" || r.History[0].User != SystemUser {
		t.Fatalf("times/history = %v %v %+v", r.FirstSeen, r.LastSeen, r.History)
	}
	if r.Evidence == nil || r.Evidence.Summary == "" {
		t.Fatalf("evidence = %+v", r.Evidence)
	}
	ev := e.pub.take()
	if len(ev) != 1 || ev[0].Name != EventCreated || ev[0].Payload != (CreatedEvent{FindingID: r.ID, AssetID: "a-1", CVE: r.CVE, Severity: SeverityMedium, Basis: BasisProduct}) {
		t.Fatalf("events = %+v", ev)
	}
	if got := e.auditActions(); len(got) != 1 || got[0] != "findings.created" {
		t.Fatalf("audit = %v", got)
	}
}

func TestOnMatchChangedUnknownAsset(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.svc.OnMatchChanged(t.Context(), "a-404"); !errors.Is(err, ErrUnknownAsset) {
		t.Fatalf("err = %v", err)
	}
}

func TestContract_INV2_UpsertRaisesBasisOfOpenFindingOnly(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	e.advance(time.Hour)
	// the feed now knows the affected range and the device is inside it
	a := nas("6.1.1")
	vuln := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.2"}})
	res, err := e.svc.UpsertFromMatch(t.Context(), a, []Vuln{vuln})
	if err != nil || len(res.Created) != 0 || res.Touched != 1 {
		t.Fatalf("result = %+v err=%v", res, err)
	}
	r, _ := e.svc.Get(t.Context(), id)
	if r.Basis != BasisVersion || r.Confidence != ConfVersion || r.Status != StatusSuspected || !r.LastSeen.Equal(t0.Add(time.Hour)) || !r.FirstSeen.Equal(t0) {
		t.Fatalf("finding = %+v", r)
	}
	if got := e.auditActions(); len(got) != 2 || got[1] != "findings.basis_raised" {
		t.Fatalf("audit = %v", got)
	}
	// a repeated match never publishes created (POST-1); the raise to high goes out as status_changed (review H2)
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Name != EventStatusChanged || ev[0].Payload.(StatusChangedEvent).Severity != SeverityHigh {
		t.Fatalf("events = %+v", ev)
	}
}

func TestContract_INV6_UpsertIsIdempotentAndNeverReopens(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	if _, err := e.svc.SetStatus(t.Context(), id, ActionPatched, "updated", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	for range 3 {
		res, err := e.svc.OnMatchChanged(t.Context(), "a-1")
		if err != nil || len(res.Created) != 0 || res.Touched != 1 {
			t.Fatalf("result = %+v err=%v", res, err)
		}
	}
	r, _ := e.svc.Get(t.Context(), id)
	if r.Status != StatusPatched || len(r.History) != 2 {
		t.Fatalf("a closed finding was changed: %+v", r)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding`); n != 1 {
		t.Fatalf("findings = %d", n)
	}
	if len(e.pub.take()) != 0 {
		t.Fatal("no event expected")
	}
}

func TestContract_INV3_SetStatusWritesHistoryAuditAndEvent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	e.advance(time.Minute)
	r, err := e.svc.SetStatus(t.Context(), id, ActionFalsePositive, "  lab box  ", "it@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusFalsePositive || r.ResolvedBy != "it@acme.example" || r.ResolutionNote != "lab box" || !r.ResolvedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("finding = %+v", r)
	}
	if h := r.History[len(r.History)-1]; h.Action != "false_positive" || h.Note != "lab box" || h.User != "it@acme.example" {
		t.Fatalf("history = %+v", r.History)
	}
	ev := e.pub.take()
	if len(ev) != 1 || ev[0].Name != EventStatusChanged || ev[0].Payload != (StatusChangedEvent{FindingID: id, From: StatusSuspected, To: StatusFalsePositive}) {
		t.Fatalf("events = %+v", ev)
	}
	// reopen goes back to suspected (basis product)
	r, err = e.svc.SetStatus(t.Context(), id, ActionReopen, "", "it@acme.example")
	if err != nil || r.Status != StatusSuspected || r.ResolvedBy != "" || !r.ResolvedAt.IsZero() || r.ResolutionNote != "" {
		t.Fatalf("reopen = %+v err=%v", r, err)
	}
	if got := e.auditActions(); len(got) != 3 || got[1] != "findings.status" || got[2] != "findings.status" {
		t.Fatalf("audit = %v", got)
	}
}

func TestContract_INV3_SetStatusErrorsChangeNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	before := e.count(`SELECT count(*) FROM core_audit`)
	for _, c := range []struct {
		name   string
		id     string
		action Action
		note   string
		want   *APIError
	}{
		{"unknown id", "f-nope", ActionPatched, "", ErrNotFound},
		{"bad action", id, Action("explode"), "", ErrBadAction},
		{"long note", id, ActionPatched, string(make([]rune, 501)) + "x", ErrNoteTooLong},
		{"note required fp", id, ActionFalsePositive, "ab", ErrNoteRequired},
		{"note required nr", id, ActionNotRelevant, "   ", ErrNoteRequired},
		{"already open", id, ActionReopen, "", ErrAlreadyOpen},
	} {
		_, err := e.svc.SetStatus(t.Context(), c.id, c.action, c.note, "it@acme.example")
		var ae *APIError
		if !errors.As(err, &ae) || ae != c.want {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	r, _ := e.svc.Get(t.Context(), id)
	if r.Status != StatusSuspected || len(r.History) != 1 || e.count(`SELECT count(*) FROM core_audit`) != before || len(e.pub.take()) != 0 {
		t.Fatalf("something changed: %+v", r)
	}
}

func scanEv(template string) Evidence {
	return Evidence{Summary: "matched", Template: template, Request: "GET /photo/", Response: "200", CheckedAt: t0.Add(time.Hour)}
}

func TestContract_POST2_ConfirmFromScan(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	e.advance(time.Hour)
	r, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", scanEv("t1"))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != id || r.Status != StatusConfirmed || r.Basis != BasisScan || r.Confidence != ConfScan || r.Evidence.Template != "t1" {
		t.Fatalf("finding = %+v", r)
	}
	if h := r.History[len(r.History)-1]; h.Action != "confirmed" || h.User != SystemUser {
		t.Fatalf("history = %+v", r.History)
	}
	ev := e.pub.take()
	if len(ev) != 1 || ev[0].Payload != (StatusChangedEvent{FindingID: id, From: StatusSuspected, To: StatusConfirmed}) {
		t.Fatalf("events = %+v", ev)
	}
	// a second confirmation of an already confirmed finding is a "rescanned" row and no event
	if r, err = e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", scanEv("t1")); err != nil || r.History[len(r.History)-1].Action != "rescanned" || len(e.pub.take()) != 0 {
		t.Fatalf("rescan = %+v err=%v", r.History, err)
	}
}

func TestContract_POST2_ConfirmFromScanKeepsPersonsDecisionAndSignalsOncePerTemplate(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	if _, err := e.svc.SetStatus(t.Context(), id, ActionFalsePositive, "lab box", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	for i, want := range []int{1, 0, 1} { // same template twice, then a new one
		tmpl := "t1"
		if i == 2 {
			tmpl = "t2"
		}
		r, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", scanEv(tmpl))
		if err != nil || r.Status != StatusFalsePositive || r.Basis != BasisScan {
			t.Fatalf("round %d: %+v err=%v", i, r, err)
		}
		ev := e.pub.take()
		if len(ev) != want {
			t.Fatalf("round %d: events = %+v", i, ev)
		}
		if want == 1 && ev[0].Payload != (StatusChangedEvent{FindingID: id, From: StatusFalsePositive, To: StatusFalsePositive}) {
			t.Fatalf("round %d: payload = %+v", i, ev[0].Payload)
		}
	}
}

func TestContract_POST2_ConfirmFromScanReopensPatched(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	if _, err := e.svc.SetStatus(t.Context(), id, ActionPatched, "", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	r, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", scanEv("t1"))
	if err != nil || r.Status != StatusConfirmed || r.ResolvedBy != "" {
		t.Fatalf("finding = %+v err=%v", r, err)
	}
	if h := r.History[len(r.History)-1]; h.Action != "reopened" {
		t.Fatalf("history = %+v", r.History)
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Payload != (StatusChangedEvent{FindingID: id, From: StatusPatched, To: StatusConfirmed}) {
		t.Fatalf("events = %+v", ev)
	}
}

func TestConfirmFromScanRefusals(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "not-a-cve", scanEv("t")); !errors.Is(err, ErrInvalidCVE) {
		t.Errorf("bad cve: %v", err)
	}
	if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2020-0001", scanEv("t")); !errors.Is(err, ErrNotFound) {
		t.Errorf("no finding: %v", err)
	}
	if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", Evidence{CheckedAt: t0}); !errors.Is(err, ErrInvalidEvidence) {
		t.Errorf("no template: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE status = 'confirmed'`); n != 0 {
		t.Errorf("confirmed rows = %d", n)
	}
}

func TestContract_POST2_RescanClearOnlyWritesHistory(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", scanEv("t1")); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	if err := e.svc.RescanClear(t.Context(), "a-1", "CVE-2022-27593"); err != nil {
		t.Fatal(err)
	}
	r, _ := e.svc.Get(t.Context(), id)
	if r.Status != StatusConfirmed || r.History[len(r.History)-1].Action != "rescan_clear" || len(e.pub.take()) != 0 {
		t.Fatalf("finding = %+v", r)
	}
}

func TestContract_INV7_OnAssetDeletedRemovesFindingsAndHistory(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	other := Asset{ID: "a-2", Name: "nas02", Software: nas("6.1.1").Software}
	if _, err := e.svc.UpsertFromMatch(t.Context(), other, e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	n, err := e.svc.OnAssetDeleted(t.Context(), "a-1")
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-1'`) != 0 || e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-2'`) != 1 {
		t.Fatal("wrong findings removed")
	}
	if e.count(`SELECT count(*) FROM fnd_finding_history`) != 1 {
		t.Fatal("history of the deleted findings is still there")
	}
	if got := e.auditActions(); got[len(got)-1] != "findings.deleted_with_asset" {
		t.Fatalf("audit = %v", got)
	}
	// deleting again changes nothing and writes no audit row
	before := e.count(`SELECT count(*) FROM core_audit`)
	if n, err := e.svc.OnAssetDeleted(t.Context(), "a-1"); err != nil || n != 0 || e.count(`SELECT count(*) FROM core_audit`) != before {
		t.Fatalf("second delete: n=%d err=%v", n, err)
	}
}

func TestContract_INV1_DatabaseRefusesWhatTheLibraryNeverBuilds(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	ts := store.FormatTS(t0)
	insert := func(status, basis string, evidence any, cve string) error {
		return e.db.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(t.Context(), `INSERT INTO fnd_finding (id, asset_id, cve, status, severity, confidence, basis, evidence, first_seen, last_seen)
				VALUES (?, 'a-9', ?, ?, 'high', 0.5, ?, ?, ?, ?)`, store.NewID("f"), cve, status, basis, evidence, ts, ts)
			return err
		})
	}
	if err := insert("confirmed", "version", `{"summary":"x","checked_at":"`+ts+`"}`, "CVE-2022-0001"); err == nil {
		t.Error("confirmed with basis version accepted")
	}
	if err := insert("confirmed", "scan", nil, "CVE-2022-0002"); err == nil {
		t.Error("confirmed without evidence accepted")
	}
	if err := insert("suspected", "product", nil, "CVE-2022-0003; DROP"); err == nil {
		t.Error("malformed cve accepted")
	}
	if err := insert("suspected", "product", nil, "CVE-2022-27593"); err != nil {
		t.Errorf("valid row refused: %v", err)
	}
	// UNIQUE(asset_id, cve)
	err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO fnd_finding (id, asset_id, cve, status, severity, confidence, basis, first_seen, last_seen)
			VALUES ('f-dup', 'a-1', 'CVE-2022-27593', 'suspected', 'high', 0.5, 'product', ?, ?)`, ts, ts)
		return err
	})
	if err == nil {
		t.Error("a second finding for the same pair was accepted")
	}
	// the history is append-only
	err = e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE fnd_finding_history SET note = 'rewritten'`)
		return err
	})
	if err == nil {
		t.Error("history row was updated")
	}
}

func TestMigrationsUsePrefix(t *testing.T) {
	t.Parallel()
	storetest.AssertMigrationsUsePrefix(t, "findings", Migrations, "fnd_", storetest.Migration{Module: "core", FS: core.Migrations})
}

// ctxPub cancels the caller's context when the first event goes out, like a client that hangs up
// right after the commit, and records the state of the context each event arrived with.
type ctxPub struct {
	cancel context.CancelFunc
	names  []string
	errs   []error
}

func (p *ctxPub) Publish(ctx context.Context, name string, _ any) error {
	p.names = append(p.names, name)
	p.errs = append(p.errs, ctx.Err())
	if len(p.names) == 1 {
		p.cancel()
	}
	return nil
}

func TestContract_POST1_EventsSurviveACancelledContextAfterCommit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	pub := &ctxPub{cancel: cancel}
	e.svc.cfg.Publisher = pub
	vulns := []Vuln{qnapVuln(), {CVE: "CVE-2021-0001", Vendor: "QNAP", Product: "Photo Station"}}
	res, err := e.svc.UpsertFromMatch(ctx, nas("6.1.1"), vulns)
	if err != nil || len(res.Created) != 2 {
		t.Fatalf("result = %+v err=%v", res, err)
	}
	if len(pub.names) != 2 {
		t.Fatalf("published %v: an event was lost after the commit", pub.names)
	}
	for i, err := range pub.errs {
		if err != nil {
			t.Errorf("event %d got a cancelled context: %v", i, err)
		}
	}
}

func TestAuditFailureRollsBackTheRowAndTheEvent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	auditBefore := e.count(`SELECT count(*) FROM core_audit`)
	// NUL passes the library but not the audit log, which runs after the update and the history insert
	if _, err := e.svc.SetStatus(t.Context(), id, ActionPatched, "a\x00b", "it@acme.example"); err == nil {
		t.Fatal("expected the audit failure to surface")
	}
	r, _ := e.svc.Get(t.Context(), id)
	if r.Status != StatusSuspected || len(r.History) != 1 || e.count(`SELECT count(*) FROM core_audit`) != auditBefore || len(e.pub.take()) != 0 {
		t.Fatalf("a failed audit left something behind: %+v", r)
	}
}

func TestContract_INV3_SetStatusRefusesAnInvalidUser(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	for _, u := range []string{"", strings.Repeat("a", 321), "a\x00b", "\xff\xfe"} {
		_, err := e.svc.SetStatus(t.Context(), id, ActionPatched, "", u)
		if !errors.Is(err, ErrInvalidUser) {
			t.Errorf("user %q: err = %v", u, err)
		}
		var ae *apierr.Error
		if !errors.As(ToAPIError(err), &ae) || ae.Status != 400 {
			t.Errorf("user %q: not mapped to an API error", u)
		}
	}
	if r, _ := e.svc.Get(t.Context(), id); r.Status != StatusSuspected || len(r.History) != 1 {
		t.Fatalf("finding changed: %+v", r)
	}
}

func TestContract_INV6_ConcurrentMatchesMakeOneFinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var wg sync.WaitGroup
	created := make(chan int, 16)
	for range 16 {
		wg.Go(func() {
			res, err := e.svc.OnMatchChanged(t.Context(), "a-1")
			if err != nil {
				t.Error(err)
			}
			created <- len(res.Created)
		})
	}
	wg.Wait()
	close(created)
	total := 0
	for n := range created {
		total += n
	}
	if total != 1 || e.count(`SELECT count(*) FROM fnd_finding`) != 1 || len(e.pub.take()) != 1 {
		t.Fatalf("created %d findings, want 1", total)
	}
}

// matchErr makes MatchInput fail for the listed devices; assetsErr makes Assets fail.
type failingInv struct {
	*fakeInv
	matchErr  map[string]error
	assetsErr error
}

func (f failingInv) MatchInput(ctx context.Context, id string) (Asset, bool, error) {
	if err := f.matchErr[id]; err != nil {
		return Asset{}, false, err
	}
	return f.fakeInv.MatchInput(ctx, id)
}

func (f failingInv) Assets(ctx context.Context, ids []string) (map[string]AssetView, error) {
	if f.assetsErr != nil {
		return nil, f.assetsErr
	}
	return f.fakeInv.Assets(ctx, ids)
}

// D-439: when CISA changes the product of an entry, the finding of the old product stays open and says so once in its
// history; a list without the CVE judges nothing.
func TestUpsert_NoLongerMatchesIsNotedOnceAndNeverClosed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	const q = `SELECT count(*) FROM fnd_finding_history WHERE action = 'no_longer_matches'`
	moved := Vuln{CVE: "CVE-2022-27593", Vendor: "QNAP", Product: "Other Station"}
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{{CVE: "CVE-2021-44228", Vendor: "Apache", Product: "Log4j"}}); err != nil || e.count(q) != 0 {
		t.Fatalf("a list without the CVE noted something: %v", err)
	}
	for range 2 {
		if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{moved}); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.count(q); n != 1 {
		t.Fatalf("history rows: %d, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE status = 'suspected'`); n != 1 {
		t.Fatalf("the finding was closed: %d suspected", n)
	}
}

// D-439: match, no longer match, match again: one history row each way, none added by repeated runs.
func TestUpsert_NoLongerMatchesThenMatchesAgain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	moved := Vuln{CVE: "CVE-2022-27593", Vendor: "QNAP", Product: "Other Station"}
	run := func(v Vuln) {
		t.Helper()
		if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{v}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(a string) int {
		return e.count(`SELECT count(*) FROM fnd_finding_history WHERE action = '` + a + `'`)
	}
	run(moved)
	run(moved)
	run(qnapVuln())
	run(qnapVuln())
	if count("no_longer_matches") != 1 || count("matches_again") != 1 {
		t.Fatalf("rows: %d and %d, want 1 and 1", count("no_longer_matches"), count("matches_again"))
	}
	run(moved) // flaps again: the newest row is matches_again, so a new note is written
	if count("no_longer_matches") != 2 {
		t.Fatalf("second no_longer_matches: %d", count("no_longer_matches"))
	}
}

// D-500 on kien's box: the product findings of a software without a version stay open (FORBID-2) with a note that
// says why, the device gets ONE "add the version" item, and the item goes away with the version or the device.
func TestUpsert_NoVersionIsOneItemAndOldFindingsGetANote(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), e.feeds.vulns); err != nil { // the old flood: a product finding
		t.Fatal(err)
	}
	res, err := e.svc.UpsertFromMatch(t.Context(), nas(""), e.feeds.vulns)
	if err != nil || len(res.Created) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	items, err := e.svc.ListVersionNeeded(t.Context(), "")
	if err != nil || len(items) != 1 || items[0].AssetID != "a-1" || items[0].CVEs != 1 || items[0].Software != "Photo Station" {
		t.Fatalf("items = %+v %v", items, err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_history WHERE action = 'no_longer_matches' AND note LIKE '%Add the version%'`); n != 1 {
		t.Fatalf("notes = %d", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE status = 'suspected'`); n != 1 {
		t.Fatalf("the finding must stay open (FORBID-2): %d", n)
	}
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	if items, _ := e.svc.ListVersionNeeded(t.Context(), ""); len(items) != 0 {
		t.Fatalf("the version was added, item stays: %+v", items)
	}
	if _, err := e.svc.UpsertFromMatch(t.Context(), nas(""), e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.OnAssetDeleted(t.Context(), "a-1"); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_version_needed`); n != 0 {
		t.Fatalf("items left after the device was deleted: %d", n)
	}
}
