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
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

type fakeInv struct {
	mu     sync.Mutex
	assets map[string]AssetView
	match  map[string]Asset
	idsErr error
	// ignored are the devices a person ignored; the test also removes them from match, as the inventory does.
	ignored    map[string]bool
	ignoredErr error // IgnoredIDs fails with it (review r2 N1 of #945)
	// onMatch runs (without the lock) when MatchInput reads a device: a test can change the world while a pass reads it.
	onMatch func(id string)
	// matchErr makes MatchInput of a device fail (a device that cannot be read).
	matchErr map[string]error
	lines    map[string]Line // Lines: named lines, before the match input's
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
	a, ok := f.match[id]
	hook := f.onMatch
	err := f.matchErr[id]
	f.mu.Unlock()
	if hook != nil {
		hook(id)
	}
	if err != nil {
		return Asset{}, false, err
	}
	return a, ok, nil
}

// AssetIDs lists the devices that exist: the ones the matcher can read. idsErr makes the read fail.
func (f *fakeInv) IgnoredIDs(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ignoredErr != nil {
		return nil, f.ignoredErr
	}
	return slices.Sorted(maps.Keys(f.ignored)), nil
}

func (f *fakeInv) IsIgnored(_ context.Context, id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ignored[id], nil
}

func (f *fakeInv) EffectiveSoftware(context.Context, string) ([]EffectiveSoftware, error) {
	return []EffectiveSoftware{}, nil
}

// Lines names the lines of lines, else a line of the device's match input with that id.
func (f *fakeInv) Lines(_ context.Context, ids []string) (map[string]Line, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]Line{}
	for _, id := range ids {
		if l, ok := f.lines[id]; ok {
			out[id] = l
			continue
		}
		for aid, a := range f.match {
			for _, sw := range a.Software {
				if sw.ID == id {
					out[id] = Line{ID: id, AssetID: aid, Display: sw.Display, ProductKey: productid.Key(sw.Vendor, sw.Product), Version: sw.Version}
				}
			}
		}
	}
	return out, nil
}

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
	cvss  map[string]CVSS
	vulns []Vuln
	tier  TierStatus
	tiers []TierVuln // TierVulns keeps those whose entries the scope keeps
	// distro: TierDistro keeps the rows of the packages asked for; covered: the releases it says the feeds hold rows for
	distro  []TierVuln
	covered map[string]bool
	loading map[string]bool // TierDistro's Loading: the distributions the plan still waits for
	stamp   string
	// onMatchSet runs when a pass reads the match set: a test can change the world while the catalogue is read.
	onMatchSet func()
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

func (f *fakeFeeds) CVSS(_ context.Context, cves []string) (map[string]CVSS, error) {
	out := map[string]CVSS{}
	for _, c := range cves {
		if v, ok := f.cvss[c]; ok {
			out[c] = v
		}
	}
	return out, nil
}

func (f *fakeFeeds) Vulns(context.Context) ([]Vuln, error) { return f.vulns, nil }

func (f *fakeFeeds) MatchSet(context.Context, MatchScope) ([]Vuln, error) {
	if f.onMatchSet != nil {
		f.onMatchSet()
	}
	return f.vulns, nil
}

func (f *fakeFeeds) TierStatus(context.Context) (TierStatus, error) { return f.tier, nil }

func (f *fakeFeeds) TierVulns(_ context.Context, keep func(string) bool) ([]TierVuln, error) {
	var out []TierVuln
	for _, t := range f.tiers {
		var kept []Affected
		for _, af := range t.Affected {
			if keep(af.CPE) {
				kept = append(kept, af)
			}
		}
		if len(kept) > 0 {
			t.Affected = kept
			out = append(out, t)
		}
	}
	return out, nil
}

func (f *fakeFeeds) TierStamp(context.Context) (string, error) { return f.stamp, nil }

func (f *fakeFeeds) TierDistro(_ context.Context, pkgs []DistroPackage) (DistroTier, error) {
	asked := map[DistroPackage]bool{}
	for _, p := range pkgs {
		asked[p] = true
	}
	out := DistroTier{Covered: f.covered, Known: map[string]bool{}, Loading: f.loading}
	for _, t := range f.distro {
		var kept []DistroFix
		for _, d := range t.Distro {
			if asked[DistroPackage{Distro: d.Distro, Release: d.Release, Package: d.Package}] || asked[DistroPackage{Distro: d.Distro, Package: d.Package}] {
				kept = append(kept, d)
				out.Known[d.Distro+"/"+d.Package] = true
			}
		}
		if len(kept) > 0 {
			t.Distro = kept
			out.Vulns = append(out.Vulns, t)
		}
	}
	return out, nil
}

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
	t     testing.TB
	db    *store.DB
	svc   *Service
	inv   *fakeInv
	feeds *fakeFeeds
	pub   *fakePub
	clock *time.Time
}

func newEnv(t testing.TB) *env {
	t.Helper()
	db := storetest.New(t)
	migrateWithInventory(t, db)
	e := &env{t: t, db: db, pub: &fakePub{}, clock: new(time.Time)}
	*e.clock = t0
	e.inv = &fakeInv{
		assets: map[string]AssetView{"a-1": {ID: "a-1", Hostname: ptr("nas01"), IP: "192.168.10.21", Kind: "nas", Display: "Photo Station"}},
		match:  map[string]Asset{"a-1": nas("6.1.1")},
	}
	e.feeds = &fakeFeeds{
		kev:   map[string]KevInfo{"CVE-2022-27593": {Name: "QNAP Photo Station External Reference", Vendor: "QNAP", Product: "Photo Station", RequiredAction: "Apply updates.", Links: []string{"https://example.test/a"}, DateAdded: "2022-09-01", Ransomware: true}},
		vulns: []Vuln{qnapScanned()},
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
	if r.AssetID != "a-1" || r.CVE != "CVE-2022-27593" || r.Status != StatusSuspected || r.Row.State != StateOpen || !r.Row.Detected || r.Row.Verified != VerifiedNo ||
		r.Row.SoftwareID != "s-1" || r.Row.MatchedVersion != "6.1.1" || r.Row.FixKey == "" || r.Row.Urgency != 2 {
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
	var detail string // the audit page prints the stored text under the named one: an id in it showed each line twice
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT detail FROM core_audit WHERE action = 'findings.created'`).Scan(&detail); err != nil || detail != "CVE-2022-27593, basis "+string(r.Row.Basis) {
		t.Fatalf("detail = %q err=%v", detail, err)
	}
}

func TestOnMatchChangedUnknownAsset(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.svc.OnMatchChanged(t.Context(), "a-404"); !errors.Is(err, ErrUnknownAsset) {
		t.Fatalf("err = %v", err)
	}
}

func TestContract_INV2_UpsertKeepsOneFindingWhenTheRangeArrives(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.seed()
	e.advance(time.Hour)
	// the feed now knows the affected range and the device is inside it: the same finding, its evidence and last seen move
	a := nas("6.1.1")
	vuln := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.2"}})
	res, err := e.svc.UpsertFromMatch(t.Context(), a, []Vuln{vuln})
	if err != nil || len(res.Created) != 0 || res.Touched != 1 {
		t.Fatalf("result = %+v err=%v", res, err)
	}
	r, _ := e.svc.Get(t.Context(), id)
	if r.Status != StatusSuspected || !r.LastSeen.Equal(t0.Add(time.Hour)) || !r.FirstSeen.Equal(t0) || !strings.Contains(r.Evidence.Summary, "before 6.1.2") {
		t.Fatalf("finding = %+v", r)
	}
	if got := e.auditActions(); len(got) != 1 {
		t.Fatalf("audit = %v", got)
	}
	if ev := e.pub.take(); len(ev) != 0 {
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
	// a second confirmation of an already confirmed finding adds no event and tells nobody
	n := len(r.History)
	if r, err = e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", scanEv("t1")); err != nil || len(r.History) != n || len(e.pub.take()) != 0 {
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
	for i, want := range []int{1, 0, 0} { // the first safe check that confirms it is told; the finding keeps the person's decision
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
	if h := r.History[len(r.History)-1]; h.Action != "matches_again" || !strings.Contains(h.Note, "Still detected after it was marked patched") {
		t.Fatalf("history = %+v", r.History)
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Payload != (StatusChangedEvent{FindingID: id, From: StatusPatched, To: StatusConfirmed, Reason: ReasonStillDetected}) {
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
	if _, err := e.svc.ConfirmFromScan(t.Context(), "a-404", "CVE-2020-0001", scanEv("t")); !errors.Is(err, ErrUnknownAsset) {
		t.Errorf("no device: %v", err)
	}
	if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", Evidence{CheckedAt: t0}); !errors.Is(err, ErrInvalidEvidence) {
		t.Errorf("no template: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE verified <> 'no'`); n != 0 {
		t.Errorf("confirmed rows = %d", n)
	}
}

func TestContract_INV7_DeviceDeletedRemovesFindingsAndHistory(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	other := Asset{ID: "a-2", Name: "nas02", Software: nas("6.1.1").Software}
	if _, err := e.svc.UpsertFromMatch(t.Context(), other, e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	e.deleteDevice(t, "a-1")
	if e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-1'`) != 0 || e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-2'`) != 1 {
		t.Fatal("wrong findings removed")
	}
	if e.count(`SELECT count(*) FROM fnd_finding_event`) != 1 {
		t.Fatal("history of the deleted findings is still there")
	}
	if got := e.auditActions(); got[len(got)-1] != "findings.deleted_with_asset" {
		t.Fatalf("audit = %v", got)
	}
	// deleting again changes nothing and writes no audit row
	before := e.count(`SELECT count(*) FROM core_audit`)
	if e.deleteDevice(t, "a-1"); e.count(`SELECT count(*) FROM core_audit`) != before {
		t.Fatal("a second delete wrote an audit row")
	}
}

func TestContract_INV1_DatabaseRefusesWhatTheLibraryNeverBuilds(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.seed()
	ok := Finding{ID: "f-ok", AssetID: "a-9", CVE: "CVE-2022-0001", FirstSeen: t0}
	insert := func(f Finding) error {
		return e.db.Write(t.Context(), func(tx *sql.Tx) error { return writeTestFinding(t.Context(), tx, f) })
	}
	bad := map[string]func(f *Finding){
		"handled without a resolution": func(f *Finding) {
			f.State, f.Via, f.ResolvedBy, f.ResolvedAt = StateHandled, ViaPerson, "it@acme.example", t0
		},
		"open with a resolution":      func(f *Finding) { f.Resolution = ResolutionPatched },
		"open with a way":             func(f *Finding) { f.Via = ViaPerson },
		"accepted without a last day": func(f *Finding) { f.State, f.Resolution = StateHandled, ResolutionAccepted },
		"a last day without accepted": func(f *Finding) { f.AcceptedUntil = t0 },
		"version moved to the same": func(f *Finding) {
			f.State, f.Resolution, f.Via, f.FromVersion, f.ToVersion = StateHandled, ResolutionPatched, ViaVersionMoved, "1.0", "1.0"
		},
		"version moved without from": func(f *Finding) {
			f.State, f.Resolution, f.Via, f.ToVersion = StateHandled, ResolutionPatched, ViaVersionMoved, "1.0"
		},
		"versions without a move": func(f *Finding) {
			f.State, f.Resolution, f.FromVersion, f.ToVersion = StateHandled, ResolutionPatched, "1.0", "2.0"
		},
		"an unknown verification":  func(f *Finding) { f.Verified = "maybe" },
		"a way that is not a word": func(f *Finding) { f.State, f.Resolution, f.Via = StateHandled, ResolutionPatched, "Version Moved" },
		"urgency outside 1..5":     func(f *Finding) { f.Urgency = 6 },
		"a malformed CVE":          func(f *Finding) { f.CVE = "CVE-2022-0003; DROP" },
	}
	for name, change := range bad {
		f := ok
		f.ID = store.NewID("f")
		change(&f)
		if err := insert(f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := insert(ok); err != nil {
		t.Fatalf("valid row refused: %v", err)
	}
	dup := ok
	dup.ID = "f-dup"
	if err := insert(dup); err == nil {
		t.Error("a second finding for the same (device, CVE, line) was accepted")
	}
	other := ok
	other.ID, other.SoftwareID = "f-line", "s-other"
	if err := insert(other); err != nil {
		t.Errorf("the same CVE on another software line refused: %v", err)
	}
	err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE fnd_finding_event SET actor = 'rewritten'`)
		return err
	})
	if err == nil {
		t.Error("an event was updated")
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
	vulns := []Vuln{qnapScanned(), {CVE: "CVE-2021-0001", Vendor: "QNAP", Product: "Photo Station", HasTemplate: true}}
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
