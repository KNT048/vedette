package findings

import (
	"database/sql"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// D-498: accept_risk needs a note like false positive and a day from tomorrow to a year ahead (one day of slack each side
// for the person's time zone); anything else is refused and changes nothing.
func TestFinding_AcceptRisk_NoteAndUntilBounds(t *testing.T) {
	t.Parallel()
	today := dayOf(t0)
	for _, c := range []struct {
		name  string
		note  string
		until time.Time
		want  *APIError
	}{
		{"tomorrow", "March window", today.AddDate(0, 0, 1), nil},
		{"a year", "March window", today.AddDate(0, 0, MaxAcceptDays), nil},
		{"today (a person west of UTC)", "March window", today, nil},
		{"a year and a day (a person east of UTC)", "March window", today.AddDate(0, 0, MaxAcceptDays+1), nil},
		{"yesterday", "March window", today.AddDate(0, 0, -1), ErrBadUntil},
		{"too far", "March window", today.AddDate(0, 0, MaxAcceptDays+2), ErrBadUntil},
		{"no day", "March window", time.Time{}, ErrBadUntil},
		{"not a day", "March window", today.AddDate(0, 0, 1).Add(time.Hour), ErrBadUntil},
		{"no note", " ab ", today.AddDate(0, 0, 30), ErrNoteRequired},
	} {
		start := suspected()
		got, h, err := start.AcceptRisk(c.note, "ann", c.until, t0)
		if c.want != nil {
			if !errors.Is(err, c.want) || got != start {
				t.Errorf("%s: err = %v, finding %+v", c.name, err, got)
			}
			continue
		}
		if err != nil || got.Status != StatusRiskAccepted || !got.AcceptedUntil.Equal(c.until) || got.ResolvedBy != "ann" || got.Validate() != nil {
			t.Errorf("%s: %+v %v", c.name, got, err)
		}
		if h.Action != "risk_accepted" || !strings.HasSuffix(h.Note, "(until "+FmtDay(c.until)+")") {
			t.Errorf("%s: history %+v", c.name, h)
		}
	}
	if _, _, err := suspected().Apply(ActionAcceptRisk, "March window", "ann", t0); !errors.Is(err, ErrBadUntil) {
		t.Errorf("accept_risk without a day: %v", err)
	}
	if err := ValidUntil(ActionPatched, today.AddDate(0, 0, 3), t0); !errors.Is(err, ErrBadUntil) {
		t.Errorf("a day with another action: %v", err)
	}
}

// D-498, INV-13: the acceptance holds through its last day and reopens the next one, to what a fresh match gives.
func TestFinding_ExpireAcceptance(t *testing.T) {
	t.Parallel()
	until := dayOf(t0).AddDate(0, 0, 30)
	acc, _, err := suspected().AcceptRisk("March window", "ann@example.com", until, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := acc.ExpireAcceptance(until.Add(23 * time.Hour)); ok {
		t.Fatal("expired on its last day")
	}
	re, h, ok := acc.ExpireAcceptance(until.AddDate(0, 0, 1))
	if !ok || re.Status != StatusSuspected || !re.AcceptedUntil.IsZero() || re.ResolvedBy != "" || re.Validate() != nil {
		t.Fatalf("reopened = %+v %v", re, ok)
	}
	if h.User != SystemUser || h.Action != "reopened" || h.Note != "Risk acceptance expired (accepted by ann@example.com until "+FmtDay(until)+")." {
		t.Fatalf("history = %+v", h)
	}
	scan := acc
	scan.Basis, scan.Evidence = BasisScan, &Evidence{Template: "t", CheckedAt: t0}
	if re, _, _ := scan.ExpireAcceptance(until.AddDate(0, 0, 2)); re.Status != StatusConfirmed {
		t.Fatalf("scan basis reopened as %s", re.Status)
	}
	if _, _, ok := suspected().ExpireAcceptance(until.AddDate(1, 0, 0)); ok {
		t.Fatal("an open finding expired")
	}
}

// D-498: accepted findings stay accepted on a re-match, reopen in the hourly reconcile once the day passed (system history,
// audit, status_changed with its reason), and bulk accept keeps INV-10 (closed ones skipped, a bad day writes nothing).
func TestService_AcceptRiskThenExpiresInReconcile(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.feeds.vulns = append(e.feeds.vulns, Vuln{CVE: "CVE-2024-0001", Vendor: "QNAP", Product: "Photo Station"})
	res, err := e.svc.OnMatchChanged(t.Context(), "a-1")
	if err != nil || len(res.Created) != 2 {
		t.Fatalf("seed: %+v %v", res, err)
	}
	if _, err := e.svc.SetStatus(t.Context(), res.Created[1], ActionPatched, "", "it@acme.example"); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	until := dayOf(t0).AddDate(0, 0, 30)
	if _, _, err := e.svc.setStatusMany(t.Context(), res.Created, ActionAcceptRisk, "March window", "it@acme.example", dayOf(t0).AddDate(0, 0, -1)); !errors.Is(err, ErrBadUntil) {
		t.Fatalf("bad day: %v", err)
	}
	n, skipped, err := e.svc.setStatusMany(t.Context(), res.Created, ActionAcceptRisk, "March window", "it@acme.example", until)
	if err != nil || n != 1 || skipped != 1 {
		t.Fatalf("bulk accept = %d, %d, %v", n, skipped, err)
	}
	id := res.Created[0]
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Payload != (StatusChangedEvent{FindingID: id, From: StatusSuspected, To: StatusRiskAccepted}) {
		t.Fatalf("events = %+v", ev)
	}
	if _, err := e.svc.OnMatchChanged(t.Context(), "a-1"); err != nil {
		t.Fatal(err)
	}
	e.advance(30 * 24 * time.Hour) // the last day: still accepted
	if r, err := e.svc.Reconcile(t.Context()); err != nil || r.Expired != 0 {
		t.Fatalf("reconcile on the last day = %+v %v", r, err)
	}
	r, _ := e.svc.Get(t.Context(), id)
	if r.Status != StatusRiskAccepted || !r.AcceptedUntil.Equal(until) || r.ResolutionNote != "March window" {
		t.Fatalf("accepted = %+v", r)
	}
	e.pub.take()
	e.advance(24 * time.Hour)
	if r, err := e.svc.Reconcile(t.Context()); err != nil || r.Expired != 1 {
		t.Fatalf("reconcile after the day = %+v %v", r, err)
	}
	r, _ = e.svc.Get(t.Context(), id)
	last := r.History[len(r.History)-1]
	if r.Status != StatusSuspected || !r.AcceptedUntil.IsZero() || last.User != SystemUser || !strings.HasPrefix(last.Note, "Risk acceptance expired (accepted by it@acme.example") {
		t.Fatalf("expired = %+v %+v", r.Finding, last)
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Payload != (StatusChangedEvent{FindingID: id, From: StatusRiskAccepted, To: StatusSuspected, Reason: ReasonRiskExpired}) {
		t.Fatalf("events = %+v", ev)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.status' AND detail LIKE '%risk acceptance expired%'`) != 1 {
		t.Fatal("no audit row for the expiry")
	}
	if p, _ := e.svc.Get(t.Context(), res.Created[1]); p.Status != StatusPatched {
		t.Fatalf("the patched one became %s", p.Status)
	}
}

// Migration 0005 rebuilds fnd_finding, the parent of ON DELETE CASCADE keys of findings and mitigation: every child row
// must survive it, and foreign keys must be on again afterwards.
func TestMigration0005_KeepsTheRowsThatHangOffAFinding(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	before := fstest.MapFS{}
	if err := fs.WalkDir(Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(p, "0005") {
			return err
		}
		b, err := fs.ReadFile(Migrations, p)
		before[p] = &fstest.MapFile{Data: b}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "findings", before); err != nil {
		t.Fatal(err)
	}
	ts := store.FormatTS(t0)
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`CREATE TABLE x_child (finding_id TEXT NOT NULL REFERENCES fnd_finding (id) ON DELETE CASCADE)`,
			`INSERT INTO fnd_finding (id, asset_id, cve, status, severity, confidence, basis, first_seen, last_seen) VALUES ('f-1', 'a-1', 'CVE-2022-27593', 'suspected', 'medium', 0.5, 'product', '` + ts + `', '` + ts + `')`,
			`INSERT INTO fnd_finding_history (id, finding_id, ts, user, action) VALUES ('fh-1', 'f-1', '` + ts + `', 'system', 'created')`,
			`INSERT INTO x_child (finding_id) VALUES ('f-1')`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "findings", Migrations); err != nil {
		t.Fatal(err)
	}
	count := func(q string) (n int) {
		if err := db.Reader().QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(`SELECT count(*) FROM fnd_finding_history`) != 1 || count(`SELECT count(*) FROM x_child`) != 1 {
		t.Fatal("the rebuild deleted rows that hang off a finding")
	}
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM fnd_finding WHERE id = 'f-1'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if count(`SELECT count(*) FROM fnd_finding_history`) != 0 || count(`SELECT count(*) FROM x_child`) != 0 {
		t.Fatal("foreign keys are off after the migration: deleting a finding left its rows")
	}
}
