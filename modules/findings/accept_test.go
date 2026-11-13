package findings

import (
	"errors"
	"strings"
	"testing"
	"time"
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

// D-498, INV-13: the acceptance holds until its last day has ended everywhere (the next day 12:00 UTC, the end of the day at
// UTC-12), then reopens to what a fresh match gives.
func TestFinding_ExpireAcceptance(t *testing.T) {
	t.Parallel()
	until := dayOf(t0).AddDate(0, 0, 30)
	acc, _, err := suspected().AcceptRisk("March window", "ann@example.com", until, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := acc.ExpireAcceptance(until.AddDate(0, 0, 1).Add(12*time.Hour - time.Millisecond)); ok {
		t.Fatal("expired before the last day ended at UTC-12")
	}
	re, h, ok := acc.ExpireAcceptance(AcceptanceEnds(until))
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
	for _, step := range []time.Duration{30 * 24 * time.Hour, 24 * time.Hour} { // the last day, then the next morning UTC: it is still that day at UTC-12
		e.advance(step)
		if r, err := e.svc.Reconcile(t.Context()); err != nil || r.Expired != 0 {
			t.Fatalf("reconcile at %s = %+v %v", *e.clock, r, err)
		}
	}
	r, _ := e.svc.Get(t.Context(), id)
	if r.Status != StatusRiskAccepted || !r.AcceptedUntil.Equal(until) || r.ResolutionNote != "March window" {
		t.Fatalf("accepted = %+v", r)
	}
	e.pub.take()
	e.advance(2 * time.Hour) // the next day 12:00 UTC: the last day has ended everywhere
	if r, err := e.svc.Reconcile(t.Context()); err != nil || r.Expired != 1 {
		t.Fatalf("reconcile after the day = %+v %v", r, err)
	}
	e.advance(time.Hour)
	if r, err := e.svc.Reconcile(t.Context()); err != nil || r.Expired != 0 {
		t.Fatalf("second reconcile = %+v %v", r, err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_history WHERE user = 'system' AND note LIKE 'Risk acceptance expired%'`); n != 1 {
		t.Fatalf("expiry history rows = %d, want exactly 1", n)
	}
	r, _ = e.svc.Get(t.Context(), id)
	last := r.History[len(r.History)-1]
	if r.Status != StatusSuspected || !r.AcceptedUntil.IsZero() || last.User != SystemUser || !strings.HasPrefix(last.Note, "Risk acceptance expired (accepted by it@acme.example") {
		t.Fatalf("expired = %+v %+v", r.Finding, last)
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Payload != (StatusChangedEvent{FindingID: id, From: StatusRiskAccepted, To: StatusSuspected, Reason: ReasonRiskExpired,
		AcceptedBy: "it@acme.example", AcceptedUntil: until.Format(time.DateOnly)}) {
		t.Fatalf("events = %+v", ev)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.status' AND detail LIKE '%risk acceptance expired%'`) != 1 {
		t.Fatal("no audit row for the expiry")
	}
	if p, _ := e.svc.Get(t.Context(), res.Created[1]); p.Status != StatusPatched {
		t.Fatalf("the patched one became %s", p.Status)
	}
}
