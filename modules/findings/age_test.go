package findings

import (
	"strings"
	"testing"
	"time"
)

// D-615, S-TIER-4: a KEV CVE published more than 12 months ago makes a finding only on confirmed evidence (the device's
// agent here; a scan comes through ConfirmFromScan). A banner or typed version, or the product name alone, makes none; a
// recent CVE and one with no known published day keep today's rules.
func TestMatchAsset_D615_OldKEVNeedsConfirmedEvidence(t *testing.T) {
	t.Parallel()
	old, recent := t0.AddDate(-2, 0, 0), t0.AddDate(0, -1, 0)
	ranged := func(pub time.Time) []Vuln {
		v := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
		v.Published = pub
		return []Vuln{v}
	}
	productOnly := func(pub time.Time) []Vuln { v := qnapVuln(); v.Published = pub; return []Vuln{v} }
	agent := func(ver string) Asset { a := nas(ver); a.Software[0].Source = "agent"; return a }
	for name, tc := range map[string]struct {
		a       Asset
		vulns   []Vuln
		want    Basis // "" = no finding
		agentEv bool
	}{
		"old, banner version inside":   {nas("6.1.1"), ranged(old), "", false},
		"old, product only":            {nas("6.1.1"), productOnly(old), "", false},
		"old, agent version inside":    {agent("6.1.1"), ranged(old), BasisVersion, true},
		"recent, banner version":       {nas("6.1.1"), ranged(recent), BasisVersion, false},
		"recent, product only":         {nas("6.1.1"), productOnly(recent), BasisProduct, false},
		"unknown day, banner version":  {nas("6.1.1"), ranged(time.Time{}), BasisVersion, false},
		"unknown day, product only":    {nas("6.1.1"), productOnly(time.Time{}), BasisProduct, false},
		"just inside 12 months":        {nas("6.1.1"), ranged(t0.Add(-AgeLimit + time.Hour)), BasisVersion, false},
		"just over 12 months":          {nas("6.1.1"), ranged(t0.Add(-AgeLimit - time.Hour)), "", false},
		"old, banner version outside":  {nas("6.2.0"), ranged(old), "", false},
		"old, agent version outside":   {agent("6.2.0"), ranged(old), "", false},
		"old, banner, existing pair":   {nas("6.1.1"), ranged(old), "", false},
		"recent, agent version inside": {agent("6.1.1"), ranged(recent), BasisVersion, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			res := MatchAsset(tc.a, tc.vulns, nil, t0)
			if tc.want == "" {
				if len(res.New) != 0 {
					t.Fatalf("new = %+v; want none", res.New)
				}
				return
			}
			if len(res.New) != 1 || res.New[0].Basis != tc.want || res.New[0].Evidence.Agent != tc.agentEv {
				t.Fatalf("new = %+v; want basis %s, agent %v", res.New, tc.want, tc.agentEv)
			}
		})
	}
	// a device that has the finding: the unconfirmed old match is in Aged with the sentence that closes it
	res := MatchAsset(nas("6.1.1"), ranged(old), map[string]bool{"CVE-2022-27593": true}, t0)
	if len(res.Existing) != 0 || len(res.Aged) != 1 || !strings.HasPrefix(res.Aged[0].Evidence.Summary, AgedNote+": CVE-2022-27593 was published on 9 Nov 2024") {
		t.Fatalf("existing %+v, aged %+v", res.Existing, res.Aged)
	}
	// D-615: no "add the version" item for an old CVE (a typed version would not be confirmed evidence); a recent one keeps it
	if res := MatchAsset(nas(""), ranged(old), nil, t0); len(res.NeedVersion) != 0 || len(res.New) != 0 {
		t.Fatalf("old CVE, no version: %+v", res)
	}
	if res := MatchAsset(nas(""), ranged(recent), nil, t0); len(res.NeedVersion) != 1 {
		t.Fatalf("recent CVE, no version: %+v", res)
	}
}

// D-615, S-TIER-4: an open finding of an old KEV CVE that rests on no confirmed evidence closes with the reason in its history
// (never deleted, no alert: notify ignores not_relevant), and reopens when confirmed evidence arrives (the agent here). A
// finding a scan confirmed, or one a person reopened, never closes for its age.
func TestContract_D615_AgedFindingClosesAndReopens(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})
	upsert := func(a Asset, pub time.Time) {
		t.Helper()
		e.advance(time.Minute)
		x := v
		x.Published = pub
		if _, err := e.svc.UpsertFromMatch(t.Context(), a, []Vuln{x}); err != nil {
			t.Fatal(err)
		}
	}
	load := func() Record {
		t.Helper()
		r, err := loadByPair(t.Context(), e.db.Reader(), "a-1", "CVE-2022-27593")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	upsert(nas("6.1.1"), time.Time{}) // before nvd-kev stored the day: counts as recent, a version finding
	e.pub.take()
	upsert(nas("6.1.1"), t0.AddDate(-3, 0, 0)) // the day arrives: old, banner version only
	r := load()
	if r.Status != StatusNotRelevant || r.ResolvedBy != SystemUser || r.ResolutionReason != ReasonNotAffectedVersion || !strings.HasPrefix(r.ResolutionNote, AgedNote) {
		t.Fatalf("not closed for its age: %+v", r.Finding)
	}
	if last := r.History[len(r.History)-1]; last.User != SystemUser || !strings.HasPrefix(last.Note, AgedNote) {
		t.Fatalf("history %+v", r.History)
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Payload != (StatusChangedEvent{FindingID: r.ID, From: StatusSuspected, To: StatusNotRelevant, Reason: ReasonNotAffectedVersion}) {
		t.Fatalf("events = %+v", ev)
	}
	upsert(nas("6.1.1"), t0.AddDate(-3, 0, 0)) // said once
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.auto_resolved' AND detail LIKE '%D-615%'`); n != 1 {
		t.Fatalf("audit rows %d", n)
	}
	a := nas("6.1.1")
	a.Software[0].Source = "agent"
	upsert(a, t0.AddDate(-3, 0, 0)) // the agent reports the version: confirmed evidence
	if r = load(); r.Status != StatusSuspected || r.ResolutionNote != "" {
		t.Fatalf("not reopened: %+v", r.Finding)
	}
	if last := r.History[len(r.History)-1]; last.Action != "matches_again" || !strings.Contains(last.Note, "older than 12 months") {
		t.Fatalf("reopen row %+v", last)
	}

	// a scan-confirmed finding stays open whatever its age
	s := newEnv(t)
	if _, err := s.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{v}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", Evidence{Template: "CVE-2022-27593", CheckedAt: t0}); err != nil {
		t.Fatal(err)
	}
	old := v
	old.Published = t0.AddDate(-3, 0, 0)
	if _, err := s.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{old}); err != nil {
		t.Fatal(err)
	}
	if r, _ := loadByPair(t.Context(), s.db.Reader(), "a-1", "CVE-2022-27593"); r.Status != StatusConfirmed {
		t.Fatalf("scan finding closed: %+v", r.Finding)
	}

	// a person who reopened it decided: never closed for its age again, and its history says why it is no longer matched
	p := newEnv(t)
	if _, err := p.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{v}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{old}); err != nil {
		t.Fatal(err)
	}
	pr, _ := loadByPair(t.Context(), p.db.Reader(), "a-1", "CVE-2022-27593")
	if _, err := p.svc.SetStatus(t.Context(), pr.ID, ActionReopen, "", "kim@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.svc.UpsertFromMatch(t.Context(), nas("6.1.1"), []Vuln{old}); err != nil {
		t.Fatal(err)
	}
	pr, _ = loadByPair(t.Context(), p.db.Reader(), "a-1", "CVE-2022-27593")
	if pr.Status != StatusSuspected || !strings.HasPrefix(pr.History[len(pr.History)-1].Note, AgedNote) {
		t.Fatalf("person's reopen not kept: %+v, history %+v", pr.Finding, pr.History)
	}
}

// D-616: GET /findings/plan (S-TIER-1, S-TIER-2) answers before the tier matcher exists: no item, compared false, and the
// state of each tier feed, so the page says what is missing instead of "no update to plan"; "plan" is never a finding id.
func TestPlan_HonestStateBeforeTheMatcher(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	c, b := e.call("GET", "/findings/plan", "viewer", "")
	if c != 200 || b["compared"] != false || len(b["items"].([]any)) != 0 {
		t.Fatalf("%d %v", c, b)
	}
	if d := b["data"].(map[string]any); d["epss"] != "off" || d["recent"] != "off" || d["epss_date"] != nil {
		t.Fatalf("data %v", d)
	}
	e.feeds.tier = TierStatus{EPSS: "ready", Recent: "loading", EPSSDate: t0}
	c, b = e.call("GET", "/findings/plan?tier=likely&asset=a-1", "viewer", "")
	if d := b["data"].(map[string]any); c != 200 || d["epss"] != "ready" || d["recent"] != "loading" || d["epss_date"] != "2026-11-09" || d["recent_since"] != nil {
		t.Fatalf("%d %v", c, b)
	}
	if c, _ = e.call("GET", "/findings/plan?tier=bogus", "viewer", ""); c != 400 {
		t.Fatalf("bad tier: %d", c)
	}
}
