package findings

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

const winrarCVE = "CVE-2025-8088"

func winrarVulns() []Vuln {
	return []Vuln{{CVE: winrarCVE, Vendor: "RARLAB", Product: "WinRAR",
		Affected: []Affected{{CPE: "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "7.13"}}}}}
}

func winrarPC(version, source string, seen time.Time) Asset {
	return Asset{ID: "a-1", Name: "pc-sql", AgentOS: "Microsoft Windows 11 Pro", Software: []Software{
		{ID: "s-rar", Display: "WinRAR", Vendor: "RARLAB", Product: "WinRAR", Version: version, Source: source, KevKeys: []string{"rarlab|winrar"}, SeenAt: seen},
	}}
}

// The owner updates WinRAR from 6.24 to 7.23.0 and the agent reports it: the finding matched on 6.24 is patched by an update, by the
// system user, with the history line naming both versions and the reader, and no notice (only a status_changed event with its reason).
func TestFixedByUpdate_AgentReportsANewVersion(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := func(a Asset) {
		t.Helper()
		e.advance(time.Hour)
		if _, err := e.svc.UpsertFromMatch(t.Context(), a, winrarVulns()); err != nil {
			t.Fatal(err)
		}
	}
	run(winrarPC("6.24", "agent", *e.clock))
	r, err := loadByPair(t.Context(), e.db.Reader(), "a-1", winrarCVE)
	if err != nil || !r.Status.Open() || r.Evidence.Read == nil || r.Evidence.Read.Version != "6.24" || r.Evidence.Read.Source != "agent" {
		t.Fatalf("matched on 6.24: %+v %v", r.Finding, err)
	}
	was := r.Status
	e.pub.take()
	seen := time.Date(2026, 11, 17, 6, 45, 0, 0, time.UTC)
	run(winrarPC("7.23.0", "agent", seen))
	r, _ = loadByPair(t.Context(), e.db.Reader(), "a-1", winrarCVE)
	want := "Fixed by an update: WinRAR 6.24 → 7.23.0 (agent, 17 Nov 2026)."
	if r.Status != StatusPatched || r.ResolvedBy != SystemUser || r.ResolutionReason != ReasonFixedByUpdate || !strings.HasPrefix(r.ResolutionNote, want) {
		t.Fatalf("finding = %+v", r.Finding)
	}
	if h := r.History[len(r.History)-1]; h.Action != "patched" || h.User != SystemUser || !strings.HasPrefix(h.Note, want) {
		t.Fatalf("history = %+v", h)
	}
	if ev := e.pub.take(); len(ev) != 1 || ev[0].Payload != (StatusChangedEvent{FindingID: r.ID, From: was, To: StatusPatched, Reason: ReasonFixedByUpdate}) {
		t.Fatalf("events = %+v", ev)
	}
	// a rollback into the range reopens it, like Vedette's own "not affected"
	run(winrarPC("6.24", "agent", *e.clock))
	r, _ = loadByPair(t.Context(), e.db.Reader(), "a-1", winrarCVE)
	if !r.Status.Open() || r.ResolutionReason != "" {
		t.Fatalf("rollback: %+v", r.Finding)
	}
}

// The same version judged again with better data, a guess replaced by the device's reading, and a person's correction stay "not
// affected": the device was never inside the range, so nothing was patched.
func TestFixedByUpdate_NeverAffectedStaysNotRelevant(t *testing.T) {
	t.Parallel()
	narrowed := []Vuln{{CVE: winrarCVE, Vendor: "RARLAB", Product: "WinRAR",
		Affected: []Affected{{CPE: "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "6.20"}}}}}
	for name, tc := range map[string]struct {
		first, then Asset
		vulns       []Vuln
	}{
		"same version, NVD's range corrected": {winrarPC("6.24", "agent", t0), winrarPC("6.24", "agent", t0), narrowed},
		"banner guess replaced by the agent":  {winrarPC("6.24", "nmap", t0), winrarPC("7.23.0", "agent", t0), winrarVulns()},
		"a person corrects the version":       {winrarPC("6.24", "agent", t0), winrarPC("7.23.0", "manual", t0), winrarVulns()},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			if _, err := e.svc.UpsertFromMatch(t.Context(), tc.first, winrarVulns()); err != nil {
				t.Fatal(err)
			}
			e.advance(time.Hour)
			if _, err := e.svc.UpsertFromMatch(t.Context(), tc.then, tc.vulns); err != nil {
				t.Fatal(err)
			}
			r, err := loadByPair(t.Context(), e.db.Reader(), "a-1", winrarCVE)
			if err != nil {
				t.Fatal(err)
			}
			if r.Status != StatusNotRelevant || r.ResolutionReason != ReasonNotAffectedVersion {
				t.Fatalf("finding = %+v", r.Finding)
			}
		})
	}
}

// The one-time pass: a finding closed as not affected before the rule, matched on the agent's 6.24 and closed on its 7.23.0, becomes
// patched with a line built from what is stored (resolved_at kept); one closed on the same version it was matched on stays; no event
// is sent, one audit row says how many, and the marker is gone so the pass never runs again.
func TestReclassifyPatched_OnceAndQuiet(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	closedAt := time.Date(2026, 11, 17, 6, 45, 0, 0, time.UTC)
	old := func(id, cve, matched, proved string) Record {
		return Record{ID: id, AssetID: "a-1", CVE: cve, FirstSeen: t0, LastSeen: t0, Finding: Finding{
			Status: StatusNotRelevant, Severity: SeverityHigh, Confidence: ConfVersion, Basis: BasisVersion,
			Evidence:   &Evidence{Summary: "The agent on pc-sql reports WinRAR " + matched + " installed. That version is inside the range NVD lists as affected by " + cve + " (before 7.13).", CheckedAt: t0, Agent: true},
			ResolvedBy: SystemUser, ResolvedAt: closedAt, ResolutionReason: ReasonNotAffectedVersion, SoftwareID: "s-rar", ProvedVersion: proved,
			ResolutionNote: "Not affected: version " + proved + " of WinRAR is outside every version range NVD lists for " + cve + ". Vedette closed this by itself and reopens it if a later match says the device is affected.",
		}}
	}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, r := range []Record{old("f-upd", winrarCVE, "6.24", "7.23.0"), old("f-same", "CVE-2025-6218", "6.24", "6.24")} {
			if err := insertRecord(t.Context(), tx, r); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := e.svc.reclassifyPatched(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	r, _ := loadByPair(t.Context(), e.db.Reader(), "a-1", winrarCVE)
	if r.Status != StatusPatched || r.ResolutionReason != ReasonFixedByUpdate || !r.ResolvedAt.Equal(closedAt) ||
		!strings.HasPrefix(r.ResolutionNote, "Fixed by an update: WinRAR 6.24 → 7.23.0 (agent, 17 Nov 2026).") {
		t.Fatalf("updated one = %+v", r.Finding)
	}
	if s, _ := loadByPair(t.Context(), e.db.Reader(), "a-1", "CVE-2025-6218"); s.Status != StatusNotRelevant {
		t.Fatalf("same version = %+v", s.Finding)
	}
	if ev := e.pub.take(); len(ev) != 0 {
		t.Fatalf("the pass sent events: %+v", ev)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.patched_backfill'`); n != 1 {
		t.Fatalf("audit rows %d", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_patched_backfill_pending`); n != 0 {
		t.Fatalf("marker left")
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_history WHERE action = 'patched'`); n != 1 {
		t.Fatalf("history rows %d", n)
	}
}
