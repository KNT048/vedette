package findings

import (
	"strings"
	"testing"
	"time"
)

// INV-6c (inventory INV-41 (6)): a person says the Photo Station row a scan reported is not installed. Inventory leaves the
// row out of matching and gives it in Asset.NotInstalled; its open finding closes with the person named, a history row, an audit row
// and no notice; the next match changes nothing; Clear brings the row back and reopens it without a notice; a new install (the scan
// reads another version) reopens it with the usual notice. A CVE another row still produces stays open.
func TestContract_INV6c_NotInstalledClosesAndClearReopens(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})}
	run := func(a Asset) {
		t.Helper()
		e.advance(time.Minute)
		if _, err := e.svc.UpsertFromMatch(t.Context(), a, v); err != nil {
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
	reasons := func() []string {
		var out []string
		for _, p := range e.pub.take() {
			if p.Name == EventStatusChanged {
				out = append(out, p.Payload.(StatusChangedEvent).Reason)
			}
		}
		return out
	}
	scanned := nas("6.1.1")
	scanned.Software[0].Source = "nmap"
	run(scanned)
	if r := load(); r.Status != StatusSuspected {
		t.Fatalf("seed: %+v", r.Finding)
	}
	e.pub.take()

	const said = "op@example.com said Photo Station 6.1.1 (nmap) is not installed on 17 Nov 2026"
	gone := Asset{ID: "a-1", Name: "nas01", Software: []Software{}, NotInstalled: []Software{scanned.Software[0]}}
	gone.NotInstalled[0].Correction = said
	run(gone)
	r := load()
	const note = "Closed: a person said the software is not installed. op@example.com said Photo Station 6.1.1 (nmap) is not installed on nas01 (17 Nov 2026)."
	if r.Status != StatusNotRelevant || r.ResolvedBy != SystemUser || r.ResolutionReason != ReasonNotAffectedVersion || r.ResolutionNote != note {
		t.Fatalf("closed: %+v", r.Finding)
	}
	if got := reasons(); len(got) != 1 || got[0] != ReasonNotInstalled {
		t.Fatalf("one status change, reason not_installed (notify sends nothing): %v", got)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_history WHERE action = 'not_relevant' AND note = '` + note + `'`); n != 1 {
		t.Fatalf("history rows %d", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_history WHERE action = 'no_longer_matches'`); n != 0 {
		t.Fatal("a close for Not installed is no 'no longer matches' note")
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.auto_resolved' AND detail = 'CVE-2022-27593: not installed (` + said + `)'`); n != 1 {
		t.Fatalf("audit rows %d", n)
	}
	// The next scan at the same version: nothing changes.
	hist := len(load().History)
	run(gone)
	if r := load(); r.Status != StatusNotRelevant || len(r.History) != hist || len(reasons()) != 0 {
		t.Fatalf("the next match must change nothing: %+v", r.Finding)
	}

	// Clear: the row is back, the finding reopens, without a notice.
	run(scanned)
	r = load()
	if r.Status != StatusSuspected || r.History[len(r.History)-1].Action != "matches_again" ||
		!strings.Contains(r.History[len(r.History)-1].Note, "because a person said the software is not installed") {
		t.Fatalf("cleared: %+v %+v", r.Finding, r.History[len(r.History)-1])
	}
	if got := reasons(); len(got) != 1 || got[0] != ReasonNotInstalledCleared {
		t.Fatalf("a reopen after Clear sends no notice: %v", got)
	}

	// Not installed again; then the scan reads another version: a new install, which reopens it with the usual notice.
	run(gone)
	reasons()
	update := nas("6.1.0")
	update.Software[0].ID, update.Software[0].Source = "s-2", "nmap"
	update.Software[0].Superseded = said + "; nmap now reads Photo Station 6.1.0, so Vedette uses that until the correction is set again"
	run(update)
	r = load()
	if last := r.History[len(r.History)-1]; r.Status != StatusSuspected || !strings.Contains(last.Note, "nmap now reads Photo Station 6.1.0") {
		t.Fatalf("new install: %+v %+v", r.Finding, last)
	}
	if got := reasons(); len(got) != 1 || got[0] != ReasonMatchesAgain {
		t.Fatalf("a new install reopens with the usual notice: %v", got)
	}

	// A CVE another row still produces stays open: the agent reads 6.1.0 next to the nmap row the person said is not there.
	both := Asset{ID: "a-1", Name: "nas01", Software: []Software{update.Software[0]}, NotInstalled: gone.NotInstalled}
	both.Software[0].Superseded = ""
	run(both)
	if r := load(); r.Status != StatusSuspected {
		t.Fatalf("another row still matches: %+v", r.Finding)
	}
}

func TestNotInstalledNote(t *testing.T) {
	t.Parallel()
	for in, want := range map[[2]string]string{
		{"op said OpenSSH 10.2 (nmap) is not installed on 17 Nov 2026", "router-1"}: "Closed: a person said the software is not installed. op said OpenSSH 10.2 (nmap) is not installed on router-1 (17 Nov 2026).",
		{"", "router-1"}: NotInstalledNote,
		{"op said OpenSSH 10.2 (nmap) is not installed on 17 Nov 2026", ""}: "Closed: a person said the software is not installed. op said OpenSSH 10.2 (nmap) is not installed on 17 Nov 2026.",
	} {
		if got := notInstalledNote(in[0], in[1]); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

// notInstalledEnv is the nas finding of a row nmap reads (suspected, version basis) and the device as inventory gives it once a person
// said that row is not installed.
func notInstalledEnv(t *testing.T) (e *env, v []Vuln, scanned, gone Asset, run func(Asset), load func() Record) {
	t.Helper()
	e = newEnv(t)
	v = []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})}
	run = func(a Asset) {
		t.Helper()
		e.advance(time.Minute)
		if _, err := e.svc.UpsertFromMatch(t.Context(), a, v); err != nil {
			t.Fatal(err)
		}
	}
	load = func() Record {
		t.Helper()
		r, err := loadByPair(t.Context(), e.db.Reader(), "a-1", "CVE-2022-27593")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	scanned = nas("6.1.1")
	scanned.Software[0].Source = "nmap"
	gone = Asset{ID: "a-1", Name: "nas01", Software: []Software{}, NotInstalled: []Software{scanned.Software[0]}}
	gone.NotInstalled[0].Correction = "op@example.com said Photo Station 6.1.1 (nmap) is not installed on 17 Nov 2026"
	run(scanned)
	return e, v, scanned, gone, run, load
}

// INV-6c: like every close by Vedette, "Not installed" never closes again a finding a person reopened after it, nor one whose risk a
// person accepted and whose acceptance expired; the history says once why it stays open.
func TestContract_INV6c_APersonsReopenAndAnExpiredAcceptanceStayOpen(t *testing.T) {
	t.Parallel()
	t.Run("reopen", func(t *testing.T) {
		t.Parallel()
		e, _, _, gone, run, load := notInstalledEnv(t)
		run(gone)
		if r := load(); r.Status != StatusNotRelevant {
			t.Fatalf("closed first: %+v", r.Finding)
		}
		if _, err := e.svc.SetStatus(t.Context(), load().ID, ActionReopen, "it is there after all", "kim@example.com"); err != nil {
			t.Fatal(err)
		}
		run(gone)
		run(gone)
		r := load()
		if r.Status != StatusSuspected {
			t.Fatalf("a person's reopen must hold: %+v", r.Finding)
		}
		if n := e.count(`SELECT count(*) FROM fnd_finding_history WHERE action = 'no_longer_matches' AND note LIKE '%This finding stays open because a person reopened it or accepted its risk%'`); n != 1 {
			t.Fatalf("the history must say once why it stays open: %d", n)
		}
	})
	t.Run("expired acceptance", func(t *testing.T) {
		t.Parallel()
		e, _, _, gone, run, load := notInstalledEnv(t)
		until := dayOf(*e.clock).AddDate(0, 0, 30)
		if _, err := e.svc.setStatus(t.Context(), load().ID, ActionAcceptRisk, "fixed next week", "kim@example.com", until); err != nil {
			t.Fatal(err)
		}
		run(gone) // accepted: not touched
		if r := load(); r.Status != StatusRiskAccepted {
			t.Fatalf("an accepted finding is not closed: %+v", r.Finding)
		}
		*e.clock = AcceptanceEnds(until).Add(time.Minute)
		if n, err := e.svc.expireAcceptances(t.Context()); err != nil || n != 1 {
			t.Fatalf("expired %d %v", n, err)
		}
		run(gone)
		if r := load(); r.Status != StatusSuspected {
			t.Fatalf("an expired acceptance reopened with a notice must not be closed silently: %+v", r.Finding)
		}
	})
}

// INV-6c: a reopen that a new reading brings is a real reopen with its notice: the agent starts reporting the very row the person said
// nmap reads wrongly. Only the person's Clear (the same row back, or a person's row) reopens without one.
func TestContract_INV6c_ANewReadingReopensWithItsNotice(t *testing.T) {
	t.Parallel()
	e, _, scanned, gone, run, load := notInstalledEnv(t)
	run(gone)
	e.pub.take()
	reason := func() string {
		t.Helper()
		for _, p := range e.pub.take() {
			if p.Name == EventStatusChanged {
				return p.Payload.(StatusChangedEvent).Reason
			}
		}
		return ""
	}
	agent := gone
	agent.Software = []Software{scanned.Software[0]}
	agent.Software[0].ID, agent.Software[0].Source = "s-agent", "agent"
	run(agent)
	if r := load(); r.Status != StatusSuspected {
		t.Fatalf("the agent's row reopens it: %+v", r.Finding)
	}
	if got := reason(); got != ReasonMatchesAgain {
		t.Fatalf("a new reading reopens with the usual notice: %q", got)
	}
	// the person's own row (they now say what is installed) reopens without one
	run(gone)
	e.pub.take()
	mine := gone
	mine.NotInstalled = nil
	mine.Software = []Software{scanned.Software[0]}
	mine.Software[0].ID, mine.Software[0].Source = "s-mine", "manual"
	run(mine)
	if got := reason(); got != ReasonNotInstalledCleared {
		t.Fatalf("a person's row reopens without a notice: %q", got)
	}
}

// INV-6c: a finding a scan confirmed stays open on a row a person said is not installed, and To fix still names that row.
func TestContract_INV6c_AScanConfirmedFindingKeepsItsSoftwareName(t *testing.T) {
	t.Parallel()
	e, v, _, gone, run, load := notInstalledEnv(t)
	e.feeds.vulns = v
	if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2022-27593", Evidence{Template: "CVE-2022-27593", CheckedAt: t0}); err != nil {
		t.Fatal(err)
	}
	run(gone)
	if r := load(); r.Status != StatusConfirmed {
		t.Fatalf("a scan-confirmed finding stays open: %+v", r.Finding)
	}
	e.inv.mu.Lock()
	e.inv.match["a-1"] = gone
	e.inv.mu.Unlock()
	u, ok, err := e.svc.DeviceUpdates(t.Context(), "a-1", false)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	acts := append(u.Exploited, u.NoUpdate...)
	if len(acts) != 1 || acts[0].Software != "Photo Station" || acts[0].Version != "6.1.1" || acts[0].SoftwareID != "s-1" {
		t.Fatalf("To fix must name the row: %+v", acts)
	}
}
