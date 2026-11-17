package findings

import (
	"strings"
	"testing"
	"time"
)

// INV-6c (inventory INV-41 (6), kien G15): a person says the Photo Station row a scan reported is not installed. Inventory leaves the
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
		{"op said OpenSSH 10.2 (nmap) is not installed on 17 Nov 2026", "BN340"}: "Closed: a person said the software is not installed. op said OpenSSH 10.2 (nmap) is not installed on BN340 (17 Nov 2026).",
		{"", "BN340"}: NotInstalledNote,
		{"op said OpenSSH 10.2 (nmap) is not installed on 17 Nov 2026", ""}: "Closed: a person said the software is not installed. op said OpenSSH 10.2 (nmap) is not installed on 17 Nov 2026.",
	} {
		if got := notInstalledNote(in[0], in[1]); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
