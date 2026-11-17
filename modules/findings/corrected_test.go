package findings

import (
	"strings"
	"testing"
	"time"
)

// Review r1 M3 of #950 (inventory INV-39): a finding Vedette closes or reopens because of a person's correction says who corrected what
// and when, in the close note and the history, instead of reading as Vedette's own proof.
func TestContract_INV39_ACorrectionNamesThePersonInTheHistory(t *testing.T) {
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
	run(nas("6.1.1"))
	corrected := nas("6.2.0")
	corrected.Software[0].Source, corrected.Software[0].ReportedSource = "manual", "nmap"
	corrected.Software[0].Correction = "it@acme.example corrected Photo Station 6.1.1 (nmap) to Photo Station 6.2.0 on 17 Nov 2026"
	run(corrected)
	r, err := loadByPair(t.Context(), e.db.Reader(), "a-1", "CVE-2022-27593")
	if err != nil {
		t.Fatal(err)
	}
	const why = "This follows a person's correction: it@acme.example corrected Photo Station 6.1.1 (nmap) to Photo Station 6.2.0 on 17 Nov 2026."
	if r.Status != StatusNotRelevant || !strings.HasSuffix(r.ResolutionNote, why) {
		t.Fatalf("the close must name the correction: %+v", r.Finding)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_history WHERE action = 'not_relevant' AND note LIKE '%it@acme.example corrected Photo Station%'`); n != 1 {
		t.Fatalf("history rows %d", n)
	}
	// The correction changed to an affected version: the reopen names it too.
	back := nas("6.0.0")
	back.Software[0].Source, back.Software[0].ReportedSource = "manual", "nmap"
	back.Software[0].Correction = "it@acme.example corrected Photo Station 6.1.1 (nmap) to Photo Station 6.0.0 on 18 Nov 2026"
	run(back)
	if n := e.count(`SELECT count(*) FROM fnd_finding_history WHERE action = 'matches_again' AND note LIKE '%to Photo Station 6.0.0 on 18 Nov 2026.'`); n != 1 {
		t.Fatalf("the reopen must name the correction: %d", n)
	}
}

func TestCorrectionWhy(t *testing.T) {
	t.Parallel()
	a := Asset{OSCorrection: "op set the OS to Alpine Linux 3.23 on 17 Nov 2026", Software: []Software{
		{ID: "s-1", Correction: "op corrected OpenSSH 10.2 (nmap) to OpenSSH 10.2p1 on 17 Nov 2026"}, {ID: "s-2"},
	}}
	for id, want := range map[string]string{
		"s-1":  "This follows a person's correction: op corrected OpenSSH 10.2 (nmap) to OpenSSH 10.2p1 on 17 Nov 2026; op set the OS to Alpine Linux 3.23 on 17 Nov 2026.",
		"s-2":  "This follows a person's correction: op set the OS to Alpine Linux 3.23 on 17 Nov 2026.",
		"os:x": "This follows a person's correction: op set the OS to Alpine Linux 3.23 on 17 Nov 2026.",
		"":     "This device has a person's correction: op corrected OpenSSH 10.2 (nmap) to OpenSSH 10.2p1 on 17 Nov 2026; op set the OS to Alpine Linux 3.23 on 17 Nov 2026.",
	} {
		if got := correctionWhy(a, id); got != want {
			t.Errorf("%q: %q", id, got)
		}
	}
	if correctionWhy(Asset{Software: []Software{{ID: "s-1"}}}, "s-1") != "" {
		t.Error("no correction, no words")
	}
}
