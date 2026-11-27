package exposure

import "testing"

// A rule the host says the target's settings left out of a page (WebScan.SkippedRules: a class of the disruptive rules turned off,
// a rule that requests fixed file names while paths are skipped) did not look at the page again: its open issues there stay open,
// while the issues of the rules that ran are closed as before. A later pass that runs the rule and no longer finds it closes them.
func TestZapActive_ARuleTheSettingsLeftOutClosesNoIssue(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireActive(xssReport)
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	open := func(plugin string) int {
		return e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND key LIKE '` + plugin + `@%' AND state = 'open'`)
	}
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	first := open("40012")
	if first == 0 {
		t.Fatal("the first pass opened no issue of 40012")
	}
	w.active, w.skipped = emptyReport, []string{"40012"}
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if open("40012") != first {
		t.Fatalf("a pass that left rule 40012 out closed %d of its issues", first-open("40012"))
	}
	w.skipped = nil
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if open("40012") != 0 {
		t.Fatalf("a pass that ran rule 40012 left %d of its issues open", open("40012"))
	}
}
