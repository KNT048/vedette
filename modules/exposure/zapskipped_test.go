package exposure

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

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

// An alert seen only under a web path the target now skips was not looked at again: ZAP never requested that path (the host keeps
// it out of the spider and of both passes), so its issue stays open while the path is skipped, on either pass. Alerts elsewhere on
// the page close as before, and once the path is no longer skipped a pass that no longer finds the alert closes its issue.
func TestZap_AnAlertUnderASkippedPathIsNotGone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	underAdmin := func(plugin, name string) func(string) []byte {
		return func(page string) []byte {
			return []byte(fmt.Sprintf(`{"site":[{"@name":%q,"alerts":[{"pluginid":%q,"alert":%q,"riskcode":"2","confidence":"2","cweid":"79","instances":[{"uri":%q}]}]}]}`,
				strings.TrimSuffix(page, "/"), plugin, name, page+"ADMIN/search"))
		}
	}
	w := e.wireActive(underAdmin("40012", "Cross Site Scripting (Reflected)"))
	w.report = func(page string) []byte {
		return []byte(fmt.Sprintf(`{"site":[{"@name":%q,"alerts":[{"pluginid":"10036","alert":"Server Leaks Version","riskcode":"1","confidence":"3","cweid":"200","instances":[{"uri":%q},{"uri":%q}]}]}]}`,
			strings.TrimSuffix(page, "/"), page+"admin/login", page+"admin/"))
	}
	e.svc.cfg.Web = pathWeb{w}
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	open := func(plugin string) int {
		return e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND key LIKE '` + plugin + `@%' AND state = 'open'`)
	}
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	active, passive := open("40012"), open("10036")
	if active == 0 || passive == 0 {
		t.Fatalf("the first pass opened %d issues of 40012 and %d of 10036", active, passive)
	}
	e.deepRow(id, false, true, true, true, true, SpeedNormal, "[]", `["/admin"]`)
	w.active, w.report = emptyReport, emptyReport
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if len(w.calls) < 2 || !slices.Equal(w.calls[len(w.calls)-1].SkipPaths, []string{"/admin"}) {
		t.Fatalf("the second active pass did not run with the path to skip: %d calls", len(w.calls))
	}
	if open("40012") != active || open("10036") != passive {
		t.Fatalf("a pass that never requested /admin closed issues seen only there: 40012 %d of %d open, 10036 %d of %d open",
			open("40012"), active, open("10036"), passive)
	}
	e.deepRow(id, false, true, true, true, true, SpeedNormal, "[]", "[]")
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if open("40012") != 0 || open("10036") != 0 {
		t.Fatalf("a pass that requested /admin again left issues open: 40012 %d, 10036 %d", open("40012"), open("10036"))
	}
}
