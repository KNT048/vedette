package exposure

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// FULL-4 (Trưởng), for Mlee (D-527): the template step of a Full scan.

// deadlineTemplates records the time left before the step's bound when it is called.
type deadlineTemplates struct {
	*fakeTemplates
	left time.Duration
	mode ScanMode
}

func (d *deadlineTemplates) ScanTemplates(ctx context.Context, t ScanTarget, ip netip.Addr, jobs []TemplateJob) (TemplateScan, error) {
	if dl, ok := ctx.Deadline(); ok {
		d.left = time.Until(dl)
	}
	d.mode = t.Mode
	return d.fakeTemplates.ScanTemplates(ctx, t, ip, jobs)
}

// In a Full scan every identified port gets a job of depth full, CVE-matched or not, with what nmap read; the step's bound follows
// the ports (10 minutes a web port, 2 another) instead of 5 minutes; a deep result without a CVE is stored with its name and
// severity; one with a bad name or severity is not.
func TestFull_JobsForEveryPortAndTheBoundFollowsTheMode(t *testing.T) {
	t.Parallel()
	e, f := tplEnv(t)
	d := &deadlineTemplates{fakeTemplates: f}
	e.svc.cfg.Templates = d
	no := false
	e.terms = &no
	f.results = []TemplateResult{
		{Port: 80, Template: "git-config", Outcome: OutcomeMatched, Name: "Git Configuration - Detect", Severity: "medium"},
		{Port: 80, Template: "nginx-version", Outcome: OutcomeNoMatch, Name: "Nginx Version", Severity: "info"}, // a deep no-match is not kept
		{Port: 22, Template: "bad-name", Outcome: OutcomeMatched, Name: "a\nb", Severity: "high"},
		{Port: 80, Template: "CVE-2021-41773", CVE: "CVE-2021-41773", Outcome: OutcomeNoMatch, Name: "Apache 2.4.49", Severity: "high"},
	}
	s := e.scanIP(Content{})
	if !d.mode.Full || len(f.jobs) != 1 || len(f.jobs[0]) != 2 {
		t.Fatalf("mode %+v, jobs %+v", d.mode, f.jobs)
	}
	ssh, web := f.jobs[0][0], f.jobs[0][1] // in port order
	if ssh.Port != 22 || ssh.Depth != DepthFull || len(ssh.CVEs) != 0 || ssh.Service != "ssh" || ssh.Product != "OpenSSH" || ssh.Scheme != "" || ssh.RPS != FullTemplateRPS {
		t.Fatalf("ssh job %+v", ssh)
	}
	if web.Port != 80 || web.Depth != DepthFull || len(web.CVEs) != 2 || web.CPE == "" || web.Scheme != "http" {
		t.Fatalf("web job %+v", web)
	}
	if want := fullWebPort + fullOtherPort; d.left > want || d.left < want-time.Minute {
		t.Fatalf("bound %s, want about %s", d.left, want)
	}
	if f.logged[0] != 2 || !strings.Contains(f.log.rows[0].Request, "deep templates") {
		t.Fatalf("planned rows %d: %+v", f.logged[0], f.log.rows)
	}
	var deep, kev TemplateRow
	for _, r := range s.Templates {
		switch r.Template {
		case "git-config":
			deep = r
		case "CVE-2021-41773":
			kev = r
		case "nginx-version", "bad-name":
			t.Errorf("kept %+v", r)
		}
	}
	if deep.CVE != "" || deep.Name != "Git Configuration - Detect" || deep.Severity != "medium" || deep.Port != 80 || deep.Outcome != OutcomeMatched {
		t.Fatalf("deep row %+v (all %+v)", deep, s.Templates)
	}
	if kev.Outcome != OutcomeNoMatch || kev.Name != "Apache 2.4.49" {
		t.Fatalf("KEV row of a full job %+v", kev)
	}
	var line string
	for _, c := range s.Checks {
		if c.Kind == "templates" {
			line = c.Text
		}
	}
	if !strings.HasPrefix(line, "Deep templates (nuclei, testing terms accepted, at most 20 requests a second") {
		t.Fatalf("line %q", line)
	}
}

// Without the terms the step is what it was: jobs only for CVE-matched ports, at 5 a second, bounded by 5 minutes.
func TestFull_NoTermsKeepsTheKEVStep(t *testing.T) {
	t.Parallel()
	e, f := tplEnv(t)
	d := &deadlineTemplates{fakeTemplates: f}
	e.svc.cfg.Templates = d
	e.scanIP(Content{})
	if d.mode.Full || len(f.jobs[0]) != 1 || f.jobs[0][0].Depth != "" || f.jobs[0][0].RPS != TemplateRPS || d.left > TemplatesTimeout || d.left < TemplatesTimeout-time.Minute {
		t.Fatalf("mode %+v, jobs %+v, bound %s", d.mode, f.jobs, d.left)
	}
}

func TestFull_TimeoutOfThePorts(t *testing.T) {
	t.Parallel()
	web := TemplateJob{Port: 443, Scheme: "https"}
	other := TemplateJob{Port: 22}
	if got := FullTemplatesTimeout([]TemplateJob{web, web, other}); got != fullWebPort+fullOtherPort {
		t.Errorf("one web and one other port: %s", got)
	}
	var many []TemplateJob
	for p := 1; p <= 20; p++ {
		many = append(many, TemplateJob{Port: p, Scheme: "http"})
	}
	if got := FullTemplatesTimeout(many); got != fullTemplatesCap {
		t.Errorf("20 web ports: %s, want the cap %s", got, fullTemplatesCap)
	}
	if got := fmtSlow(fullWebPort); got != "Deep templates did not finish within 10 minutes, so the ones that had not finished are not reported." {
		t.Errorf("%q", got)
	}
}

func fmtSlow(d time.Duration) string { return strings.Replace(notFullSlow, "%s", minutes(d), 1) }
