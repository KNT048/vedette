package exposure

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeTemplates is the TemplateScanner seam with canned results per port; probes says what the probe log held when it was called.
type fakeTemplates struct {
	results []TemplateResult
	notes   []string
	err     error
	jobs    [][]TemplateJob
	log     *fakeProbeLog
	logged  []int // how many probe rows were in the log at each call
}

func (f *fakeTemplates) ScanTemplates(_ context.Context, t ScanTarget, ip netip.Addr, jobs []TemplateJob) (TemplateScan, error) {
	if ip.String() != t.Value {
		return TemplateScan{}, errors.New("asked for another address than the target")
	}
	f.jobs = append(f.jobs, jobs)
	f.logged = append(f.logged, len(f.log.rows))
	return TemplateScan{Results: f.results, NotChecked: f.notes}, f.err
}

type fakeProbeLog struct {
	rows []TemplateProbe
	err  error
}

func (f *fakeProbeLog) RecordTemplateProbes(_ context.Context, p []TemplateProbe) error {
	if f.err != nil {
		return f.err
	}
	f.rows = append(f.rows, p...)
	return nil
}

// tplEnv wires services (80 Apache 2.4.49 with two exploited CVEs, 22 ssh with none), a matcher, and the template seam.
func tplEnv(t *testing.T) (*env, *fakeTemplates) {
	t.Helper()
	e := newEnv(t)
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: 98, Services: []ServiceRow{
		{IP: ipA, Port: 80, Name: "http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49"},
		{IP: ipA, Port: 22, Name: "ssh", Product: "OpenSSH", Version: "9.0"}}}}
	e.svc.cfg.Matcher = &fakeMatcher{m: Matches{Compared: 2, Listed: 1500, Vulns: []VulnRow{
		{IP: ipA, Port: 80, CVE: "CVE-2021-41773", Name: "Path traversal", Basis: "version", Summary: "In range."},
		{IP: ipA, Port: 80, CVE: "CVE-2021-42013", Name: "Path traversal 2", Basis: "version", Summary: "In range."}}}}
	probes := &fakeProbeLog{}
	f := &fakeTemplates{log: probes}
	e.svc.cfg.Templates, e.svc.cfg.Probes = f, probes
	return e, f
}

func vulnOf(s ScanResult, cve string) VulnRow {
	for _, v := range s.Vulns {
		if v.CVE == cve {
			return v
		}
	}
	return VulnRow{}
}

// INV-23: a template that matched confirms its CVE; one that did not says "no match", never "not vulnerable"; one that failed says so; a
// CVE with no template stays as it was. Only the port with an exploited CVE gets a job, the probes are in the log before the call,
// and the "what was checked" line names the templates.
func TestContract_INV23_TemplateOutcomesOnTheRows(t *testing.T) {
	t.Parallel()
	e, f := tplEnv(t)
	f.results = []TemplateResult{{Port: 80, Template: "CVE-2021-41773", CVE: "CVE-2021-41773", Outcome: OutcomeMatched},
		{Port: 80, Template: "CVE-2021-42013", CVE: "CVE-2021-42013", Outcome: OutcomeNoMatch},
		{Port: 22, Template: "CVE-2000-0001", CVE: "CVE-2000-0001", Outcome: OutcomeMatched}} // a port without a job: dropped
	s := e.scanIP(Content{})
	if len(f.jobs) != 1 || len(f.jobs[0]) != 1 {
		t.Fatalf("jobs = %+v", f.jobs)
	}
	j := f.jobs[0][0]
	if j.Port != 80 || j.Scheme != "http" || j.Host != ipA || j.Scope != ScopeOwnIP || j.RPS != TemplateRPS ||
		!slices.Equal(j.CVEs, []string{"CVE-2021-41773", "CVE-2021-42013"}) {
		t.Fatalf("job = %+v", j)
	}
	if f.logged[0] != len(j.CVEs) || !strings.Contains(f.log.rows[0].Request, ipA+":80") {
		t.Fatalf("probe rows at the call = %d, rows = %+v", f.logged[0], f.log.rows)
	}
	a, b := vulnOf(s, "CVE-2021-41773"), vulnOf(s, "CVE-2021-42013")
	if a.Basis != "template" || a.Template != "CVE-2021-41773" || a.TemplateResult != OutcomeMatched || !strings.HasPrefix(a.Summary, "Confirmed by template CVE-2021-41773") {
		t.Fatalf("matched row = %+v", a)
	}
	if b.Basis != "version" || b.TemplateResult != OutcomeNoMatch || !strings.Contains(b.Summary, "No match reported by the safe template CVE-2021-42013") ||
		strings.Contains(strings.ToLower(b.Summary), "not vulnerable") {
		t.Fatalf("no-match row = %+v", b)
	}
	if len(s.Templates) != 2 {
		t.Fatalf("stored templates = %+v", s.Templates)
	}
	var line string
	for _, c := range s.Checks {
		if c.Kind == "templates" {
			line = c.Text
		}
	}
	if !strings.Contains(line, "2 templates sent on 1 port, 1 matched, 1 no match, 0 error") || !strings.Contains(line, "CVE-2021-41773") {
		t.Fatalf("checks line = %q", line)
	}
	if vulnOf(s, "CVE-2021-41773").Basis != "template" {
		t.Fatalf("vulns = %+v", s.Vulns)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'nuclei' AND key = 'CVE-2021-41773' AND state = 'open'`); n != 1 {
		t.Fatalf("%d nuclei issues for the matched template", n)
	}
}

func TestContract_INV23_ErrorUnavailableAndNotSetUp(t *testing.T) {
	t.Parallel()
	e, f := tplEnv(t)
	f.results = []TemplateResult{{Port: 80, Template: "CVE-2021-41773", CVE: "CVE-2021-41773", Outcome: OutcomeError}}
	s := e.scanIP(Content{})
	if v := vulnOf(s, "CVE-2021-41773"); v.Basis != "version" || v.TemplateResult != OutcomeError || !strings.Contains(v.Summary, "neither confirmed nor ruled this out") {
		t.Fatalf("error row = %+v", v)
	}

	e, f = tplEnv(t)
	f.err = &Unavailable{Reason: "the scan container is busy"}
	s = e.scanIP(Content{})
	if !slices.Contains(notChecked(s), "Safe templates for exploited vulnerabilities did not run: the scan container is busy") || vulnOf(s, "CVE-2021-41773").Basis != "version" {
		t.Fatalf("not checked = %q", notChecked(s))
	}

	e, _ = tplEnv(t)
	e.svc.cfg.Templates = nil
	if s = e.scanIP(Content{}); !slices.Contains(notChecked(s), NotSetUpTemplates) {
		t.Fatalf("not checked = %q", notChecked(s))
	}
}

// INV-23: no probe log, no probe: a log that cannot be written stops the step before the scanner is called.
func TestContract_INV23_NothingIsSentWithoutTheProbeLog(t *testing.T) {
	t.Parallel()
	e, f := tplEnv(t)
	f.log.err = errors.New("disk full")
	s := e.scanIP(Content{})
	if len(f.jobs) != 0 || !slices.Contains(notChecked(s), notTemplatesNoLog) {
		t.Fatalf("calls = %d, not checked = %q", len(f.jobs), notChecked(s))
	}
	e, f = tplEnv(t)
	e.svc.cfg.Probes = nil
	s = e.scanIP(Content{})
	if len(f.jobs) != 0 || !slices.Contains(notChecked(s), notTemplatesNoLog) {
		t.Fatalf("calls = %d, not checked = %q", len(f.jobs), notChecked(s))
	}
}

// INV-23: a port with more than 32 exploited CVEs gets jobs of at most 32; a paused target and a domain get no job.
func TestContract_INV23_JobSizeAndWhoGetsOne(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr(ipA)
	var vulns []VulnRow
	for i := 0; i < 70; i++ {
		vulns = append(vulns, VulnRow{IP: ipA, Port: 80, CVE: fmt.Sprintf("CVE-2021-%04d", 1000+i)})
	}
	vulns = append(vulns, VulnRow{IP: ipA, Port: 9999, CVE: "CVE-2021-9999"}) // not an identified port: no job
	jobs, skipped := buildJobs(ip, []ServiceRow{{IP: ipA, Port: 80, Name: "https"}}, vulns)
	if len(jobs) != 3 || skipped != 0 || len(jobs[0].CVEs) != TemplatesPerJob || len(jobs[2].CVEs) != 6 || jobs[0].Scheme != "https" {
		t.Fatalf("jobs = %+v", jobs)
	}

	e, f := tplEnv(t)
	a := e.committedIP(ipA)
	e.advance(time.Minute)
	e.fullAs(ipB) // a full check that does not see A pauses it
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", a.ID); err == nil || len(f.jobs) != 0 {
		t.Fatalf("paused target scanned: %v, calls %d", err, len(f.jobs))
	}
	dom := e.committedDomain()
	e.advance(ScanEvery)
	e.svc.SetRunner(&fakeRunner{})
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID); err != nil || len(f.jobs) != 0 {
		t.Fatalf("domain: %v, calls %d", err, len(f.jobs))
	}
}

// INV-22, INV-23: a port an earlier scan saw and this one missed is carried with the templates it had and is not probed again.
func TestContract_INV23_CarriedPortIsNotProbedAgain(t *testing.T) {
	t.Parallel()
	e, f := tplEnv(t)
	f.results = []TemplateResult{{Port: 80, Template: "CVE-2021-41773", CVE: "CVE-2021-41773", Outcome: OutcomeMatched}}
	first := e.scanIP(Content{Ports: []PortRow{{IP: ipA, Port: 80}}})
	id := e.detectedID(ipA)
	// the next scan's nmap answers nothing for port 80 (a miss)
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: 98}}
	e.svc.SetRunner(&fakeRunner{content: Content{Ports: []PortRow{{IP: ipA, Port: 443}}}})
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if len(f.jobs) != 1 {
		t.Fatalf("the carried port was probed again: %d calls", len(f.jobs))
	}
	got, err := first, error(nil)
	if err != nil || len(got.Templates) != 1 || got.Templates[0].Outcome != OutcomeMatched {
		t.Fatalf("carried templates = %+v, %v", got.Templates, err)
	}
}

// INV-23: what the scanner says is untrusted; a result for another CVE or port, or with a bad id, is dropped.
func TestContract_INV23_SanitizeResults(t *testing.T) {
	t.Parallel()
	jobs := []TemplateJob{{Port: 80, CVEs: []string{"CVE-2021-41773"}}}
	got, _ := sanitizeTemplateResults([]TemplateResult{
		{Port: 80, Template: "CVE-2021-41773", CVE: "CVE-2021-41773", Outcome: OutcomeMatched},
		{Port: 80, Template: "CVE-2021-41773", CVE: "CVE-2021-41773", Outcome: OutcomeNoMatch}, // twice
		{Port: 80, Template: "x", CVE: "CVE-2099-0001", Outcome: OutcomeMatched},               // a CVE nobody asked for
		{Port: 81, Template: "y", Outcome: OutcomeMatched},                                     // another port
		{Port: 80, Template: "../etc", Outcome: OutcomeMatched},                                // a bad id
		{Port: 80, Template: "z", Outcome: "vulnerable"},                                       // a bad outcome
		{Port: 80, Template: "apache-tag", Outcome: OutcomeNoMatch},                            // no CVE: nothing asked for it
		{Port: 80, Template: "CVE-2021-41773-b", CVE: "CVE-2021-41773", Outcome: OutcomeNoMatch},
	}, jobs)
	if len(got) != 2 || got[0].Outcome != OutcomeMatched || got[1].Template != "CVE-2021-41773-b" {
		t.Fatalf("got = %+v", got)
	}
}

// INV-23: TLS comes from the data ("ssl/http" is nmap's tunnel="ssl"), on any port; any other "http" is https on the
// well-known TLS ports (a TLS server's plaintext error page can make nmap read "http nginx" there) and http elsewhere.
func TestContract_INV23_SchemeOfTLSServices(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, product string
		port          int
		want          string
	}{{"http", "", 443, "https"}, {"http", "", 8443, "https"}, {"http", "nginx", 443, "https"}, {"http", "Apache httpd", 9443, "https"},
		{"ssl/http", "", 9000, "https"}, {"ssl/http", "lighttpd", 4443, "https"}, {"https-alt", "", 8080, "https"},
		{"http", "", 80, "http"}, {"http", "nginx", 4443, "http"}, {"http-proxy", "", 3128, "http"}, {"ssh", "", 22, ""}} {
		if got := schemeOf(ServiceRow{Name: tc.name, Product: tc.product, Port: tc.port}); got != tc.want {
			t.Errorf("schemeOf(%s %s:%d) = %q, want %q", tc.name, tc.product, tc.port, got, tc.want)
		}
	}
}

// An HTTPS admin page on 4443 that nmap read as name="http" tunnel="ssl" reaches the template step as "ssl/http" and its
// job speaks https, so the KEV template really runs over TLS instead of "No match reported" from a plain-HTTP request.
func TestContract_INV23_TLSOnANonStandardPortGetsHTTPS(t *testing.T) {
	t.Parallel()
	e, f := tplEnv(t)
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: 98, Services: []ServiceRow{
		{IP: ipA, Port: 4443, Name: "ssl/http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49"}}}}
	e.svc.cfg.Matcher = &fakeMatcher{m: Matches{Compared: 1, Listed: 1500, Vulns: []VulnRow{{IP: ipA, Port: 4443, CVE: "CVE-2021-41773", Basis: "version"}}}}
	e.scanIP(Content{Ports: []PortRow{{IP: ipA, Port: 4443}}})
	if len(f.jobs) != 1 || len(f.jobs[0]) != 1 || f.jobs[0][0].Port != 4443 || f.jobs[0][0].Scheme != "https" {
		t.Fatalf("jobs = %+v", f.jobs)
	}
}

// An address that answers on more than 40 ports (a router or SYN proxy): the default scan still asks for service
// identification, which reads the fixed list and keeps the ports where a service named itself, so the services are stored and
// compared and one "Not checked" line says the address answers everywhere (the surface scan saw it, or the scanner said so;
// exactly 40 is a normal scan; ports of another address do not count; an IPv4-mapped address counts as itself). A scanner error
// that says it (ErrAnswersEverywhere) or nmap's limit are their own lines: no template and no web page runs, and no line says
// "no services".
func TestContract_INV19_AnswersEverywhereAndTimedOut(t *testing.T) {
	t.Parallel()
	open := func(n int, ip string) []PortRow {
		var out []PortRow
		for p := 1; p <= n; p++ {
			out = append(out, PortRow{IP: ip, Port: p})
		}
		return out
	}
	one := []PortRow{{IP: ipA, Port: 80}}
	for name, tc := range map[string]struct {
		ports      []PortRow
		svcErr     error
		everywhere bool     // the scanner says the address answers everywhere
		kept       bool     // identified and checked, with the "answers everywhere" line
		want       []string // lines that must be under "Not checked"
	}{
		"41 open on the surface": {ports: open(41, ipA), kept: true},
		"60 open, IPv4-mapped":   {ports: open(60, "::ffff:"+ipA), kept: true},
		"the scanner says it":    {ports: one, everywhere: true, kept: true},
		"exactly 40 open":        {ports: open(40, ipA)},
		"60 open on another IP":  {ports: append(open(60, ipB), one...)},
		"nmap saw it (an error)": {ports: one, svcErr: ErrAnswersEverywhere, want: []string{notAnswersEverywhere, notWebTarpit}},
		"nmap timed out":         {ports: one, svcErr: ErrServicesTimedOut, want: []string{notServicesGaveUp, notTemplatesNoIdent, notWebNoIdent}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, f := tplEnv(t)
			sv := &fakeServices{scan: ServiceScan{Ports: 98, AnswersEverywhere: tc.everywhere, Services: []ServiceRow{{IP: ipA, Port: 80, Name: "http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49"}}}, err: tc.svcErr}
			web := &fakeWeb{report: func(string) []byte { return nil }}
			e.svc.cfg.Services, e.svc.cfg.Web = sv, web
			s := e.scanIP(Content{Ports: tc.ports})
			if len(sv.calls) != 1 { // the default scan always asks for service identification
				t.Fatalf("service scanner called %d times", len(sv.calls))
			}
			if tc.want == nil { // identified and checked as usual
				if len(s.Services) != 1 || len(f.jobs) != 1 || slices.Contains(notChecked(s), notAnswersEverywhere) || slices.Contains(notChecked(s), notAnswersEverywhereKept) != tc.kept {
					t.Fatalf("services %+v, jobs %d, not checked %q", s.Services, len(f.jobs), notChecked(s))
				}
				return
			}
			for _, w := range tc.want {
				if !slices.Contains(notChecked(s), w) {
					t.Errorf("missing line %q in %q", w, notChecked(s))
				}
			}
			if len(s.Services) != 0 || len(f.jobs) != 0 || len(web.asked) != 0 {
				t.Fatalf("services %+v, template jobs %d, web pages %v", s.Services, len(f.jobs), web.asked)
			}
			for _, n := range notChecked(s) {
				if l := strings.ToLower(n); strings.Contains(l, "no services") || strings.Contains(l, "no service was identified") || strings.Contains(l, "no web port was identified") {
					t.Errorf("a line claims nothing is there: %q", n)
				}
			}
			for _, c := range s.Checks {
				if c.Kind == "services" || c.Kind == "templates" {
					t.Fatalf("a %s check line for a result that says nothing: %q", c.Kind, c.Text)
				}
			}
		})
	}
}

// INV-23: a match is never dropped to the cap, and jobs over the limit are said, not hidden.
func TestContract_INV23_MatchSurvivesTheCapAndSkippedJobsAreSaid(t *testing.T) {
	t.Parallel()
	var in []TemplateResult
	cves := []string{}
	for i := 0; i < 40; i++ {
		c := fmt.Sprintf("CVE-2021-%04d", 2000+i)
		cves = append(cves, c)
		o := OutcomeNoMatch
		if i == 39 {
			o = OutcomeMatched
		}
		in = append(in, TemplateResult{Port: 80, Template: c, CVE: c, Outcome: o})
	}
	got, _ := sanitizeTemplateResults(in, []TemplateJob{{Port: 80, CVEs: cves}})
	if len(got) != 40 || got[0].Outcome != OutcomeMatched {
		t.Fatalf("got %d, first %+v", len(got), got[0])
	}
	var many []TemplateResult
	for i := 0; i < 300; i++ {
		c := fmt.Sprintf("CVE-2021-%04d", 3000+i)
		o := OutcomeNoMatch
		if i == 299 {
			o = OutcomeMatched
		}
		many = append(many, TemplateResult{Port: 80, Template: c, CVE: c, Outcome: o})
	}
	rows := sanitizeTemplates(templateRows([]ServiceRow{{IP: ipA, Port: 80}}, netip.MustParseAddr(ipA), many), []ServiceRow{{IP: ipA, Port: 80}})
	if len(rows) != maxTemplateRows || rows[0].Outcome != OutcomeMatched {
		t.Fatalf("rows = %d, first %+v", len(rows), rows[0])
	}
	var vulns []VulnRow
	for i := 0; i < TemplatesPerJob*maxTemplateJobs+5; i++ {
		vulns = append(vulns, VulnRow{IP: ipA, Port: 80, CVE: fmt.Sprintf("CVE-2022-%05d", i)})
	}
	jobs, skipped := buildJobs(netip.MustParseAddr(ipA), []ServiceRow{{IP: ipA, Port: 80, Name: "http"}}, vulns)
	if len(jobs) != maxTemplateJobs || skipped != 5 {
		t.Fatalf("jobs = %d, skipped = %d", len(jobs), skipped)
	}
}

// fakeServicesThen is a ServiceScanner whose scan ends by changing the world, as an admin or a full check can while the scan runs.
type fakeServicesThen struct {
	ServiceScanner
	after func()
}

func (f fakeServicesThen) ScanServices(ctx context.Context, t ScanTarget, ip netip.Addr) (ServiceScan, error) {
	r, err := f.ServiceScanner.ScanServices(ctx, t, ip)
	f.after()
	return r, err
}

// INV-23 (M1): the gate runs again right before the step: an IP whose proof ran out while nmap ran gets no probe log row and no call.
func TestContract_INV23_GateRunsAgainBeforeTheTemplates(t *testing.T) {
	t.Parallel()
	e, f := tplEnv(t)
	e.svc.cfg.Services = fakeServicesThen{ServiceScanner: e.svc.cfg.Services, after: func() {
		e.prober.set(ipB)   // the box goes out through another IP
		e.advance(91 * day) // and A has not been seen for 90 days: expired
	}}
	s := e.scanIP(Content{})
	if len(f.jobs) != 0 || len(f.log.rows) != 0 || !slices.Contains(notChecked(s), notTemplatesGate) {
		t.Fatalf("calls = %d, rows = %d, not checked = %q", len(f.jobs), len(f.log.rows), notChecked(s))
	}
}

// The scanner's own "Not checked" sentences (a CVE whose template is not a read-only request, a run that did not finish) are
// shown next to the results it kept, at most maxTemplateNotes of them, the last saying how many more there were.
func TestContract_INV23_ScannerNotCheckedLines(t *testing.T) {
	t.Parallel()
	e, f := tplEnv(t)
	f.results = []TemplateResult{{Port: 80, Template: "CVE-2021-41773", CVE: "CVE-2021-41773", Outcome: OutcomeMatched}}
	f.notes = []string{"Safe templates for exploited vulnerabilities: CVE-2021-42013 on port 80 was not run on a public IP: this check is not a read-only request."}
	for range 10 {
		f.notes = append(f.notes, "x")
	}
	s := e.scanIP(Content{})
	n := 0
	for _, r := range s.NotChecked {
		if r.Kind == "templates" {
			n++
		}
	}
	if vulnOf(s, "CVE-2021-41773").Basis != "template" || n != maxTemplateNotes ||
		!slices.ContainsFunc(s.NotChecked, func(r NotCheckedRow) bool { return strings.HasSuffix(r.Text, "and 4 more lines like these.") }) ||
		!slices.ContainsFunc(s.NotChecked, func(r NotCheckedRow) bool { return strings.Contains(r.Text, "not a read-only request") }) {
		t.Fatalf("%d lines: %+v", n, s.NotChecked)
	}
}

// A template counts as having looked at a port only when it ran there and found nothing: a match is a finding, and a call that
// failed or was refused leaves every port unchecked, so a template issue there is not taken as fixed.
func TestTemplatesRanOnlyWhereTheCallAnswered(t *testing.T) {
	t.Parallel()
	e, f := tplEnv(t)
	f.results = []TemplateResult{{Port: 80, Template: "CVE-2021-41773", CVE: "CVE-2021-41773", Outcome: OutcomeMatched},
		{Port: 80, Template: "CVE-2021-42013", CVE: "CVE-2021-42013", Outcome: OutcomeNoMatch}}
	if s := e.scanIP(Content{}); !slices.Equal(s.TemplatesRan, []string{ipA + ":80|CVE-2021-42013"}) {
		t.Fatalf("answered: ran on %q", s.TemplatesRan)
	}
	e2, f2 := tplEnv(t)
	f2.err = errors.New("nuclei timed out")
	if s := e2.scanIP(Content{}); len(s.TemplatesRan) != 0 {
		t.Fatalf("failed: ran on %q", s.TemplatesRan)
	}
}

// Only the results the scanner reports decide what ran: a port whose run never went out, an error outcome and a template that is not
// a known template id give no coverage.
func TestTemplatesCoveredOnlyNoMatchResults(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr(ipA)
	jobs := []TemplateJob{{Port: 80}, {Port: 443}}
	got := TemplatesCovered(ip, jobs, TemplateScan{Results: []TemplateResult{
		{Port: 80, Template: "CVE-2021-41773", Outcome: OutcomeNoMatch},
		{Port: 80, Template: "CVE-2021-42013", Outcome: OutcomeError},
		{Port: 80, Template: "CVE-2021-44228", Outcome: OutcomeMatched},
		{Port: 8080, Template: "CVE-2021-41773", Outcome: OutcomeNoMatch},
		{Port: 80, Template: "../x", Outcome: OutcomeNoMatch},
	}})
	if !slices.Equal(got, []string{ipA + ":80|CVE-2021-41773"}) {
		t.Fatalf("covered %q", got)
	}
}
