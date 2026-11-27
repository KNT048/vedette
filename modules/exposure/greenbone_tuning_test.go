package exposure

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The generic web fuzzing OpenVAS runs is left to the web scanner: its checkbox is off and the three directory-traversal tests
// are out of the web family, in every level (each of those tests ran to its 30-minute timeout and found nothing).
func TestOpenVASTuning_WebFuzzingIsOffInEveryLevel(t *testing.T) {
	t.Parallel()
	traversal := []string{"1.3.6.1.4.1.25623.1.0.106756", "1.3.6.1.4.1.25623.1.0.113002", "1.3.6.1.4.1.25623.1.0.117574"}
	for _, disruptive := range []bool{false, true} {
		e, h := gbEnv(t)
		h.gvm.with(func(g *fakeGVM) { g.webExtra = []string{"1.3.6.1.4.1.25623.1.0.200000"} })
		e.enable()
		e.terms = &disruptive
		e.scanIP(gbOpen())
		name := "vedette-deep-full-and-fast"
		if disruptive {
			name = "vedette-disruptive-full-and-fast"
		}
		c, used := h.gvm.cfg(name)
		if used != name {
			t.Fatalf("disruptive=%v: the task used %q, want %q", disruptive, used, name)
		}
		if v := c.prefs["Enable generic web application scanning"]; v != "no" {
			t.Errorf("disruptive=%v: generic web application scanning = %q, want no", disruptive, v)
		}
		for _, oid := range traversal {
			if slices.Contains(c.web, oid) {
				t.Errorf("disruptive=%v: traversal test %s is still selected", disruptive, oid)
			}
		}
		if !slices.Contains(c.web, "1.3.6.1.4.1.25623.1.0.200000") {
			t.Errorf("disruptive=%v: the rest of the web family is not selected: %q", disruptive, c.web)
		}
	}
}

// The family selection is what "Full and fast" selects, growing flags included: a family it selects only in part (its two port
// scanners) is copied NVT by NVT, never switched on whole, and the disruptive families are the only difference of the deep level.
func TestOpenVASTuning_FamiliesAreTheBaseConfigs(t *testing.T) {
	t.Parallel()
	ports := []string{"1.3.6.1.4.1.25623.1.0.10180", "1.3.6.1.4.1.25623.1.0.100315"}
	faf := []fakeFam{
		{name: "General", count: 400, max: 400, growing: true},
		{name: "Port scanners", count: 2, max: 9, nvts: ports},
		{name: "Service detection", count: 300, max: 300, growing: true},
		{name: "Web application abuses", count: 3, max: 3, growing: true},
		{name: "Brute force attacks", count: 50, max: 50, growing: true},
		{name: "Default Accounts", count: 20, max: 20, growing: true},
		{name: "Denial of Service", count: 30, max: 30, growing: true},
	}
	for _, disruptive := range []bool{false, true} {
		e, h := gbEnv(t)
		h.gvm.with(func(g *fakeGVM) { g.faf = faf })
		e.enable()
		e.terms = &disruptive
		s := e.scanIP(gbOpen())
		name := "vedette-deep-full-and-fast"
		if disruptive {
			name = "vedette-disruptive-full-and-fast"
		}
		c, used := h.gvm.cfg(name)
		if used != name {
			t.Fatalf("disruptive=%v: not started: used %q, not checked %q", disruptive, used, notChecked(s))
		}
		var want []string
		for _, f := range faf {
			if disruptive || !slices.Contains(gmpDisruptiveFamilies, f.name) {
				if f.nvts == nil {
					want = append(want, f.name)
				}
			}
		}
		for _, f := range want {
			if !slices.Contains(c.families, f) {
				t.Errorf("disruptive=%v: family %q is not selected: %q", disruptive, f, c.families)
			}
		}
		for _, f := range c.families {
			if f == "Port scanners" {
				t.Errorf("disruptive=%v: Port scanners is switched on whole, Full and fast selects two of its NVTs", disruptive)
			}
		}
		if !slices.Equal(c.sel["Port scanners"], ports) {
			t.Errorf("disruptive=%v: Port scanners NVTs = %q, want %q", disruptive, c.sel["Port scanners"], ports)
		}
		if got := slices.ContainsFunc(c.families, func(f string) bool { return slices.Contains(gmpDisruptiveFamilies, f) }); got != disruptive {
			t.Errorf("disruptive=%v: disruptive families on = %v", disruptive, got)
		}
	}
}

func fxResult(name, oid, port string, sev, qod int, detail string) string {
	return `<result><name>` + name + `</name><host>` + ipA + `</host><port>` + port + `</port><nvt oid="` + oid + `"><name>` + name +
		`</name><refs><ref type="cve" id="CVE-2024-6387"/></refs></nvt><severity>` + fmt.Sprint(sev) + `</severity><qod><value>` + fmt.Sprint(qod) +
		`</value></qod><description>` + detail + `</description></result>`
}

func fxWrap(results ...string) string {
	return `<get_reports_response status="200"><report id="` + gbReportID + `"><report id="` + gbReportID + `"><results>` + strings.Join(results, "") +
		`</results></report></report></get_reports_response>`
}

// A configuration fact at the log level (SSH offering password logins) becomes a Low issue with its fix line; a banner-guessed CVE
// with a low QoD and a log note that is no fact stay hidden.
func TestOpenVASTuning_ConfigurationFactBecomesALowIssue(t *testing.T) {
	t.Parallel()
	raw := fxWrap(
		fxResult("SSH Server type and version", "1.3.6.1.4.1.25623.1.0.10267", "22/tcp", 0, 80, "Remote SSH supported authentication: password,publickey"),
		fxResult("OpenSSH regreSSHion", "1.3.6.1.4.1.25623.1.0.114680", "22/tcp", 8, 30, "banner only"),
		fxResult("Services", "1.3.6.1.4.1.25623.1.0.10330", "22/tcp", 0, 80, "An SSH server is running on this port"),
	)
	rows, _, err := readReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want only the password-login fact", rows)
	}
	is := openvasIssue(rows[0])
	if is.severity != "low" || len(is.cves) != 0 || !strings.Contains(is.title, "password") ||
		!strings.Contains(is.detail.Solution, "PasswordAuthentication no") {
		t.Fatalf("issue = %+v", is)
	}
}

// The main report read is as it always was (QoD 70, high, medium, low), so its size and result caps behave as before; the facts are
// a second request for the allowlisted OIDs only, at any QoD and level.
func TestOpenVASTuning_FactsAreASecondRequest(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	e.scanIP(gbOpen())
	h.gvm.mu.Lock()
	defer h.gvm.mu.Unlock()
	var reads []string
	for i, c := range h.gvm.cmds {
		if c == "get_reports" {
			reads = append(reads, h.gvm.bodies[i])
		}
	}
	if len(reads) != 2 || !strings.Contains(reads[0], "min_qod=70 levels=hml ") || strings.Contains(reads[0], "nvt=") ||
		!strings.Contains(reads[1], "nvt=1.3.6.1.4.1.25623.1.0.10267") || !strings.Contains(reads[1], "min_qod=0") || !strings.Contains(reads[1], "levels=hmlg") {
		t.Fatalf("get_reports bodies = %q", reads)
	}
}

// A fact read at the log level reaches the stored rows; a facts read that fails never loses the main results, and the step says so.
func TestOpenVASTuning_FactsAreBestEffort(t *testing.T) {
	t.Parallel()
	fact := fxWrap(fxResult("SSH Server type and version", "1.3.6.1.4.1.25623.1.0.10267", "22/tcp", 0, 80, "Remote SSH supported authentication: password,publickey"))
	for _, fail := range []bool{false, true} {
		e, h := gbEnv(t)
		e.enable()
		h.gvm.with(func(g *fakeGVM) { g.factsReport, g.factsFail = fact, fail })
		s := e.scanIP(gbOpen())
		hasFact := slices.ContainsFunc(s.Greenbone, func(r GreenboneRow) bool { return r.OID == "1.3.6.1.4.1.25623.1.0.10267" })
		noted := slices.ContainsFunc(notChecked(s), func(l string) bool {
			return strings.Contains(l, "configuration facts") && strings.Contains(l, "could not be read")
		})
		if len(s.Greenbone) < 4 || hasFact == fail || noted != fail {
			t.Errorf("facts failing=%v: rows %d, fact shown %v, noted %v, not checked %q", fail, len(s.Greenbone), hasFact, noted, notChecked(s))
		}
	}
}

// Every allowlisted NVT has a title and a fix line, and one fixture result that becomes a Low issue with both, at a log level result
// (severity 0) and at a QoD below 70.
func TestOpenVASFactsHaveTitleAndFix(t *testing.T) {
	t.Parallel()
	detections := map[string]string{
		"1.3.6.1.4.1.25623.1.0.10267":  "Remote SSH supported authentication: publickey,password",
		"1.3.6.1.4.1.25623.1.0.117839": "The server offers diffie-hellman-group-exchange-sha256",
		"1.3.6.1.4.1.25623.1.0.117414": "HTTP compression is enabled on /",
		"1.3.6.1.4.1.25623.1.0.11213":  "The web server has the following HTTP methods enabled: TRACE",
		"1.3.6.1.4.1.25623.1.0.103140": "The certificate is self-signed",
		"1.3.6.1.4.1.25623.1.0.103141": "The certificate subject does not match",
		"1.3.6.1.4.1.25623.1.0.117764": "The certificate is not trusted",
	}
	seen := map[string]bool{}
	for _, f := range gmpFacts {
		if strings.TrimSpace(f.title) == "" || strings.TrimSpace(f.fix) == "" || seen[f.oid] {
			t.Errorf("entry %s: title %q fix %q (or listed twice)", f.oid, f.title, f.fix)
		}
		seen[f.oid] = true
		d, ok := detections[f.oid]
		if !ok {
			t.Errorf("entry %s has no fixture result", f.oid)
			continue
		}
		for _, r := range []struct{ sev, qod int }{{0, 80}, {5, 30}} {
			rows, _, err := readReport(fxWrap(fxResult("nvt name", f.oid, "443/tcp", r.sev, r.qod, d)))
			if err != nil || len(rows) != 1 {
				t.Errorf("entry %s sev %d qod %d: rows %+v, %v", f.oid, r.sev, r.qod, rows, err)
				continue
			}
			is := openvasIssue(rows[0])
			if is.severity != "low" || is.title != f.title || is.detail.Solution != f.fix || len(is.cves) != 0 || !strings.Contains(is.key, ":443@") {
				t.Errorf("entry %s: issue %+v", f.oid, is)
			}
		}
	}
	if len(detections) != len(gmpFacts) {
		t.Errorf("%d fixtures for %d entries", len(detections), len(gmpFacts))
	}
}

// The methods enumeration lists what the server did not refuse: on a port that answers 301 to every method it still names TRACE, and
// that is no proof TRACE works. It raises no fact; only the NVT that confirms the echo does, and it then becomes the Low issue with its fix line.
func TestOpenVASFacts_TraceNeedsTheEchoCheck(t *testing.T) {
	t.Parallel()
	rows, _, err := readReport(fxWrap(
		fxResult("Allowed HTTP Methods Enumeration", "1.3.6.1.4.1.25623.1.0.153974", "80/tcp", 0, 80,
			"Supported methods: GET, HEAD, POST, PUT, DELETE, TRACE"),
	))
	if err != nil || len(rows) != 0 {
		t.Fatalf("enumeration alone: rows %+v, %v", rows, err)
	}
	rows, _, err = readReport(fxWrap(
		fxResult("HTTP Debugging Methods (TRACE/TRACK) Enabled", "1.3.6.1.4.1.25623.1.0.11213", "8080/tcp", 6, 99,
			"The web server has the following HTTP methods enabled: TRACE"),
	))
	if err != nil || len(rows) != 1 {
		t.Fatalf("echo check: rows %+v, %v", rows, err)
	}
	is := openvasIssue(rows[0])
	if is.severity != "low" || is.title != "The web server allows TRACE" || !strings.Contains(is.detail.Solution, "TraceEnable off") ||
		len(is.cves) != 0 || !strings.Contains(is.key, ":8080@") {
		t.Fatalf("issue = %+v", is)
	}
}

// A note of an NVT on the allowlist that does not state the fact is no issue: SSH with key logins only, methods without TRACE (PUT and DELETE are normal on
// an API).
func TestOpenVASFactsNeedTheirDetectionText(t *testing.T) {
	t.Parallel()
	rows, _, err := readReport(fxWrap(
		fxResult("SSH Server type and version", "1.3.6.1.4.1.25623.1.0.10267", "22/tcp", 0, 80, "Remote SSH supported authentication: publickey"),
		fxResult("Allowed HTTP Methods Enumeration", "1.3.6.1.4.1.25623.1.0.153974", "80/tcp", 0, 70, "Supported methods: GET, HEAD, POST, PUT, DELETE"),
	))
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
}

// The check line keeps "QoD 70 or more" true: an allowlisted configuration fact is read at any QoD, so it is counted on its own and
// not among the results with QoD 70 or more.
func TestOpenVASTuning_CheckLineCountsFactsApart(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	h.gvm.with(func(g *fakeGVM) {
		g.report = fxWrap(
			fxResult("SSH Server type and version", "1.3.6.1.4.1.25623.1.0.10267", "22/tcp", 0, 80, "Remote SSH supported authentication: password,publickey"),
			fxResult("D(HE)ater", "1.3.6.1.4.1.25623.1.0.117839", "22/tcp", 7, 30, "DHE key exchange offered"),
			fxResult("TCP Timestamps", "1.3.6.1.4.1.25623.1.0.80091", "general/tcp", 2, 80, "timestamps"),
		)
	})
	e.enable()
	s := e.scanIP(gbOpen())
	if !slices.ContainsFunc(s.Checks, func(c CheckRow) bool {
		return c.Kind == "greenbone" && strings.Contains(c.Text, "1 result with QoD 70 or more (0 high or medium, 1 hardening note) and 2 configuration facts,")
	}) {
		t.Fatalf("checks = %+v", s.Checks)
	}
}
