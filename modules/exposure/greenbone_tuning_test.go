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

// The report is asked for with every level and QoD, so the facts at the log level reach the parser.
func TestOpenVASTuning_ReportIsReadAtEveryLevel(t *testing.T) {
	t.Parallel()
	e, h := gbEnv(t)
	e.enable()
	e.scanIP(gbOpen())
	h.gvm.mu.Lock()
	defer h.gvm.mu.Unlock()
	i := slices.IndexFunc(h.gvm.cmds, func(c string) bool { return c == "get_reports" })
	if i < 0 || !strings.Contains(h.gvm.bodies[i], "levels=hmlg") {
		t.Fatalf("get_reports bodies = %q", h.gvm.bodies)
	}
}
