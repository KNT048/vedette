package exposure

import (
	"strings"
	"testing"
)

// The probe log row of an OpenVAS scan is written before its task starts ("sent, no answer yet") and completed with how the scan
// ended: matched when it reported results, not_matched when it scanned and reported none, not_run when it never started scanning.
// A failed scan keeps the first write's empty result, which the probe log reads as no_response.
func TestGreenboneProbeRowSaysHowTheScanEnded(t *testing.T) {
	t.Parallel()
	empty := `<get_reports_response status="200" status_text="OK"><report id="` + gbReportID + `"><report id="` + gbReportID + `"><scan_run_status>Done</scan_run_status><results start="1" max="-1"></results></report></report></get_reports_response>`
	for name, tc := range map[string]struct {
		report string
		states []string
		fail   string
		want   string
	}{
		"results":         {states: []string{"Requested", "Running", "Done"}, want: "matched"},
		"no results":      {report: empty, states: []string{"Requested", "Running", "Done"}, want: "not_matched"},
		"ended unscanned": {report: empty, states: []string{"Requested", "Interrupted"}, want: "not_run"},
		"report failed":   {states: []string{"Requested", "Running", "Done"}, fail: "get_reports", want: ""}, // the probe log reads it as no_response
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, h := gbEnv(t)
			e.enable()
			h.gvm.with(func(g *fakeGVM) {
				g.states = tc.states
				if tc.report != "" {
					g.report = tc.report
				}
				if tc.fail != "" {
					g.fail = map[string]bool{tc.fail: true}
				}
			})
			e.scanIP(gbOpen())
			l := h.gvm.log
			if len(l.rows) != 1 || l.rows[0].IP != ipA {
				t.Fatalf("probe rows = %+v", l.rows)
			}
			if l.rows[0].Result != tc.want {
				t.Fatalf("probe row result %q, want %q", l.rows[0].Result, tc.want)
			}
			if l.planned[l.rows[0].ID] != "" {
				t.Fatalf("the row before the task started carried the result %q", l.planned[l.rows[0].ID])
			}
		})
	}
}

// An OpenVAS issue says what Greenbone found, not only its solution: the test's summary, the detection result of this host, the
// insight, the affected software and the impact, as plain text. A result without any of them names the test that reported it.
func TestContract_INV25_IssueDetailHasGreenbonesDescription(t *testing.T) {
	t.Parallel()
	rows, _, err := readReport(gbFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	terrapin := rows[1]
	d := openvasIssue(terrapin).detail
	for _, want := range []string{
		"The remote SSH server is vulnerable to a prefix truncation attack dubbed Terrapin.",
		"Detection result: Vulnerable key exchange algorithm: chacha20-poly1305@openssh.com on port 22",
		"Insight: The SSH transport protocol",
		"Affected: OpenSSH before 9.6",
		"Impact: An attacker in the middle",
	} {
		if !strings.Contains(d.Description, want) {
			t.Fatalf("description %q has no %q", d.Description, want)
		}
	}
	if strings.ContainsAny(d.Description, "<>|") || strings.Contains(d.Description, "cvss_base_vector") || strings.Contains(d.Description, "solution_type") {
		t.Fatalf("description %q", d.Description)
	}
	if d.Solution == "" {
		t.Fatalf("solution lost: %+v", d)
	}
	weak := openvasIssue(rows[0]).detail
	if !strings.HasPrefix(weak.Description, "The remote SSH server is configured to allow weak MAC algorithm(s).") || !strings.Contains(weak.Description, "umac-64-etm@openssh.com") {
		t.Fatalf("weak MAC description %q", weak.Description)
	}
	timestamps := openvasIssue(rows[3]).detail
	if timestamps.Description != `OpenVAS's test "TCP Timestamps Information Disclosure" reported this result.` {
		t.Fatalf("a result without text: %q", timestamps.Description)
	}
	long, _, err := readReport(strings.Replace(gbFixture(t), "summary=The remote SSH", "summary="+strings.Repeat("x ", 5000)+"The remote SSH", 1))
	if err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(long[0].Description)); n > gmpMaxDescription {
		t.Fatalf("description of %d runes, the cap is %d", n, gmpMaxDescription)
	}
}

// A detection result over several lines (a list of ciphers or algorithms) keeps its lines in the issue's description, and each part of
// the description starts on a line of its own; each line is still plain text.
func TestOpenVASDescriptionKeepsItsLines(t *testing.T) {
	t.Parallel()
	report := strings.Replace(gbFixture(t), "client-to-server MAC algorithm(s): umac-64-etm@openssh.com",
		"client-to-server MAC algorithm(s):\n\numac-64-etm@openssh.com\r\nhmac-sha1  &lt;b&gt;x&lt;/b&gt;\n", 1)
	rows, _, err := readReport(report)
	if err != nil {
		t.Fatal(err)
	}
	d := openvasIssue(rows[0]).detail.Description
	want := "The remote SSH server is configured to allow weak MAC algorithm(s).\nDetection result: The remote SSH server supports the following weak client-to-server MAC algorithm(s):\numac-64-etm@openssh.com\nhmac-sha1 x"
	if d != want {
		t.Fatalf("description %q, want %q", d, want)
	}
}
