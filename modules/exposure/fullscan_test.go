package exposure

// FULL-4 (Trưởng), for Mlee: the service step of a deep scan (D-526).

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// boundServices is the ServiceScanner seam that records how long the step gave it, and answers what it is told.
type boundServices struct {
	fakeServices
	given time.Duration
}

func (b *boundServices) ScanServices(ctx context.Context, t ScanTarget, ip netip.Addr) (ServiceScan, error) {
	if d, ok := ctx.Deadline(); ok {
		b.given = time.Until(d)
	}
	return b.fakeServices.ScanServices(ctx, t, ip)
}

// D-526: the service step's bound follows the scan mode: 5 minutes without accepted terms, FullServicesTimeout for a deep scan,
// which the scanner reads from ScanTarget.Mode.
func TestFullScanStepBoundFollowsTheMode(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		terms *bool
		want  time.Duration
		full  bool
	}{"terms not accepted": {nil, ServicesTimeout, false}, "deep": {new(false), FullServicesTimeout, true}, "deep and disruptive": {new(true), FullServicesTimeout, true}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.terms = c.terms
			sv := &boundServices{fakeServices: fakeServices{scan: ServiceScan{Services: []ServiceRow{{IP: ipA, Port: 22, Name: "ssh"}}, Ports: 98}}}
			e.svc.cfg.Services = sv
			e.scanIP(Content{})
			if sv.given > c.want || sv.given < c.want-time.Minute {
				t.Fatalf("the step gave the scanner %s, want %s", sv.given, c.want)
			}
			if len(sv.calls) != 1 || sv.calls[0].Mode.Full != c.full || sv.calls[0].Mode.Disruptive != (c.terms != nil && *c.terms) {
				t.Fatalf("mode = %+v", sv.calls)
			}
		})
	}
}

// D-526: a deep scan stores its script results (sanitized, findings first, rows of another address dropped), says how many and how
// many say VULNERABLE, and has no "TCP ports outside the fixed list" line; when its nmap run did not finish, the lines say so with
// the deep scan's own numbers.
func TestFullScanScriptsAndLines(t *testing.T) {
	t.Parallel()
	deep := false
	e := newEnv(t)
	e.terms = &deep
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: 65535,
		Services: []ServiceRow{{IP: ipA, Port: 49152, Name: "http", Product: "Jetty"}},
		Scripts: []ScriptRow{
			{IP: ipA, Port: 49152, ID: "http-title", Output: "Site title: admin" + string(rune(0x202e))}, // a right-to-left override
			{IP: ipA, Port: 0, ID: "smb-vuln-ms17-010", Output: "VULNERABLE:\n    State: VULNERABLE", CVEs: []string{"CVE-2017-0143", "not-a-cve"}, Vulnerable: true},
			{IP: ipB, Port: 22, ID: "ssh-hostkey", Output: "another address"},
			{IP: ipA, Port: 22, ID: "Bad Id", Output: "dropped"},
		}}}
	s := e.scanIP(Content{})
	want := []ScriptRow{
		{IP: ipA, Port: 0, ID: "smb-vuln-ms17-010", Output: "VULNERABLE:\n    State: VULNERABLE", CVEs: []string{"CVE-2017-0143"}, Vulnerable: true},
		{IP: ipA, Port: 49152, ID: "http-title", Output: "Site title: admin", CVEs: []string{}},
	}
	if len(s.Scripts) != 2 || !slices.EqualFunc(s.Scripts, want, func(a, b ScriptRow) bool {
		return a.IP == b.IP && a.Port == b.Port && a.ID == b.ID && a.Output == b.Output && slices.Equal(a.CVEs, b.CVEs) && a.Vulnerable == b.Vulnerable
	}) {
		t.Fatalf("scripts = %+v", s.Scripts)
	}
	if got := s.Checks[1].Text; got != "Service identification (nmap -sV) on 65535 TCP ports: 1 service identified. nmap's scripts: 2 results, 1 saying VULNERABLE." {
		t.Fatalf("services line = %q", got)
	}
	if slices.Contains(notChecked(s), notOtherPortsIP) || slices.Contains(notChecked(s), notOtherPortsDeep) {
		t.Fatalf("not checked = %q", notChecked(s))
	}

	gaveUp := newEnv(t)
	gaveUp.terms = &deep
	gaveUp.svc.cfg.Services = &fakeServices{err: ErrServicesTimedOut}
	s = gaveUp.scanIP(Content{})
	nc := notChecked(s)
	if !slices.Contains(nc, notOtherPortsDeep) || !slices.ContainsFunc(nc, func(n string) bool {
		return strings.HasPrefix(n, "The deep scan") && strings.Contains(n, "within 60 minutes, nmap's limit")
	}) || slices.Contains(nc, notOtherPortsIP) {
		t.Fatalf("not checked = %q", nc)
	}
	if len(s.Scripts) != 0 {
		t.Fatalf("scripts = %+v", s.Scripts)
	}
}

// D-526: the script rows are bounded: at most maxScripts, findings kept first, each output cut to maxScriptOutput runes.
func TestFullScanSanitizeScripts(t *testing.T) {
	t.Parallel()
	in := make([]ScriptRow, 0, maxScripts+10)
	for i := range maxScripts + 9 {
		in = append(in, ScriptRow{IP: ipA, Port: 80, ID: "http-headers", Output: strings.Repeat("x", maxScriptOutput+5) + string(rune('a'+i%26))})
	}
	in = append(in, ScriptRow{IP: ipA, Port: 445, ID: "smb-vuln-ms17-010", Vulnerable: true}, ScriptRow{IP: "::1", Port: 1, ID: "x"}, ScriptRow{IP: ipA, Port: 70000, ID: "x"})
	got := sanitizeScripts(in)
	if len(got) != maxScripts || got[0].ID != "smb-vuln-ms17-010" || len([]rune(got[1].Output)) != maxScriptOutput {
		t.Fatalf("%d rows, first %q, output %d runes", len(got), got[0].ID, len([]rune(got[1].Output)))
	}
}
