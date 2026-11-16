package worker

import (
	"bytes"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/sensorlink"
)

// #830: the progress readers take untrusted output. Whatever they are fed, they never panic, never keep more than their cap, and
// never produce a report that core would refuse.

func validReport(p sensorlink.JobProgress) bool {
	return (p.Phase == "discovery" || p.Phase == "ports" || p.Phase == "services" || p.Phase == "scripts" || p.Phase == "vulns") &&
		(p.Percent == -1 || p.Percent >= 0 && p.Percent <= 100) && p.Done >= 0 && p.Done <= p.Total && p.Total <= sensorlink.MaxProgressCount &&
		p.RemainingS >= 0 && p.RemainingS <= sensorlink.MaxProgressRemaining
}

func TestNmapProgressLines(t *testing.T) {
	for line, want := range map[string]*sensorlink.JobProgress{
		`<taskprogress task="SYN Stealth Scan" time="1700000000" percent="42.50" remaining="60" etc="1700000060"/>`: {Phase: "ports", Percent: 42.5, RemainingS: 60},
		`  <taskprogress task="Service scan" time="1700000000" percent="0.50"/>  `:                                  {Phase: "services", Percent: 0.5},
		`<taskprogress task="Ping Scan" time="1" percent="100.00" remaining="0"/>`:                                  {Phase: "discovery", Percent: 100},
		`<taskprogress task="NSE" time="1" percent="10.00" remaining="864000" etc="2"/>`:                            {Phase: "scripts", Percent: 10}, // nmap's "over 10 days" is no estimate
		`<taskbegin task="ARP Ping Scan" time="1700000000"/>`:                                                       {Phase: "discovery"},
		`<taskprogress task="Traceroute" time="1" percent="10.00"/>`:                                                nil,
		`<taskprogress task="SYN Stealth Scan" time="1" percent="100.01"/>`:                                         nil,
		`<taskprogress task="SYN Stealth Scan" time="1" percent="-1"/>`:                                             nil,
		`<taskprogress task="SYN Stealth Scan" time="1" percent="1e2"/>`:                                            nil,
		`<taskprogress task="SYN Stealth Scan" time="1" percent="NaN"/>`:                                            nil,
		`<taskprogress task="SYN Stealth Scan" percent="1" percent="2"/>`:                                           nil,
		`<taskprogress task="SYN Stealth Scan" time="1" percent="1" remaining="-5"/>`:                               nil,
		`<taskprogress task="SYN Stealth Scan" time="1" percent="1"/><host>`:                                        nil,
		`<taskprogress task="SYN Stealth Scan" time="1"/>`:                                                          nil,
		`<taskend task="SYN Stealth Scan" time="1"/>`:                                                               nil,
		`<host><status state="up"/></host>`:                                                                         nil,
	} {
		got, ok := nmapProgress([]byte(line))
		switch {
		case want == nil && ok:
			t.Errorf("%s: reported %+v", line, got)
		case want != nil && (!ok || got != *want):
			t.Errorf("%s: got %+v %v, want %+v", line, got, ok, *want)
		}
	}
}

func TestLinesDropsALineOverItsCap(t *testing.T) {
	var got []string
	l := &lines{max: 8, onLine: func(b []byte) { got = append(got, string(b)) }}
	for _, chunk := range []string{"ab", "c\n0123456789", "abc\nok\n", "tail"} {
		if n, err := l.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("Write = %d %v", n, err)
		}
	}
	if strings.Join(got, "|") != "abc|ok" || len(l.buf) > 8 {
		t.Fatalf("lines = %q, buffer %d", got, len(l.buf))
	}
}

func FuzzNmapProgress(f *testing.F) {
	f.Add([]byte(`<taskprogress task="SYN Stealth Scan" time="1700000000" percent="42.50" remaining="60" etc="1700000060"/>` + "\n<taskbegin task=\"NSE\" time=\"1\"/>\n"))
	f.Add([]byte("<nmaprun>\n<host/>\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		l := &lines{max: maxNmapProgressLine, onLine: func(line []byte) {
			if p, ok := nmapProgress(line); ok && !validReport(p) {
				t.Fatalf("%q gave %+v", line, p)
			}
		}}
		_, _ = l.Write(b)
		if len(l.buf) > maxNmapProgressLine {
			t.Fatalf("kept %d bytes", len(l.buf))
		}
	})
}

func FuzzNucleiCounter(f *testing.F) {
	f.Add([]byte(`{"template-id":"CVE-2024-1","host":"192.168.10.20","port":"8080","matcher-status":false}` + "\n"))
	f.Add([]byte(`{"template-id":"CVE-2024-2","host":"http://10.0.0.7:22","matcher-status":true}` + "\n{\n"))
	nj := &sensorlink.NucleiJob{Templates: []string{"CVE-2024-1", "CVE-2024-2"}, Targets: []sensorlink.NucleiTarget{{Host: "192.168.10.20", Port: 8080}, {Host: "10.0.0.7", Port: 22}}}
	f.Fuzz(func(t *testing.T, b []byte) {
		rep := &reporter{}
		w := nucleiWatch(nj, rep)
		for _, part := range bytes.SplitAfter(b, []byte("x")) { // in pieces, like a pipe
			_, _ = w.Stdout.Write(part)
		}
		p, _ := rep.take()
		if !validReport(p) || p.Total != 4 {
			t.Fatalf("report %+v", p)
		}
	})
}
