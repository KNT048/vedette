package listen

import "testing"

// pfSense (FreeBSD syslogd) sends the BSD header without a hostname: the first token is "tag[pid]:", the program.
func TestParse3164WithoutHostname(t *testing.T) {
	for _, c := range []struct{ line, host, app, proc, msg string }{
		{"<134>Nov  9 10:00:00 filterlog[53123]: 5,,,1000", "", "filterlog", "53123", "5,,,1000"},
		{"<134>Nov  9 10:00:00 filterlog: 5,,,1000", "", "filterlog", "", "5,,,1000"},
		{"<134>Nov  9 10:00:00 fw filterlog[1]: x", "fw", "filterlog", "1", "x"},
		{"<134>Nov  9 10:00:00 fe80::1 sshd[1]: x", "fe80::1", "sshd", "1", "x"},
		{"<134>Nov  9 10:00:00 host: sshd[1]: x", "", "host", "", "sshd[1]: x"},
		{"<134>Nov  9 10:00:00 UDM-Pro,18e829,v3 kernel: x", "UDM-Pro,18e829,v3", "kernel", "", "x"},
	} {
		e := ParseSyslog(c.line)
		if e.Host != c.host || e.App != c.app || e.ProcID != c.proc || e.Msg != c.msg {
			t.Errorf("%q: host %q app %q proc %q msg %q", c.line, e.Host, e.App, e.ProcID, e.Msg)
		}
	}
}
