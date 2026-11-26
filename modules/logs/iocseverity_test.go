package logs

import (
	"strings"
	"testing"
)

// The severity of a bad-address incident follows how sure the feeds are: a listing the feeds rate at 50% or more is high (the default
// alert triggers send it), a weaker one (a Tor exit relay alone) is medium, and a confirmed botnet command-and-control server is
// critical. The incident text carries the confidence the feeds gave.
func TestIOCBadAddressSeverityFollowsTheListing(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	cases := []struct {
		dest string
		l    Listing
		sev  string
		conf string
	}{
		{"80.0.0.1", Listing{Feeds: []string{"ET Open compromised IPs"}, Confidence: 0.85}, "high", "Confidence 85%"},
		{"80.0.0.2", Listing{Feeds: []string{"IPsum"}, Confidence: 0.78}, "high", "Confidence 78%"},
		{"80.0.0.3", Listing{Feeds: []string{"custom"}, Confidence: 0.5}, "high", "Confidence 50%"},
		{"80.0.0.4", Listing{Feeds: []string{"Tor exit list"}, Confidence: 0.2}, "medium", "Confidence 20%"},
		{"80.0.0.5", Listing{Feeds: []string{"IPsum", "Tor exit list"}, Confidence: 0.39}, "medium", "Confidence 39%"},
		{"80.0.0.6", Listing{Feeds: []string{"abuse.ch Feodo Tracker"}, Confidence: 0.95, C2: true}, "critical", "Confidence 95%"},
	}
	for _, c := range cases {
		ff.listed["ip:"+c.dest] = c.l
	}
	for _, c := range cases {
		e.feedAll(src, []string{traffic(lanDevice, c.dest)})
	}
	got := map[string]BadAddressEvent{}
	for _, b := range p.bad {
		got[b.Dest] = b
	}
	for _, c := range cases {
		b, ok := got[c.dest]
		if !ok {
			t.Errorf("%s: no event", c.dest)
			continue
		}
		if b.Severity != c.sev || !strings.Contains(b.What, c.conf) {
			t.Errorf("%s (%v): severity %s, want %s; what %q", c.dest, c.l.Feeds, b.Severity, c.sev, b.What)
		}
	}
}

// A blocked attempt to reach a command-and-control server is as severe as a connection: the device runs the malware that beacons.
func TestIOCBlockedCommandAndControlAttemptIsCritical(t *testing.T) {
	t.Parallel()
	if got := (Listing{Feeds: []string{"abuse.ch Feodo Tracker"}, Confidence: 0.95, C2: true}).Severity(); got != "critical" {
		t.Errorf("C2 listing: %s", got)
	}
	h := IocHit{SrcIP: lanDevice, Dest: "80.0.0.9", DestKind: "ip", SeenVia: "syslog:FW-HQ", Feeds: []string{"abuse.ch Feodo Tracker"}, Confidence: 0.95, Blocked: true}
	if b := badAddressEvent(h, "critical"); b.Severity != "critical" || !strings.Contains(b.Title, "tried to reach") {
		t.Errorf("%+v", b)
	}
	// A listing with a value outside 0..1 (a broken adapter) is read clamped: NaN and below zero are medium, above one high.
	for conf, want := range map[float64]string{-1: "medium", 2: "high"} {
		if got := (Listing{Feeds: []string{"x"}, Confidence: conf}).Severity(); got != want {
			t.Errorf("confidence %v: %s, want %s", conf, got, want)
		}
	}
}
