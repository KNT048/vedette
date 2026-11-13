package logs

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const attacker = "45.155.205.233"

func failedPassword(user, ip string) string {
	return fmt.Sprintf("<38>Nov  9 10:00:00 web1 sshd[123]: Failed password for invalid user %s from %s port 41022 ssh2", user, ip)
}

func authEnv(t *testing.T) (*env, Source, *iocPubs) {
	t.Helper()
	e := newEnv(t)
	p := &iocPubs{}
	e.svc.cfg.Events = p
	src, err := e.svc.AddSource(t.Context(), "admin@acme.example", Input{Kind: "syslog-generic", Name: "Web-server", SenderIP: "192.168.10.200", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	return e, src, p
}

func (e *env) ingest(src Source, texts ...string) {
	e.t.Helper()
	if _, err := e.svc.Ingest(e.t.Context(), lines(src.ID, *e.clock, texts...)); err != nil {
		e.t.Fatal(err)
	}
}

// The first day, no baseline: five failures from one address are one incident; four are none; more lines inside the dedupe time add no second one.
func TestAuthFail_ThresholdDedupeAndBelow(t *testing.T) {
	t.Parallel()
	e, src, p := authEnv(t)
	for i := range AuthFailThreshold - 1 {
		e.ingest(src, failedPassword(fmt.Sprintf("u%d", i), attacker))
	}
	if len(p.summaries) != 0 {
		t.Fatalf("below the threshold: %d incidents", len(p.summaries))
	}
	e.ingest(src, failedPassword("admin", attacker))
	if len(p.summaries) != 1 {
		t.Fatalf("at the threshold: %d incidents, want 1", len(p.summaries))
	}
	ev := p.summaries[0]
	if ev.Target != "auth:"+attacker || ev.Source != "Web-server" || ev.Severity != "medium" || !strings.Contains(ev.What, "5 failed") || !strings.Contains(ev.What, "u0, u1, u2, u3, admin") {
		t.Fatalf("event = %+v", ev)
	}
	for range 20 {
		e.advance(time.Second)
		e.ingest(src, failedPassword("root", attacker))
	}
	if len(p.summaries) != 1 {
		t.Fatalf("inside the dedupe time: %d incidents, want 1", len(p.summaries))
	}
	e.advance(AuthDedupe) // a new hour of the same attack is a new incident
	e.ingest(src, failedPassword("a", attacker), failedPassword("b", attacker), failedPassword("c", attacker), failedPassword("d", attacker), failedPassword("e", attacker))
	if len(p.summaries) != 2 {
		t.Fatalf("after the dedupe time: %d incidents, want 2", len(p.summaries))
	}
}

// Failures spread over more than the window never add up; another address has its own count; a LAN address counts and says so.
func TestAuthFail_WindowPerAddressAndLAN(t *testing.T) {
	t.Parallel()
	e, src, p := authEnv(t)
	for range 8 {
		e.ingest(src, failedPassword("root", attacker))
		e.advance(AuthFailWindow / 2)
	}
	if len(p.summaries) != 0 {
		t.Fatalf("slow failures: %d incidents", len(p.summaries))
	}
	for range 3 {
		e.ingest(src, failedPassword("x", "203.0.113.9"), failedPassword("x", "198.51.100.4"))
	}
	if len(p.summaries) != 0 {
		t.Fatalf("two addresses, three each: %d incidents", len(p.summaries))
	}
	for range 5 {
		e.ingest(src, failedPassword("x", "192.168.10.77"))
	}
	if len(p.summaries) != 1 || !strings.Contains(p.summaries[0].What, "your own network") {
		t.Fatalf("LAN address: %+v", p.summaries)
	}
}

// One sshd attempt writes up to three lines: it is one attempt, not three. Windows 4625 counts too.
func TestAuthFail_OneAttemptThreeLinesIsOne(t *testing.T) {
	t.Parallel()
	e, src, p := authEnv(t)
	for range 3 {
		e.ingest(src,
			"Nov  9 10:00:00 web1 sshd[1]: Invalid user admin from "+attacker+" port 5",
			"Nov  9 10:00:00 web1 sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost="+attacker,
			failedPassword("admin", attacker),
			"Nov  9 10:00:00 web1 sshd[1]: Connection closed by invalid user admin "+attacker+" port 5 [preauth]",
			"Nov  9 10:00:00 web1 sshd[1]: Disconnected from invalid user admin "+attacker+" port 5 [preauth]")
	}
	if len(p.summaries) != 0 {
		t.Fatalf("3 attempts made %d incidents", len(p.summaries))
	}
	e.ingest(src, failedPassword("admin", attacker), failedPassword("admin", attacker))
	if len(p.summaries) != 1 {
		t.Fatalf("5 attempts made %d incidents", len(p.summaries))
	}
}

// A login that is accepted from the address after the incident opened is a second incident, high; one that came before the threshold makes the first high.
func TestAuthFail_SuccessAfterFailuresEscalates(t *testing.T) {
	t.Parallel()
	e, src, p := authEnv(t)
	accepted := "Nov  9 10:01:00 web1 sshd[9]: Accepted password for root from " + attacker + " port 5 ssh2"
	e.ingest(src, accepted) // no failures before: nothing
	for range 5 {
		e.ingest(src, failedPassword("root", attacker))
	}
	if len(p.summaries) != 1 || p.summaries[0].Severity != "medium" {
		t.Fatalf("first: %+v", p.summaries)
	}
	e.ingest(src, accepted, accepted)
	if len(p.summaries) != 2 {
		t.Fatalf("after the acceptance: %d incidents, want 2", len(p.summaries))
	}
	if ev := p.summaries[1]; ev.Severity != "high" || ev.Target != "auth:"+attacker+" accepted" || !strings.Contains(ev.Title, "ACCEPTED") {
		t.Fatalf("second = %+v", ev)
	}

	e2, src2, p2 := authEnv(t) // the acceptance in between: the one incident is high
	e2.ingest(src2, failedPassword("root", attacker), failedPassword("root", attacker), accepted)
	e2.ingest(src2, failedPassword("root", attacker), failedPassword("root", attacker), failedPassword("root", attacker))
	if len(p2.summaries) != 1 || p2.summaries[0].Severity != "high" || !strings.Contains(p2.summaries[0].What, "ACCEPTED") {
		t.Fatalf("accepted in between: %+v", p2.summaries)
	}
}

// Names from the log are plain text and short; the pairs followed and the announcements per hour are bounded.
func TestAuthFail_Bounds(t *testing.T) {
	t.Parallel()
	e, src, p := authEnv(t)
	long := strings.Repeat("a", 500)
	for range 5 {
		e.ingest(src, failedPassword(long, attacker))
	}
	if len(p.summaries) != 1 || len(p.summaries[0].What) > MaxEventText || strings.Contains(p.summaries[0].What, long[:40]) {
		t.Fatalf("long name: %+v", p.summaries)
	}
	for i := range AuthEventsPerHour + 5 {
		ip := fmt.Sprintf("203.0.113.%d", i+10)
		for range 5 {
			e.ingest(src, failedPassword("x", ip))
		}
	}
	if len(p.summaries) != AuthEventsPerHour {
		t.Fatalf("hourly budget: %d incidents, want %d", len(p.summaries), AuthEventsPerHour)
	}
	if got := userAfter("Failed password for root from x", "Failed password for "); got != "root" {
		t.Fatalf("userAfter = %q", got)
	}
}

// A Windows failed logon (event 4625) with a remote address is a failed attempt, 4624 an accepted login.
func TestAuthFail_WindowsEventIDs(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	line := "<14>Nov  9 10:00:00 SRV-AD Microsoft-Windows-Security-Auditing: 4625: An account failed to log on. Logon Type: 3 Source Network Address: 203.0.113.50"
	r := e.svc.sigs.Of("windows", line)
	if class, _, ok := authLine(r.Signature, r.Bounded, line); !ok || class != authPassword {
		t.Fatalf("4625 = %q, class %d ok %v", r.Signature, class, ok)
	}
	if class, _, ok := authLine("4624: Successful logon", true, ""); !ok || class != -1 {
		t.Fatal("4624 is an accepted login")
	}
}

// The phrases of a login line count only when sshd (or PAM's service) writes them at the start of the message: a visitor's User-Agent or an
// account name can hold any words, and anyone on the Internet must not be able to make an incident, least of all an "accepted" one.
func TestAuthFail_OnlySshdSaysItIsALogin(t *testing.T) {
	t.Parallel()
	e, src, p := authEnv(t)
	const v = "203.0.113.7"
	for range 6 {
		e.ingest(src,
			v+` - - [09/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "Failed password for root"`,
			`<190>Nov  9 10:00:00 web nginx: `+v+` - - [09/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "Failed password for root"`,
			`<190>Nov  9 10:00:00 web nginx: `+v+` - - [09/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "Invalid user root"`,
			`<38>Nov  9 10:00:00 web sudo: Failed password for root from `+v+` port 5 ssh2`)
	}
	e.ingest(src, `<190>Nov  9 10:00:00 web nginx: `+v+` - - [09/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "Accepted password for root from `+v+`"`)
	if len(p.summaries) != 0 {
		t.Fatalf("a web log made %d incidents: %+v", len(p.summaries), p.summaries)
	}
	for range 5 { // the real thing, in an RFC 5424 header
		e.ingest(src, "<38>1 2026-11-09T10:00:00Z web sshd 123 - - Failed password for root from "+v+" port 5 ssh2")
	}
	if len(p.summaries) != 1 {
		t.Fatalf("sshd in RFC 5424: %d incidents, want 1", len(p.summaries))
	}
}

// The hourly budget never cuts the incident that says a login was accepted; a medium one that it cut opens again at the next failure.
func TestAuthFail_BudgetNeverCutsAnAcceptedLogin(t *testing.T) {
	t.Parallel()
	e, src, p := authEnv(t)
	e.advance(55 * time.Minute) // five minutes to the next clock hour, inside the counting window
	ips := make([]string, AuthEventsPerHour+1)
	for i := range ips {
		ips[i] = fmt.Sprintf("203.0.113.%d", i+10)
		for range 5 {
			e.ingest(src, failedPassword("x", ips[i]))
		}
	}
	if len(p.summaries) != AuthEventsPerHour {
		t.Fatalf("%d incidents, want %d", len(p.summaries), AuthEventsPerHour)
	}
	e.ingest(src, "Nov  9 10:01:00 web1 sshd[9]: Accepted password for root from "+ips[0]+" port 5 ssh2")
	if n := len(p.summaries); n != AuthEventsPerHour+1 || p.summaries[n-1].Severity != "high" {
		t.Fatalf("the accepted login was not announced: %d incidents", len(p.summaries))
	}
	e.advance(6 * time.Minute)
	e.ingest(src, failedPassword("x", ips[AuthEventsPerHour]))
	if n := len(p.summaries); n != AuthEventsPerHour+2 || !strings.Contains(p.summaries[n-1].Target, ips[AuthEventsPerHour]) {
		t.Fatalf("the cut incident did not open again: %d incidents", len(p.summaries))
	}
}

// A table full of one-line addresses does not blind the rule; a pair that never reached an incident goes after the window; an IPv6 host
// is one pair by its /64.
func TestAuthFail_TableFullQuietPairsAndIPv6(t *testing.T) {
	t.Parallel()
	e, src, p := authEnv(t)
	for batch := range MaxAuthTracked/500 + 1 {
		var texts []string
		for i := range 500 {
			n := batch*500 + i
			texts = append(texts, failedPassword("x", fmt.Sprintf("100.%d.%d.%d", 64+n/65536, n/256%256, n%256)))
		}
		e.ingest(src, texts...)
		e.advance(time.Second)
	}
	if got := len(e.svc.auth); got != MaxAuthTracked {
		t.Fatalf("pairs followed = %d, want the table full (%d)", got, MaxAuthTracked)
	}
	for range 5 {
		e.ingest(src, failedPassword("root", attacker))
	}
	if len(p.summaries) != 1 || p.summaries[0].Target != "auth:"+attacker {
		t.Fatalf("a real attacker behind a full table: %+v", p.summaries)
	}
	e.advance(AuthFailWindow + time.Minute)
	e.ingest(src, failedPassword("x", "198.51.100.1"))
	if got := len(e.svc.auth); got != 2 { // the attacker (an incident is open) and the new line
		t.Fatalf("quiet pairs after the window: %d followed, want 2", got)
	}
	for i := range 5 {
		e.ingest(src, failedPassword("x", fmt.Sprintf("2001:db8:1:2::%x", i+1)))
	}
	if n := len(p.summaries); n != 2 || p.summaries[1].Target != "auth:2001:db8:1:2::/64" {
		t.Fatalf("IPv6 per /64: %+v", p.summaries)
	}
}

// An incident that opens with an accepted login in it has the "accepted" target: the target of the failures may be an open incident that
// would absorb it.
func TestAuthFail_AcceptedFirstIncidentHasItsOwnTarget(t *testing.T) {
	t.Parallel()
	e, src, p := authEnv(t)
	for range 5 {
		e.ingest(src, failedPassword("root", attacker))
	}
	e.advance(AuthDedupe)
	e.ingest(src, failedPassword("root", attacker), failedPassword("root", attacker),
		"Nov  9 11:00:00 web1 sshd[9]: Accepted password for root from "+attacker+" port 5 ssh2",
		failedPassword("root", attacker), failedPassword("root", attacker), failedPassword("root", attacker))
	if n := len(p.summaries); n != 2 || p.summaries[1].Severity != "high" || p.summaries[1].Target != "auth:"+attacker+" accepted" {
		t.Fatalf("incidents: %+v", p.summaries)
	}
}

// An IPv6 pair is a /64, but a login is the attacker's only when its own address failed: a neighbour on the same LAN logging in is not.
func TestAuthFail_IPv6NeighbourLoginIsNotAcceptedAttacker(t *testing.T) {
	t.Parallel()
	e, src, p := authEnv(t)
	for range 5 {
		e.ingest(src, failedPassword("root", "2001:db8:aa:1::50"))
	}
	e.ingest(src, "Nov  9 10:01:00 web1 sshd[9]: Accepted publickey for kien from 2001:db8:aa:1::77 port 5 ssh2")
	if len(p.summaries) != 1 || p.summaries[0].Severity != "medium" {
		t.Fatalf("a neighbour's login: %+v", p.summaries)
	}
	e.ingest(src, "Nov  9 10:01:00 web1 sshd[9]: Accepted publickey for kien from 2001:db8:aa:1::50 port 5 ssh2")
	if n := len(p.summaries); n != 2 || p.summaries[1].Severity != "high" {
		t.Fatalf("the failing address logging in: %+v", p.summaries)
	}
}

// "app: sshd[1]: ..." is a program called app whose message says sshd: the words are the sender's.
func TestAuthFail_ProgramFirstWordIsNotSshd(t *testing.T) {
	t.Parallel()
	e, src, p := authEnv(t)
	for range 6 {
		e.ingest(src, "<13>Nov  9 10:00:00 app: sshd[1]: Failed password for root from "+attacker+" port 5 ssh2")
	}
	e.ingest(src, "<13>Nov  9 10:00:00 app: sshd[1]: Accepted password for root from "+attacker+" port 5 ssh2")
	if len(p.summaries) != 0 {
		t.Fatalf("visitor text made %d incidents", len(p.summaries))
	}
}

// A login accepted before the threshold (D-490 review H2) says ACCEPTED in the title, so a report or a person reading the list does not
// take it for a plain failed-login attack; the failures-only incident keeps its title.
func TestAuthFail_AcceptedBeforeTheThresholdIsTitledAccepted(t *testing.T) {
	t.Parallel()
	a := authAlert{source: "s1", addr: netip.MustParseAddr(attacker), at: time.Now(), attempts: 6, accepted: true}
	ev := authEvent(a, "web-1", nil)
	if ev.Title != "A login from "+attacker+" was ACCEPTED after 6 failed attempts on web-1" || ev.Severity != "high" || ev.Target != "auth:"+attacker+" accepted" {
		t.Fatalf("event = %+v", ev)
	}
	a.accepted = false
	if ev := authEvent(a, "web-1", nil); !strings.Contains(ev.Title, " failed logins from ") || ev.Severity != "medium" {
		t.Fatalf("failures only = %+v", ev)
	}
}
