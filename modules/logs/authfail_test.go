package logs

import (
	"fmt"
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
			failedPassword("admin", attacker))
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
	if got := userAfter("Failed password for root from x", "failed password for root from x", "failed password for"); got != "root" {
		t.Fatalf("userAfter = %q", got)
	}
}

// A Windows failed logon (event 4625) with a remote address is a failed attempt, 4624 an accepted login.
func TestAuthFail_WindowsEventIDs(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	line := "<14>Nov  9 10:00:00 SRV-AD Microsoft-Windows-Security-Auditing: 4625: An account failed to log on. Logon Type: 3 Source Network Address: 203.0.113.50"
	r := e.svc.sigs.Of("windows", line)
	if class, _, ok := authLine(r.Signature, line); !ok || class != authPassword {
		t.Fatalf("4625 = %q, class %d ok %v", r.Signature, class, ok)
	}
	if class, _, ok := authLine("4624: Successful logon", ""); !ok || class != -1 {
		t.Fatal("4624 is an accepted login")
	}
}
