package exposure

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

// QA pass 2026-11-09: a paused IP is a state of the target (the GET says so), IPv6 is an IP, messages carry dates in one
// human format, and the wait after the 10 attempts an hour is part of the settings.

// An IP that the latest full check did not see is a state of the target (INV-13): the node says the box does not go out through it
// now, so the page can say it, and the IP stays scannable until its ValidDays run out (INV-4). Reading it probes nothing.
func TestContract_INV13_PausedIsAStateOfTheTarget(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.committedIP(ipA)
	if e.isPaused(a.ID) {
		t.Fatal("a current IP is not current")
	}

	e.advance(time.Minute)
	e.detect(ipB) // the box moved to B: the full check just ran and did not see A
	calls := e.prober.count()
	if !e.isPaused(a.ID) {
		t.Fatal("A after the box moved is shown as current")
	}
	v := e.target(a.ID)
	if !v.Scannable || v.BlockedReason != nil || v.Status != "verified" || str(v.VerifiedAt) != "2026-11-09T10:00:00.000Z" {
		t.Fatalf("A stays verified and scannable, last seen at the earlier time: %+v", v)
	}
	if e.prober.count() != calls {
		t.Fatal("reading the target probed the network")
	}

	// The gate and the view give the same answer, and the gate runs no new check inside the window.
	if ok, why := e.scannable(a.ID); !ok || why != "" {
		t.Fatalf("gate: %v %q", ok, why)
	}
	if e.prober.count() != calls {
		t.Fatal("the gate probed again inside the 5 minutes")
	}

	// Ownership reasons come first: an IP without the commitment says so.
	b := e.detect(ipB)[0]
	if v := e.target(b.ID); v.BlockedReason == nil || *v.BlockedReason != BlockedNoCommitment {
		t.Fatalf("B without commitment: %v", v.BlockedReason)
	}

	// Seen again: current. A full check that does not see it sets it again, and no clock ends that.
	e.detect(ipA)
	if e.isPaused(a.ID) {
		t.Fatal("A seen again is not current")
	}
	e.advance(time.Minute)
	e.detect(ipB)
	e.advance(6 * time.Minute)
	if !e.isPaused(a.ID) {
		t.Fatal("A after the window is current without a check that saw it")
	}
}

// A domain is never paused: its own re-check is the TXT record.
func TestContract_INV13_DomainIsNeverPaused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	d := e.addVerifiedDomain()
	if _, err := e.commit(d.ID); err != nil {
		t.Fatal(err)
	}
	e.detect(ipB)
	if v := e.target(d.ID); v.BlockedReason != nil {
		t.Fatalf("domain = %v", *v.BlockedReason)
	}
}

// The wait is part of the settings, so the page can say it on the button instead of only after a refused click.
func TestContract_INV5_SettingsSayWhenTheNextAttemptIsPossible(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b, err := e.svc.Settings(e.ctx())
	if err != nil || b.RetryInMin != nil {
		t.Fatalf("with attempts left: %+v %v", b, err)
	}
	for i := range MaxAttemptsPerHour {
		if i > 0 {
			e.advance(time.Minute)
		}
		if err := e.svc.attempt(e.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	b, err = e.svc.Settings(e.ctx())
	if err != nil || b.RetryInMin == nil || *b.RetryInMin != 51 { // the first attempt left the hour 51 minutes from now
		t.Fatalf("used up: %+v %v", b, err)
	}
	if err := e.svc.attempt(e.ctx()); err == nil || !strings.Contains(err.Error(), "about 51 minutes") {
		t.Fatalf("the 429 and the settings disagree: %v", err)
	}
	saved, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", false, 60)
	if err != nil || saved.RetryInMin == nil {
		t.Fatalf("PUT answers the same shape: %+v %v", saved, err)
	}
	e.advance(time.Hour)
	if b, _ = e.svc.Settings(e.ctx()); b.RetryInMin != nil {
		t.Fatalf("after the hour: %v", *b.RetryInMin)
	}
}

// IPv6 is an IP too: the same answer as IPv4, not "enter only a domain name".
func TestContract_INV2_IPv6IsNotTypedInEither(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, v := range []string{"2001:4860:4860::8888", "[::1]", "::1", "::ffff:8.8.8.8", "2001:DB8::1", " [2001:db8::1] ", "fe80::1%eth0"} {
		_, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", v)
		wantAPI(t, err, 400, "ip_not_allowed")
		var ae *APIError
		if !errors.As(err, &ae) || !strings.HasPrefix(ae.Message, "That is an IP address, not a domain") {
			t.Fatalf("%q: %v", v, err)
		}
	}
	for _, v := range []string{"acme.example:8080", "[acme.example]", "a:b", "http://acme.example"} {
		_, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", v)
		wantAPI(t, err, 400, "bad_value")
	}
}

// Dates in the messages are "9 Nov 2026" and "9 Nov 2026, 17:00", in the box time zone, never ISO or "UTC".
func TestContract_INV13_MessagesUseOneHumanDateFormat(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.Location = time.FixedZone("ICT", 7*3600) // 10:00 UTC is 17:00 in the box
	human := regexp.MustCompile(`\d{1,2} [A-Z][a-z]{2} \d{4}`)
	iso := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)

	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	a := e.committedIP(ipA)
	e.advance(time.Minute)
	e.detect(ipB)
	_, err := e.svc.Verify(e.ctx(), "operator@acme.example", a.ID)
	var ae *APIError
	if v := e.target(a.ID); err != nil || v.LastCheck == nil || !strings.Contains(v.LastCheck.Message, "The proof found on 9 Nov 2026 stays valid until 7 Feb 2027") ||
		strings.Contains(v.LastCheck.Message, "UTC") || iso.MatchString(v.LastCheck.Message) {
		t.Fatalf("a check of an IP the box does not use now: %v %+v", err, v.LastCheck)
	}

	r, err := e.svc.Detect(e.ctx(), "admin@acme.example", true)
	if err != nil || !strings.Contains(r.Message, "Verified until 7 Feb 2027.") || iso.MatchString(r.Message) {
		t.Fatalf("detect message: %q %v", r.Message, err)
	}
	v := e.target(r.Items[0].ID)
	if v.LastCheck == nil || iso.MatchString(v.LastCheck.Message) || !human.MatchString(v.LastCheck.Message) {
		t.Fatalf("stored message: %+v", v.LastCheck)
	}

	e.advance(91 * 24 * time.Hour) // not seen for more than 90 days
	e.prober.set(ipC)
	e.detect(ipC)
	_, err = e.svc.Scan(e.ctx(), "operator@acme.example", a.ID)
	if !errors.As(err, &ae) || ae.Code != "expired" || !regexp.MustCompile(`expired on \d{1,2} [A-Z][a-z]{2} \d{4}, so`).MatchString(ae.Message) || iso.MatchString(ae.Message) {
		t.Fatalf("expired: %v", err)
	}
}

// Through the generated response types: an IP the box does not go out through now stays scannable (no blocked reason), and the wait
// is part of box_ip.
func TestContract_INV13_PausedAndRetryOverHTTP(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	a := e.committedIP(ipA)
	e.advance(time.Minute)
	e.detect(ipB)

	code, one := e.call("GET", "/exposure/targets/"+a.ID, "viewer", "")
	if code != 200 || one["blocked_reason"] != nil || one["scannable"] != true || one["status"] != "verified" {
		t.Fatalf("GET target: %d %v", code, one)
	}
	code, node := e.call("GET", "/exposure/tree/"+a.ID, "viewer", "")
	if proof, _ := node["proof"].(map[string]any); code != 200 || proof["state"] != ProofNotCurrent || node["blocked"] != nil {
		t.Fatalf("GET node: %d %v", code, node)
	}
	code, all := e.call("GET", "/exposure/targets", "viewer", "")
	if code != 200 {
		t.Fatalf("GET list: %d %v", code, all)
	}
	if box, _ := all["box_ip"].(map[string]any); box["retry_in_min"] != nil {
		t.Fatalf("retry_in_min with attempts left = %v", box["retry_in_min"])
	}

	for range MaxAttemptsPerHour {
		if err := e.svc.attempt(e.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	_, all = e.call("GET", "/exposure/targets", "viewer", "")
	if box, _ := all["box_ip"].(map[string]any); box["retry_in_min"] != float64(60) {
		t.Fatalf("retry_in_min = %v", box["retry_in_min"])
	}
	code, b := e.call("POST", "/exposure/box-ip/verify", "admin", "")
	if code != 429 || errCode(b) != "rate_limited" {
		t.Fatalf("Detect now: %d %v", code, b)
	}
	code, put := e.call("PUT", "/exposure/box-ip/settings", "admin", `{"auto":true,"interval_min":60}`)
	if code != 200 || put["retry_in_min"] != float64(60) {
		t.Fatalf("PUT settings: %d %v", code, put)
	}
}
