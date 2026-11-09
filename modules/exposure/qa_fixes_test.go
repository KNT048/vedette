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

// The scan gate refuses an IP that the latest full check did not see (INV-13). The same state is on the target, so the page
// and the list can say "paused" and not only a toast after a click. Reading it probes nothing.
func TestContract_INV13_PausedIsAStateOfTheTarget(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.committedIP(ipA)
	if v := e.target(a.ID); !v.Scannable || v.BlockedReason != nil {
		t.Fatalf("a current IP: %+v", v)
	}

	e.advance(time.Minute)
	e.detect(ipB) // the box moved to B: the full check just ran and did not see A
	calls := e.prober.count()
	v := e.target(a.ID)
	if v.Scannable || v.BlockedReason == nil || *v.BlockedReason != BlockedNotCurrent {
		t.Fatalf("A after the box moved: scannable=%v blocked=%v", v.Scannable, v.BlockedReason)
	}
	if v.Status != "verified" || str(v.VerifiedAt) != "2026-11-09T10:00:00.000Z" {
		t.Fatalf("A stays verified, last seen at the earlier time: %+v", v)
	}
	all, err := e.svc.Targets(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range all {
		if x.ID == a.ID && (x.Scannable || x.BlockedReason == nil || *x.BlockedReason != BlockedNotCurrent) {
			t.Fatalf("the list says %+v", x)
		}
	}
	if e.prober.count() != calls {
		t.Fatal("reading the target probed the network")
	}

	// The gate and the view give the same answer, and the gate runs no new check inside the window.
	if ok, why := e.scannable(a.ID); ok || why != BlockedNotCurrent {
		t.Fatalf("gate: %v %q", ok, why)
	}
	if e.prober.count() != calls {
		t.Fatal("the gate probed again inside the 5 minutes")
	}

	// Ownership reasons come first: a paused IP without the commitment says so.
	b := e.detect(ipB)[0]
	if v := e.target(b.ID); v.BlockedReason == nil || *v.BlockedReason != BlockedNoCommitment {
		t.Fatalf("B without commitment: %v", v.BlockedReason)
	}

	// Seen again: the pause ends. A full check that does not see it pauses it again, and no clock ends that.
	e.detect(ipA)
	if v := e.target(a.ID); !v.Scannable || v.BlockedReason != nil {
		t.Fatalf("A seen again: %+v", v)
	}
	e.advance(time.Minute)
	e.detect(ipB)
	e.advance(6 * time.Minute)
	if v := e.target(a.ID); v.Scannable || v.BlockedReason == nil || *v.BlockedReason != BlockedNotCurrent {
		t.Fatalf("A after the window stays paused until a check sees it: %+v", v)
	}
}

// A domain is never paused: its own re-check is the TXT record.
func TestContract_INV13_DomainIsNeverPaused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	d := e.addVerifiedDomain()
	if _, err := e.svc.Commit(e.ctx(), "admin@acme.example", d.ID, true); err != nil {
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
		if !errors.As(err, &ae) || !strings.HasPrefix(ae.Message, "Public IPs are not typed in") {
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
	_, err := e.svc.Scan(e.ctx(), "operator@acme.example", a.ID)
	var ae *APIError
	if !errors.As(err, &ae) || !strings.Contains(ae.Message, "it was last seen 9 Nov 2026, 17:00. Scans of it are paused") || strings.Contains(ae.Message, "UTC") || iso.MatchString(ae.Message) {
		t.Fatalf("ip_not_current: %v", err)
	}

	r, err := e.svc.Detect(e.ctx(), "admin@acme.example", true)
	if err != nil || !strings.Contains(r.Message, "Verified until 9 Dec 2026.") || iso.MatchString(r.Message) {
		t.Fatalf("detect message: %q %v", r.Message, err)
	}
	v := e.target(r.Items[0].ID)
	if v.LastCheck == nil || iso.MatchString(v.LastCheck.Message) || !human.MatchString(v.LastCheck.Message) {
		t.Fatalf("stored message: %+v", v.LastCheck)
	}

	e.advance(31 * 24 * time.Hour) // not seen for more than 30 days
	e.prober.set(ipC)
	e.detect(ipC)
	_, err = e.svc.Scan(e.ctx(), "operator@acme.example", a.ID)
	if !errors.As(err, &ae) || ae.Code != "expired" || !regexp.MustCompile(`expired on \d{1,2} [A-Z][a-z]{2} \d{4}, so`).MatchString(ae.Message) || iso.MatchString(ae.Message) {
		t.Fatalf("expired: %v", err)
	}
}

// Through the generated response types: the paused reason is in the contract's enum, and the wait is part of box_ip.
func TestContract_INV13_PausedAndRetryOverHTTP(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	a := e.committedIP(ipA)
	e.advance(time.Minute)
	e.detect(ipB)

	code, one := e.call("GET", "/exposure/targets/"+a.ID, "viewer", "")
	if code != 200 || one["blocked_reason"] != "ip_not_current" || one["scannable"] != false || one["status"] != "verified" {
		t.Fatalf("GET target: %d %v", code, one)
	}
	code, all := e.call("GET", "/exposure/targets", "viewer", "")
	if code != 200 {
		t.Fatalf("GET list: %d %v", code, all)
	}
	paused := 0
	for _, x := range list(all, "items") {
		if m, _ := x.(map[string]any); m["id"] == a.ID && m["blocked_reason"] == "ip_not_current" {
			paused++
		}
	}
	if paused != 1 {
		t.Fatalf("the list does not show A as paused: %v", all["items"])
	}
	if box, _ := all["box_ip"].(map[string]any); box["retry_in_min"] != nil {
		t.Fatalf("retry_in_min with attempts left = %v", box["retry_in_min"])
	}
	code, b := e.call("POST", "/exposure/targets/"+a.ID+"/scan", "operator", "")
	if code != 409 || errCode(b) != "ip_not_current" {
		t.Fatalf("scan: %d %v", code, b)
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
	code, b = e.call("POST", "/exposure/box-ip/verify", "admin", "")
	if code != 429 || errCode(b) != "rate_limited" {
		t.Fatalf("Detect now: %d %v", code, b)
	}
	code, put := e.call("PUT", "/exposure/box-ip/settings", "admin", `{"auto":true,"interval_min":60}`)
	if code != 200 || put["retry_in_min"] != float64(60) {
		t.Fatalf("PUT settings: %d %v", code, put)
	}
}
