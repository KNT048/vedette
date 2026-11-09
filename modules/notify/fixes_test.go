package notify_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// fnNet is an HTTP transport written as a function.
type fnNet func(*http.Request) (*http.Response, error)

func (f fnNet) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func ok200(r *http.Request) *http.Response {
	_, _ = io.ReadAll(r.Body)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":{}}`)), Header: http.Header{}, Request: r}
}

func withNet(f func(*http.Request) (*http.Response, error)) func(*notify.Config) {
	return func(c *notify.Config) { c.HTTPClient = &http.Client{Transport: fnNet(f)} }
}

func eventually(t *testing.T, d time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the condition")
		}
		select {
		case <-time.After(5 * time.Millisecond):
		case <-t.Context().Done():
			t.Fatal("test ended while waiting")
		}
	}
}

func (e *env) critical(id, product, cve string) {
	e.t.Helper()
	if err := e.svc.Publish(e.ctx(), e.vulnNotice(id, product, cve, notify.Critical, "NAS-01")); err != nil {
		e.t.Fatal(err)
	}
}

// ---- BaseURL ----

func TestNoBaseURLMessagesCarryNoInventedLink(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) { c.BaseURL = "" })
	e.telegram(notify.Low)
	e.plain()
	if _, _, err := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: notify.IncidentTrap, Source: "s", Target: "t", Title: "x touched the trap", Severity: notify.Critical, Link: "/honeypot/hits/h1"}); err != nil {
		t.Fatal(err)
	}
	n := e.vulnNotice("n1", "QNAP", "CVE-2026-1", notify.Critical, "NAS-01")
	n.Link = "" // what the findings events build when there is no box address
	if err := e.svc.Publish(e.ctx(), n); err != nil {
		t.Fatal(err)
	}
	e.flush()
	calls := e.net.to("api.telegram.org")
	if len(calls) != 2 {
		t.Fatalf("telegram calls = %d", len(calls))
	}
	for _, c := range calls {
		if strings.Contains(c.Body, "vedette.local") || strings.Contains(c.Body, "http") || !strings.Contains(c.Body, "Open Vedette to see details.") {
			t.Errorf("a message without a box address must say to open Vedette and carry no link: %s", c.Body)
		}
	}
}

func TestContract_PRE4_NoBaseURLNoApprovalRequest(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) { c.BaseURL = "" })
	s := newFakeSMTP(t)
	e.email(s, func(in *notify.ChannelInput) {
		in.Approvals = true
		in.Approvers = []notify.Approver{{UserID: "u-op", Address: "it@acme.example"}}
	})
	_, err := e.svc.SendApprovalRequest(e.ctx(), notify.ApprovalRequest{ID: "req-1", Title: "Block x", Severity: notify.High, Risk: notify.RiskLow, Expires: e.clock.Now().Add(15 * time.Minute)})
	if !errors.Is(err, notify.ErrApprovalUnavailable) || len(s.messages()) != 0 || len(e.tokens.recs) != 0 {
		t.Fatalf("err = %v, %d messages, %d tokens", err, len(s.messages()), len(e.tokens.recs))
	}
}

// ---- approval recipients ----

func TestContract_PRE4_ApprovalMailsGoToTheApproverNotTheAlertList(t *testing.T) {
	e := newEnv(t)
	s := newFakeSMTP(t)
	e.email(s, func(in *notify.ChannelInput) {
		in.Approvals = true
		in.Approvers = []notify.Approver{{UserID: "u-admin", Address: "admin@acme.example"}}
	})
	req := notify.ApprovalRequest{ID: "req-h", Title: "Block x", Severity: notify.High, Risk: notify.RiskHigh, Expires: e.clock.Now().Add(15 * time.Minute)}
	sv, err := e.svc.SendApprovalRequest(e.ctx(), req)
	if err != nil || len(sv) != 1 {
		t.Fatalf("sends = %+v, %v", sv, err)
	}
	rc := s.recipients()
	if len(rc) != 1 || !strings.Contains(rc[0], "admin@acme.example") || strings.Contains(strings.Join(rc, " "), "director@acme.example") || strings.Contains(strings.Join(rc, " "), "it@acme.example") {
		t.Fatalf("a high-risk approval mail must go to the approver only: %v", rc)
	}
	if body := emailBody(t, s.messages()[0]); strings.Contains(body, "/approve/") || !strings.Contains(body, "/response") {
		t.Fatalf("high-risk body: %s", body)
	}
	// A resend goes to the same person, for a high-risk and for a low-risk request.
	req.ID, req.Risk = "req-l", notify.RiskLow
	low, err := e.svc.SendApprovalRequest(e.ctx(), req)
	if err != nil || len(low) != 1 {
		t.Fatal(err)
	}
	n := len(s.recipients())
	for _, id := range []string{sv[0].ID, low[0].ID} {
		if _, err := e.svc.Resend(e.ctx(), "op@x", id); err != nil {
			t.Fatal(err)
		}
	}
	got := s.recipients()[n:]
	if len(got) != 2 || !strings.Contains(got[0], "admin@acme.example") || !strings.Contains(got[1], "admin@acme.example") {
		t.Fatalf("resend went to %v", got)
	}
	if body := emailBody(t, s.messages()[len(s.messages())-1]); strings.Contains(body, "/approve/") {
		t.Fatalf("a resend never carries a token: %s", body)
	}
	if e.count(`SELECT COUNT(*) FROM notify_send WHERE kind = 'approval' AND recipient = 'admin@acme.example'`) != 4 {
		t.Fatal("the recipient is not kept on the send rows")
	}
}

func TestContract_PRE4_TokenRecordCarriesTheAddress(t *testing.T) {
	e := newEnv(t)
	s := newFakeSMTP(t)
	e.email(s, func(in *notify.ChannelInput) {
		in.Approvals = true
		in.Approvers = []notify.Approver{{UserID: "u-op", Address: "it@acme.example"}, {UserID: "u-admin", Address: "admin@acme.example"}}
	})
	if _, err := e.svc.SendApprovalRequest(e.ctx(), notify.ApprovalRequest{ID: "req-1", Title: "t", Severity: notify.High, Risk: notify.RiskLow, Expires: e.clock.Now().Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(e.tokens.addrs, ","); got != "it@acme.example,admin@acme.example" {
		t.Fatalf("addresses on the token records = %q", got)
	}
}

func TestApprovalWithoutRecorderStillTellsEveryone(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) { c.Tokens = nil })
	s := newFakeSMTP(t)
	e.email(s, func(in *notify.ChannelInput) {
		in.Approvals = true
		in.Approvers = []notify.Approver{{UserID: "u-op", Address: "it@acme.example"}}
	})
	e.save(channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "-1002145678901"}, Secret: tgToken, MinSeverity: notify.Low,
		Approvals: true, Approvers: []notify.Approver{{UserID: "u-admin", Address: "123456789"}}})
	sv, err := e.svc.SendApprovalRequest(e.ctx(), notify.ApprovalRequest{ID: "req-1", Title: "t", Severity: notify.High, Risk: notify.RiskLow, Expires: e.clock.Now().Add(15 * time.Minute)})
	if err != nil || len(sv) != 2 {
		t.Fatalf("sends = %+v, %v", sv, err)
	}
	if body := emailBody(t, s.messages()[0]); strings.Contains(body, "/approve/") || !strings.Contains(body, "/response") {
		t.Fatalf("without a token recorder the mail only says to open Vedette: %s", body)
	}
	if len(e.net.to("api.telegram.org")) != 1 {
		t.Fatal("the chat notice was blocked by the missing recorder")
	}
}

func TestSendApprovalRequestChecksTheRequestID(t *testing.T) {
	e := newEnv(t)
	s := newFakeSMTP(t)
	e.email(s, func(in *notify.ChannelInput) {
		in.Approvals = true
		in.Approvers = []notify.Approver{{UserID: "u-op", Address: "it@acme.example"}}
	})
	for _, id := range []string{"", strings.Repeat("a", 129), "bad id", "x\ny"} {
		_, err := e.svc.SendApprovalRequest(e.ctx(), notify.ApprovalRequest{ID: id, Title: "t", Severity: notify.High, Risk: notify.RiskLow, Expires: e.clock.Now().Add(15 * time.Minute)})
		if err == nil || len(s.messages()) != 0 {
			t.Fatalf("id %q: err = %v, %d messages", id, err, len(s.messages()))
		}
	}
}

func TestContract_INV7_EmailApproverIsTheSignInAddress(t *testing.T) {
	e := newEnv(t)
	s := newFakeSMTP(t)
	_, err := e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.Email, notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Secret: relayLogin,
		Fields:    map[string]string{"host": "127.0.0.1", "port": s.port(), "security": "none", "username": "a", "from": "alerts@acme.example", "to": "it@acme.example"},
		Approvals: true, Approvers: []notify.Approver{{UserID: "u-op", Address: "director@acme.example"}}})
	wantCode(t, err, 400, "bad_approver_address")
	// Same address in another case is the same address.
	_, err = e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.Email, notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Secret: relayLogin,
		Fields:    map[string]string{"host": "127.0.0.1", "port": s.port(), "security": "none", "username": "a", "from": "alerts@acme.example", "to": "it@acme.example"},
		Approvals: true, Approvers: []notify.Approver{{UserID: "u-op", Address: "IT@Acme.Example"}}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSlackTokensAreCheckedEvenWithApprovalsOff(t *testing.T) {
	e := newEnv(t)
	in := notify.ChannelInput{Enabled: true, Fields: map[string]string{"label": "#it"}, Secret: slackURL, MinSeverity: notify.Low}
	in.AppToken = "nope"
	_, err := e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.Slack, in)
	wantCode(t, err, 400, "bad_app_token")
	in.AppToken, in.BotToken = "", "nope"
	_, err = e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.Slack, in)
	wantCode(t, err, 400, "bad_bot_token")
}

// ---- reopening ----

func TestContract_INV10_ReopenWhileANewerOneIsOpen(t *testing.T) {
	e := newEnv(t)
	in := notify.IncidentInput{Kind: notify.IncidentTrap, Source: "10.0.0.5", Target: "smb", Title: "x touched the trap", Severity: notify.Critical, Link: "/honeypot/hits/h1"}
	a, _, err := e.svc.OpenIncident(e.ctx(), in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.HandleIncident(e.ctx(), "op@x", a, notify.StatusResolved, ""); err != nil {
		t.Fatal(err)
	}
	b, created, err := e.svc.OpenIncident(e.ctx(), in)
	if err != nil || !created || b == a {
		t.Fatalf("second = %s %v %v", b, created, err)
	}
	for _, st := range []notify.IncidentStatus{notify.StatusNew, notify.StatusAcknowledged} {
		_, err = e.svc.HandleIncident(e.ctx(), "op@x", a, st, "")
		wantCode(t, err, 409, "already_open")
		if ae, _ := apierr.As(err); ae.Extra["open_id"] != b {
			t.Fatalf("the open incident is not named: %v", ae.Extra)
		}
	}
	// Once the newer one is resolved too, the older one can be reopened.
	if _, err := e.svc.HandleIncident(e.ctx(), "op@x", b, notify.StatusResolved, ""); err != nil {
		t.Fatal(err)
	}
	if d, err := e.svc.HandleIncident(e.ctx(), "op@x", a, notify.StatusNew, ""); err != nil || d.Incident.Status != notify.StatusNew {
		t.Fatalf("reopen = %+v, %v", d.Incident, err)
	}
}

// ---- interrupted delivery ----

func TestContract_INV6_CancelledRunKeepsItsRecordAndReturnsTheUnattempted(t *testing.T) {
	var cancel context.CancelFunc
	var calls atomic.Int32
	e := newEnv(t, withNet(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			cancel() // the run ends while the first message is on its way
		}
		return ok200(r), nil
	}))
	e.telegram(notify.Low)
	e.plain()
	e.critical("c1", "WordPress", "CVE-2026-31")
	e.critical("c2", "QNAP", "CVE-2026-32")
	ctx, c := context.WithCancel(e.ctx())
	cancel = c
	if err := e.svc.Flush(ctx); err == nil {
		t.Fatal("a cancelled run reported success")
	}
	if calls.Load() != 1 || e.count(`SELECT COUNT(*) FROM notify_send WHERE ok = 1`) != 1 {
		t.Fatalf("calls = %d, ok records = %d: the message that went out lost its record", calls.Load(), e.count(`SELECT COUNT(*) FROM notify_send WHERE ok = 1`))
	}
	if e.count(`SELECT COUNT(*) FROM notify_pending WHERE state = 'pending'`) != 1 || e.count(`SELECT COUNT(*) FROM notify_pending WHERE state <> 'pending'`) != 0 {
		t.Fatal("the message that was never attempted is not back in the queue")
	}
	e.flush() // alerts are at-least-once: the unattempted one goes now
	if calls.Load() != 2 || e.count(`SELECT COUNT(*) FROM notify_send`) != 2 || e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
		t.Fatalf("after the next run: calls = %d, records = %d", calls.Load(), e.count(`SELECT COUNT(*) FROM notify_send`))
	}
}

func TestContract_INV6_SendCutOffByCancelIsRecordedHonestlyAndNotRetried(t *testing.T) {
	var cancel context.CancelFunc
	var calls atomic.Int32
	e := newEnv(t, withNet(func(r *http.Request) (*http.Response, error) {
		_, _ = io.ReadAll(r.Body)
		calls.Add(1)
		cancel()
		return nil, r.Context().Err() // the answer never arrives: the message may have been delivered
	}))
	e.telegram(notify.Low)
	e.plain()
	e.critical("c1", "WordPress", "CVE-2026-31")
	ctx, c := context.WithCancel(e.ctx())
	cancel = c
	_ = e.svc.Flush(ctx)
	h, _ := e.svc.History(e.ctx())
	if len(h.Items) != 1 || h.Items[0].OK || !strings.Contains(h.Items[0].Error, "may or may not have been sent") {
		t.Fatalf("history = %+v", h.Items)
	}
	if e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
		t.Fatal("a send that had started stays in the queue and would be sent again")
	}
	e.flush()
	if calls.Load() != 1 {
		t.Fatalf("the message was sent %d times", calls.Load())
	}
}

func TestResendRecordsEvenWhenTheRequestEnds(t *testing.T) {
	var cancel context.CancelFunc
	var calls atomic.Int32
	armed := false
	e := newEnv(t, withNet(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if armed {
			cancel()
		}
		return ok200(r), nil
	}))
	e.telegram(notify.Low)
	e.plain()
	e.critical("c1", "WordPress", "CVE-2026-31")
	e.flush()
	h, _ := e.svc.History(e.ctx())
	before := e.count(`SELECT COUNT(*) FROM notify_send`)
	ctx, c := context.WithCancel(e.ctx())
	cancel, armed = c, true
	item, err := e.svc.Resend(ctx, "op@x", h.Items[0].ID)
	if err != nil || !item.OK || e.count(`SELECT COUNT(*) FROM notify_send`) != before+1 {
		t.Fatalf("resend = %+v, %v, rows %d -> %d", item, err, before, e.count(`SELECT COUNT(*) FROM notify_send`))
	}
}

func TestApprovalRequestRecordsEvenWhenTheRequestEnds(t *testing.T) {
	var cancel context.CancelFunc
	e := newEnv(t, withNet(func(r *http.Request) (*http.Response, error) {
		cancel()
		return ok200(r), nil
	}))
	e.save(channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "-1002145678901"}, Secret: tgToken, MinSeverity: notify.Low,
		Approvals: true, Approvers: []notify.Approver{{UserID: "u-admin", Address: "123456789"}}})
	ctx, c := context.WithCancel(e.ctx())
	cancel = c
	sv, err := e.svc.SendApprovalRequest(ctx, notify.ApprovalRequest{ID: "req-1", Title: "t", Severity: notify.High, Risk: notify.RiskLow, Expires: e.clock.Now().Add(15 * time.Minute)})
	if err != nil || len(sv) != 1 || e.count(`SELECT COUNT(*) FROM notify_send WHERE kind = 'approval'`) != 1 {
		t.Fatalf("sends = %+v, %v", sv, err)
	}
}

// ---- webhook targets ----

func TestWebhookCannotPointAtTheBoxOrLoopback(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.HTTPClient = nil
		c.BoxAddrs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("10.9.9.9")} }
	})
	targets := []string{"http://127.0.0.1:8443/api/v1/core/updates/apply", "http://localhost:11434/api/generate", "https://127.0.0.1/x", "https://10.9.9.9/x"}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if p, ok := a.(*net.IPNet); ok && p.IP.To4() != nil && !p.IP.IsLoopback() && !p.IP.IsLinkLocalUnicast() {
			targets = append(targets, "https://"+p.IP.String()+":8443/x") // an address of this machine, read from its interfaces
		}
	}
	for _, u := range targets {
		_, err := e.svc.SaveChannel(e.ctx(), "admin@x", channel.Webhook, notify.ChannelInput{Enabled: true, Fields: map[string]string{"url": u}, Secret: "0123456789abcdef0123", MinSeverity: notify.Low})
		if s, c := apiCode(err); s != 400 || c != "bad_url" {
			t.Errorf("webhook %s: %v", u, err)
		}
	}
}

func TestWebhookTestButtonDoesNotReportRawStatus(t *testing.T) {
	e := newEnv(t)
	e.net.mu.Lock()
	e.net.status = map[string]int{"hooks.company.com": 404}
	e.net.mu.Unlock()
	e.save(channel.Webhook, notify.ChannelInput{Enabled: true, Fields: map[string]string{"url": "https://hooks.company.com/vedette"}, Secret: "0123456789abcdef0123", MinSeverity: notify.Low})
	res, err := e.svc.TestChannel(e.ctx(), "admin@x", channel.Webhook)
	if err != nil || res.OK || strings.Contains(res.Detail, "404") || strings.Contains(res.Detail, "HTTP") || strings.Contains(res.Detail, "nope") {
		t.Fatalf("test result = %+v, %v", res, err)
	}
}

func TestWebhookPreviewMatchesTheMock(t *testing.T) {
	e := newEnv(t)
	e.save(channel.Webhook, notify.ChannelInput{Enabled: true, Fields: map[string]string{"url": "https://hooks.company.com/vedette"}, Secret: "0123456789abcdef0123", MinSeverity: notify.Low})
	id, _, err := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: notify.IncidentTrap, Source: "s", Target: "t", Title: "PC-HR-01 touched the SMB trap", Severity: notify.Critical, What: "w", Action: "a",
		Link: "/honeypot/hits/h1", Devices: []notify.Device{{ID: "a-pc07", Name: "PC-HR-01"}}})
	if err != nil {
		t.Fatal(err)
	}
	e.plain()
	e.flush()
	d, err := e.svc.IncidentDetail(e.ctx(), id)
	if err != nil || len(d.Previews) != 1 {
		t.Fatalf("detail = %+v, %v", d, err)
	}
	for _, want := range []string{`"event": "incident.created"`, `"kind": "trap"`, `"devices": [`, `"id": "a-pc07"`, `"name": "PC-HR-01"`, `"url": "https://box.example:8443/incidents/` + id + `"`} {
		if !strings.Contains(d.Previews[0].Text, want) {
			t.Errorf("webhook preview lacks %s:\n%s", want, d.Previews[0].Text)
		}
	}
	if c := e.net.to("hooks.company.com"); len(c) != 1 || !strings.Contains(c[0].Body, `"event":"incident.created"`) || !strings.Contains(c[0].Body, `"kind":"trap"`) {
		t.Fatalf("webhook calls = %+v", c)
	}
}

func TestSendFailuresAreShownInFriendlyWords(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.plain()
	e.net.failTelegram(400)
	e.critical("c1", "WordPress", "CVE-2026-31")
	e.flush()
	h, _ := e.svc.History(e.ctx())
	if len(h.Items) != 1 || h.Items[0].OK || h.Items[0].Error != "Telegram refused the message (HTTP 400)." {
		t.Fatalf("history = %+v", h.Items)
	}
}

// ---- one slow channel does not hold up the others ----

func TestDeliveryIsPerChannel(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	e := newEnv(t, withNet(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "api.telegram.org" {
			select {
			case started <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
		return ok200(r), nil
	}))
	e.telegram(notify.Low)
	e.slack(notify.Low)
	e.plain()
	e.critical("c1", "WordPress", "CVE-2026-31")
	done := make(chan error, 1)
	go func() { done <- e.svc.Flush(e.ctx()) }()
	<-started
	eventually(t, 5*time.Second, func() bool { return e.count(`SELECT COUNT(*) FROM notify_send WHERE channel = 'slack'`) == 1 })
	if e.count(`SELECT COUNT(*) FROM notify_send WHERE channel = 'telegram'`) != 0 {
		t.Fatal("telegram finished before it was released")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT COUNT(*) FROM notify_send`) != 2 {
		t.Fatal("both channels must have a record")
	}
}

func TestDeliveryCriticalFirstAndBoundedPerRun(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.plain()
	for i := range 25 {
		if err := e.svc.Publish(e.ctx(), e.vulnNotice(fmt.Sprintf("h%d", i), fmt.Sprintf("Product%d", i), fmt.Sprintf("CVE-2026-9%02d", i), notify.High, "NAS-01")); err != nil {
			t.Fatal(err)
		}
	}
	e.critical("late-critical", "Late", "CVE-2026-999")
	e.flush()
	calls := e.net.to("api.telegram.org")
	if len(calls) != 20 || !strings.Contains(calls[0].Body, "Critical:") {
		t.Fatalf("calls = %d, first = %.120s", len(calls), func() string {
			if len(calls) == 0 {
				return ""
			}
			return calls[0].Body
		}())
	}
	if e.count(`SELECT COUNT(*) FROM notify_pending`) != 6 {
		t.Fatalf("pending = %d, want the 6 that did not fit", e.count(`SELECT COUNT(*) FROM notify_pending`))
	}
	e.flush()
	if len(e.net.to("api.telegram.org")) != 26 || e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
		t.Fatal("the rest was not sent by the next run")
	}
}

// ---- events and the suppressed count ----

func TestSuppressedCountFollowsKEVAndFindingEvents(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.Findings = fakeFindings{map[string]notify.FindingInfo{
			"f-1": {CVE: "CVE-2026-100", Product: "QNAP Photo Station", Severity: notify.High, Title: "QNAP is being exploited", What: "w", Action: "a", Devices: []string{"NAS-01"}},
		}}
		c.Devices = fakeDevices{"a-new": "192.168.10.157"}
	})
	e.telegram(notify.Low)
	e.plain()
	e.svc.Subscribe(e.bus)
	pub := func(name string, data any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), events.Event{Name: name, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	suppressed := func() int {
		h, err := e.svc.History(e.ctx())
		if err != nil {
			t.Fatal(err)
		}
		return h.Suppressed.Count
	}
	for _, cve := range []string{"CVE-2026-100", "CVE-2026-101", "CVE-2026-777", "CVE-2026-777"} {
		pub(feeds.EventNewKEV, feeds.NewKEVEvent{CVE: cve, Vendor: "QNAP", Product: "Photo Station"})
	}
	if n := suppressed(); n != 3 {
		t.Fatalf("after 3 new KEV CVEs (one twice) suppressed = %d, want 3", n)
	}
	pub(findings.EventCreated, findings.CreatedEvent{FindingID: "f-1", AssetID: "a-1", CVE: "CVE-2026-100", Severity: findings.SeverityHigh, Basis: findings.BasisProduct})
	if n := suppressed(); n != 2 {
		t.Fatalf("a finding for CVE-2026-100 must take it out of the count: %d", n)
	}
	pub(findings.EventCreated, findings.CreatedEvent{FindingID: "f-2", AssetID: "a-2", CVE: "cve-2026-101", Severity: findings.SeverityHigh, Basis: findings.BasisVersion})
	if n := suppressed(); n != 1 {
		t.Fatalf("suppressed = %d, want only CVE-2026-777", n)
	}
	pub(feeds.EventNewKEV, feeds.NewKEVEvent{CVE: "CVE-2026-100"}) // a repeat of a matched CVE does not bring it back
	if n := suppressed(); n != 1 {
		t.Fatalf("a matched CVE came back: %d", n)
	}
	pub(findings.EventStatusChanged, findings.StatusChangedEvent{FindingID: "f-1", From: findings.StatusSuspected, To: findings.StatusConfirmed})
	pub(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "a-new", Notify: true})
	l, _ := e.svc.Incidents(e.ctx())
	if len(l) != 1 || l[0].Kind != notify.IncidentUnknownDevice || l[0].Devices[0].Name != "192.168.10.157" {
		t.Fatalf("incidents = %+v", l)
	}
	e.clock.Add(4 * time.Minute)
	e.flush()
	if n := e.count(`SELECT COUNT(*) FROM notify_send WHERE kind = 'vuln'`); n != 2 {
		t.Fatalf("vuln messages = %d (the finding and its confirmation)", n)
	}
}

// ---- the module is off ----

func TestPublishAndOpenIncidentWhileOffQueueNothing(t *testing.T) {
	off := false
	e := newEnv(t, func(c *notify.Config) { c.Modules = gateFunc(func(string) bool { return !off }) })
	e.telegram(notify.Low)
	s := newFakeSMTP(t)
	e.email(s, func(in *notify.ChannelInput) {
		in.Approvals = true
		in.Approvers = []notify.Approver{{UserID: "u-op", Address: "it@acme.example"}}
	})
	e.plain()
	off = true
	if _, _, err := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: notify.IncidentTrap, Source: "s", Target: "t", Title: "x", Severity: notify.Critical, Link: "/logs"}); !errors.Is(err, notify.ErrModuleOff) {
		t.Fatalf("OpenIncident err = %v", err)
	}
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("n", "QNAP", "CVE-2026-1", notify.Critical, "NAS-01")); !errors.Is(err, notify.ErrModuleOff) {
		t.Fatalf("Publish err = %v", err)
	}
	if _, err := e.svc.SendApprovalRequest(e.ctx(), notify.ApprovalRequest{ID: "r", Title: "t", Risk: notify.RiskLow, Expires: e.clock.Now().Add(time.Minute)}); !errors.Is(err, notify.ErrModuleOff) {
		t.Fatalf("SendApprovalRequest err = %v", err)
	}
	if e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 || e.count(`SELECT COUNT(*) FROM notify_incident`) != 0 || e.count(`SELECT COUNT(*) FROM notify_notice`) != 0 || len(s.messages()) != 0 {
		t.Fatal("something was queued while the module is off")
	}
}

// ---- sign-in codes ----

func TestSendCodeErrorsCarryNothingFromTheServer(t *testing.T) {
	e := newEnv(t)
	s := newFakeSMTP(t)
	s.rcptReply = "550 5.1.1 mx7.internal.corp: user jane.doe@acme.example unknown, relay 10.1.2.3"
	e.email(s)
	err := e.svc.CodeMailer().SendCode(e.ctx(), "jane.doe@acme.example", "246810")
	if err == nil {
		t.Fatal("a refused code was reported as sent")
	}
	for _, bad := range []string{"mx7", "internal.corp", "jane", "acme.example", "10.1.2.3", "246810", "unknown"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("error %q contains %q", err, bad)
		}
	}
	if !strings.Contains(err.Error(), "550") {
		t.Errorf("the SMTP status is the one thing it may say: %q", err)
	}
	if strings.Contains(err.Error(), "HTTP") {
		t.Errorf("SMTP is not HTTP: %q", err)
	}
}

// ---- time zone of the quiet hours ----

func TestQuietHoursFollowTheBoxTimeZoneNotTheProcess(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) { c.Location = nil }) // no zone given: Asia/Ho_Chi_Minh
	e.telegram(notify.Low)
	e.rules(notify.Quiet{Enabled: true, From: "22:00", To: "06:30", AllowCritical: false}, notify.Grouping{Enabled: false, WindowMin: 60})
	// 10:00 UTC is 17:00 in Ho Chi Minh: awake.
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("a", "QNAP", "CVE-2026-1", notify.High, "NAS-01")); err != nil {
		t.Fatal(err)
	}
	e.flush()
	if len(e.net.to("api.telegram.org")) != 1 {
		t.Fatal("17:00 local time is not quiet")
	}
	// 16:00 UTC is 23:00 there: quiet, although it is the middle of the afternoon in UTC.
	e.clock.Add(6 * time.Hour)
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("b", "WordPress", "CVE-2026-2", notify.High, "WEB01")); err != nil {
		t.Fatal(err)
	}
	e.flush()
	if len(e.net.to("api.telegram.org")) != 1 || e.count(`SELECT COUNT(*) FROM notify_pending WHERE reason = 'quiet'`) != 1 {
		t.Fatal("23:00 in Ho Chi Minh must be held")
	}
	// 23:30 UTC the next morning, 06:30 local: released.
	e.clock.Add(7*time.Hour + 30*time.Minute)
	e.flush()
	if len(e.net.to("api.telegram.org")) != 2 {
		t.Fatal("the held notice was not released when quiet hours ended")
	}
}

func TestQuietHoursUseTheZoneCoreGives(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.Location = nil
		c.Zone = func(context.Context) string { return "America/New_York" }
	})
	e.telegram(notify.Low)
	e.rules(notify.Quiet{Enabled: true, From: "22:00", To: "06:30", AllowCritical: false}, notify.Grouping{Enabled: false, WindowMin: 60})
	// 10:00 UTC is 05:00 in New York in November: quiet there, daytime in Ho Chi Minh.
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("a", "QNAP", "CVE-2026-1", notify.High, "NAS-01")); err != nil {
		t.Fatal(err)
	}
	e.flush()
	if len(e.net.to("api.telegram.org")) != 0 {
		t.Fatal("05:00 in New York must be held")
	}
}

// ---- the incident list ----

func TestIncidentsListIsCappedAndEachHasItsOwnChildren(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.plain()
	var ids []string
	for i := range 3 {
		id, _, err := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: notify.IncidentTrap, Source: fmt.Sprintf("10.0.0.%d", i), Target: "smb", Title: fmt.Sprintf("incident %d", i), Severity: notify.High, Link: "/logs",
			Devices: []notify.Device{{ID: fmt.Sprintf("a-%d", i), Name: fmt.Sprintf("PC-%d", i)}, {ID: fmt.Sprintf("b-%d", i), Name: fmt.Sprintf("LAP-%d", i)}}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		e.clock.Add(time.Minute)
	}
	e.flush()
	l, err := e.svc.Incidents(e.ctx())
	if err != nil || len(l) != 3 {
		t.Fatalf("incidents = %+v, %v", l, err)
	}
	for k, inc := range l { // newest seen first
		i := 2 - k
		if inc.ID != ids[i] || len(inc.Devices) != 2 || inc.Devices[0].ID != fmt.Sprintf("a-%d", i) || inc.Devices[1].Name != fmt.Sprintf("LAP-%d", i) || len(inc.Sends) != 1 {
			t.Fatalf("incident %d = %+v", i, inc)
		}
	}
	e.write(func(tx *sql.Tx) error { // 510 more, straight into the table: only the size of the list is under test
		for i := range 510 {
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_incident (id, kind, title, link, severity, what, action, first_seen, last_seen, dedupe_key) VALUES (?, 'bad_address', 't', '/logs', 'low', '', '', ?, ?, ?)`,
				fmt.Sprintf("in-bulk-%d", i), store.FormatTS(e.clock.Now().Add(time.Duration(i)*time.Second)), store.FormatTS(e.clock.Now().Add(time.Duration(i)*time.Second)), fmt.Sprintf("%064d", i)); err != nil {
				return err
			}
		}
		return nil
	})
	if l, err = e.svc.Incidents(e.ctx()); err != nil || len(l) != 500 {
		t.Fatalf("incidents = %d, %v", len(l), err)
	}
}

// ---- D-78: the first CISA pull is silent ----

func baselineEnv(t *testing.T) (*env, func(string, any)) {
	t.Helper()
	m := map[string]notify.FindingInfo{}
	for i := range 5 {
		m[fmt.Sprintf("f-%d", i)] = notify.FindingInfo{CVE: fmt.Sprintf("CVE-2026-50%d", i), Product: fmt.Sprintf("Product%d", i), Severity: notify.Critical, Title: "is being exploited", What: "w", Action: "a", Devices: []string{"NAS-01"}}
	}
	m["f-new"] = notify.FindingInfo{CVE: "CVE-2026-900", Product: "Fresh", Severity: notify.Critical, Title: "is being exploited", What: "w", Action: "a", Devices: []string{"NAS-01"}}
	e := newEnv(t, func(c *notify.Config) { c.Findings = fakeFindings{m} })
	e.telegram(notify.Low)
	e.plain()
	e.svc.Subscribe(e.bus)
	return e, func(name string, data any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), events.Event{Name: name, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
}

func createdBatch(pub func(string, any)) {
	for i := range 5 {
		pub(findings.EventCreated, findings.CreatedEvent{FindingID: fmt.Sprintf("f-%d", i), AssetID: "a-1", CVE: fmt.Sprintf("CVE-2026-50%d", i), Severity: findings.SeverityCritical, Basis: findings.BasisProduct})
	}
}

// notify subscribed before inventory: the baseline event comes first and the re-match findings after it.
func TestBaselineIsSilentWhenTheBaselineEventComesFirst(t *testing.T) {
	e, pub := baselineEnv(t)
	pub(feeds.EventSyncBaseline, feeds.SyncBaselineEvent{Source: "cisa-kev", Count: 1200})
	createdBatch(pub)
	e.clock.Add(time.Hour)
	e.flush()
	if e.net.total() != 0 || e.count(`SELECT COUNT(*) FROM notify_send`) != 0 || e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
		t.Fatalf("the baseline sent %d messages", e.net.total())
	}
	if h, _ := e.svc.History(e.ctx()); h.Suppressed.Count != 0 {
		t.Fatalf("a baseline is not new: suppressed = %d", h.Suppressed.Count)
	}
	// A later pull: new_kev, then the finding it creates: one message.
	pub(feeds.EventNewKEV, feeds.NewKEVEvent{CVE: "CVE-2026-900", Vendor: "V", Product: "Fresh"})
	pub(findings.EventCreated, findings.CreatedEvent{FindingID: "f-new", AssetID: "a-1", CVE: "CVE-2026-900", Severity: findings.SeverityCritical, Basis: findings.BasisProduct})
	e.flush()
	if len(e.net.to("api.telegram.org")) != 0 {
		t.Fatal("the notice must wait out its settle time first")
	}
	e.clock.Add(4 * time.Minute)
	e.flush()
	if n := len(e.net.to("api.telegram.org")); n != 1 {
		t.Fatalf("the later finding sent %d messages, want 1", n)
	}
}

// notify subscribed after inventory (the order in cmd/vedette today): the re-match findings are already queued when the
// baseline event arrives, and they must not go out.
func TestBaselineIsSilentWhenTheRematchFindingsComeFirst(t *testing.T) {
	e, pub := baselineEnv(t)
	createdBatch(pub)
	e.flush() // a job run in the middle of the re-match sends nothing: the notices are still settling
	if e.net.total() != 0 {
		t.Fatalf("a settling notice was sent: %d", e.net.total())
	}
	pub(feeds.EventSyncBaseline, feeds.SyncBaselineEvent{Source: "cisa-kev", Count: 1200})
	e.clock.Add(time.Hour)
	e.flush()
	if e.net.total() != 0 || e.count(`SELECT COUNT(*) FROM notify_send`) != 0 || e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
		t.Fatalf("the baseline sent %d messages", e.net.total())
	}
	pub(feeds.EventNewKEV, feeds.NewKEVEvent{CVE: "CVE-2026-900", Vendor: "V", Product: "Fresh"})
	pub(findings.EventCreated, findings.CreatedEvent{FindingID: "f-new", AssetID: "a-1", CVE: "CVE-2026-900", Severity: findings.SeverityCritical, Basis: findings.BasisProduct})
	e.clock.Add(4 * time.Minute)
	e.flush()
	if n := len(e.net.to("api.telegram.org")); n != 1 {
		t.Fatalf("the later finding sent %d messages, want 1", n)
	}
}

func TestNewDeviceAfterTheBaselineAlertsNormally(t *testing.T) {
	e, pub := baselineEnv(t)
	pub(feeds.EventSyncBaseline, feeds.SyncBaselineEvent{Source: "cisa-kev", Count: 1200})
	e.clock.Add(10 * time.Minute) // the window is over
	pub(findings.EventCreated, findings.CreatedEvent{FindingID: "f-new", AssetID: "a-new", CVE: "CVE-2026-900", Severity: findings.SeverityCritical, Basis: findings.BasisProduct})
	e.clock.Add(4 * time.Minute)
	e.flush()
	if n := len(e.net.to("api.telegram.org")); n != 1 {
		t.Fatalf("a finding of a device added after the baseline sent %d messages, want 1", n)
	}
}
