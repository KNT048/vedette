package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

func TestContract_INV7_ApproverRules(t *testing.T) {
	e := newEnv(t)
	tg := func(approvals bool, a ...notify.Approver) notify.ChannelInput {
		return notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "-1002145678901"}, Secret: tgToken, MinSeverity: notify.High, Approvals: approvals, Approvers: a}
	}
	save := func(in notify.ChannelInput) error {
		_, err := e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.Telegram, in)
		return err
	}
	wantCode(t, save(tg(true)), 400, "approvers_required")
	wantCode(t, save(tg(true, notify.Approver{UserID: "u-view", Address: "123456"})), 400, "viewer_not_allowed")
	wantCode(t, save(tg(true, notify.Approver{UserID: "u-off", Address: "123456"})), 400, "no_such_user")
	wantCode(t, save(tg(true, notify.Approver{UserID: "u-ghost", Address: "123456"})), 400, "no_such_user")
	wantCode(t, save(tg(true, notify.Approver{UserID: "u-op", Address: "123456"}, notify.Approver{UserID: "u-op", Address: "654321"})), 400, "duplicate_user")
	wantCode(t, save(tg(true, notify.Approver{UserID: "u-op", Address: "@name"})), 400, "bad_approver_address")
	if e.count(`SELECT COUNT(*) FROM notify_channel`) != 0 {
		t.Fatal("a refused save left a row")
	}
	if err := save(tg(true, notify.Approver{UserID: "u-op", Address: "123456"}, notify.Approver{UserID: "u-admin", Address: " 777777 "})); err != nil {
		t.Fatal(err)
	}
	v, _ := e.svc.Channels(e.ctx())
	if c := v.Channels[0]; !c.Approvals || len(c.Approvers) != 2 || c.Approvers[1].Address != "777777" {
		t.Fatalf("telegram = %+v", c)
	}
	// Turning approvals off clears the list.
	if err := save(tg(false, notify.Approver{UserID: "u-op", Address: "123456"})); err != nil {
		t.Fatal(err)
	}
	if v, _ = e.svc.Channels(e.ctx()); v.Channels[0].Approvals || len(v.Channels[0].Approvers) != 0 {
		t.Fatalf("telegram = %+v", v.Channels[0])
	}
	// Webhook and Zalo OA cannot take approvals; email takes an email address.
	_, err := e.svc.SaveChannel(e.ctx(), "a@x.example", channel.Webhook, notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Approvals: true,
		Fields: map[string]string{"url": "https://hooks.company.com/vedette"}, Secret: "0123456789abcdef0123", Approvers: []notify.Approver{{UserID: "u-op", Address: "x"}}})
	wantCode(t, err, 400, "approvals_unsupported")
	s := newFakeSMTP(t)
	_, err = e.svc.SaveChannel(e.ctx(), "a@x.example", channel.Email, notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Approvals: true, Secret: relayLogin,
		Fields:    map[string]string{"host": "127.0.0.1", "port": s.port(), "security": "none", "username": "a", "from": "alerts@acme.example", "to": "it@acme.example"},
		Approvers: []notify.Approver{{UserID: "u-op", Address: "not an email"}}})
	wantCode(t, err, 400, "bad_approver_address")
}

func TestContract_INV8_BoundaryChecks(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) { c.SMTPLoopback = false }) // as in production: an SMTP server on loopback is refused
	in := func(fields map[string]string, secret string) notify.ChannelInput {
		return notify.ChannelInput{Enabled: true, Fields: fields, Secret: secret, MinSeverity: notify.High}
	}
	for _, tc := range []struct {
		name string
		t    channel.Type
		in   notify.ChannelInput
		code string
	}{
		{"slack host", channel.Slack, in(nil, "https://evil.example/services/T1/B1/xx"), "bad_webhook"},
		{"slack no secret", channel.Slack, in(nil, ""), "secret_required"},
		{"telegram token", channel.Telegram, in(map[string]string{"chat_id": "-100123456"}, "abc"), "bad_token"},
		{"telegram chat", channel.Telegram, in(map[string]string{"chat_id": "x"}, tgToken), "bad_chat_id"},
		{"webhook http public", channel.Webhook, in(map[string]string{"url": "http://hooks.company.com/x"}, "0123456789abcdef0123"), "bad_url"},
		{"webhook loopback", channel.Webhook, in(map[string]string{"url": "https://localhost/x"}, "0123456789abcdef0123"), "bad_url"},
		{"webhook short key", channel.Webhook, in(map[string]string{"url": "https://hooks.company.com/x"}, "short"), "bad_secret"},
		{"zalo oa", channel.Zalo, in(map[string]string{"oa_id": "1", "user_id": "123456"}, "0123456789abcdef0123"), "bad_oa_id"},
		{"zalo personal session", channel.ZaloPersonal, in(map[string]string{"user_id": "123456"}, "not json"), "bad_secret"},
		{"email port mismatch", channel.Email, in(map[string]string{"host": "smtp.acme.example", "port": "587", "security": "ssl", "username": "a", "from": "a@acme.example", "to": "b@acme.example"}, "pw"), "port_mismatch"},
		{"email bad port", channel.Email, in(map[string]string{"host": "smtp.acme.example", "port": "abc", "security": "ssl", "username": "a", "from": "a@acme.example", "to": "b@acme.example"}, "pw"), "bad_port"},
		{"email none public", channel.Email, in(map[string]string{"host": "smtp.acme.example", "port": "25", "security": "none", "username": "a", "from": "a@acme.example", "to": "b@acme.example"}, "pw"), "bad_security"},
		{"email to", channel.Email, in(map[string]string{"host": "smtp.acme.example", "port": "587", "security": "starttls", "username": "a", "from": "a@acme.example", "to": "b@acme.example, nope"}, "pw"), "bad_to"},
		{"email host", channel.Email, in(map[string]string{"host": "not a host", "port": "587", "security": "starttls", "username": "a", "from": "a@acme.example", "to": "b@acme.example"}, "pw"), "bad_host"},
		// walk 3: in a container 127.0.0.1 is core itself; the webhook's rule (loopback, the box, link-local and metadata) applies
		{"email loopback", channel.Email, in(map[string]string{"host": "127.0.0.1", "port": "25", "security": "none", "username": "a", "from": "a@acme.example", "to": "b@acme.example"}, "pw"), "bad_host"},
		{"email metadata", channel.Email, in(map[string]string{"host": "169.254.169.254", "port": "587", "security": "starttls", "username": "a", "from": "a@acme.example", "to": "b@acme.example"}, "pw"), "bad_host"},
	} {
		_, err := e.svc.SaveChannel(e.ctx(), "admin@acme.example", tc.t, tc.in)
		if s, c := apiCode(err); s != 400 || c != tc.code {
			t.Errorf("%s: %v (%d %s), want 400 %s", tc.name, err, s, c, tc.code)
		}
	}
	_, err := e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "-100123456"}, Secret: tgToken, MinSeverity: "info"})
	wantCode(t, err, 400, "bad_severity")
	if e.count(`SELECT COUNT(*) FROM notify_channel`) != 0 || e.count(`SELECT COUNT(*) FROM core_secret`) != 0 {
		t.Fatal("a refused save left a row or a secret")
	}
}

func TestContract_INV9_EmailChannelCarriesCodes(t *testing.T) {
	e := newEnv(t)
	e.users.emailCode = 3
	s := newFakeSMTP(t)
	e.email(s)
	v, err := e.svc.Channels(e.ctx())
	if err != nil || v.EmailCodeUsers != 3 {
		t.Fatalf("email_code_users = %d, %v", v.EmailCodeUsers, err)
	}
	// Removing the channel still works; the count stays so the screen can warn.
	if err := e.svc.DeleteChannel(e.ctx(), "admin@acme.example", channel.Email); err != nil {
		t.Fatal(err)
	}
	if v, _ = e.svc.Channels(e.ctx()); v.EmailCodeUsers != 3 || v.Channels[4].Configured {
		t.Fatalf("view = %+v", v)
	}
}

func TestContract_POST5_EmailReadyAndCodes(t *testing.T) {
	var on = true
	gate := gateFunc(func(string) bool { return on })
	e := newEnv(t, func(c *notify.Config) { c.Modules = gate })
	if ok, why := e.svc.EmailReady(e.ctx()); ok || why != notify.ReasonChannelNotReady {
		t.Fatalf("EmailReady = %v %q", ok, why)
	}
	m := e.svc.CodeMailer()
	if m.Available(e.ctx()) || m.SendCode(e.ctx(), "it@acme.example", "123456") == nil {
		t.Fatal("codes available without an email channel")
	}
	s := newFakeSMTP(t)
	e.email(s)
	if ok, why := e.svc.EmailReady(e.ctx()); !ok || why != "" || !m.Available(e.ctx()) {
		t.Fatalf("EmailReady = %v %q", ok, why)
	}
	if err := m.SendCode(e.ctx(), "u@acme.example", "482913"); err != nil {
		t.Fatal(err)
	}
	if rc := s.recipients(); len(rc) != 1 || !strings.Contains(rc[0], "u@acme.example") {
		t.Fatalf("recipients = %v (a code goes to the user only, not the alert list)", rc)
	}
	if body := emailBody(t, s.messages()[0]); !strings.Contains(body, "482913") {
		t.Fatalf("body = %q", body)
	}
	// The code is not kept anywhere: not in history, not in the audit log.
	if e.count(`SELECT COUNT(*) FROM notify_send`) != 0 || e.count(`SELECT COUNT(*) FROM core_audit WHERE detail LIKE '%482913%' OR target LIKE '%482913%'`) != 0 {
		t.Fatal("the sign-in code was recorded")
	}
	e.save(channel.Email, notify.ChannelInput{Enabled: false, MinSeverity: notify.High, Fields: map[string]string{"host": "127.0.0.1", "port": s.port(), "security": "none", "username": "a", "from": "alerts@acme.example", "to": "it@acme.example"}})
	if ok, why := e.svc.EmailReady(e.ctx()); ok || why != notify.ReasonChannelNotReady {
		t.Fatalf("a disabled channel is ready: %v %q", ok, why)
	}
	e.save(channel.Email, notify.ChannelInput{Enabled: true, MinSeverity: notify.High, Fields: map[string]string{"host": "127.0.0.1", "port": s.port(), "security": "none", "username": "a", "from": "alerts@acme.example", "to": "it@acme.example"}})
	on = false
	if ok, why := e.svc.EmailReady(e.ctx()); ok || why != notify.ReasonModuleOff || m.SendCode(e.ctx(), "u@acme.example", "111111") == nil {
		t.Fatalf("module off: %v %q", ok, why)
	}
}

type gateFunc func(string) bool

func (g gateFunc) Enabled(id string) bool { return g(id) }

// emailBody returns the decoded text of a message the fake server kept.
func emailBody(t *testing.T, raw string) string {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(quotedprintable.NewReader(m.Body))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestContract_INV10_IncidentsGroupRepeats(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.plain()
	in := notify.IncidentInput{Kind: notify.IncidentTrap, Source: "192.168.10.107", Target: "FILESRV-OLD|smb", Title: "PC-HR-01 touched the SMB trap", Severity: notify.Critical,
		What: "x", Action: "y", Link: "/honeypot/hits/hit-1", Devices: []notify.Device{{ID: "a-pc07", Name: "PC-HR-01"}}}
	id, created, err := e.svc.OpenIncident(e.ctx(), in)
	if err != nil || !created {
		t.Fatalf("first = %q %v %v", id, created, err)
	}
	e.clock.Add(time.Minute)
	in.At = e.clock.Now()
	id2, created, err := e.svc.OpenIncident(e.ctx(), in)
	if err != nil || created || id2 != id {
		t.Fatalf("repeat = %q %v %v", id2, created, err)
	}
	l, _ := e.svc.Incidents(e.ctx())
	if len(l) != 1 || l[0].Count != 2 || l[0].FirstSeen == l[0].LastSeen || l[0].Status != notify.StatusNew || l[0].HandledBy != nil {
		t.Fatalf("incidents = %+v", l)
	}
	if e.seen.count("notify.incident.created") != 1 {
		t.Fatalf("incident.created published %d times", e.seen.count("notify.incident.created"))
	}
	// A different target is another incident.
	in.Target = "FILESRV-OLD|rdp"
	if _, created, _ := e.svc.OpenIncident(e.ctx(), in); !created {
		t.Fatal("a different target was merged")
	}
	e.flush()
	if n := len(e.net.to("api.telegram.org")); n != 2 {
		t.Fatalf("telegram messages = %d: one per new incident, none for the repeat", n)
	}
	// Never a vulnerability kind, never a bad shape.
	for _, bad := range []notify.IncidentInput{
		{Kind: "vuln", Title: "t", Severity: notify.High, Link: "/logs"},
		{Kind: notify.IncidentTrap, Title: "", Severity: notify.High, Link: "/logs"},
		{Kind: notify.IncidentTrap, Title: "t", Severity: "meh", Link: "/logs"},
		{Kind: notify.IncidentTrap, Title: "t", Severity: notify.High, Link: "https://evil.example/"},
		{Kind: notify.IncidentTrap, Title: "t", Severity: notify.High, Link: "//evil.example/"},
	} {
		if _, _, err := e.svc.OpenIncident(e.ctx(), bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	// Handling: acknowledge with a note, reopen, resolve; a repeat after resolve is a new incident.
	d, err := e.svc.HandleIncident(e.ctx(), "it@acme.example", id, notify.StatusAcknowledged, "  looking into it  ")
	if err != nil || d.Incident.Status != notify.StatusAcknowledged || *d.Incident.HandledBy != "it@acme.example" || *d.Incident.Note != "looking into it" || d.Incident.HandledAt == nil {
		t.Fatalf("ack = %+v, %v", d.Incident, err)
	}
	if len(d.Previews) != 1 || d.Previews[0].Channel != channel.Telegram || !strings.Contains(d.Previews[0].Text, "PC-HR-01") {
		t.Fatalf("previews = %+v", d.Previews)
	}
	_, err = e.svc.HandleIncident(e.ctx(), "it@acme.example", id, notify.StatusResolved, strings.Repeat("é", 501))
	wantCode(t, err, 400, "note_too_long")
	_, err = e.svc.HandleIncident(e.ctx(), "it@acme.example", id, "weird", "")
	wantCode(t, err, 400, "bad_status")
	_, err = e.svc.HandleIncident(e.ctx(), "it@acme.example", "in-nope", notify.StatusResolved, "")
	wantCode(t, err, 404, "not_found")
	if d, err = e.svc.HandleIncident(e.ctx(), "it@acme.example", id, notify.StatusNew, "ignored"); err != nil || d.Incident.HandledBy != nil || d.Incident.Note != nil || d.Incident.HandledAt != nil {
		t.Fatalf("reopen = %+v, %v", d.Incident, err)
	}
	if _, err = e.svc.HandleIncident(e.ctx(), "it@acme.example", id, notify.StatusResolved, strings.Repeat("é", 500)); err != nil {
		t.Fatal(err)
	}
	in.Target = "FILESRV-OLD|smb"
	if id3, created, _ := e.svc.OpenIncident(e.ctx(), in); !created || id3 == id {
		t.Fatal("a repeat after resolving was merged into the resolved incident")
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.incident_status'`); n != 3 {
		t.Fatalf("incident status audit rows = %d, want 3 (every PATCH is audited, the refused ones are not)", n)
	}
}

func TestContract_INV11_TestAndResend(t *testing.T) {
	e := newEnv(t)
	_, err := e.svc.TestChannel(e.ctx(), "admin@acme.example", channel.Telegram)
	wantCode(t, err, 400, "not_configured")
	e.telegram(notify.Low)
	e.plain()
	res, err := e.svc.TestChannel(e.ctx(), "admin@acme.example", channel.Telegram)
	if err != nil || !res.OK || res.At == "" {
		t.Fatalf("test = %+v %v", res, err)
	}
	v, _ := e.svc.Channels(e.ctx())
	if lt := v.Channels[0].LastTest; lt == nil || !lt.OK || lt.Detail == "" {
		t.Fatalf("last_test = %+v", lt)
	}
	// Saving clears last_test.
	e.telegram(notify.Low)
	if v, _ = e.svc.Channels(e.ctx()); v.Channels[0].LastTest != nil {
		t.Fatal("last_test kept after save")
	}
	e.net.failTelegram(401)
	if res, _ = e.svc.TestChannel(e.ctx(), "admin@acme.example", channel.Telegram); res.OK || res.Detail == "" || strings.Contains(res.Detail, tgSecret) {
		t.Fatalf("failed test = %+v", res)
	}
	e.net.failTelegram(200)

	if err := e.svc.Publish(e.ctx(), e.vulnNotice("rs", "WordPress", "CVE-2026-30", notify.High, "WEB01")); err != nil {
		t.Fatal(err)
	}
	e.flush()
	h, _ := e.svc.History(e.ctx())
	if len(h.Items) != 1 {
		t.Fatalf("history = %+v", h)
	}
	before := len(e.net.to("api.telegram.org"))
	it, err := e.svc.Resend(e.ctx(), "it@acme.example", h.Items[0].ID)
	if err != nil || !it.OK || it.Kind != "vuln" || it.ID == h.Items[0].ID || it.Link != h.Items[0].Link {
		t.Fatalf("resend = %+v, %v", it, err)
	}
	if len(e.net.to("api.telegram.org")) != before+1 {
		t.Fatal("resend did not send")
	}
	if l, _ := e.svc.FindingNotices(e.ctx(), "f-rs"); len(l) != 2 {
		t.Fatalf("finding notices after resend = %+v", l)
	}
	e.net.failTelegram(500)
	if it, err = e.svc.Resend(e.ctx(), "it@acme.example", h.Items[0].ID); err != nil || it.OK || it.Error == "" {
		t.Fatalf("failed resend = %+v, %v (a failed send is a record, not an API error)", it, err)
	}
	_, err = e.svc.Resend(e.ctx(), "it@acme.example", "sd-nope")
	wantCode(t, err, 404, "not_found")
	e.save(channel.Telegram, notify.ChannelInput{Enabled: false, Fields: map[string]string{"chat_id": "-1002145678901"}, MinSeverity: notify.Low})
	_, err = e.svc.Resend(e.ctx(), "it@acme.example", h.Items[0].ID)
	wantCode(t, err, 409, "channel_not_ready")
}

const zaloSession = `{"imei":"abcdefgh12345","userAgent":"Mozilla/5.0","cookie":[{"name":"zpsid","value":"abcdefgh1234"}]}`

func TestContract_INV12_DeletingZaloPersonalDeletesTheSession(t *testing.T) {
	e := newEnv(t)
	e.save(channel.ZaloPersonal, notify.ChannelInput{Enabled: true, Fields: map[string]string{"user_id": "123456789", "group": "true", "junk": "x"}, Secret: zaloSession, MinSeverity: notify.High})
	if e.count(`SELECT COUNT(*) FROM core_secret`) != 1 {
		t.Fatal("session not stored")
	}
	v, _ := e.svc.Channels(e.ctx())
	zp := v.Channels[3]
	if zp.Fields["group"] != "true" || zp.Fields["junk"] != "" || zp.SecretLast4 == nil {
		t.Fatalf("zalo-personal = %+v", zp)
	}
	if err := e.svc.DeleteChannel(e.ctx(), "admin@acme.example", channel.ZaloPersonal); err != nil {
		t.Fatal(err)
	}
	v, _ = e.svc.Channels(e.ctx())
	if e.count(`SELECT COUNT(*) FROM core_secret`) != 0 || v.Channels[3].Configured || v.Channels[3].SecretLast4 != nil || len(v.Channels[3].Fields) != 0 {
		t.Fatalf("after delete: %+v, %d secrets", v.Channels[3], e.count(`SELECT COUNT(*) FROM core_secret`))
	}
	if err := e.svc.DeleteChannel(e.ctx(), "admin@acme.example", channel.Webhook); err != nil {
		t.Fatalf("deleting a channel that was never saved: %v", err)
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.channel_remove'`) != 2 {
		t.Fatal("deletes not audited")
	}
}

func TestContract_PRE4_ApprovalLinks(t *testing.T) {
	e := newEnv(t)
	s := newFakeSMTP(t)
	e.email(s, func(in *notify.ChannelInput) {
		in.Approvals = true
		in.Approvers = []notify.Approver{{UserID: "u-op", Address: "it@acme.example"}, {UserID: "u-admin", Address: "admin@acme.example"}}
	})
	req := notify.ApprovalRequest{ID: "req-1", Title: "Block 185.220.101.47 on the firewall", What: "w", Action: "a", Severity: notify.High, Risk: notify.RiskLow, Expires: e.clock.Now().Add(15 * time.Minute), Channels: allApprovalChannels}
	sends, err := e.svc.SendApprovalRequest(e.ctx(), req)
	if err != nil || len(sends) != 2 {
		t.Fatalf("sends = %+v, %v", sends, err)
	}
	if len(e.tokens.recs) != 2 || e.tokens.recs[0].UserID != "u-op" || e.tokens.recs[1].UserID != "u-admin" || e.tokens.recs[0].Channel != "email" ||
		e.tokens.recs[0].ExpiresAt.After(req.Expires) || e.tokens.recs[0].RequestID != "req-1" {
		t.Fatalf("records = %+v", e.tokens.recs)
	}
	msgs := s.messages()
	if len(msgs) != 2 {
		t.Fatalf("messages = %d", len(msgs))
	}
	b0, b1 := emailBody(t, msgs[0]), emailBody(t, msgs[1])
	i0, i1 := strings.Index(b0, "/approve/v1."), strings.Index(b1, "/approve/v1.")
	if i0 < 0 || i1 < 0 || b0[i0:i0+48] == b1[i1:i1+48] {
		t.Fatalf("each approver gets their own link:\n%s\n%s", b0, b1)
	}
	// The history never holds a token.
	if e.count(`SELECT COUNT(*) FROM notify_send WHERE message LIKE '%/approve/%' OR link LIKE '%/approve/%' OR what LIKE '%v1.%'`) != 0 {
		t.Fatal("a token is in the history")
	}
	if h, _ := e.svc.History(e.ctx()); len(h.Items) != 2 || h.Items[0].Kind != "approval" || h.Items[0].Link != "/response" {
		t.Fatalf("history = %+v", h.Items)
	}
	if e.seen.count("notify.approval.requested") != 1 {
		t.Fatal("notify.approval.requested not published")
	}
	// High risk: no link that approves, only the app.
	req.ID, req.Risk = "req-2", notify.RiskHigh
	before := len(e.tokens.recs)
	if _, err = e.svc.SendApprovalRequest(e.ctx(), req); err != nil {
		t.Fatal(err)
	}
	if len(e.tokens.recs) != before {
		t.Fatal("a token was minted for a high-risk request")
	}
	last := emailBody(t, s.messages()[len(s.messages())-1])
	if strings.Contains(last, "/approve/") || !strings.Contains(last, "/response") {
		t.Fatalf("high-risk body = %q", last)
	}
	// Approval channels are readable through the interface.
	ac, err := e.svc.ApprovalChannels(e.ctx())
	if err != nil || len(ac) != 1 || ac[0].Type != channel.Email || len(ac[0].Approvers) != 2 {
		t.Fatalf("ApprovalChannels = %+v, %v", ac, err)
	}
	// Without the box address no approval request is sent: a link that approves must point at the real box.
	e2 := newEnv(t, func(c *notify.Config) { c.BaseURL = nil })
	if _, err := e2.svc.SendApprovalRequest(e2.ctx(), req); !errors.Is(err, notify.ErrApprovalUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

type fakeFindings struct{ m map[string]notify.FindingInfo }

func (f fakeFindings) Finding(_ context.Context, id string) (notify.FindingInfo, bool, error) {
	x, ok := f.m[id]
	return x, ok, nil
}

type fakeDevices map[string]string

func (f fakeDevices) DeviceName(_ context.Context, id string) (string, bool, error) {
	n, ok := f[id]
	return n, ok, nil
}

func (f fakeDevices) DeviceLabel(ctx context.Context, id string) (string, bool, error) {
	return f.DeviceName(ctx, id)
}

func TestSubscribeTurnsEventsIntoNoticesAndIncidents(t *testing.T) {
	var on = true
	e := newEnv(t, func(c *notify.Config) {
		c.Modules = gateFunc(func(string) bool { return on })
		c.Findings = fakeFindings{map[string]notify.FindingInfo{
			"f-1": {CVE: "CVE-2026-100", Product: "QNAP Photo Station", Severity: notify.High, Title: "QNAP is being exploited", What: "w", Action: "a", Devices: []string{"NAS-01"}},
			"f-2": {CVE: "CVE-2026-101", Product: "WordPress", Severity: notify.High, Title: "WordPress is being exploited", What: "w", Action: "a"},
		}}
		c.Devices = fakeDevices{"a-new": "192.168.10.157"}
	})
	e.telegram(notify.Low)
	e.plain()
	unsub := e.svc.Subscribe(e.bus)
	pub := func(name string, data any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), events.Event{Name: name, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-1", AssetID: "a-1", CVE: "CVE-2026-100", Severity: findings.SeverityHigh, Basis: findings.BasisProduct})
	pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-1"}) // the same finding again: one notice
	pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-2"}) // matched no device: counted, not sent
	pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-9"}) // unknown finding: nothing
	pub(notify.EventFindingStatusChanged, findings.StatusChangedEvent{FindingID: "f-1", From: findings.StatusSuspected, To: findings.StatusPatched})
	pub(notify.EventFindingStatusChanged, findings.StatusChangedEvent{FindingID: "f-1", From: findings.StatusSuspected, To: findings.StatusConfirmed})
	pub(notify.EventAssetDiscovered, inventory.AssetEvent{AssetID: "a-new", Notify: true})
	pub(notify.EventAssetDiscovered, inventory.AssetEvent{AssetID: "a-quiet"})
	pub(notify.EventHoneypotHit, map[string]any{"id": "hit-1", "ts": "2026-11-09T09:59:00Z", "kind": "service", "service": "smb", "src_ip": "192.168.10.107", "label": "FILESRV-OLD"})
	pub(notify.EventLogBadAddress, map[string]any{"source": "192.168.10.105", "target": "185.220.101.47", "title": "PC-SALES-02 connected to 185.220.101.47", "what": "w", "action": "a", "severity": "high",
		"devices": []map[string]string{{"id": "a-pc05", "name": "PC-SALES-02"}}})
	e.flush()
	h, _ := e.svc.History(e.ctx())
	kinds := map[string]int{}
	for _, it := range h.Items {
		kinds[it.Kind]++
	}
	if kinds["vuln"] != 1 || kinds["incident"] != 3 || h.Suppressed.Count != 1 { // the finding and its confirmation: one digest (D-483)
		t.Fatalf("history kinds = %v, suppressed %d, items %+v", kinds, h.Suppressed.Count, h.Items)
	}
	l, _ := e.svc.Incidents(e.ctx())
	got := map[notify.IncidentKind]notify.Incident{}
	for _, i := range l {
		got[i.Kind] = i
	}
	if got[notify.IncidentTrap].Severity != notify.Critical || got[notify.IncidentTrap].Link != "/honeypot/hits/hit-1" ||
		got[notify.IncidentUnknownDevice].Title != "1 device found on your network: approve it in Devices" || got[notify.IncidentBadAddress].Devices[0].Name != "PC-SALES-02" {
		t.Fatalf("incidents = %+v", l)
	}
	// Module off: events are ignored.
	on = false
	pub(notify.EventHoneypotHit, map[string]any{"id": "hit-2", "src_ip": "10.0.0.9", "label": "x"})
	on = true
	if l, _ := e.svc.Incidents(e.ctx()); len(l) != 3 {
		t.Fatalf("incidents while off = %d", len(l))
	}
	unsub()
	pub(notify.EventHoneypotHit, map[string]any{"id": "hit-3", "src_ip": "10.0.0.8", "label": "x"})
	if l, _ := e.svc.Incidents(e.ctx()); len(l) != 3 {
		t.Fatalf("incident after unsubscribe")
	}
}

// A blocked connection (logs D-227: "blocked" in logs.bad_address.detected) is an attempt: the incident says so (walk 3). An attempt
// counts on an open connection of the same pair; a connection never counts on an attempt (D-227 (4)), so it is an incident of its own.
func TestBlockedBadAddressIsAnAttemptIncident(t *testing.T) {
	e := newEnv(t)
	e.svc.Subscribe(e.bus)
	hit := func(blocked bool) {
		t.Helper()
		ev := map[string]any{"source": "logs", "target": "ioc:185.220.101.47", "title": "192.168.1.50 tried to reach 185.220.101.47", "what": "w", "action": "a", "severity": "high", "blocked": blocked}
		if err := e.bus.Publish(e.ctx(), events.Event{Name: notify.EventLogBadAddress, Data: ev}); err != nil {
			t.Fatal(err)
		}
	}
	list := func() []notify.Incident {
		t.Helper()
		l, err := e.svc.Incidents(e.ctx())
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	hit(true)
	hit(true)
	if l := list(); len(l) != 1 || !l[0].Attempt || l[0].Count != 2 {
		t.Fatalf("two blocked hits = %+v, want one attempt seen twice", l)
	}
	hit(false) // the connection that follows an attempt is not hidden in it
	l := list()
	if len(l) != 2 || l[0].Attempt || l[0].Count != 1 || !l[1].Attempt || l[1].Count != 2 {
		t.Fatalf("after a connection = %+v, want a connection incident and the attempt", l)
	}
	hit(true) // an attempt while the connection is open counts on the connection
	if l := list(); len(l) != 2 || l[0].Attempt || l[0].Count != 2 || l[1].Count != 2 {
		t.Fatalf("an attempt after the connection = %+v", l)
	}
	if d, err := e.svc.IncidentDetail(e.ctx(), l[1].ID); err != nil || !d.Incident.Attempt {
		t.Fatalf("detail = %+v, %v", d, err)
	}
	if _, _, err := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: notify.IncidentTrap, Title: "t", Severity: notify.High, Link: "/x", Attempt: true}); !errors.Is(err, notify.ErrInvalidNotice) {
		t.Fatalf("a trap attempt = %v, want ErrInvalidNotice", err)
	}
}

func TestAlertTargetAndEscaping(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.slack(notify.Low)
	e.plain()
	n := e.vulnNotice("al-1", "Evil <!channel> *Product*", "CVE-2026-1", notify.High, "NAS-01")
	n.Title = "<!channel> *bold* @everyone https://evil.example"
	if err := e.svc.Publish(e.ctx(), n); err != nil {
		t.Fatal(err)
	}
	e.flush()
	slack := e.net.to("hooks.slack.com")
	var sent struct{ Text string }
	if len(slack) != 1 || json.Unmarshal([]byte(slack[0].Body), &sent) != nil || strings.Contains(sent.Text, "<!channel>") || !strings.Contains(sent.Text, "&lt;!channel&gt;") {
		t.Fatalf("slack body = %+v", slack)
	}
	to, err := e.svc.AlertTarget(e.ctx(), "al-1")
	if err != nil || to != "/findings/f-al-1" {
		t.Fatalf("target = %q, %v", to, err)
	}
	id, _, _ := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: notify.IncidentLogAnomaly, Title: "t", Severity: notify.Low, Link: "/logs"})
	if to, err = e.svc.AlertTarget(e.ctx(), id); err != nil || to != "/incidents/"+id {
		t.Fatalf("target = %q, %v", to, err)
	}
	_, err = e.svc.AlertTarget(e.ctx(), "al-nope")
	wantCode(t, err, 404, "not_found")
}

func TestRulesValidation(t *testing.T) {
	e := newEnv(t)
	v, _ := e.svc.Channels(e.ctx())
	if v.Quiet.Enabled || !v.Grouping.Enabled || v.Grouping.WindowMin != 60 {
		t.Fatalf("defaults = %+v %+v", v.Quiet, v.Grouping)
	}
	save := func(q notify.Quiet, g notify.Grouping) error {
		_, err := e.svc.SaveRules(e.ctx(), "admin@acme.example", notify.Rules{Quiet: q, Grouping: g})
		return err
	}
	ok := notify.Grouping{Enabled: true, WindowMin: 15}
	wantCode(t, save(notify.Quiet{Enabled: true, From: "22:00", To: "22:00"}, ok), 400, "bad_quiet")
	wantCode(t, save(notify.Quiet{Enabled: true, From: "25:00", To: "06:00"}, ok), 400, "bad_time")
	wantCode(t, save(notify.Quiet{From: "22:00", To: "06:00"}, notify.Grouping{Enabled: true, WindowMin: 30}), 400, "bad_window")
	if err := save(notify.Quiet{Enabled: true, From: "22:00", To: "06:30", AllowCritical: true}, ok); err != nil {
		t.Fatal(err)
	}
	if v, _ = e.svc.Channels(e.ctx()); !v.Quiet.Enabled || v.Grouping.WindowMin != 15 {
		t.Fatalf("rules = %+v %+v", v.Quiet, v.Grouping)
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.rules_save'`) != 1 {
		t.Fatal("rules save not audited once")
	}
}

func TestSubscribeToldWhenAFindingGetsMoreSeriousOrIsReopened(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.Findings = fakeFindings{map[string]notify.FindingInfo{
			"f-1": {CVE: "CVE-2026-100", Product: "QNAP Photo Station", Severity: notify.Critical, Title: "t", What: "It is exploited.", Action: "a", Devices: []string{"NAS-01"}},
			"f-2": {CVE: "CVE-2026-101", Product: "WordPress", Severity: notify.High, Title: "t", What: "w", Action: "a"}, // matched no device
		}}
	})
	smtp := newFakeSMTP(t)
	e.email(smtp)
	e.plain()
	e.svc.Subscribe(e.bus)
	pub := func(name string, data any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), events.Event{Name: name, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	raised := func(id string, from, to findings.Severity) findings.SeverityRaisedEvent {
		return findings.SeverityRaisedEvent{FindingID: id, AssetID: "a-1", CVE: "CVE-2026-100", FromSeverity: from, ToSeverity: to, Basis: findings.BasisVersion}
	}
	pub(notify.EventFindingRaised, raised("f-1", findings.SeverityMedium, findings.SeverityCritical))
	pub(notify.EventFindingRaised, raised("f-1", findings.SeverityMedium, findings.SeverityCritical)) // the same raise again: still one
	pub(notify.EventFindingRaised, raised("f-2", findings.SeverityMedium, findings.SeverityHigh))     // matched no device: not sent
	pub(notify.EventFindingStatusChanged, findings.StatusChangedEvent{FindingID: "f-1", From: findings.StatusNotRelevant, To: findings.StatusSuspected, Reason: findings.ReasonMatchesAgain})
	pub(notify.EventFindingStatusChanged, findings.StatusChangedEvent{FindingID: "f-1", From: findings.StatusNotRelevant, To: findings.StatusSuspected, Reason: findings.ReasonMatchesAgain}) // flaps the same day: still one
	e.flush()
	if n := e.count(`SELECT COUNT(*) FROM notify_notice WHERE id = 'nt-f-1-raised-critical'`); n != 1 {
		t.Fatalf("raised notices = %d", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_notice WHERE id LIKE 'nt-f-1-reopened-%'`); n != 1 {
		t.Fatalf("reopened notices = %d", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_notice WHERE id LIKE 'nt-f-2-%'`); n != 0 {
		t.Fatalf("a finding without a device was sent: %d", n)
	}
	all := strings.Join(smtp.messages(), "\n")
	for _, want := range []string{"CVE-2026-100 on NAS-01: now critical (was medium)", "CVE-2026-100 on NAS-01: reopened, it matches again"} {
		if !strings.Contains(all, want) {
			t.Fatalf("text %q missing: %s", want, all)
		}
	}
}

func TestSubscribeRaisedNoticeSaysWhyInPlainWords(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.Findings = fakeFindings{map[string]notify.FindingInfo{
			"f-1": {CVE: "CVE-2026-100", Product: "QNAP Photo Station", Severity: notify.Critical, Title: "t", What: "It is exploited.", Action: "a", Devices: []string{"NAS-01"}},
		}}
	})
	smtp := newFakeSMTP(t)
	e.email(smtp)
	e.plain()
	e.svc.Subscribe(e.bus)
	ev := findings.SeverityRaisedEvent{FindingID: "f-1", AssetID: "a-1", CVE: "CVE-2026-100", FromSeverity: findings.SeverityMedium, ToSeverity: findings.SeverityCritical, Basis: findings.BasisVersion}
	if err := e.bus.Publish(e.ctx(), events.Event{Name: notify.EventFindingRaised, Data: ev}); err != nil {
		t.Fatal(err)
	}
	e.flush()
	all := strings.Join(smtp.messages(), "\n")
	for _, want := range []string{"CVE-2026-100 on NAS-01 is now critical (was medium)", "The installed version is in the range that the vendor lists as affected."} {
		if !strings.Contains(strings.NewReplacer("=\r\n", "", "=\n", "", "\r\n ", " ", "\n ", " ").Replace(all), want) {
			t.Fatalf("text %q missing: %s", want, all)
		}
	}
}

func TestSubscribeRaisedAndReopenedAreSilentInTheBaseline(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.Findings = fakeFindings{map[string]notify.FindingInfo{"f-1": {CVE: "CVE-2026-100", Product: "QNAP", Severity: notify.High, Title: "t", What: "w", Action: "a", Devices: []string{"NAS-01"}}}}
	})
	e.email(newFakeSMTP(t))
	e.plain()
	e.svc.Subscribe(e.bus)
	ctx := notify.WithBaseline(e.ctx())
	for name, data := range map[string]any{
		notify.EventFindingRaised:        findings.SeverityRaisedEvent{FindingID: "f-1", FromSeverity: findings.SeverityMedium, ToSeverity: findings.SeverityHigh, Basis: findings.BasisVersion},
		notify.EventFindingStatusChanged: findings.StatusChangedEvent{FindingID: "f-1", From: findings.StatusNotRelevant, To: findings.StatusSuspected, Reason: findings.ReasonMatchesAgain},
	} {
		if err := e.bus.Publish(ctx, events.Event{Name: name, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_notice`); n != 0 {
		t.Fatalf("notices in the baseline = %d", n)
	}
}

// D-498, INV-21: an accepted risk whose day passed is told once, by name, and not in the baseline.
func TestSubscribeToldWhenARiskAcceptanceEnds(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.Findings = fakeFindings{map[string]notify.FindingInfo{
			"f-1": {CVE: "CVE-2026-100", Product: "QNAP Photo Station", Severity: notify.Critical, Title: "t", What: "It is exploited.", Action: "a", Devices: []string{"NAS-01"}},
		}}
	})
	smtp := newFakeSMTP(t)
	e.email(smtp)
	e.plain()
	e.svc.Subscribe(e.bus)
	ev := findings.StatusChangedEvent{FindingID: "f-1", From: findings.StatusRiskAccepted, To: findings.StatusConfirmed, Reason: findings.ReasonRiskExpired,
		AcceptedBy: "it@acme.example", AcceptedUntil: "2027-02-12"}
	if err := e.bus.Publish(notify.WithBaseline(e.ctx()), events.Event{Name: notify.EventFindingStatusChanged, Data: ev}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_notice`); n != 0 {
		t.Fatalf("notices in the baseline = %d", n)
	}
	for range 2 {
		if err := e.bus.Publish(e.ctx(), events.Event{Name: notify.EventFindingStatusChanged, Data: ev}); err != nil {
			t.Fatal(err)
		}
	}
	e.flush()
	if n := e.count(`SELECT COUNT(*) FROM notify_notice`); n != 1 || e.count(`SELECT COUNT(*) FROM notify_notice WHERE id LIKE 'nt-f-1-reopened-%'`) != 1 {
		t.Fatalf("notices = %d", n)
	}
	all := strings.NewReplacer("=\r\n", "", "=\n", "", "\r\n ", " ", "\n ", " ").Replace(strings.Join(smtp.messages(), "\n"))
	for _, want := range []string{"Risk acceptance ended: CVE-2026-100 on NAS-01 is open again", "it@acme.example accepted this risk until 12 Feb 2027; that date has passed."} {
		if !strings.Contains(all, want) {
			t.Fatalf("text %q missing: %s", want, all)
		}
	}
}
