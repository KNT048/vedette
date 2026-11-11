package notify_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// ---- SendStepUpCode (D-98) ----

var _ auth.StepUpMailer = notify.CodeMailer{}

func TestSendStepUpCode_SaysWhatIsApprovedHasNoLinkAndIsCleaned(t *testing.T) {
	e := newEnv(t)
	m := e.svc.CodeMailer()
	if m.Available(e.ctx()) {
		t.Fatal("available without SMTP")
	}
	if err := m.SendStepUpCode(e.ctx(), "it@acme.example", "246810", "Block 203.0.113.9"); !errors.Is(err, notify.ErrEmailNotReady) {
		t.Fatalf("without SMTP: %v", err)
	}
	s := newFakeSMTP(t)
	e.email(s)
	if !m.Available(e.ctx()) {
		t.Fatal("not available with SMTP")
	}
	dirty := "Block 203.0.113.9\nBcc: evil@x.example\u202e on the \x07firewall\u200b"
	if err := m.SendStepUpCode(e.ctx(), "it@acme.example", "246810", dirty); err != nil {
		t.Fatal(err)
	}
	if rc := s.recipients(); len(rc) != 1 || !strings.Contains(rc[0], "it@acme.example") || strings.Contains(rc[0], "director") {
		t.Fatalf("recipients = %v", rc)
	}
	raw := s.messages()[0]
	if strings.Contains(raw, "Bcc: evil") && strings.Index(raw, "Bcc: evil") < strings.Index(raw, "\r\n\r\n") {
		t.Fatal("the summary injected a header")
	}
	body := emailBody(t, raw)
	for _, want := range []string{"246810", "Block 203.0.113.9 Bcc: evil@x.example on the firewall", "10 minutes", "if this was not you, do not share the code"} {
		if !strings.Contains(strings.ToLower(body), strings.ToLower(want)) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	if strings.ContainsAny(body, "\u202e\u200b\x07") {
		t.Fatalf("bidi or control characters survived:\n%q", body)
	}
	if strings.Contains(body, "http") || strings.Contains(body, "/approve") {
		t.Fatalf("a step-up mail carries no link:\n%s", body)
	}
	if e.count(`SELECT COUNT(*) FROM notify_send`) != 0 || e.count(`SELECT COUNT(*) FROM core_audit WHERE detail LIKE '%246810%' OR target LIKE '%246810%'`) != 0 {
		t.Fatal("the code was recorded")
	}
	// An empty summary still says that something is being approved.
	if err := m.SendStepUpCode(e.ctx(), "it@acme.example", "111111", " \n "); err != nil {
		t.Fatal(err)
	}
	if b := emailBody(t, s.messages()[1]); !strings.Contains(b, "111111") || !strings.Contains(b, "approve") {
		t.Fatalf("body = %s", b)
	}
}

func TestSendStepUpCode_RefusesABadAddress(t *testing.T) {
	e := newEnv(t)
	s := newFakeSMTP(t)
	e.email(s)
	for _, to := range []string{"", "a@x.example, b@x.example", "not an address"} {
		if err := e.svc.CodeMailer().SendStepUpCode(e.ctx(), to, "123456", "x"); err == nil {
			t.Fatalf("to %q accepted", to)
		}
	}
	if len(s.messages()) != 0 {
		t.Fatal("a message was sent")
	}
}

// ---- PRE-4: Channels and InAppOnly ----

func (e *env) approvalSetup(s *fakeSMTP, telegramApprovals bool) {
	e.t.Helper()
	e.email(s, func(in *notify.ChannelInput) {
		in.Approvals = true
		in.Approvers = []notify.Approver{{UserID: "u-op", Address: "it@acme.example"}}
	})
	e.save(channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "-1002145678901"}, Secret: tgToken, MinSeverity: notify.Low,
		Approvals: telegramApprovals, Approvers: []notify.Approver{{UserID: "u-admin", Address: "123456789"}}})
}

func (e *env) approvalReq(id string, ch ...channel.Type) notify.ApprovalRequest {
	return notify.ApprovalRequest{ID: id, Title: "Block 203.0.113.9", What: "w", Action: "a", Severity: notify.High, Risk: notify.RiskLow,
		Expires: e.clock.Now().Add(15 * time.Minute), Channels: ch}
}

func TestContract_PRE4_EmptyChannelsSendsNothing(t *testing.T) {
	e := newEnv(t)
	s := newFakeSMTP(t)
	e.approvalSetup(s, true)
	sv, err := e.svc.SendApprovalRequest(e.ctx(), e.approvalReq("req-1"))
	if err != nil || len(sv) != 0 || len(s.messages()) != 0 || len(e.net.to("api.telegram.org")) != 0 || len(e.tokens.recs) != 0 {
		t.Fatalf("sends = %+v, %v, %d mails, %d chats, %d tokens", sv, err, len(s.messages()), len(e.net.to("api.telegram.org")), len(e.tokens.recs))
	}
}

func TestContract_PRE4_OnlyListedChannelsWithApprovalsOnReceive(t *testing.T) {
	e := newEnv(t)
	s := newFakeSMTP(t)
	e.approvalSetup(s, true)
	// Telegram is not in the list: it gets nothing, email gets its link.
	sv, err := e.svc.SendApprovalRequest(e.ctx(), e.approvalReq("req-1", channel.Email))
	if err != nil || len(sv) != 1 || sv[0].Channel != channel.Email || len(s.messages()) != 1 || len(e.net.to("api.telegram.org")) != 0 {
		t.Fatalf("sends = %+v, %v, %d chats", sv, err, len(e.net.to("api.telegram.org")))
	}
	if !strings.Contains(emailBody(t, s.messages()[0]), "/approve/v1.") {
		t.Fatal("the listed email channel got no link")
	}
	// Both listed: both receive.
	sv, err = e.svc.SendApprovalRequest(e.ctx(), e.approvalReq("req-2", channel.Email, channel.Telegram))
	if err != nil || len(sv) != 2 || len(e.net.to("api.telegram.org")) != 1 {
		t.Fatalf("sends = %+v, %v", sv, err)
	}
	// Telegram listed but with approvals off: nothing.
	e2 := newEnv(t)
	s2 := newFakeSMTP(t)
	e2.approvalSetup(s2, false)
	sv, err = e2.svc.SendApprovalRequest(e2.ctx(), e2.approvalReq("req-3", channel.Telegram))
	if err != nil || len(sv) != 0 || len(e2.net.to("api.telegram.org")) != 0 || len(s2.messages()) != 0 {
		t.Fatalf("approvals=false channel got %+v, %v", sv, err)
	}
}

func TestContract_PRE4_InAppOnlyMintsNothingAndSaysOpenVedette(t *testing.T) {
	e := newEnv(t)
	s := newFakeSMTP(t)
	e.approvalSetup(s, true)
	req := e.approvalReq("req-ai", channel.Email, channel.Telegram)
	req.InAppOnly = true
	req.Risk = notify.RiskLow // even a low risk request has no link once it is in-app only
	sv, err := e.svc.SendApprovalRequest(e.ctx(), req)
	if err != nil || len(sv) != 2 {
		t.Fatalf("sends = %+v, %v", sv, err)
	}
	if len(e.tokens.recs) != 0 || len(e.tokens.codes) != 0 {
		t.Fatalf("a token or code was recorded: %d, %d", len(e.tokens.recs), len(e.tokens.codes))
	}
	body := emailBody(t, s.messages()[0])
	if strings.Contains(body, "/approve/") || strings.Contains(body, "v1.") || !strings.Contains(body, "Open Vedette") {
		t.Fatalf("email body:\n%s", body)
	}
	tg := e.net.to("api.telegram.org")
	if len(tg) != 1 || strings.Contains(tg[0].Body, "/approve/") || !strings.Contains(tg[0].Body, "Open Vedette") || strings.Contains(tg[0].Body, "reply_markup") {
		t.Fatalf("telegram body: %+v", tg)
	}
	if e.count(`SELECT COUNT(*) FROM notify_send WHERE message LIKE '%/approve/%'`) != 0 {
		t.Fatal("a link is in the history")
	}
}

func TestContract_POST4_InAppOnlyStillRechecksApprovers(t *testing.T) {
	e := newEnv(t)
	s := newFakeSMTP(t)
	e.email(s, func(in *notify.ChannelInput) {
		in.Approvals = true
		in.Approvers = []notify.Approver{{UserID: "u-admin", Address: "admin@acme.example"}, {UserID: "u-op", Address: "it@acme.example"}}
	})
	e.users.mu.Lock()
	u := e.users.users["u-admin"]
	u.Active = false
	e.users.users["u-admin"] = u
	e.users.mu.Unlock()
	req := e.approvalReq("req-ai", channel.Email)
	req.InAppOnly = true
	sv, err := e.svc.SendApprovalRequest(e.ctx(), req)
	if err != nil || len(sv) != 1 || len(s.messages()) != 1 {
		t.Fatalf("sends = %+v, %v", sv, err)
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.approval_skipped'`) != 1 {
		t.Fatal("the skipped approver is not audited")
	}
}

// ---- PRE-7: VerifyApprovalLink ----

func (e *env) mintFor(b notify.Binding) (token string, key []byte) {
	e.t.Helper()
	key, err := e.sec.OpenOrCreate(e.ctx(), e.db, "approval.hmac_key", notify.MinApprovalKeyLen)
	if err != nil {
		e.t.Fatal(err)
	}
	token, _, err = notify.MintApprovalToken(key, b, notify.RiskLow, e.clock.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return token, key
}

func TestContract_PRE7_VerifyApprovalLink(t *testing.T) {
	e := newEnv(t)
	b := notify.Binding{RequestID: "req-1", UserID: "u-op", Channel: "email", ExpiresAt: e.clock.Now().Add(20 * time.Minute)}
	token, _ := e.mintFor(b)
	before := e.count(`SELECT COUNT(*) FROM core_secret`)
	auditBefore := e.count(`SELECT COUNT(*) FROM core_audit`)

	id, err := e.svc.VerifyApprovalLink(e.ctx(), token, b, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := notify.ParseApprovalToken(token); id != want {
		t.Fatalf("id = %v, want %v", id, want)
	}
	// An expired binding still verifies: expiry is the record's business (response answers 409 expired, not 404).
	e.clock.Add(time.Hour)
	if _, err := e.svc.VerifyApprovalLink(e.ctx(), token, b, "k1"); err != nil {
		t.Fatalf("expired: %v", err)
	}

	wrong := func(name string, tok string, bb notify.Binding, key string) {
		t.Helper()
		if _, err := e.svc.VerifyApprovalLink(e.ctx(), tok, bb, key); !errors.Is(err, notify.ErrTokenInvalid) {
			t.Errorf("%s: err = %v, want ErrTokenInvalid", name, err)
		}
	}
	o := b
	o.RequestID = "req-2"
	wrong("other request", token, o, "k1")
	o = b
	o.UserID = "u-admin"
	wrong("other user", token, o, "k1")
	o = b
	o.Channel = "zalo"
	wrong("other channel", token, o, "k1")
	o = b
	o.ExpiresAt = b.ExpiresAt.Add(time.Second)
	wrong("other expiry", token, o, "k1")
	o = b
	o.RequestID = "bad id\n"
	wrong("binding outside the alphabet", token, o, "k1")
	wrong("wrong key id", token, b, "k2")
	wrong("empty key id", token, b, "")
	flipped := []byte(token)
	flipped[len(flipped)-3] ^= 1
	wrong("flipped bit", string(flipped), b, "k1")
	wrong("bad prefix", "v2."+token[3:], b, "k1")
	wrong("trailing junk", token+"x", b, "k1")
	wrong("trailing dot", token+".", b, "k1")
	wrong("empty", "", b, "k1")
	wrong("huge", strings.Repeat("v1.", 1<<20), b, "k1")

	if e.count(`SELECT COUNT(*) FROM core_secret`) != before || e.count(`SELECT COUNT(*) FROM core_audit`) != auditBefore || len(e.tokens.recs) != 0 {
		t.Fatal("a verification wrote something")
	}
}

func TestContract_PRE7_NeverCreatesTheKey(t *testing.T) {
	e := newEnv(t)
	b := notify.Binding{RequestID: "req-1", UserID: "u-op", Channel: "email", ExpiresAt: e.clock.Now().Add(20 * time.Minute)}
	key := []byte(strings.Repeat("k", notify.MinApprovalKeyLen))
	token, _, err := notify.MintApprovalToken(key, b, notify.RiskLow, e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.VerifyApprovalLink(e.ctx(), token, b, "k1")
	if err == nil || errors.Is(err, notify.ErrTokenInvalid) {
		t.Fatalf("a missing key must be an error of its own, got %v", err)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_secret`); n != 0 {
		t.Fatalf("%d secret(s) were created", n)
	}
	// A malformed token never even reaches the key store.
	if _, err := e.svc.VerifyApprovalLink(e.ctx(), "junk", b, "k1"); !errors.Is(err, notify.ErrTokenInvalid) {
		t.Fatalf("junk: %v", err)
	}
}

func TestContract_PRE7_LinkSentByTheServiceVerifies(t *testing.T) {
	e := newEnv(t)
	s := newFakeSMTP(t)
	e.approvalSetup(s, false)
	if _, err := e.svc.SendApprovalRequest(e.ctx(), e.approvalReq("req-1", channel.Email)); err != nil {
		t.Fatal(err)
	}
	body := emailBody(t, s.messages()[0])
	i := strings.Index(body, "/approve/") + len("/approve/")
	token := strings.Fields(body[i:])[0]
	if _, err := e.svc.VerifyApprovalLink(e.ctx(), token, e.tokens.recs[0], "k1"); err != nil {
		t.Fatal(err)
	}
}

// ---- PRE-8: the reply-code recorder and the Decisions port are types only ----

func TestContract_PRE8_PortTypes(t *testing.T) {
	var _ notify.TokenRecorder = (*fakeTokens)(nil)
	var d notify.Decisions = fakeDecisions{}
	r, err := d.Decide(context.Background(), notify.Decision{Channel: channel.Telegram, ExternalID: "1", RequestID: "req-1", Approve: true, Code: ""})
	if err != nil || r.Status != "approved" || r.Message == "" {
		t.Fatalf("%+v %v", r, err)
	}
	_ = notify.ReplyCode{RequestID: "r", UserID: "u", Address: "a", Approve: true, CodeHash: "h", ExpiresAt: time.Now()}
}

type fakeDecisions struct{}

func (fakeDecisions) Decide(context.Context, notify.Decision) (notify.DecisionResult, error) {
	return notify.DecisionResult{Status: "approved", Message: "Recorded."}, nil
}

func (fakeDecisions) LinkChat(context.Context, notify.Decision) (notify.DecisionResult, error) {
	return notify.DecisionResult{Status: "linked", Message: "Linked."}, nil
}

// allApprovalChannels is what the older tests pass: every channel the response module could allow.
var allApprovalChannels = []channel.Type{channel.Email, channel.Telegram, channel.Slack, channel.Zalo, channel.ZaloPersonal}
