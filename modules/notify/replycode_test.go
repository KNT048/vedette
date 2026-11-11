package notify_test

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

const (
	zaloAdmin = "2938475610293847561"
	zaloOp    = "3847561029384756102"
)

// The test vector of spec approval-tokens.md 7.1, pinned by notify and response alike.
func TestContract_PRE8_ReplyCodeHashVector(t *testing.T) {
	if got := notify.ReplyCodeHashForTest("req-20261109-0001", "u-lan", true, "A-7KQ2MX"); got != "1f16413d45bce5c596496fc0a4d169a0c09ade7bb044335507f4020e15060fa0" {
		t.Errorf("approve hash %s", got)
	}
	if got := notify.ReplyCodeHashForTest("req-20261109-0001", "u-lan", false, "R-7KQ2MX"); got != "560dd02a99d9bc0e022a7b7c50a9d6834cc2c8ab8587c50089bda4ce7077b671" {
		t.Errorf("reject hash %s", got)
	}
}

func TestReplyCodesHaveTheFormOfSpec71(t *testing.T) {
	re := regexp.MustCompile(`^[AR]-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{6}$`)
	seen := map[string]bool{}
	chars := map[rune]bool{}
	for range 2000 {
		a, r, err := notify.NewReplyCodesForTest()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(a) || !re.MatchString(r) || a[0] != 'A' || r[0] != 'R' || a[2:] == r[2:] && seen[a] {
			t.Fatalf("codes %q %q", a, r)
		}
		seen[a] = true
		for _, c := range a[2:] + r[2:] {
			chars[c] = true
		}
	}
	if len(seen) < 1990 || len(chars) != 32 { // 30 bits each: a repeat in 2000 is very unlikely; every character of the alphabet shows up
		t.Errorf("%d distinct codes, %d characters", len(seen), len(chars))
	}
}

// sentZalo is one message the direct Zalo sender of the test got, with what was recorded when it was sent.
type sentZalo struct {
	to          string
	msg         channel.Message
	codesBefore int
}

type zaloRecorder struct {
	mu    sync.Mutex
	sent  []sentZalo
	codes func() int
	fail  error
}

func (z *zaloRecorder) direct(_ channel.Sender, user string) (channel.Sender, error) {
	return &zaloDirectFake{rec: z, user: user}, nil
}

type zaloDirectFake struct {
	rec  *zaloRecorder
	user string
}

func (*zaloDirectFake) Type() channel.Type { return channel.ZaloPersonal }
func (d *zaloDirectFake) Dest() string     { return "Zalo " + d.user }
func (d *zaloDirectFake) Send(_ context.Context, m channel.Message) (channel.Receipt, error) {
	d.rec.mu.Lock()
	defer d.rec.mu.Unlock()
	d.rec.sent = append(d.rec.sent, sentZalo{to: d.user, msg: m, codesBefore: d.rec.codes()})
	if d.rec.fail != nil {
		return channel.Receipt{}, d.rec.fail
	}
	return channel.Receipt{To: d.Dest()}, nil
}

// newZaloEnv is newEnv with what reply codes need: a Decisions port, and the listener switch on (export_test.go).
func newZaloEnv(t *testing.T, opts ...func(*notify.Config)) *env {
	e := newEnv(t, append([]func(*notify.Config){func(c *notify.Config) { c.Decisions = fakeDecisions{} }}, opts...)...)
	e.svc.SetZaloRepliesForTest()
	return e
}

func (e *env) zaloApprovals(approvers ...notify.Approver) *zaloRecorder {
	e.t.Helper()
	if approvers == nil {
		approvers = []notify.Approver{{UserID: "u-admin", Address: zaloAdmin}, {UserID: "u-op", Address: zaloOp}}
	}
	e.save(channel.ZaloPersonal, notify.ChannelInput{Enabled: true, Fields: map[string]string{"user_id": "123456789", "group": "true"}, Secret: zaloSession,
		MinSeverity: notify.Low, Approvals: true, Approvers: approvers})
	z := &zaloRecorder{codes: func() int { e.tokens.mu.Lock(); defer e.tokens.mu.Unlock(); return len(e.tokens.codes) }}
	e.svc.SetZaloToForTest(z.direct)
	return z
}

// Each approver gets their own direct message with their own two codes; the hash of each code is recorded before the message goes out
// (spec 7.1), bound to the request, the person and the decision; the codes never reach the history or the configured group.
func TestContract_PRE8_ZaloReplyCodesPerApprover(t *testing.T) {
	e := newZaloEnv(t)
	z := e.zaloApprovals()
	req := e.approvalReq("req-z1", channel.ZaloPersonal)
	req.Expires = e.clock.Now().Add(45 * time.Minute) // the codes still end 30 minutes from now
	sv, err := e.svc.SendApprovalRequest(e.ctx(), req)
	if err != nil || len(sv) != 2 {
		t.Fatalf("sends = %+v, %v", sv, err)
	}
	if len(z.sent) != 2 || z.sent[0].to != zaloAdmin || z.sent[1].to != zaloOp {
		t.Fatalf("sent %+v", z.sent)
	}
	if z.sent[0].codesBefore < 2 || z.sent[1].codesBefore < 4 { // each message only after its own two codes are recorded
		t.Errorf("codes recorded before each send: %d, %d", z.sent[0].codesBefore, z.sent[1].codesBefore)
	}
	codes := e.tokens.codes
	if len(codes) != 4 {
		t.Fatalf("%d codes recorded", len(codes))
	}
	want := e.clock.Now().Add(30 * time.Minute)
	for i, s := range z.sent {
		rc := s.msg.ReplyCodes
		if rc == nil || rc.Until != want.Format("15:04") {
			t.Fatalf("message %d codes %+v", i, rc)
		}
		user := []string{"u-admin", "u-op"}[i]
		for j, c := range codes[2*i : 2*i+2] {
			approve := j == 0
			code := rc.Reject
			if approve {
				code = rc.Approve
			}
			if c.RequestID != "req-z1" || c.UserID != user || c.Address != s.to || c.Approve != approve || !c.ExpiresAt.Equal(want) ||
				c.CodeHash != notify.ReplyCodeHashForTest("req-z1", user, approve, code) {
				t.Errorf("record %d/%d = %+v", i, j, c)
			}
		}
	}
	if z.sent[0].msg.ReplyCodes.Approve == z.sent[1].msg.ReplyCodes.Approve {
		t.Error("two approvers got the same code")
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_send WHERE kind = 'approval' AND channel = 'zalo-personal'`); n != 2 {
		t.Errorf("%d history rows", n)
	}
	for _, s := range z.sent {
		if n := e.count(`SELECT COUNT(*) FROM notify_send WHERE message LIKE ? OR message LIKE ?`, "%"+s.msg.ReplyCodes.Approve+"%", "%"+s.msg.ReplyCodes.Reject+"%"); n != 0 {
			t.Error("a code is in the history")
		}
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_send WHERE channel = 'zalo-personal' AND recipient IN (?, ?)`, zaloAdmin, zaloOp); n != 2 {
		t.Errorf("history recipients: %d", n)
	}
	if e.net.total() != 0 {
		t.Errorf("the network was called %d times: the configured group got a message", e.net.total())
	}
}

// No code is made for a high-risk or in-app-only request, one without chat buttons (the change does not fit one message, D-175) or
// without a recorder: the configured recipient gets the "open Vedette" message, as before.
func TestContract_PRE8_ZaloNoCodesWhenNotAllowed(t *testing.T) {
	cases := map[string]struct {
		mod  func(*notify.ApprovalRequest)
		opts []func(*notify.Config)
	}{
		"high risk":       {mod: func(r *notify.ApprovalRequest) { r.Risk = notify.RiskHigh }},
		"in app only":     {mod: func(r *notify.ApprovalRequest) { r.InAppOnly = true }},
		"no chat buttons": {mod: func(r *notify.ApprovalRequest) { r.NoChatButtons = true }},
		"unknown risk":    {mod: func(r *notify.ApprovalRequest) { r.Risk = "" }},
		"no recorder":     {mod: func(*notify.ApprovalRequest) {}, opts: []func(*notify.Config){func(c *notify.Config) { c.Tokens = nil }}},
		"no decisions":    {mod: func(*notify.ApprovalRequest) {}, opts: []func(*notify.Config){func(c *notify.Config) { c.Decisions = nil }}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newZaloEnv(t, c.opts...)
			z := e.zaloApprovals()
			req := e.approvalReq("req-z2", channel.ZaloPersonal)
			c.mod(&req)
			sv, err := e.svc.SendApprovalRequest(e.ctx(), req)
			if err != nil || len(sv) != 1 || len(z.sent) != 0 || len(e.tokens.codes) != 0 {
				t.Fatalf("sends %+v, %v, direct %d, codes %d", sv, err, len(z.sent), len(e.tokens.codes))
			}
		})
	}
}

// An approver who no longer qualifies gets no code and no message, and is audited; the others still get theirs.
func TestContract_POST4_ZaloSkippedApproverGetsNoCode(t *testing.T) {
	e := newZaloEnv(t)
	z := e.zaloApprovals()
	e.users.mu.Lock()
	u := e.users.users["u-admin"]
	u.Active = false
	e.users.users["u-admin"] = u
	e.users.mu.Unlock()
	sv, err := e.svc.SendApprovalRequest(e.ctx(), e.approvalReq("req-z3", channel.ZaloPersonal))
	if err != nil || len(sv) != 1 || len(z.sent) != 1 || z.sent[0].to != zaloOp || len(e.tokens.codes) != 2 {
		t.Fatalf("sends %+v, %v, direct %+v, codes %d", sv, err, z.sent, len(e.tokens.codes))
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.approval_skipped'`) != 1 {
		t.Fatal("the skipped approver is not audited")
	}
}

// A code that could not be recorded is never sent: the request fails and nothing goes out.
func TestContract_PRE8_ZaloCodeNotRecordedIsNotSent(t *testing.T) {
	e := newZaloEnv(t)
	z := e.zaloApprovals()
	e.tokens.codeErr = errors.New("the request is no longer pending")
	if _, err := e.svc.SendApprovalRequest(e.ctx(), e.approvalReq("req-z4", channel.ZaloPersonal)); err == nil {
		t.Fatal("no error")
	}
	if len(z.sent) != 0 || e.count(`SELECT COUNT(*) FROM notify_send`) != 0 {
		t.Fatalf("sent %d", len(z.sent))
	}
}

// A failed direct message is recorded like any failed approval message (history row, not ok); the codes stay recorded and expire.
func TestZaloReplyCodeSendFailureIsRecorded(t *testing.T) {
	e := newZaloEnv(t)
	z := e.zaloApprovals(notify.Approver{UserID: "u-op", Address: zaloOp})
	z.fail = errors.New("zalo said no")
	sv, err := e.svc.SendApprovalRequest(e.ctx(), e.approvalReq("req-z5", channel.ZaloPersonal))
	if err != nil || len(sv) != 1 || sv[0].OK || sv[0].To != "Zalo "+zaloOp {
		t.Fatalf("sends %+v, %v", sv, err)
	}
}

// D-242: the Zalo approver is the user ID (a reply carries it), never a phone number; one address is one approver (UNIQUE).
func TestContract_INV7_ZaloApproverIsAUserIDAndUnique(t *testing.T) {
	e := newZaloEnv(t)
	in := func(a ...notify.Approver) notify.ChannelInput {
		return notify.ChannelInput{Enabled: true, Fields: map[string]string{"user_id": "123456789"}, Secret: zaloSession, MinSeverity: notify.Low, Approvals: true, Approvers: a}
	}
	for _, phone := range []string{"0912345678", "84912345678", "+84912345678"} {
		_, err := e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.ZaloPersonal, in(notify.Approver{UserID: "u-op", Address: phone}))
		var ae *apierr.Error
		if !errors.As(err, &ae) || ae.Code != "bad_approver_address" || !strings.Contains(ae.Message, "not a phone number") {
			t.Errorf("%s: %v", phone, err)
		}
	}
	_, err := e.svc.SaveChannel(e.ctx(), "admin@acme.example", channel.ZaloPersonal, in(notify.Approver{UserID: "u-op", Address: zaloOp}, notify.Approver{UserID: "u-admin", Address: " " + zaloOp + " "}))
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != "duplicate_address" {
		t.Fatalf("duplicate address: %v", err)
	}
	e.save(channel.ZaloPersonal, in(notify.Approver{UserID: "u-op", Address: zaloOp}, notify.Approver{UserID: "u-admin", Address: zaloAdmin}))
	// The database refuses it too, whatever writes the row.
	exec := func(q string, args ...any) error {
		return e.db.Write(e.ctx(), func(tx *sql.Tx) error { _, err := tx.ExecContext(e.ctx(), q, args...); return err })
	}
	if err := exec(`INSERT INTO notify_approver (channel_type, user_id, address) VALUES ('zalo-personal', 'u-x', ?)`, zaloOp); err == nil {
		t.Error("the database took a second approver with the same address")
	}
	// The same address on another channel is a different address.
	if err := exec(`INSERT INTO notify_channel (type, configured, enabled, fields, min_severity, approvals, rev, updated_at) VALUES ('telegram', 1, 1, '{}', 'low', 1, 1, '2026-11-09T10:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO notify_approver (channel_type, user_id, address) VALUES ('telegram', 'u-x', ?)`, zaloOp); err != nil {
		t.Errorf("another channel: %v", err)
	}
}

// A resend of an approver's own message goes to that approver again through the channel's session, without codes (they are not kept).
func TestContract_INV11_ZaloApprovalResendGoesToTheSameApprover(t *testing.T) {
	e := newZaloEnv(t)
	z := e.zaloApprovals(notify.Approver{UserID: "u-op", Address: zaloOp})
	sv, err := e.svc.SendApprovalRequest(e.ctx(), e.approvalReq("req-z6", channel.ZaloPersonal))
	if err != nil || len(sv) != 1 {
		t.Fatalf("sends %+v, %v", sv, err)
	}
	h, err := e.svc.Resend(e.ctx(), "it@acme.example", sv[0].ID)
	if err != nil || !h.OK || h.To != "Zalo "+zaloOp {
		t.Fatalf("resend %+v, %v", h, err)
	}
	if len(z.sent) != 2 || z.sent[1].to != zaloOp || z.sent[1].msg.ReplyCodes != nil || e.net.total() != 0 {
		t.Fatalf("sent %+v, network calls %d", z.sent, e.net.total())
	}
}

// Until the listener exists nothing reads a reply, so no code is sent: the channel gets the "open Vedette" message as before.
func TestZaloNoCodesWhileNothingReadsTheReplies(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) { c.Decisions = fakeDecisions{} })
	z := e.zaloApprovals()
	sv, err := e.svc.SendApprovalRequest(e.ctx(), e.approvalReq("req-z7", channel.ZaloPersonal))
	if err != nil || len(sv) != 1 || len(z.sent) != 0 || len(e.tokens.codes) != 0 {
		t.Fatalf("sends %+v, %v, direct %d, codes %d", sv, err, len(z.sent), len(e.tokens.codes))
	}
}

// When every approver is skipped, the channel still hears about the request (the "open Vedette" message to its recipient).
func TestZaloAllApproversSkippedFallsBackToTheChannel(t *testing.T) {
	e := newZaloEnv(t)
	z := e.zaloApprovals(notify.Approver{UserID: "u-op", Address: zaloOp})
	e.users.mu.Lock()
	u := e.users.users["u-op"]
	u.Role = "viewer"
	e.users.users["u-op"] = u
	e.users.mu.Unlock()
	sv, err := e.svc.SendApprovalRequest(e.ctx(), e.approvalReq("req-z8", channel.ZaloPersonal))
	if err != nil || len(sv) != 1 || sv[0].To == "Zalo "+zaloOp || len(z.sent) != 0 || len(e.tokens.codes) != 0 {
		t.Fatalf("sends %+v, %v, direct %d, codes %d", sv, err, len(z.sent), len(e.tokens.codes))
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.approval_skipped'`) != 1 {
		t.Fatal("the skipped approver is not audited")
	}
}
