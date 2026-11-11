package response_test

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/response"
)

// Approvers prove their own channel identity (S-RESP-2, D-191, WP-31 R3, finding L7).

type fakeMailer struct {
	mu    sync.Mutex
	off   bool
	fail  error
	codes map[string]string // address -> last code
}

func (m *fakeMailer) Available(context.Context) bool { m.mu.Lock(); defer m.mu.Unlock(); return !m.off }
func (m *fakeMailer) SendLinkCode(_ context.Context, to, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	if m.codes == nil {
		m.codes = map[string]string{}
	}
	m.codes[to] = code
	return nil
}
func (m *fakeMailer) last(to string) string { m.mu.Lock(); defer m.mu.Unlock(); return m.codes[to] }

var codeInMessage = regexp.MustCompile(`code (\d{6})`)

func linkCodeOf(t *testing.T, err error) string {
	t.Helper()
	s, code := apiCode(err)
	if s != 403 || code != "approver_not_linked" {
		t.Fatalf("error = %v, want 403 approver_not_linked", err)
	}
	m := codeInMessage.FindStringSubmatch(err.Error())
	if m == nil {
		return ""
	}
	return m[1]
}

var (
	op  = response.Actor{ID: "u-op", Email: "it@acme.example", Name: "IT Operator", Via: response.ViaApp}
	op2 = response.Actor{ID: "u-op2", Email: "it2@acme.example", Name: "IT Operator Two", Via: response.ViaApp}
)

// unlinkedChat is the chat set-up with no proof recorded: the lists are typed by an administrator, nobody linked yet.
func unlinkedChat(t *testing.T) *chatEnv {
	t.Helper()
	c := newChatEnv(t)
	c.exec1(`DELETE FROM resp_identity`)
	return c
}

func TestContract_D191_AnUnlinkedPressDecidesNothingAndAnswersAPrivateCode(t *testing.T) {
	c := unlinkedChat(t)
	a := c.pending()
	_, err := c.button("slack", slackOp, a.ID, true)
	code := linkCodeOf(t, err)
	if code == "" {
		t.Fatalf("no code in the private answer: %v", err)
	}
	if got := c.only(); got.Status != response.StatusPending || len(got.Approvals) != 0 {
		t.Fatalf("an unlinked press decided: %+v", got)
	}
	// Only the hash is kept, and no log or audit line holds the code.
	if n := c.count(`SELECT COUNT(*) FROM resp_link_codes WHERE code_hash = ?`, code); n != 0 {
		t.Fatal("the code is stored in clear")
	}
	if rows := c.dump(`SELECT detail FROM resp_log`) + c.dump(`SELECT detail FROM core_audit`); strings.Contains(rows, code) {
		t.Fatalf("the code reached a log: %s", rows)
	}
	if c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'approver_not_linked:%'`) != 1 {
		t.Fatal("the refusal is not logged")
	}
	ids, err := c.svc.MyIdentities(c.ctx(), op)
	c.must(err)
	var slack response.Identity
	for _, r := range ids {
		if r.Channel == "slack" {
			slack = r
		}
	}
	if slack.Linked || !slack.CodeWaiting || slack.Method != "chat_code" || slack.Address != slackOp {
		t.Fatalf("my slack row = %+v", slack)
	}
	// The code is held to the listed person: someone else signed in cannot use it.
	if _, err := c.svc.ConfirmLink(c.ctx(), op2, "slack", code); !isCode(err, "no_code") {
		t.Fatalf("another person used the code: %v", err)
	}
	got, err := c.svc.ConfirmLink(c.ctx(), op, "slack", code)
	c.must(err)
	if !got.Linked || got.LinkedAt == nil {
		t.Fatalf("confirm = %+v", got)
	}
	if c.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.identity_link' AND target = 'slack'`) != 1 {
		t.Fatal("no audit line for the link")
	}
	if _, err := c.svc.ConfirmLink(c.ctx(), op, "slack", code); !isCode(err, "no_code") {
		t.Fatalf("a code worked twice: %v", err)
	}
	out, err := c.button("slack", slackOp, a.ID, true)
	c.must(err)
	if out.Status != "approved" {
		t.Fatalf("a linked press = %+v", out)
	}
}

func TestContract_D191_WrongCodesExpiryAndTheHourlyCap(t *testing.T) {
	c := unlinkedChat(t)
	a := c.pending()
	_, err := c.button("telegram", tgOp, a.ID, true)
	code := linkCodeOf(t, err)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for range 4 {
		if _, err := c.svc.ConfirmLink(c.ctx(), op, "telegram", wrong); !isCode(err, "wrong_code") {
			t.Fatalf("wrong code: %v", err)
		}
	}
	if _, err := c.svc.ConfirmLink(c.ctx(), op, "telegram", "12a456"); !isCode(err, "invalid_code") {
		t.Fatalf("not digits: %v", err)
	}
	if _, err := c.svc.ConfirmLink(c.ctx(), op, "telegram", wrong); !isCode(err, "too_many_tries") {
		t.Fatalf("fifth wrong code: %v", err)
	}
	if _, err := c.svc.ConfirmLink(c.ctx(), op, "telegram", code); !isCode(err, "no_code") {
		t.Fatalf("the right code after the code was cancelled: %v", err)
	}
	// A new press makes a new code; it ends after 10 minutes.
	_, err = c.button("telegram", tgOp, a.ID, true)
	code = linkCodeOf(t, err)
	c.clock.Advance(10*time.Minute + time.Second)
	if _, err := c.svc.ConfirmLink(c.ctx(), op, "telegram", code); !isCode(err, "code_expired") {
		t.Fatalf("an ended code: %v", err)
	}
	// Two codes so far this hour; three more, then the answer holds none.
	for range 3 {
		if linkCodeOf(t, func() error { _, err := c.button("telegram", tgOp, a.ID, true); return err }()) == "" {
			t.Fatal("a code was not made within the hourly cap")
		}
	}
	if got := linkCodeOf(t, func() error { _, err := c.button("telegram", tgOp, a.ID, true); return err }()); got != "" {
		t.Fatal("a sixth code in one hour")
	}
}

func TestContract_D191_AChangedAddressOrAnUnlinkDropsTheProof(t *testing.T) {
	c := unlinkedChat(t)
	a := c.pending()
	_, err := c.button("slack", slackOp, a.ID, true)
	_, err = c.svc.ConfirmLink(c.ctx(), op, "slack", linkCodeOf(t, err))
	c.must(err)
	c.note.mu.Lock()
	c.note.approvers["slack"] = []response.Approver{{UserID: "u-op", Address: "U0NEW0001"}, {UserID: "u-op2", Address: slackOp2}}
	c.note.mu.Unlock()
	if _, err := c.button("slack", "U0NEW0001", a.ID, true); linkCodeOf(t, err) == "" {
		t.Fatal("a new address counted on the proof of the old one")
	}
	c.note.mu.Lock()
	c.note.approvers["slack"] = []response.Approver{{UserID: "u-op", Address: slackOp}, {UserID: "u-op2", Address: slackOp2}}
	c.note.mu.Unlock()
	c.must(c.svc.Unlink(c.ctx(), op, "slack"))
	if c.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.identity_unlink'`) != 1 {
		t.Fatal("no audit line for the unlink")
	}
	if _, err := c.button("slack", slackOp, a.ID, true); linkCodeOf(t, err) == "" {
		t.Fatal("an unlinked id still counts")
	}
	if err := c.svc.Unlink(c.ctx(), op, "slack"); !isCode(err, "not_linked") {
		t.Fatalf("second unlink: %v", err)
	}
}

func TestContract_D191_UnlinkedWhileThePressWaitsForTheLock(t *testing.T) {
	c := newChatEnv(t)
	a := c.pending()
	c.svc.SetBeforeLockForTest(func() { c.exec1(`DELETE FROM resp_identity WHERE user_id = 'u-op'`) })
	_, err := c.button("slack", slackOp, a.ID, true)
	if s, code := apiCode(err); s != 403 || code != "approver_not_linked" {
		t.Fatalf("error = %v", err)
	}
	if got := c.only(); got.Status != response.StatusPending || len(got.Approvals) != 0 {
		t.Fatalf("a press counted after its proof was removed: %+v", got)
	}
}

// emailEnv is the link set-up with a mailer and no proof recorded.
func emailEnv(t *testing.T) (*linkEnv, *fakeMailer) {
	t.Helper()
	fl, m := &fakeLinks{}, &fakeMailer{}
	e := newEnv(t, func(c *response.Config) { c.Links = fl; c.Mailer = m })
	e.note.chs = []response.NotifyChannel{{Type: "email", Label: "Email", Configured: true, Enabled: true, Approvals: true, Approvers: 2},
		{Type: "telegram", Label: "Telegram", Configured: true, Enabled: true, Approvals: true, Approvers: 1}}
	e.note.approvers = map[string][]response.Approver{"email": {{UserID: "u-op", Address: "it@acme.example"}, {UserID: "u-op2", Address: "it2@acme.example"}},
		"telegram": {{UserID: "u-op", Address: tgOp}}}
	e.saveSettings(func(in *response.SettingsInput) { in.ApprovalChannels = []string{"email"} })
	return &linkEnv{env: e, links: fl}, m
}

func TestContract_D191_EmailIsLinkedByAMailedCodeAndLostWithTheSignInEmail(t *testing.T) {
	e, m := emailEnv(t)
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	if v := e.view(tok); v.State != "unknown" {
		t.Fatalf("the link of an unlinked address reads %q", v.State)
	}
	if _, err := e.decide(tok, "approve"); !isCode(err, "approver_not_listed") {
		t.Fatalf("an unlinked address approved: %v", err)
	}
	sent, err := e.svc.SendLinkCode(e.ctx(), op, "email")
	e.must(err)
	if sent.SentTo != "i•••@acme.example" || sent.ResendAfter != 60 || m.last("it@acme.example") == "" {
		t.Fatalf("sent = %+v", sent)
	}
	if _, err := e.svc.SendLinkCode(e.ctx(), op, "email"); !isCode(err, "resend_too_soon") {
		t.Fatalf("a second code at once: %v", err)
	}
	e.clock.Advance(61 * time.Second)
	_, err = e.svc.SendLinkCode(e.ctx(), op, "email")
	e.must(err)
	_, err = e.svc.ConfirmLink(e.ctx(), op, "email", m.last("it@acme.example"))
	e.must(err)
	if _, err := e.svc.SendLinkCode(e.ctx(), op, "email"); !isCode(err, "already_linked") {
		t.Fatalf("send after link: %v", err)
	}
	if v := e.view(tok); v.State != "ready" {
		t.Fatalf("the link of a linked address reads %q", v.State)
	}
	u := e.users.m["u-op"]
	u.Email = "it-new@acme.example"
	e.users.m["u-op"] = u
	if v := e.view(tok); v.State != "unknown" {
		t.Fatalf("after the sign-in email changed the link reads %q", v.State)
	}
	if _, err := e.svc.SendLinkCode(e.ctx(), response.Actor{ID: "u-op", Email: u.Email}, "email"); !isCode(err, "address_mismatch") {
		t.Fatalf("send to an address that is not the sign-in email: %v", err)
	}
}

func TestContract_D191_SendCodeRefusals(t *testing.T) {
	e, m := emailEnv(t)
	if _, err := e.svc.SendLinkCode(e.ctx(), op, "telegram"); !isCode(err, "chat_channel") {
		t.Fatalf("telegram: %v", err)
	}
	if _, err := e.svc.SendLinkCode(e.ctx(), op, "slack"); !isCode(err, "not_listed") {
		t.Fatalf("slack: %v", err)
	}
	if _, err := e.svc.SendLinkCode(e.ctx(), response.Actor{ID: "u-view"}, "email"); !isCode(err, "forbidden") {
		t.Fatalf("unknown person: %v", err)
	}
	m.mu.Lock()
	m.off = true
	m.mu.Unlock()
	if _, err := e.svc.SendLinkCode(e.ctx(), op, "email"); !isCode(err, "email_not_ready") {
		t.Fatalf("mail off: %v", err)
	}
	for range 5 {
		_, _ = e.svc.SendLinkCode(e.ctx(), op2, "email")
		e.clock.Advance(61 * time.Second)
	}
	m.mu.Lock()
	m.off = false
	m.mu.Unlock()
	if _, err := e.svc.SendLinkCode(e.ctx(), op2, "email"); err != nil {
		t.Fatalf("a refused send (mail off) used up the hourly cap: %v", err)
	}
}

func TestContract_D191_SettingsShowWhoHasNotLinked(t *testing.T) {
	c := unlinkedChat(t)
	c.must(c.svc.LinkForTest(c.ctx(), "u-op", "slack", slackOp))
	v, err := c.svc.Settings(c.ctx())
	c.must(err)
	for _, ch := range v.Channels {
		if ch.Type == "slack" && (ch.Linked != 1 || len(ch.Unlinked) != 1 || ch.Unlinked[0] != "IT Operator Two") {
			t.Fatalf("slack = %+v", ch)
		}
	}
}

func isCode(err error, code string) bool { _, c := apiCode(err); return c == code }
