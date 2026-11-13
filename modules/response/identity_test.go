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
	t.Parallel()
	c := unlinkedChat(t)
	a := c.pending()
	_, err := c.button("telegram", tgOp, a.ID, true)
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
	var tg response.Identity
	for _, r := range ids {
		if r.Channel == "telegram" {
			tg = r
		}
	}
	if tg.Linked || !tg.CodeWaiting || tg.Method != "chat_code" || tg.Address != tgOp {
		t.Fatalf("my telegram row = %+v", tg)
	}
	// The code is held to the listed person: someone else signed in, with a code of their own waiting, cannot use it.
	_, err = c.button("telegram", tgOp2, a.ID, true)
	if linkCodeOf(t, err) == "" {
		t.Fatal("no code for the second person")
	}
	if _, err := c.svc.ConfirmLink(c.ctx(), op2, "telegram", code); !isCode(err, "wrong_code") {
		t.Fatalf("another person used the code: %v", err)
	}
	got, err := c.svc.ConfirmLink(c.ctx(), op, "telegram", code)
	c.must(err)
	if !got.Linked || got.LinkedAt == nil {
		t.Fatalf("confirm = %+v", got)
	}
	if c.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.identity_link' AND target = 'telegram'`) != 1 {
		t.Fatal("no audit line for the link")
	}
	if _, err := c.svc.ConfirmLink(c.ctx(), op, "telegram", code); !isCode(err, "no_code") {
		t.Fatalf("a code worked twice: %v", err)
	}
	out, err := c.button("telegram", tgOp, a.ID, true)
	c.must(err)
	if out.Status != "approved" {
		t.Fatalf("a linked press = %+v", out)
	}
}

func TestContract_D191_WrongCodesExpiryAndTheHourlyCap(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	c := unlinkedChat(t)
	a := c.pending()
	_, err := c.button("telegram", tgOp, a.ID, true)
	_, err = c.svc.ConfirmLink(c.ctx(), op, "telegram", linkCodeOf(t, err))
	c.must(err)
	c.note.mu.Lock()
	c.note.approvers["telegram"] = []response.Approver{{UserID: "u-op", Address: "1009"}, {UserID: "u-op2", Address: tgOp2}}
	c.note.mu.Unlock()
	if _, err := c.button("telegram", "1009", a.ID, true); linkCodeOf(t, err) == "" {
		t.Fatal("a new address counted on the proof of the old one")
	}
	c.note.mu.Lock()
	c.note.approvers["telegram"] = []response.Approver{{UserID: "u-op", Address: tgOp}, {UserID: "u-op2", Address: tgOp2}}
	c.note.mu.Unlock()
	c.must(c.svc.Unlink(c.ctx(), op, "telegram"))
	if c.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.identity_unlink'`) != 1 {
		t.Fatal("no audit line for the unlink")
	}
	if _, err := c.button("telegram", tgOp, a.ID, true); linkCodeOf(t, err) == "" {
		t.Fatal("an unlinked id still counts")
	}
	if err := c.svc.Unlink(c.ctx(), op, "telegram"); !isCode(err, "not_linked") {
		t.Fatalf("second unlink: %v", err)
	}
}

func TestContract_D191_UnlinkedWhileThePressWaitsForTheLock(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestContract_D191_NoCodeWhereTheAnswerIsNotPrivate(t *testing.T) {
	t.Parallel()
	c := unlinkedChat(t)
	a := c.pending()
	_, err := c.button("slack", slackOp, a.ID, true)
	if code := linkCodeOf(t, err); code != "" {
		t.Fatal("a link code was answered on a channel whose answer may be seen by others")
	}
	if c.count(`SELECT COUNT(*) FROM resp_link_codes`) != 0 {
		t.Fatal("a code was made")
	}
	if got := c.only(); len(got.Approvals) != 0 {
		t.Fatal("an unlinked slack press counted")
	}
	ids, err := c.svc.MyIdentities(c.ctx(), op)
	c.must(err)
	for _, r := range ids {
		if r.Channel == "slack" && r.Method != "unavailable" {
			t.Fatalf("slack row = %+v", r)
		}
	}
}

func TestContract_D191_AListChangedAfterTheCodeDoesNotLink(t *testing.T) {
	t.Parallel()
	c := unlinkedChat(t)
	a := c.pending()
	_, err := c.button("telegram", tgOp, a.ID, true)
	code := linkCodeOf(t, err)
	c.note.mu.Lock()
	c.note.approvers["telegram"] = []response.Approver{{UserID: "u-op", Address: "1009"}}
	c.note.mu.Unlock()
	if _, err := c.svc.ConfirmLink(c.ctx(), op, "telegram", code); !isCode(err, "no_code") {
		t.Fatalf("a code made for the old ID linked: %v", err)
	}
	if c.count(`SELECT COUNT(*) FROM resp_identity`) != 0 {
		t.Fatal("a proof was recorded")
	}
}

func TestContract_D191_AnEmailLinkIsReadAgainUnderTheLockAfterAnUnlink(t *testing.T) {
	t.Parallel()
	e, _ := emailEnv(t)
	e.must(e.svc.LinkForTest(e.ctx(), "u-op", "email", "it@acme.example"))
	a := e.pending()
	tok := e.mint(a.ID, "u-op", "it@acme.example")
	if v := e.view(tok); v.State != "ready" {
		t.Fatalf("view = %q", v.State)
	}
	e.svc.SetBeforeLockForTest(func() { e.must(e.svc.Unlink(e.ctx(), op, "email")) })
	if _, err := e.decide(tok, "approve"); !isCode(err, "approver_not_listed") {
		t.Fatalf("a link counted after its proof was removed: %v", err)
	}
	if e.tokenUsed() != 0 || e.only().Status != response.StatusPending {
		t.Fatal("the request was decided")
	}
}

func TestContract_D191_AnEmailAddressDiffersOnlyInCase(t *testing.T) {
	t.Parallel()
	e, m := emailEnv(t)
	e.note.approvers["email"] = []response.Approver{{UserID: "u-op", Address: "IT@Acme.example"}}
	_, err := e.svc.SendLinkCode(e.ctx(), op, "email")
	e.must(err)
	_, err = e.svc.ConfirmLink(e.ctx(), op, "email", " "+m.last("IT@Acme.example")+" ")
	e.must(err)
	a := e.pending()
	if v := e.view(e.mint(a.ID, "u-op", "it@acme.example")); v.State != "ready" {
		t.Fatalf("view = %q", v.State)
	}
}

func TestContract_D191_ZaloOAIsNotLinkable(t *testing.T) {
	t.Parallel()
	e, _ := emailEnv(t)
	e.note.chs = append(e.note.chs, response.NotifyChannel{Type: "zalo", Label: "Zalo OA", Configured: true, Enabled: true, Approvals: true, Approvers: 1})
	e.note.approvers["zalo"] = []response.Approver{{UserID: "u-op", Address: "zoa-1"}}
	ids, err := e.svc.MyIdentities(e.ctx(), op)
	e.must(err)
	for _, r := range ids {
		if r.Channel == "zalo" {
			t.Fatalf("zalo OA listed: %+v", r)
		}
	}
}

// Zalo personal is linked the other way round (D-243): My account shows the code, and it counts only when it arrives from the listed ID.
// Typing it in the app does nothing, the same code from another ID does nothing, and an unlinked reply code gets no code in its answer
// (the answer would sit in the box account's history).
func TestContract_D191_ZaloPersonalIsLinkedBySendingTheCode(t *testing.T) {
	t.Parallel()
	c := unlinkedChat(t)
	a := c.pending()
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	_, err := c.typed(zlOp, "A-7KQ2MX", true)
	if code := linkCodeOf(t, err); code != "" || !strings.Contains(err.Error(), "get a code to send from this account") {
		t.Fatalf("unlinked reply = %v", err)
	}
	ids, err := c.svc.MyIdentities(c.ctx(), op)
	c.must(err)
	if r := zaloRow(ids); r == nil || r.Method != "send_code" || r.Linked {
		t.Fatalf("identities = %+v", ids)
	}
	sent, err := c.svc.SendLinkCode(c.ctx(), op, "zalo-personal")
	c.must(err)
	if len(sent.Code) != 6 || sent.SentTo != zlOp {
		t.Fatalf("code shown = %+v", sent)
	}
	if _, err := c.svc.ConfirmLink(c.ctx(), op, "zalo-personal", sent.Code); err == nil {
		t.Fatal("a Zalo code typed in the app linked the ID")
	}
	if _, err := c.svc.LinkFromChat(c.ctx(), response.ChatDecision{Channel: "zalo-personal", ExternalID: "9999999999", Code: sent.Code}); err == nil {
		t.Fatal("the code from an ID that is not listed linked")
	}
	if _, err := c.svc.LinkFromChat(c.ctx(), response.ChatDecision{Channel: "telegram", ExternalID: tgOp, Code: sent.Code}); err == nil {
		t.Fatal("a send-code link on another channel")
	}
	wrong := "000000"
	if sent.Code == wrong {
		wrong = "111111"
	}
	for range 4 { // wrong codes from the listed ID use up its tries and are logged as refusals, without the code
		_, err := c.svc.LinkFromChat(c.ctx(), response.ChatDecision{Channel: "zalo-personal", ExternalID: zlOp, Code: wrong})
		wantCode(t, err, 400, "wrong_code")
	}
	if n := c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'wrong_code:%'`); n != 4 {
		t.Fatalf("refusals logged = %d", n)
	}
	if rows := c.dump(`SELECT detail FROM resp_log`) + c.dump(`SELECT detail FROM core_audit`); strings.Contains(rows, sent.Code) {
		t.Fatal("the link code reached a log")
	}
	out, err := c.svc.LinkFromChat(c.ctx(), response.ChatDecision{Channel: "zalo-personal", ExternalID: zlOp, Code: sent.Code})
	c.must(err)
	if out.Status != "linked" {
		t.Fatalf("link = %+v", out)
	}
	ids, err = c.svc.MyIdentities(c.ctx(), op)
	c.must(err)
	if r := zaloRow(ids); r == nil || !r.Linked {
		t.Fatalf("after linking = %+v", ids)
	}
	if c.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.identity_link' AND target = 'zalo-personal'`) != 1 {
		t.Fatal("the link is not audited")
	}
	if again, err := c.svc.LinkFromChat(c.ctx(), response.ChatDecision{Channel: "zalo-personal", ExternalID: zlOp, Code: sent.Code}); err != nil || again.Status != "already_linked" {
		t.Fatalf("six digits from a linked ID = %+v, %v", again, err)
	}
	got, err := c.typed(zlOp, "A-7KQ2MX", true) // the reply code was not burned by the refusal
	c.must(err)
	if got.Status != "approved" || got.RequestID != a.ID {
		t.Fatalf("reply after linking = %+v", got)
	}
}

// D-447: notify sends the code to the approver's Zalo when an administrator lists them; the code is made only for the listed address,
// at most one a minute, and replying with it from that ID links the person as before.
func TestContract_D447_ZaloCodeForTheListedAddress(t *testing.T) {
	t.Parallel()
	c := unlinkedChat(t)
	_, _, err := c.svc.ChatLinkCode(c.ctx(), "u-op", "zalo-personal", "9999999999")
	wantCode(t, err, 404, "not_listed")
	_, _, err = c.svc.ChatLinkCode(c.ctx(), "u-op", "telegram", tgOp)
	wantCode(t, err, 400, "chat_channel")
	code, name, err := c.svc.ChatLinkCode(c.ctx(), "u-op", "zalo-personal", zlOp)
	c.must(err)
	if len(code) != 6 || name == "" {
		t.Fatalf("code %q name %q", code, name)
	}
	_, _, err = c.svc.ChatLinkCode(c.ctx(), "u-op", "zalo-personal", zlOp)
	wantCode(t, err, 429, "resend_too_soon")
	out, err := c.svc.LinkFromChat(c.ctx(), response.ChatDecision{Channel: "zalo-personal", ExternalID: zlOp, Code: code})
	c.must(err)
	if out.Status != "linked" {
		t.Fatalf("link = %+v", out)
	}
	_, _, err = c.svc.ChatLinkCode(c.ctx(), "u-op", "zalo-personal", zlOp)
	wantCode(t, err, 409, "already_linked")
}

func zaloRow(ids []response.Identity) *response.Identity {
	for i := range ids {
		if ids[i].Channel == "zalo-personal" {
			return &ids[i]
		}
	}
	return nil
}
