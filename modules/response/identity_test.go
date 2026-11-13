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

// D-414: a Telegram approver is linked like a Zalo one, by the confirm link the box sends to their Telegram, opened and confirmed by that
// person signed in to Vedette. A press before that decides nothing and its answer holds no code; another signed-in person is refused with
// an audit row and the link stays good for its person.
func TestContract_D414_TelegramIsLinkedByTheConfirmLinkNotByAPress(t *testing.T) {
	t.Parallel()
	c := unlinkedChat(t)
	a := c.pending()
	_, err := c.button("telegram", tgOp, a.ID, true)
	if code := linkCodeOf(t, err); code != "" || !strings.Contains(err.Error(), "Open the link Vedette sent") {
		t.Fatalf("unlinked press = %v", err)
	}
	if got := c.only(); got.Status != response.StatusPending || len(got.Approvals) != 0 {
		t.Fatalf("an unlinked press decided: %+v", got)
	}
	if c.count(`SELECT COUNT(*) FROM resp_link_codes`) != 0 {
		t.Fatal("a press made a code")
	}
	if c.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'approver_not_linked:%'`) != 1 {
		t.Fatal("the refusal is not logged")
	}
	ids, err := c.svc.MyIdentities(c.ctx(), op)
	c.must(err)
	if r := rowOf(ids, "telegram"); r == nil || r.Linked || r.CodeWaiting || r.Method != "send_code" || r.Address != tgOp {
		t.Fatalf("my telegram row = %+v", ids)
	}
	token, name, err := c.svc.ChatLinkToken(c.ctx(), "u-op", "telegram", tgOp)
	c.must(err)
	if name != "IT Operator" || !regexp.MustCompile(`^[0-9a-f]{8}-[A-Za-z0-9_-]{22}$`).MatchString(token) {
		t.Fatalf("token %q name %q", token, name)
	}
	_, err = c.svc.ConfirmLink(c.ctx(), op2, "telegram", token)
	wantCode(t, err, 403, "other_account")
	if c.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.identity_link_refused' AND user = 'it2@acme.example' AND target = 'telegram'`) != 1 {
		t.Fatal("the refusal of another account is not audited")
	}
	got, err := c.svc.ConfirmLink(c.ctx(), op, "telegram", token)
	c.must(err)
	if !got.Linked || got.LinkedAt == nil || got.Address != tgOp {
		t.Fatalf("confirm = %+v", got)
	}
	if c.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.identity_link' AND target = 'telegram'`) != 1 {
		t.Fatal("no audit line for the link")
	}
	if rows := c.dump(`SELECT detail FROM resp_log`) + c.dump(`SELECT detail FROM core_audit`); strings.Contains(rows, token[9:]) {
		t.Fatal("the token reached a log")
	}
	_, err = c.svc.ConfirmLink(c.ctx(), op, "telegram", token)
	wantCode(t, err, 400, "no_code")
	out, err := c.button("telegram", tgOp, a.ID, true)
	c.must(err)
	if out.Status != "approved" {
		t.Fatalf("a linked press = %+v", out)
	}
}

func rowOf(ids []response.Identity, channel string) *response.Identity {
	for i := range ids {
		if ids[i].Channel == channel {
			return &ids[i]
		}
	}
	return nil
}

type fakeLinkSender struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeLinkSender) SendApproverLink(_ context.Context, actor, channel, userID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, actor+"|"+channel+"|"+userID)
	return "", nil
}

// D-414: Send again in My account asks notify to send the person's own listed chat ID a new confirm link; without notify it is refused.
func TestContract_D414_SendAgainFromMyAccount(t *testing.T) {
	t.Parallel()
	c := unlinkedChat(t)
	_, err := c.svc.SendLinkCode(c.ctx(), op, "telegram")
	wantCode(t, err, 400, "chat_channel")
	ls := &fakeLinkSender{}
	c.svc.SetLinkSenderForTest(ls)
	sent, err := c.svc.SendLinkCode(c.ctx(), op, "telegram")
	c.must(err)
	if sent.SentTo != "Telegram "+tgOp || sent.Link != "" || len(ls.calls) != 1 || ls.calls[0] != "it@acme.example|telegram|u-op" {
		t.Fatalf("sent = %+v calls = %v", sent, ls.calls)
	}
	c.must(c.svc.LinkForTest(c.ctx(), "u-op", "telegram", tgOp))
	_, err = c.svc.SendLinkCode(c.ctx(), op, "telegram")
	wantCode(t, err, 409, "already_linked")
}

// A wrong, mangled or expired confirm link on Telegram does not link (the same rules as Zalo, D-447 tests below).
func TestContract_D414_TelegramWrongAndExpiredLinks(t *testing.T) {
	t.Parallel()
	c := unlinkedChat(t)
	token, _, err := c.svc.ChatLinkToken(c.ctx(), "u-op", "telegram", tgOp)
	c.must(err)
	_, err = c.svc.ConfirmLink(c.ctx(), op, "telegram", "123456")
	wantCode(t, err, 400, "invalid_link")
	_, err = c.svc.ConfirmLink(c.ctx(), op, "telegram", token[:9]+strings.Repeat("A", 22))
	wantCode(t, err, 400, "wrong_code")
	c.clock.Advance(10*time.Minute + time.Second)
	_, err = c.svc.ConfirmLink(c.ctx(), op, "telegram", token)
	wantCode(t, err, 400, "code_expired")
	if c.count(`SELECT COUNT(*) FROM resp_identity`) != 0 {
		t.Fatal("a proof was recorded")
	}
}

func TestContract_D191_AChangedAddressOrAnUnlinkDropsTheProof(t *testing.T) {
	t.Parallel()
	c := unlinkedChat(t)
	a := c.pending()
	c.must(c.svc.LinkForTest(c.ctx(), "u-op", "telegram", tgOp))
	c.note.mu.Lock()
	c.note.approvers["telegram"] = []response.Approver{{UserID: "u-op", Address: "1009"}, {UserID: "u-op2", Address: tgOp2}}
	c.note.mu.Unlock()
	if _, err := c.button("telegram", "1009", a.ID, true); !isCode(err, "approver_not_linked") {
		t.Fatal("a new address counted on the proof of the old one")
	}
	c.note.mu.Lock()
	c.note.approvers["telegram"] = []response.Approver{{UserID: "u-op", Address: tgOp}, {UserID: "u-op2", Address: tgOp2}}
	c.note.mu.Unlock()
	c.must(c.svc.Unlink(c.ctx(), op, "telegram"))
	if c.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.identity_unlink'`) != 1 {
		t.Fatal("no audit line for the unlink")
	}
	if _, err := c.button("telegram", tgOp, a.ID, true); !isCode(err, "approver_not_linked") {
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
	code, _, err := c.svc.ChatLinkToken(c.ctx(), "u-op", "telegram", tgOp)
	c.must(err)
	c.note.mu.Lock()
	c.note.approvers["telegram"] = []response.Approver{{UserID: "u-op", Address: "1009"}}
	c.note.mu.Unlock()
	if _, err := c.svc.ConfirmLink(c.ctx(), op, "telegram", code); !isCode(err, "no_code") {
		t.Fatalf("a link made for the old ID linked: %v", err)
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

// D-447 (option A): a Zalo personal approver is linked only by the confirm link the box sends to their Zalo, opened and confirmed by that
// person signed in to Vedette. A reply from the account links nothing; another signed-in person is refused and the link stays good for
// its person; reading My account (a GET) links nothing; a used, replaced or expired link does not link.
func TestContract_D447_ZaloIsLinkedOnlyByTheConfirmLink(t *testing.T) {
	t.Parallel()
	c := unlinkedChat(t)
	a := c.pending()
	c.codes(a.ID, "u-op", zlOp, "A-7KQ2MX", "R-7KQ2MX")
	_, err := c.typed(zlOp, "A-7KQ2MX", true) // a reply alone links nothing and decides nothing
	if code := linkCodeOf(t, err); code != "" || !strings.Contains(err.Error(), "Open the link Vedette sent") {
		t.Fatalf("unlinked reply = %v", err)
	}
	ids, err := c.svc.MyIdentities(c.ctx(), op)
	c.must(err)
	if r := zaloRow(ids); r == nil || r.Method != "send_code" || r.Linked {
		t.Fatalf("identities = %+v", ids)
	}
	_, err = c.svc.SendLinkCode(c.ctx(), op, "zalo-personal") // no self-service code any more
	wantCode(t, err, 400, "chat_channel")
	token, name, err := c.svc.ChatLinkToken(c.ctx(), "u-op", "zalo-personal", zlOp)
	c.must(err)
	if len(token) != 31 || name == "" {
		t.Fatalf("token %q name %q", token, name)
	}
	if rows := c.dump(`SELECT code_hash FROM resp_link_codes`); strings.Contains(rows, token[9:]) {
		t.Fatal("the token is stored in clear")
	}
	_, err = c.svc.ConfirmLink(c.ctx(), op2, "zalo-personal", token) // signed in as someone else: refused, nothing read
	wantCode(t, err, 403, "other_account")
	_, err = c.svc.ConfirmLink(c.ctx(), op, "zalo-personal", "123456") // six digits are not a link
	wantCode(t, err, 400, "invalid_link")
	if ids, _ = c.svc.MyIdentities(c.ctx(), op); zaloRow(ids).Linked || !zaloRow(ids).CodeWaiting {
		t.Fatalf("a GET or a refusal changed the link: %+v", ids)
	}
	got, err := c.svc.ConfirmLink(c.ctx(), op, "zalo-personal", token)
	c.must(err)
	if !got.Linked || got.Address != zlOp {
		t.Fatalf("confirm = %+v", got)
	}
	if c.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.identity_link' AND target = 'zalo-personal'`) != 1 {
		t.Fatal("the link is not audited")
	}
	if rows := c.dump(`SELECT detail FROM resp_log`) + c.dump(`SELECT detail FROM core_audit`); strings.Contains(rows, token[9:]) {
		t.Fatal("the token reached a log")
	}
	_, err = c.svc.ConfirmLink(c.ctx(), op, "zalo-personal", token) // used
	wantCode(t, err, 400, "no_code")
	got2, err := c.typed(zlOp, "A-7KQ2MX", true) // the reply code was not burned by the refusal
	c.must(err)
	if got2.Status != "approved" || got2.RequestID != a.ID {
		t.Fatalf("reply after linking = %+v", got2)
	}
}

// Send again (a new token) invalidates the old one; a link older than 10 minutes has expired, then is gone.
func TestContract_D447_ZaloConfirmLinkReplacedExpiredWrong(t *testing.T) {
	t.Parallel()
	c := unlinkedChat(t)
	old, _, err := c.svc.ChatLinkToken(c.ctx(), "u-op", "zalo-personal", zlOp)
	c.must(err)
	_, _, err = c.svc.ChatLinkToken(c.ctx(), "u-op", "zalo-personal", zlOp)
	wantCode(t, err, 429, "resend_too_soon")
	c.clock.Advance(61 * time.Second)
	fresh, _, err := c.svc.ChatLinkToken(c.ctx(), "u-op", "zalo-personal", zlOp)
	c.must(err)
	_, err = c.svc.ConfirmLink(c.ctx(), op, "zalo-personal", old)
	wantCode(t, err, 400, "wrong_code")
	c.clock.Advance(11 * time.Minute)
	_, err = c.svc.ConfirmLink(c.ctx(), op, "zalo-personal", fresh)
	wantCode(t, err, 400, "code_expired")
	_, err = c.svc.ConfirmLink(c.ctx(), op, "zalo-personal", fresh)
	wantCode(t, err, 400, "no_code")
	_, _, err = c.svc.ChatLinkToken(c.ctx(), "u-op", "zalo-personal", "9999999999")
	wantCode(t, err, 404, "not_listed")
	_, _, err = c.svc.ChatLinkToken(c.ctx(), "u-op", "slack", slackOp)
	wantCode(t, err, 400, "chat_channel")
}

// D-447 (review L1, L4): an administrator's change drops the proof of the old address, so naming it again needs a new proof; with
// Response off no code is made.
func TestContract_D447_DroppedZaloProofDoesNotComeBack(t *testing.T) {
	t.Parallel()
	c := newChatEnv(t) // every approver linked
	ids, err := c.svc.MyIdentities(c.ctx(), op)
	c.must(err)
	if r := zaloRow(ids); r == nil || !r.Linked {
		t.Fatalf("before = %+v", ids)
	}
	c.must(c.svc.DropChatLink(c.ctx(), "admin@acme.example", "u-op", "zalo-personal", "9999999999")) // another address: nothing to drop
	ids, _ = c.svc.MyIdentities(c.ctx(), op)
	if r := zaloRow(ids); r == nil || !r.Linked {
		t.Fatal("dropping another address removed the proof")
	}
	c.must(c.svc.DropChatLink(c.ctx(), "admin@acme.example", "u-op", "zalo-personal", zlOp))
	ids, _ = c.svc.MyIdentities(c.ctx(), op)
	if r := zaloRow(ids); r == nil || r.Linked { // the list still names zlOp (A -> B -> A): it does not count again
		t.Fatalf("after the drop = %+v", ids)
	}
	if c.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'response.identity_unlink' AND user = 'admin@acme.example'`) != 1 {
		t.Fatal("the drop is not audited")
	}
	off := newEnv(t, func(cfg *response.Config) { cfg.Modules = &gate{on: false} })
	_, _, err = off.svc.ChatLinkToken(off.ctx(), "u-op", "zalo-personal", zlOp)
	wantCode(t, err, 503, "link_unavailable")
}

func zaloRow(ids []response.Identity) *response.Identity {
	for i := range ids {
		if ids[i].Channel == "zalo-personal" {
			return &ids[i]
		}
	}
	return nil
}
