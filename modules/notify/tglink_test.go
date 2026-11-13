package notify_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// tgBot answers sendMessage like Telegram: 403 for a chat the bot may not write to first (closed), 200 otherwise.
type tgBot struct {
	mu     sync.Mutex
	closed map[string]bool
	sent   []map[string]any
}

func (b *tgBot) RoundTrip(r *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(r.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	b.mu.Lock()
	defer b.mu.Unlock()
	code, body := 200, `{"ok":true,"result":{"message_id":1,"chat":{"id":1}}}`
	if chat, _ := m["chat_id"].(string); b.closed[chat] {
		code, body = 403, `{"ok":false,"description":"Forbidden: bot can't initiate conversation with a user"}`
	} else {
		b.sent = append(b.sent, m)
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
}

func (b *tgBot) last() (chat, text string, n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sent) == 0 {
		return "", "", 0
	}
	m := b.sent[len(b.sent)-1]
	chat, _ = m["chat_id"].(string)
	text, _ = m["text"].(string)
	return chat, text, len(b.sent)
}

// D-414: saving a Telegram approver makes the bot send them one confirm link, privately; the dialog shows them waiting; Send again sends a
// new one. When the bot may not write to them first, the token never goes into the shared chat: a note there asks them to press Start, the
// undelivered link is dropped and Send again answers send_failed. Removing a linked approver drops their proof and is audited. The token
// is never in the audit log.
func TestContract_D414_TelegramApproverConfirmLink(t *testing.T) {
	links, codes, bot := &fakeLinks{}, &fakeLinkCodes{}, &tgBot{closed: map[string]bool{}}
	e := newEnv(t, func(c *notify.Config) {
		c.ApproverLinks, c.LinkCodes, c.HTTPClient = links, codes, &http.Client{Transport: bot}
	})
	const tgOp, group = "5550001", "-1002145678901"
	in := notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": group}, Secret: tgToken, MinSeverity: notify.Low, Approvals: true,
		Approvers: []notify.Approver{{UserID: "u-op", Address: tgOp}}}
	e.save(channel.Telegram, in)
	e.svc.WaitZaloForTest()
	chat, text, n := bot.last()
	if n != 1 || chat != tgOp || !strings.Contains(text, "IT Operator: open this link to link your Telegram account to Vedette.") ||
		!strings.Contains(text, "https://box.example:8443/link/telegram?c=0a1b2c3d-tokenTOKENtoken0123456") {
		t.Fatalf("sent %d to %q: %q", n, chat, text)
	}
	st, err := e.svc.TelegramApprovers(e.ctx(), "admin@acme.example")
	if err != nil || len(st) != 1 || st[0].State != "waiting" || st[0].SentAt == nil || st[0].BoxAccount {
		t.Fatalf("approvers = %+v, %v", st, err)
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.telegram_link_code' AND detail LIKE '%privately%it@acme.example%' AND detail NOT LIKE '%tokenTOKEN%'`) != 1 {
		t.Error("the send is not audited (or the token is in it)")
	}
	e.save(channel.Telegram, in) // nothing changed for the approver: no second link
	e.svc.WaitZaloForTest()
	if _, _, n := bot.last(); n != 1 {
		t.Errorf("a plain save sent %d links", n)
	}
	// The bot may not write to the person first: a note without the link goes to the approval chat.
	bot.mu.Lock()
	bot.closed[tgOp] = true
	bot.mu.Unlock()
	if _, err := e.svc.SendTelegramLink(e.ctx(), "admin@acme.example", "u-op"); zaloErr(err) != "send_failed" {
		t.Fatalf("undelivered link: %v", err)
	}
	if chat, text, n := bot.last(); n != 2 || chat != group || strings.Contains(text, "tokenTOKEN") || !strings.Contains(text, "IT Operator: to link your Telegram account to Vedette, open a private chat with this bot and press Start") {
		t.Fatalf("note: %d to %q: %q", n, chat, text)
	}
	if st, _ := e.svc.TelegramApprovers(e.ctx(), "admin@acme.example"); st[0].State != "not_sent" || !strings.Contains(st[0].Error, "press Start") {
		t.Errorf("after the note: %+v", st)
	}
	if len(codes.dropped) != 1 || codes.dropped[0] != "admin@acme.example|u-op|"+tgOp {
		t.Errorf("the undelivered link was not dropped: %v", codes.dropped)
	}
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.telegram_link_code' AND detail LIKE '%press Start was posted%' AND detail NOT LIKE '%tokenTOKEN%'`) != 1 {
		t.Error("the note is not audited")
	}
	bot.mu.Lock()
	bot.closed[tgOp] = false
	bot.mu.Unlock()
	if _, err := e.svc.SendTelegramLink(e.ctx(), "admin@acme.example", "u-admin"); zaloErr(err) != "not_listed" {
		t.Errorf("send to someone not listed: %v", err)
	}
	if _, err := e.svc.SendApproverLink(e.ctx(), "it@acme.example", channel.Telegram, "u-op"); err != nil { // My account, Send again
		t.Errorf("send again from My account: %v", err)
	}
	links.mu.Lock()
	links.linked = true
	links.mu.Unlock()
	if st, _ := e.svc.TelegramApprovers(e.ctx(), "admin@acme.example"); st[0].State != "linked" {
		t.Errorf("after the confirm: %+v", st)
	}
	in.Approvers = []notify.Approver{{UserID: "u-admin", Address: "5550002"}}
	e.save(channel.Telegram, in)
	e.svc.WaitZaloForTest()
	if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.telegram_unlink' AND detail LIKE 'it@acme.example: Telegram `+tgOp+`%'`) != 1 {
		t.Error("removing a linked approver is not audited")
	}
	if len(codes.dropped) != 2 || codes.dropped[1] != "admin@acme.example|u-op|"+tgOp {
		t.Errorf("the old proof was not dropped: %v", codes.dropped)
	}
}
