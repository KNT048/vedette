package channel

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/secrets"
)

var testCodes = &ReplyCodes{Approve: "A-7KQ2MX", Reject: "R-7KQ2MX", Until: "14:30"}

// The reply codes of an approver go to that approver alone (spec approval-tokens.md 7): a direct message to their Zalo user ID,
// through the session of the channel, even when the channel itself sends alerts to a group. The codes are on the last line, which is
// never cut, however long the request is.
func TestZaloPersonalToSendsTheCodesToOnePerson(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	s := newZPSender(t, f, func(c *ZaloPersonalConfig) { c.Group = true })
	d, err := ZaloPersonalTo(s, "2938475610293847561")
	if err != nil {
		t.Fatal(err)
	}
	m := sample
	m.Kind = "approval"
	m.What = strings.Repeat("a long change ", 400)
	m.ReplyCodes = testCodes
	rec, err := d.Send(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if rec.To != "Zalo 2938475610293847561" || d.Dest() != "Zalo 2938475610293847561" || d.Type() != ZaloPersonal {
		t.Errorf("receipt %+v dest %q", rec, d.Dest())
	}
	p := f.sent[0]
	if p["toid"] != "2938475610293847561" || p["grid"] != nil || f.paths[0] != "/api/message/sms" || f.hosts[0] != "tt-chat1-wpa.chat.zalo.me" {
		t.Errorf("params %v path %s host %s", p, f.paths[0], f.hosts[0])
	}
	text, _ := p["message"].(string)
	lines := strings.Split(text, "\n")
	last := lines[len(lines)-1]
	if !strings.Contains(last, "A-7KQ2MX") || !strings.Contains(last, "R-7KQ2MX") || !strings.Contains(last, "14:30") || len([]rune(text)) > zaloTextMax {
		t.Errorf("last line %q (%d runes)", last, len([]rune(text)))
	}
	if !strings.Contains(text, "\nDetails: "+m.Link+"\n") {
		t.Errorf("the link line is gone: %q", text[len(text)-300:])
	}
	// The group alert still goes to the group, through the same session: no second sign-in.
	if _, err := s.Send(context.Background(), sample); err != nil || f.logins != 1 || f.paths[1] != "/api/group/sendmsg" {
		t.Errorf("group send after: %v, logins %d, path %v", err, f.logins, f.paths)
	}
}

// Codes never go to the configured recipient (a group, or someone else): only ZaloPersonalTo carries them.
func TestZaloPersonalRefusesCodesForTheConfiguredRecipient(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	s := newZPSender(t, f, nil)
	m := sample
	m.ReplyCodes = testCodes
	if _, err := s.Send(context.Background(), m); !errors.Is(err, ErrInvalidMessage) || f.logins+f.sends != 0 {
		t.Fatalf("err %v, logins %d, sends %d", err, f.logins, f.sends)
	}
}

func TestZaloPersonalToRefusesBadInput(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	s := newZPSender(t, f, nil)
	for _, user := range []string{"", "0912345678", "+84912345678", "84912345678", "abc", "12345", strings.Repeat("1", 26)} {
		if _, err := ZaloPersonalTo(s, user); err == nil {
			t.Errorf("user %q accepted", user)
		}
	}
	tg, err := NewTelegram(TelegramConfig{Token: secrets.NewValue(tgToken), ChatID: "123456"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ZaloPersonalTo(tg, "2938475610293847561"); err == nil {
		t.Error("a Telegram sender was accepted")
	}
	d, err := ZaloPersonalTo(s, "2938475610293847561")
	if err != nil {
		t.Fatal(err)
	}
	for name, rc := range map[string]*ReplyCodes{
		"lower case":     {Approve: "a-7kq2mx", Reject: "R-7KQ2MX", Until: "14:30"},
		"swapped":        {Approve: "R-7KQ2MX", Reject: "A-7KQ2MX", Until: "14:30"},
		"letter O":       {Approve: "A-7KQ2MO", Reject: "R-7KQ2MX", Until: "14:30"},
		"digit 1":        {Approve: "A-7KQ2M1", Reject: "R-7KQ2MX", Until: "14:30"},
		"short":          {Approve: "A-7KQ2M", Reject: "R-7KQ2MX", Until: "14:30"},
		"until text":     {Approve: "A-7KQ2MX", Reject: "R-7KQ2MX", Until: "soon\nclick here"},
		"until too late": {Approve: "A-7KQ2MX", Reject: "R-7KQ2MX", Until: "24:00"},
	} {
		m := sample
		m.ReplyCodes = rc
		if _, err := d.Send(context.Background(), m); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: err %v", name, err)
		}
	}
	if f.logins+f.sends != 0 {
		t.Errorf("Zalo was called: logins %d sends %d", f.logins, f.sends)
	}
}

// A sign-in answer that names no chat service cannot carry a direct message, also when the group service is there.
func TestZaloPersonalToNeedsTheChatService(t *testing.T) {
	t.Parallel()
	f := newZaloFake(t)
	f.noChat = true
	s := newZPSender(t, f, func(c *ZaloPersonalConfig) { c.Group = true })
	d, err := ZaloPersonalTo(s, "2938475610293847561")
	if err != nil {
		t.Fatal(err)
	}
	m := sample
	m.ReplyCodes = testCodes
	if _, err := d.Send(context.Background(), m); err == nil || f.sends != 0 {
		t.Fatalf("err %v sends %d", err, f.sends)
	}
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Fatalf("the group alert: %v", err)
	}
}
