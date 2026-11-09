package channel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// TelegramConfig configures a Telegram bot channel.
type TelegramConfig struct {
	Token   Secret       // bot token from @BotFather: 123456789:AAH…
	ChatID  string       // number (groups look like -1001234567890) or a public @channel_name
	BaseURL string       // empty = https://api.telegram.org ; set only by tests to point at a fake
	Client  *http.Client // nil = NewHTTPClient()
}

var (
	telegramTokenRE = regexp.MustCompile(`^\d{6,12}:[A-Za-z0-9_-]{30,}$`)
	telegramChatRE  = regexp.MustCompile(`^(-?\d{5,20}|@[A-Za-z0-9_]{5,32})$`)
)

const (
	telegramAPI     = "https://api.telegram.org"
	telegramTextMax = 4096
)

type telegramSender struct {
	token  Secret
	chat   string
	base   string
	client *http.Client
}

// NewTelegram validates cfg and returns the adapter.
func NewTelegram(cfg TelegramConfig) (Sender, error) {
	tok := strings.TrimSpace(cfg.Token.Reveal())
	if tok == "" {
		return nil, cfgErr("secret_required", "Enter the bot token.")
	}
	if !telegramTokenRE.MatchString(tok) {
		return nil, cfgErr("bad_token", "A bot token looks like 123456789:AAH… and comes from @BotFather. Copy it again without extra spaces.")
	}
	chat := strings.TrimSpace(cfg.ChatID)
	if !telegramChatRE.MatchString(chat) {
		return nil, cfgErr("bad_chat_id", "Chat ID is a number (groups look like -1001234567890) or a public @channel_name.")
	}
	base := telegramAPI
	if cfg.BaseURL != "" {
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			return nil, cfgErr("bad_base_url", "The Telegram API address is not valid.")
		}
		base = strings.TrimRight(u.String(), "/")
	}
	return &telegramSender{token: NewSecret(tok), chat: chat, base: base, client: clientOrDefault(cfg.Client)}, nil
}

func (*telegramSender) Type() Type { return Telegram }

// fit joins lines with "\n" and, when the result is longer than limit runes,
// shortens everything before the last line (the link) so the link survives.
func fit(lines []string, limit int) string {
	last := lines[len(lines)-1]
	head := strings.Join(lines[:len(lines)-1], "\n")
	room := limit - utf8.RuneCountInString(last) - 1
	if room < 0 {
		room = 0
	}
	return truncRunes(head, room) + "\n" + last
}

// telegramText is plain text: no parse_mode is sent, so Telegram interprets no
// markup or entity in any field. Untrusted text therefore needs no escaping and
// cannot become a link, mention or formatting. HTML mode would need correct
// escaping of three characters plus a failure mode (400 on malformed markup)
// for no gain on a text-only alert.
func telegramText(m Message, link string) string { return fit(m.lines(link), telegramTextMax) }

func (t *telegramSender) Send(ctx context.Context, m Message) (Receipt, error) {
	if err := m.check(); err != nil {
		return Receipt{}, err
	}
	link, _ := safeLink(m.Link)
	body, err := json.Marshal(map[string]any{
		"chat_id":              t.chat,
		"text":                 telegramText(m.norm(), link),
		"link_preview_options": map[string]any{"is_disabled": true},
	})
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: telegram: encode message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+"/bot"+t.token.Reveal()+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: telegram: build request: %s", transportReason(err, []Secret{t.token}))
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	code, ans, err := do(t.client, Telegram, req, t.token)
	if err != nil {
		return Receipt{}, err
	}
	if code < 200 || code > 299 {
		return Receipt{}, statusErr(Telegram, code, telegramDescription(ans), t.token)
	}
	var ok struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(ans, &ok) != nil || !ok.OK {
		return Receipt{}, &StatusError{Channel: Telegram, Code: code, Reason: "the answer did not confirm delivery"}
	}
	return Receipt{To: "chat " + t.chat, Detail: fmt.Sprintf("Telegram received the message (chat %s).", t.chat)}, nil
}

// telegramDescription picks the "description" of an error answer, falling back to the raw text.
func telegramDescription(body []byte) []byte {
	var e struct {
		Description string `json:"description"`
	}
	if json.Unmarshal(body, &e) == nil && e.Description != "" {
		return []byte(e.Description)
	}
	return body
}

func (t *telegramSender) Dest() string { return "chat " + t.chat }
