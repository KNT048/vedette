package channel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/secrets"
)

// TelegramConfig configures a Telegram bot channel.
type TelegramConfig struct {
	Token  secrets.Value // bot token from @BotFather: 123456789:AAH…
	ChatID string        // number (groups look like -1001234567890) or a public @channel_name
	Client *http.Client  // nil = NewHTTPClient()
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
	noPrint
	token  secrets.Value
	chat   string
	base   string // official API; tests replace it inside the package (never configurable: it would ship the token anywhere)
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
	return &telegramSender{token: secrets.NewValue(tok), chat: chat, base: telegramAPI, client: clientOrDefault(cfg.Client)}, nil
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

// telegramText is plain text: no parse_mode is sent, so no markup or formatting
// entity in any field is interpreted and nothing needs HTML escaping. Telegram
// still auto-links URLs, @mentions and /commands in plain text, so feed-sourced
// fields go through defang; the box's own link stays a real link.
func telegramText(m Message, link string) string {
	return fit(m.mapText(defang).lines(link), telegramTextMax)
}

func (t *telegramSender) Send(ctx context.Context, m Message) (Receipt, error) {
	if err := m.check(); err != nil {
		return Receipt{}, err
	}
	link, _ := safeLink(m.Link)
	args := map[string]any{
		"chat_id":              t.chat,
		"text":                 telegramText(m.norm(), link),
		"link_preview_options": map[string]any{"is_disabled": true},
	}
	if len(m.Buttons) > 0 {
		args["reply_markup"] = telegramKeyboard(m.Buttons)
	}
	if m.Kind == "approval" {
		args["protect_content"] = true // an approval request cannot be forwarded or saved out of the chat
	}
	body, err := json.Marshal(args)
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: telegram: encode message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+"/bot"+t.token.Reveal()+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: telegram: build request: %s", transportReason(err, []secrets.Value{t.token}))
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
		return Receipt{}, &ProviderError{Channel: Telegram, Reason: "the answer did not confirm delivery"}
	}
	return Receipt{To: "chat " + t.chat, Detail: fmt.Sprintf("Telegram received the message (chat %s).", t.chat), MessageID: sentMessageID(ans), ChatID: sentChatID(ans)}, nil
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
