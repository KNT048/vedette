package channel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// The receiving side of a Telegram bot for approvals (spec approval-tokens.md 6, D-38): the box long-polls getUpdates (a
// connection out, no inbound port, no webhook) for button presses only, and answers each press privately with
// answerCallbackQuery. Everything Telegram sends is untrusted input: the answer is size-capped, decoded fail-closed, and a
// press whose fields do not have their documented form is dropped before anyone sees it.

// Limits of the receiving side.
const (
	maxUpdatesBody   = 1 << 20 // one getUpdates answer (10 updates; a press carries the approval message, at most 4096 characters)
	maxUpdates       = 100     // Telegram never returns more per call
	telegramPoll     = 10      // updates asked per call
	maxAnswerText    = 200     // answerCallbackQuery text limit of Telegram
	maxCallbackData  = 64      // callback_data limit of Telegram (1 to 64 bytes)
	maxButtons       = 4       // buttons under one message
	maxButtonText    = 32      // runes of a button label
	telegramCallSlop = 10 * time.Second
)

var (
	telegramFromRE   = regexp.MustCompile(`^[1-9][0-9]{0,14}$`)        // a Telegram user id (approver addresses are 5 to 15 digits)
	telegramChatIDRE = regexp.MustCompile(`^-?[1-9][0-9]{0,19}$`)      // a chat id as Telegram writes it
	telegramUserRE   = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)      // the public username of a chat, without @
	telegramQueryRE  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)     // callback_query.id
	callbackDataRE   = regexp.MustCompile(`^[A-Za-z0-9_.:@+-]{1,64}$`) // what notify puts in callback_data (and all it accepts back)
)

// Button is one inline button under a message. Data is what Telegram sends back when it is pressed (callback_data):
// 1 to 64 bytes of A-Z a-z 0-9 _ . : @ + -.
type Button struct{ Text, Data string }

func checkButtons(bs []Button) error {
	if len(bs) > maxButtons {
		return fmt.Errorf("%w: at most %d buttons", ErrInvalidMessage, maxButtons)
	}
	for _, b := range bs {
		if t := Line(b.Text, maxButtonText+1); t == "" || len([]rune(t)) > maxButtonText {
			return fmt.Errorf("%w: a button label is 1 to %d characters", ErrInvalidMessage, maxButtonText)
		}
		if !callbackDataRE.MatchString(b.Data) {
			return fmt.Errorf("%w: button data is 1 to 64 characters of letters, digits and _ . : @ + -", ErrInvalidMessage)
		}
	}
	return nil
}

// telegramKeyboard is the reply_markup of a message with buttons: one row.
func telegramKeyboard(bs []Button) map[string]any {
	row := make([]map[string]string, 0, len(bs))
	for _, b := range bs {
		row = append(row, map[string]string{"text": Line(b.Text, maxButtonText), "callback_data": b.Data})
	}
	return map[string]any{"inline_keyboard": [][]map[string]string{row}}
}

// Callback is one button press, after its fields were checked: FromID is the Telegram user id of the person who pressed (a
// decimal number, set by Telegram, not by the person), ChatID the numeric chat of the message (ChatUsername its public name
// without @, when it has one), Data the callback_data of the button. Nothing here is trusted yet: the caller still checks
// the chat against its configuration and the data against what it sent.
//
// Invalid is a press whose query id is well formed but whose other fields are not (data out of form, no chat, pressed by a
// bot): only QueryID is set, so the caller can answer it (Telegram shows a progress indicator until a press is answered) and
// must never decide anything from it. A press without a usable query id cannot be answered and is dropped.
type Callback struct {
	UpdateID     int64
	QueryID      string
	FromID       string
	ChatID       string
	ChatUsername string
	Data         string
	Invalid      bool
}

// TelegramBot polls for button presses and answers them. Its API address is fixed (a configurable one would ship the bot
// token anywhere); tests replace it inside the package. Printing it prints a fixed string.
type TelegramBot struct {
	noPrint
	token  secrets.Value
	base   string
	client *http.Client
}

// NewTelegramBot checks the bot token form. client nil = a client without redirects; every call has its own deadline.
func NewTelegramBot(token secrets.Value, client *http.Client) (*TelegramBot, error) {
	tok := strings.TrimSpace(token.Reveal())
	if !telegramTokenRE.MatchString(tok) {
		return nil, cfgErr("bad_token", "A bot token looks like 123456789:AAH… and comes from @BotFather. Copy it again without extra spaces.")
	}
	if client == nil {
		client = &http.Client{CheckRedirect: noRedirect}
	}
	c := clientOrDefault(client) // a copy: the caller's client is not changed
	c.Timeout = 0                // no total timeout: a long poll is longer than any default; each call has its own deadline
	return &TelegramBot{token: secrets.NewValue(tok), base: telegramAPI, client: c}, nil
}

// call posts one Bot API method and returns the answer body (at most limit bytes). Errors never carry the URL or the token.
func (b *TelegramBot) call(ctx context.Context, method string, args any, deadline time.Duration, limit int64) ([]byte, error) {
	body, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("notify: telegram: encode %s: %w", method, err)
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.base+"/bot"+b.token.Reveal()+"/"+method, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("notify: telegram: build request: %s", transportReason(err, []secrets.Value{b.token}))
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	code, ans, err := doLimit(b.client, Telegram, req, limit, b.token)
	if err != nil {
		return nil, err
	}
	if code < 200 || code > 299 {
		return nil, statusErr(Telegram, code, telegramDescription(ans), b.token)
	}
	return ans, nil
}

// Updates long-polls for button presses after offset, waiting up to wait for one. It returns the presses and the offset of
// the next call: every update read is confirmed by it, also the ones that are not presses or that were dropped as malformed,
// so none is read twice. The offset never goes back.
func (b *TelegramBot) Updates(ctx context.Context, offset int64, wait time.Duration) ([]Callback, int64, error) {
	secs := int(wait / time.Second)
	args := map[string]any{"offset": offset, "timeout": secs, "limit": telegramPoll, "allowed_updates": []string{"callback_query"}}
	ans, err := b.call(ctx, "getUpdates", args, wait+telegramCallSlop, maxUpdatesBody+1)
	if err != nil {
		return nil, offset, err
	}
	return ParseTelegramUpdates(ans, offset)
}

// Answer answers a press privately: Telegram shows text only to the person who pressed (an alert they close), or, when text
// is empty, only stops the progress indicator. text is cleaned to one line of at most 200 characters.
func (b *TelegramBot) Answer(ctx context.Context, queryID, text string) error {
	text = Line(text, maxAnswerText)
	ans, err := b.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": queryID, "text": text, "show_alert": text != ""}, defaultTimeout, maxResponseBody)
	if err != nil {
		return err
	}
	var ok struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(ans, &ok) != nil || !ok.OK {
		return &ProviderError{Channel: Telegram, Reason: "the answer did not confirm it"}
	}
	return nil
}

// tgUpdate is the part of an update that is read. The ids stay raw JSON so their exact text is checked: a number, never a
// string that holds one, and no float rounding.
type tgUpdate struct {
	UpdateID      *int64 `json:"update_id"`
	CallbackQuery *struct {
		ID   string `json:"id"`
		From *struct {
			ID    json.RawMessage `json:"id"`
			IsBot bool            `json:"is_bot"`
		} `json:"from"`
		Message *struct {
			Chat *struct {
				ID       json.RawMessage `json:"id"`
				Username string          `json:"username"`
			} `json:"chat"`
		} `json:"message"`
		Data *string `json:"data"`
	} `json:"callback_query"`
}

// ParseTelegramUpdates reads a getUpdates answer (fail-closed): an answer that is too big, not JSON, not ok or without a
// result list is an error and yields nothing. Inside a good answer, an update that cannot be read or whose press has a field
// out of its form is dropped (no decision can come from it) but still confirmed by the returned offset (max update_id + 1,
// never below offset). An update without a usable update_id (missing, negative, 2^62 or more) cannot be confirmed: when the
// answer has one and moves the offset nowhere, it is an error, because asking again would only return the same answer.
func ParseTelegramUpdates(body []byte, offset int64) ([]Callback, int64, error) {
	if len(body) > maxUpdatesBody {
		return nil, offset, &ProviderError{Channel: Telegram, Reason: "the updates answer is too big"}
	}
	var env struct {
		OK          bool              `json:"ok"`
		Result      []json.RawMessage `json:"result"`
		Description string            `json:"description"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, offset, &ProviderError{Channel: Telegram, Reason: "the updates answer could not be read"}
	}
	if !env.OK || env.Result == nil {
		return nil, offset, &ProviderError{Channel: Telegram, Reason: "the updates answer was not ok: " + reasonFrom([]byte(env.Description))}
	}
	if len(env.Result) > maxUpdates {
		return nil, offset, &ProviderError{Channel: Telegram, Reason: "the updates answer has too many updates"}
	}
	next := offset
	var out []Callback
	unconfirmable := 0
	for _, raw := range env.Result {
		var u tgUpdate
		if err := json.Unmarshal(raw, &u); err != nil {
			var id struct { // the update may still name itself: confirm it so it is not read again
				UpdateID *int64 `json:"update_id"`
			}
			if json.Unmarshal(raw, &id) != nil {
				id.UpdateID = nil
			}
			u = tgUpdate{UpdateID: id.UpdateID}
		}
		if u.UpdateID == nil || *u.UpdateID < 0 || *u.UpdateID >= 1<<62 {
			unconfirmable++
			continue
		}
		if *u.UpdateID+1 > next {
			next = *u.UpdateID + 1
		}
		if cb, ok := checkCallback(*u.UpdateID, u); ok {
			out = append(out, cb)
		}
	}
	if unconfirmable > 0 && next == offset {
		return nil, offset, &ProviderError{Channel: Telegram, Reason: "the updates answer has updates that cannot be confirmed"}
	}
	return out, next, nil
}

// checkCallback returns the press of an update: ok=false when there is none or its query id cannot be used to answer it;
// Invalid when it can be answered but any other field is out of form.
func checkCallback(id int64, u tgUpdate) (Callback, bool) {
	q := u.CallbackQuery
	if q == nil || !telegramQueryRE.MatchString(q.ID) {
		return Callback{}, false
	}
	invalid := Callback{UpdateID: id, QueryID: q.ID, Invalid: true}
	if q.From == nil || q.From.IsBot || q.Message == nil || q.Message.Chat == nil || q.Data == nil {
		return invalid, true // a press on an inline message has no chat: it cannot be checked against the configured one
	}
	from, chat, user := string(q.From.ID), string(q.Message.Chat.ID), q.Message.Chat.Username
	if !telegramFromRE.MatchString(from) || !telegramChatIDRE.MatchString(chat) ||
		(user != "" && !telegramUserRE.MatchString(user)) || len(*q.Data) > maxCallbackData || !callbackDataRE.MatchString(*q.Data) {
		return invalid, true
	}
	return Callback{UpdateID: id, QueryID: q.ID, FromID: from, ChatID: chat, ChatUsername: user, Data: *q.Data}, true
}
