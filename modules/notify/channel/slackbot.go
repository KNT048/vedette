package channel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/knt048/vedette/core/secrets"
)

// The Slack side of approvals (spec approval-tokens.md 5, D-38, slice 3): the box posts the approval message with Block Kit
// buttons using the bot token (chat.postMessage), opens a Socket Mode connection OUT with the app token (apps.connections.open,
// a wss URL), and reads button presses from it. No inbound port. Everything Slack sends is untrusted input: an envelope is size
// capped, decoded fail-closed, and a press whose fields are out of their documented form is "invalid" (acked, never decided).

const (
	slackAPI           = "https://slack.com/api"
	maxSlackEnvelope   = 256 << 10 // a block_actions envelope carries the message blocks
	slackEnvelopeIDMax = 64
	slackAnswerMax     = 300 // runes of a private reply
	slackAckWait       = 3 * time.Second
	slackDialWait      = 15 * time.Second
)

// Action ids of the Approve and Reject buttons.
const (
	SlackApproveAction = "vedette_a"
	SlackRejectAction  = "vedette_r"
)

var (
	slackEnvelopeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	slackTeamRE     = regexp.MustCompile(`^T[A-Z0-9]{6,20}$`)
	slackUserRE     = regexp.MustCompile(`^[UW][A-Z0-9]{8,12}$`)
	slackChannelRE  = regexp.MustCompile(`^[CGD][A-Z0-9]{8,12}$`)
	slackTSRE       = regexp.MustCompile(`^[0-9]{10}\.[0-9]{6}$`)
	slackRespPathRE = regexp.MustCompile(`^/actions/[A-Za-z0-9_/-]{1,200}$`)
	slackValueRE    = regexp.MustCompile(`^[ar]:[A-Za-z0-9_.:@+-]{1,128}$`)
)

// SlackBot posts approval messages and opens Socket Mode connections. Its API address is fixed (a configurable one would ship the
// tokens anywhere); tests reach it with a client whose transport rewrites the address. Printing it prints a fixed string.
type SlackBot struct {
	noPrint
	bot, app secrets.Value
	client   *http.Client
}

// NewSlackBot checks the token forms. bot or app may be empty when only the other half is used. client nil = a client without
// redirects.
func NewSlackBot(bot, app secrets.Value, client *http.Client) (*SlackBot, error) {
	b, a := strings.TrimSpace(bot.Reveal()), strings.TrimSpace(app.Reveal())
	if b != "" && !strings.HasPrefix(b, "xoxb-") {
		return nil, cfgErr("bad_bot_token", "The bot token starts with xoxb-. Copy it from OAuth & Permissions after installing the app.")
	}
	if a != "" && !strings.HasPrefix(a, "xapp-") {
		return nil, cfgErr("bad_app_token", "The app-level token starts with xapp- and needs the connections:write scope. Copy it again from Basic Information.")
	}
	c := clientOrDefault(client)
	return &SlackBot{bot: secrets.NewValue(b), app: secrets.NewValue(a), client: c}, nil
}

// call posts one Web API method. form=true sends an empty form body (apps.connections.open and auth.test take no JSON).
func (b *SlackBot) call(ctx context.Context, token secrets.Value, method string, args any, form bool) (map[string]json.RawMessage, error) {
	var body *bytes.Reader
	ctype := "application/json; charset=utf-8"
	if form {
		body, ctype = bytes.NewReader(nil), "application/x-www-form-urlencoded"
	} else {
		j, err := json.Marshal(args)
		if err != nil {
			return nil, fmt.Errorf("notify: slack: encode %s: %w", method, err)
		}
		body = bytes.NewReader(j)
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, slackAPI+"/"+method, body)
	if err != nil {
		return nil, fmt.Errorf("notify: slack: build request: %s", transportReason(err, []secrets.Value{token}))
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Authorization", "Bearer "+token.Reveal())
	code, ans, err := do(b.client, Slack, req, token)
	if err != nil {
		return nil, err
	}
	if code < 200 || code > 299 {
		return nil, statusErr(Slack, code, ans, token)
	}
	var env map[string]json.RawMessage
	if json.Unmarshal(ans, &env) != nil {
		return nil, &ProviderError{Channel: Slack, Reason: "the answer could not be read"}
	}
	var ok bool
	if json.Unmarshal(env["ok"], &ok) != nil || !ok {
		var why string
		_ = json.Unmarshal(env["error"], &why)
		return nil, &ProviderError{Channel: Slack, Reason: reasonFrom([]byte(why), token)}
	}
	return env, nil
}

func strField(env map[string]json.RawMessage, k string) string {
	var s string
	if json.Unmarshal(env[k], &s) != nil {
		return ""
	}
	return s
}

// AuthTest returns the id of the workspace the bot token belongs to (auth.test).
func (b *SlackBot) AuthTest(ctx context.Context) (string, error) {
	env, err := b.call(ctx, b.bot, "auth.test", nil, true)
	if err != nil {
		return "", err
	}
	id := strField(env, "team_id")
	if !slackTeamRE.MatchString(id) {
		return "", &ProviderError{Channel: Slack, Reason: "the workspace id has an unexpected form"}
	}
	return id, nil
}

// OpenConnection asks for a Socket Mode URL with the app token and returns it only when it is one Slack hosts (checkSocketURL).
func (b *SlackBot) OpenConnection(ctx context.Context) (string, error) {
	env, err := b.call(ctx, b.app, "apps.connections.open", nil, true)
	if err != nil {
		return "", err
	}
	u := strField(env, "url")
	if err := checkSocketURL(u); err != nil {
		return "", err
	}
	return u, nil
}

// checkSocketURL accepts only wss://wss-primary.slack.com or wss-backup.slack.com (exact host, no suffix matching), port 443 or
// none, no user info, path /link…. The URL carries a ticket, so nothing here repeats it.
func checkSocketURL(raw string) error {
	bad := &ProviderError{Channel: Slack, Reason: "Slack gave a connection address that is not Slack's"}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "wss" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") ||
		!(strings.HasPrefix(u.Path, "/link") && !strings.Contains(u.Path, "..")) {
		return bad
	}
	switch strings.ToLower(u.Hostname()) {
	case "wss-primary.slack.com", "wss-backup.slack.com":
		return nil
	}
	return bad
}

// SlackConn is one Socket Mode connection.
type SlackConn struct {
	c      *websocket.Conn
	ticket secrets.Value
}

// Dial connects to a URL that OpenConnection returned. Redirects are refused. Errors never carry the URL.
func (b *SlackBot) Dial(ctx context.Context, wssURL string) (*SlackConn, error) {
	if err := checkSocketURL(wssURL); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, slackDialWait)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wssURL, &websocket.DialOptions{HTTPClient: b.client})
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return nil, context.Canceled
		case errors.Is(err, context.DeadlineExceeded):
			return nil, &ProviderError{Channel: Slack, Reason: "timed out connecting to Slack"}
		}
		return nil, &ProviderError{Channel: Slack, Reason: "could not connect to Slack"} // the text of err holds the URL and its ticket
	}
	c.SetReadLimit(maxSlackEnvelope)
	return &SlackConn{c: c}, nil
}

// Read waits for the next envelope. A frame that is too big or not text ends the connection (the library closes it).
func (c *SlackConn) Read(ctx context.Context) (SlackEnvelope, error) {
	typ, b, err := c.c.Read(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return SlackEnvelope{}, ctx.Err()
		}
		return SlackEnvelope{}, &ProviderError{Channel: Slack, Reason: "the connection to Slack ended"}
	}
	if typ != websocket.MessageText {
		return SlackEnvelope{Kind: SlackOther}, nil
	}
	return ParseSlackEnvelope(b), nil
}

// Ack acknowledges an envelope (Slack wants it within 3 seconds, or it sends the press again).
func (c *SlackConn) Ack(ctx context.Context, envelopeID string) error {
	if !slackEnvelopeRE.MatchString(envelopeID) {
		return nil
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), slackAckWait)
	defer cancel()
	b, _ := json.Marshal(map[string]string{"envelope_id": envelopeID})
	if err := c.c.Write(actx, websocket.MessageText, b); err != nil {
		return &ProviderError{Channel: Slack, Reason: "the acknowledgement could not be sent"}
	}
	return nil
}

// Close ends the connection at once.
func (c *SlackConn) Close() { _ = c.c.CloseNow() }

// Kinds of envelope.
const (
	SlackHello      = "hello"
	SlackDisconnect = "disconnect"
	SlackPressKind  = "press"
	SlackOther      = "other"
)

// SlackPress is one button press after its fields were checked. When Invalid is set only ResponseURL (if it passed its check)
// is filled: the caller may answer it and must never decide from it. Nothing here is trusted yet: the caller still checks the
// team, channel, message and request.
type SlackPress struct {
	TeamID, UserID, ChannelID, TS string
	ResponseURL, RequestID        string
	Approve                       bool
	Invalid                       bool
}

// SlackEnvelope is one Socket Mode message: Kind, and for a press its EnvelopeID (empty when it is not usable to acknowledge).
type SlackEnvelope struct {
	Kind       string
	EnvelopeID string
	Press      SlackPress
}

// ParseSlackEnvelope reads one frame (fail-closed): anything that is not a documented block_actions press is hello, disconnect
// or other; a press with any field out of form, or without exactly one action of ours, is Invalid.
func ParseSlackEnvelope(b []byte) SlackEnvelope {
	if len(b) > maxSlackEnvelope {
		return SlackEnvelope{Kind: SlackOther}
	}
	var e struct {
		Type       string          `json:"type"`
		EnvelopeID string          `json:"envelope_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(b, &e) != nil {
		return SlackEnvelope{Kind: SlackOther}
	}
	id := e.EnvelopeID
	if !slackEnvelopeRE.MatchString(id) {
		id = ""
	}
	switch e.Type {
	case "hello":
		return SlackEnvelope{Kind: SlackHello}
	case "disconnect":
		return SlackEnvelope{Kind: SlackDisconnect}
	case "interactive":
		if id == "" {
			return SlackEnvelope{Kind: SlackOther}
		}
		return SlackEnvelope{Kind: SlackPressKind, EnvelopeID: id, Press: parseBlockActions(e.Payload)}
	}
	return SlackEnvelope{Kind: SlackOther, EnvelopeID: id}
}

type blockActions struct {
	Type string `json:"type"`
	Team *struct {
		ID string `json:"id"`
	} `json:"team"`
	User *struct {
		ID string `json:"id"`
	} `json:"user"`
	Channel *struct {
		ID string `json:"id"`
	} `json:"channel"`
	Container *struct {
		MessageTS string `json:"message_ts"`
		ChannelID string `json:"channel_id"`
	} `json:"container"`
	ResponseURL string `json:"response_url"`
	Actions     []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
	} `json:"actions"`
}

func parseBlockActions(raw json.RawMessage) SlackPress {
	var p blockActions
	if json.Unmarshal(raw, &p) != nil {
		return SlackPress{Invalid: true}
	}
	resp := ""
	if checkResponseURL(p.ResponseURL) == nil {
		resp = p.ResponseURL
	}
	invalid := SlackPress{Invalid: true, ResponseURL: resp}
	if p.Type != "block_actions" || p.Team == nil || p.User == nil || p.Channel == nil || p.Container == nil || len(p.Actions) != 1 {
		return invalid
	}
	a := p.Actions[0]
	var approve bool
	switch a.ActionID {
	case SlackApproveAction:
		approve = true
	case SlackRejectAction:
	default:
		return invalid
	}
	if !slackTeamRE.MatchString(p.Team.ID) || !slackUserRE.MatchString(p.User.ID) || !slackChannelRE.MatchString(p.Channel.ID) ||
		p.Container.ChannelID != p.Channel.ID || !slackTSRE.MatchString(p.Container.MessageTS) || !slackValueRE.MatchString(a.Value) ||
		(a.Value[0] == 'a') != approve {
		return invalid
	}
	return SlackPress{TeamID: p.Team.ID, UserID: p.User.ID, ChannelID: p.Channel.ID, TS: p.Container.MessageTS, ResponseURL: resp,
		RequestID: a.Value[2:], Approve: approve}
}

// checkResponseURL accepts only https://hooks.slack.com/actions/… : exact host, no port, no user info, no query or fragment, no "..".
func checkResponseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "hooks.slack.com" || u.Port() != "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || u.Opaque != "" || strings.Contains(u.Path, "..") || !slackRespPathRE.MatchString(u.Path) {
		return errors.New("notify: slack: the reply address is not Slack's")
	}
	return nil
}

// Respond answers a press privately (ephemeral, the original message is left as it is). responseURL must have passed the check of
// the parser; it is checked again here. text is escaped and cut to 300 characters.
func (b *SlackBot) Respond(ctx context.Context, responseURL, text string) error {
	if err := checkResponseURL(responseURL); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	j, _ := json.Marshal(map[string]any{"response_type": "ephemeral", "replace_original": false,
		"text": slackEscape(Line(text, slackAnswerMax))})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURL, bytes.NewReader(j))
	if err != nil {
		return fmt.Errorf("notify: slack: build reply: %s", transportReason(err, nil))
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	code, ans, err := do(b.client, Slack, req)
	if err != nil {
		return err
	}
	if code < 200 || code > 299 {
		return statusErr(Slack, code, ans)
	}
	return nil
}

// slackBotSender posts a message with chat.postMessage as the bot, so it can carry buttons and its ts can be kept.
type slackBotSender struct {
	noPrint
	bot       *SlackBot
	channelID string
}

// NewSlackApprovalSender returns the sender of approval messages with buttons: chat.postMessage with the bot token to channelID.
func NewSlackApprovalSender(bot *SlackBot, channelID string) (Sender, error) {
	if bot == nil || bot.bot.Reveal() == "" || !slackChannelRE.MatchString(channelID) {
		return nil, cfgErr("bad_channel_id", "A Slack channel ID looks like C04ABCDEF12. Open the channel details in Slack and copy the ID at the bottom.")
	}
	return &slackBotSender{bot: bot, channelID: channelID}, nil
}

func (*slackBotSender) Type() Type     { return Slack }
func (s *slackBotSender) Dest() string { return "Slack channel " + s.channelID }

func (s *slackBotSender) Send(ctx context.Context, m Message) (Receipt, error) {
	if err := m.check(); err != nil {
		return Receipt{}, err
	}
	link, _ := safeLink(m.Link)
	text := slackText(m.norm(), link)
	blocks := []any{map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": text}}}
	var elems []any
	for _, b := range m.Buttons {
		id, style := SlackRejectAction, "danger"
		switch {
		case strings.HasPrefix(b.Data, "a:"):
			id, style = SlackApproveAction, "primary"
		case !strings.HasPrefix(b.Data, "r:"):
			return Receipt{}, fmt.Errorf("%w: a Slack button is an approve or reject button", ErrInvalidMessage)
		}
		elems = append(elems, map[string]any{"type": "button", "text": map[string]any{"type": "plain_text", "text": Line(b.Text, maxButtonText)},
			"style": style, "action_id": id, "value": b.Data})
	}
	if len(elems) > 0 {
		blocks = append(blocks, map[string]any{"type": "actions", "block_id": "vedette_approval", "elements": elems})
	}
	env, err := s.bot.call(ctx, s.bot.bot, "chat.postMessage", map[string]any{"channel": s.channelID, "text": text, "mrkdwn": true,
		"blocks": blocks, "unfurl_links": false, "unfurl_media": false}, false)
	if err != nil {
		return Receipt{}, err
	}
	r := Receipt{To: s.Dest(), Detail: "Slack accepted the message (" + s.Dest() + ")."}
	// The ts and channel Slack names are kept only when they have their form; without them no button press can ever match.
	if ts, ch := strField(env, "ts"), strField(env, "channel"); slackTSRE.MatchString(ts) && slackChannelRE.MatchString(ch) {
		r.TS, r.ChatID = ts, ch
	}
	return r, nil
}
