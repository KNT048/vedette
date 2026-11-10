package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Channel types in the order the API lists them.
var channelTypes = []channel.Type{channel.Telegram, channel.Slack, channel.Zalo, channel.ZaloPersonal, channel.Email, channel.Webhook}

// errSecretUnreadable means a saved secret cannot be opened (the key file changed, the row is damaged): say so, do not print why.
var errSecretUnreadable = errors.New("notify: the saved key cannot be read")

// Purposes of the secrets (core_secret.purpose).
const (
	purposeSecret   = "notify_channel.secret"
	purposeAppToken = "notify_channel.app_token"
	purposeBotToken = "notify_channel.bot_token"
)

// savedFields lists the non-secret fields kept per channel type; anything else the client sends is dropped.
var savedFields = map[channel.Type][]string{
	channel.Telegram:     {"chat_id"},
	channel.Slack:        {"label", "channel_id"},
	channel.Zalo:         {"oa_id", "user_id"},
	channel.ZaloPersonal: {"user_id", "group"},
	channel.Email:        {"host", "port", "security", "username", "from", "to"},
	channel.Webhook:      {"url"},
}

// approverAddr is the address format an approver must have on a channel; a channel without an entry
// cannot take approvals (D-46: Zalo OA and webhook send a link that opens Vedette instead).
var approverAddr = map[channel.Type]struct {
	re  *regexp.Regexp
	msg string
}{
	channel.Slack:        {regexp.MustCompile(`^[UW][A-Z0-9]{8,12}$`), "A Slack member ID looks like U04ABCD1234 (Profile, More, Copy member ID)."},
	channel.Telegram:     {regexp.MustCompile(`^\d{5,15}$`), "A Telegram user ID is a number of 5 to 15 digits. A bot such as @userinfobot can show it."},
	channel.ZaloPersonal: {regexp.MustCompile(`^(\d{6,25}|\+?84\d{9}|0\d{9})$`), "Enter the approver Zalo user ID (digits) or the phone number registered on Zalo."},
}

const emailApproverMsg = "An approver email is not valid, for example name@company.com."

var (
	slackChannelIDRE = regexp.MustCompile(`^[CGD][A-Z0-9]{8,12}$`)
	slackAppTokenRE  = regexp.MustCompile(`^xapp-[\w-]{10,}$`)
	slackBotTokenRE  = regexp.MustCompile(`^xoxb-[\w-]{10,}$`)
)

// channelRow is a notify_channel row.
type channelRow struct {
	Type                  channel.Type
	Configured, Enabled   bool
	Fields                map[string]string
	SecretID, SecretLast4 string
	AppID, AppLast4       string
	BotID, BotLast4       string
	MinSeverity           Severity
	Approvals             bool
	LastTest              *TestResult
	Rev                   int64
}

const channelCols = `type, configured, enabled, fields, secret_id, secret_last4, app_token_secret_id, app_token_last4,
	bot_token_secret_id, bot_token_last4, min_severity, approvals, last_test, rev`

type scanner interface{ Scan(dest ...any) error }

func scanChannel(r scanner) (channelRow, error) {
	var c channelRow
	var fields string
	var sid, sl4, aid, al4, bid, bl4, lt sql.NullString
	var sev string
	if err := r.Scan(&c.Type, &c.Configured, &c.Enabled, &fields, &sid, &sl4, &aid, &al4, &bid, &bl4, &sev, &c.Approvals, &lt, &c.Rev); err != nil {
		return c, err
	}
	c.SecretID, c.SecretLast4, c.AppID, c.AppLast4, c.BotID, c.BotLast4 = sid.String, sl4.String, aid.String, al4.String, bid.String, bl4.String
	c.MinSeverity = Severity(sev)
	if err := json.Unmarshal([]byte(fields), &c.Fields); err != nil {
		return c, fmt.Errorf("notify: channel %s: stored fields: %w", c.Type, err)
	}
	if c.Fields == nil {
		c.Fields = map[string]string{}
	}
	if lt.Valid {
		c.LastTest = new(TestResult)
		if err := json.Unmarshal([]byte(lt.String), c.LastTest); err != nil {
			return c, fmt.Errorf("notify: channel %s: stored last test: %w", c.Type, err)
		}
	}
	return c, nil
}

func blankChannel(t channel.Type) channelRow {
	return channelRow{Type: t, Fields: map[string]string{}, MinSeverity: Medium}
}

// loadChannel returns the row of t, or a blank one when it was never saved.
func loadChannel(ctx context.Context, q dbtx, t channel.Type) (channelRow, error) {
	c, err := scanChannel(q.QueryRowContext(ctx, `SELECT `+channelCols+` FROM notify_channel WHERE type = ?`, string(t)))
	if errors.Is(err, sql.ErrNoRows) {
		return blankChannel(t), nil
	}
	if err != nil {
		return c, fmt.Errorf("notify: load channel %s: %w", t, err)
	}
	return c, nil
}

func loadApprovers(ctx context.Context, q dbtx, t channel.Type) ([]Approver, error) {
	rows, err := q.QueryContext(ctx, `SELECT user_id, address FROM notify_approver WHERE channel_type = ? ORDER BY rowid`, string(t))
	if err != nil {
		return nil, fmt.Errorf("notify: load approvers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Approver{}
	for rows.Next() {
		var a Approver
		if err := rows.Scan(&a.UserID, &a.Address); err != nil {
			return nil, fmt.Errorf("notify: load approvers: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (c channelRow) view(approvers []Approver) Channel {
	if approvers == nil {
		approvers = []Approver{}
	}
	return Channel{
		Type: c.Type, Configured: c.Configured, Enabled: c.Enabled, Fields: c.Fields, SecretLast4: ptr(c.SecretLast4),
		MinSeverity: c.MinSeverity, LastTest: c.LastTest, Approvals: c.Approvals, Approvers: approvers,
		ApprovalLast4: ApprovalLast4{AppToken: ptr(c.AppLast4), BotToken: ptr(c.BotLast4)},
	}
}

// Channels returns the six channels, the rules and the number of two-step email users (GET /notify/channels).
func (s *Service) Channels(ctx context.Context) (ChannelsView, error) {
	db := s.cfg.DB.Reader()
	out := ChannelsView{Channels: make([]Channel, 0, len(channelTypes))}
	for _, t := range channelTypes {
		c, err := loadChannel(ctx, db, t)
		if err != nil {
			return out, err
		}
		ap, err := loadApprovers(ctx, db, t)
		if err != nil {
			return out, err
		}
		out.Channels = append(out.Channels, c.view(ap))
	}
	r, err := loadRules(ctx, db)
	if err != nil {
		return out, err
	}
	out.Quiet, out.Grouping = r.Quiet, r.Grouping
	if out.EmailCodeUsers, err = s.cfg.Users.EmailCodeUsers(ctx); err != nil {
		return out, fmt.Errorf("notify: count email code users: %w", err)
	}
	return out, nil
}

// apiConfigCode maps the adapters' codes to the ones in API_CONVENTIONS 3.3 (the four the adapters add
// have no row there yet: they share the code of the field that has to change).
var apiConfigCode = map[string]string{"blocked_host": "bad_url", "insecure_url": "bad_url", "insecure_smtp": "bad_security", "bad_session": "bad_secret"}

// configAPIError turns an adapter's *ConfigError into a 400, and unknown box addresses (#157) into 503 host_unreachable (the
// box addresses come from vedette-host: retry later); other errors pass through.
func configAPIError(err error) error {
	if errors.Is(err, channel.ErrBoxAddrsUnknown) {
		return apierr.New(http.StatusServiceUnavailable, "host_unreachable",
			"Vedette does not know this box's own network addresses yet, so the webhook cannot be checked. Try again in a minute.")
	}
	var ce *channel.ConfigError
	if !errors.As(err, &ce) {
		return err
	}
	code := ce.Code
	if m, ok := apiConfigCode[code]; ok {
		code = m
	}
	return apierr.New(http.StatusBadRequest, code, ce.Msg)
}

func badRequest(code, msg string) *apierr.Error { return apierr.New(http.StatusBadRequest, code, msg) }

// newSender builds the adapter of type t from stored fields and the plain secret. toOverride replaces
// the recipients of an email channel (two-step codes go to one person, not to the alert list).
func (s *Service) newSender(t channel.Type, f map[string]string, secret string, toOverride []string) (channel.Sender, error) {
	sv := secrets.NewValue(secret)
	hc := s.cfg.HTTPClient
	switch t {
	case channel.Telegram:
		return channel.NewTelegram(channel.TelegramConfig{Token: sv, ChatID: f["chat_id"], Client: hc})
	case channel.Slack:
		return channel.NewSlack(channel.SlackConfig{Webhook: sv, Label: f["label"], Client: hc})
	case channel.Zalo:
		return channel.NewZalo(channel.ZaloConfig{OAID: f["oa_id"], UserID: f["user_id"], Token: sv, Client: hc})
	case channel.ZaloPersonal:
		return channel.NewZaloPersonal(channel.ZaloPersonalConfig{UserID: f["user_id"], Group: f["group"] == "true", Session: sv, Client: hc})
	case channel.Email:
		port, err := strconv.Atoi(strings.TrimSpace(f["port"]))
		if err != nil {
			return nil, &channel.ConfigError{Code: "bad_port", Msg: "The SMTP port is a number from 1 to 65535 (usually 587 or 465)."}
		}
		to := toOverride
		if to == nil {
			if to, err = channel.ParseRecipients(f["to"]); err != nil {
				return nil, err
			}
		}
		return channel.NewEmail(channel.EmailConfig{Host: f["host"], Port: port, Security: f["security"], Username: f["username"],
			Password: sv, From: f["from"], To: to, Now: s.now})
	case channel.Webhook:
		return channel.NewWebhook(channel.WebhookConfig{URL: secrets.NewValue(f["url"]), SigningKey: sv, BoxAddrsFunc: s.boxAddrs, Client: s.webhookClient, Now: s.now})
	}
	return nil, fmt.Errorf("notify: unknown channel type %q", t)
}

// openSecret reads the stored secret of a channel (purpose notify_channel.secret); a failure means the saved key cannot be
// used, which callers show as "enter it again". The Slack app and bot tokens are never opened here.
func (s *Service) openSecret(ctx context.Context, q dbtx, id string) (string, error) {
	if id == "" {
		return "", nil
	}
	pt, err := s.cfg.Secrets.Open(ctx, q, id, purposeSecret)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "notify: a saved channel secret cannot be opened", "purpose", purposeSecret, "error", err.Error())
		return "", errSecretUnreadable
	}
	return string(pt), nil
}

// savedSender returns the sender of a configured channel, cached until the channel changes. The cache
// matters for Zalo personal, whose adapter keeps the signed-in session and the sign-in pause.
func (s *Service) savedSender(ctx context.Context, c channelRow, toOverride []string) (channel.Sender, error) {
	if toOverride == nil {
		s.mu.Lock()
		cs, ok := s.senders[c.Type]
		s.mu.Unlock()
		if ok && cs.rev == c.Rev {
			return cs.sender, nil
		}
	}
	secret, err := s.openSecret(ctx, s.cfg.DB.Reader(), c.SecretID)
	if err != nil {
		return nil, err
	}
	snd, err := s.newSender(c.Type, c.Fields, secret, toOverride)
	if err != nil {
		return nil, err
	}
	if toOverride == nil {
		s.mu.Lock()
		s.senders[c.Type] = cachedSender{rev: c.Rev, sender: snd}
		s.mu.Unlock()
	}
	return snd, nil
}

func (s *Service) forget(t channel.Type) {
	s.mu.Lock()
	delete(s.senders, t)
	s.mu.Unlock()
}

// checkApprovers implements INV-7 for the list a client sent.
func (s *Service) checkApprovers(ctx context.Context, t channel.Type, in ChannelInput) error {
	if !in.Approvals {
		return nil
	}
	rule, ok := approverAddr[t]
	if !ok && t != channel.Email {
		return badRequest("approvals_unsupported", "This channel cannot take approvals. It sends a link that opens Vedette instead.")
	}
	if len(in.Approvers) == 0 {
		return badRequest("approvers_required", `Add at least one approver, or turn off "Approve actions from this channel".`)
	}
	seen := map[string]bool{}
	for _, a := range in.Approvers {
		u, found, err := s.cfg.Users.Lookup(ctx, a.UserID)
		if err != nil {
			return fmt.Errorf("notify: look up approver: %w", err)
		}
		if !found || !u.Active {
			return badRequest("no_such_user", "One of the approvers does not exist or is disabled.")
		}
		if u.Role != "operator" && u.Role != "admin" {
			return badRequest("viewer_not_allowed", u.Email+" is a viewer. Only operators and administrators can approve actions.")
		}
		if seen[u.ID] {
			return badRequest("duplicate_user", u.Email+" is listed twice.")
		}
		seen[u.ID] = true
		addr := strings.TrimSpace(a.Address)
		if t == channel.Email {
			if list, err := channel.ParseRecipients(addr); err != nil || len(list) != 1 || list[0] != addr {
				return badRequest("bad_approver_address", u.Email+": "+emailApproverMsg)
			}
			if !strings.EqualFold(addr, u.Email) { // the link is for this person: it goes to the address they sign in with
				return badRequest("bad_approver_address", u.Email+": the approval link goes to the sign-in email of the user, "+u.Email+".")
			}
		} else if !rule.re.MatchString(addr) {
			return badRequest("bad_approver_address", u.Email+": "+rule.msg)
		}
	}
	return nil
}

// SaveChannel stores the configuration of one channel (PUT /notify/channels/{type}, PRE-3, INV-1, INV-7, INV-8).
// An empty Secret, AppToken or BotToken keeps the saved one. Errors are *apierr.Error.
func (s *Service) SaveChannel(ctx context.Context, actor string, t channel.Type, in ChannelInput) (Channel, error) {
	if !in.MinSeverity.Valid() || in.MinSeverity == Info {
		return Channel{}, badRequest("bad_severity", "Choose a minimum severity: Critical, High, Medium or Low.")
	}
	if err := s.checkApprovers(ctx, t, in); err != nil {
		return Channel{}, err
	}
	var out Channel
	ob := &events.Outbox{}
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		cur, err := loadChannel(ctx, tx, t)
		if err != nil {
			return err
		}
		fields := map[string]string{}
		for _, k := range savedFields[t] {
			fields[k] = strings.TrimSpace(in.Fields[k])
		}
		if !in.Approvals {
			delete(fields, "channel_id")
		}
		if g, ok := fields["group"]; ok && g != "true" {
			delete(fields, "group")
		}
		secret := strings.TrimSpace(in.Secret)
		effective := secret
		if effective == "" {
			if effective, err = s.openSecret(ctx, tx, cur.SecretID); err != nil {
				return badRequest("secret_required", "The saved key cannot be read. Enter it again and save.")
			}
		}
		if _, err := s.newSender(t, fields, effective, nil); err != nil {
			return configAPIError(err)
		}
		if t == channel.Email {
			list, _ := channel.ParseRecipients(fields["to"]) // validated by newSender
			fields["to"] = strings.Join(list, ", ")
		}
		app, bot := strings.TrimSpace(in.AppToken), strings.TrimSpace(in.BotToken)
		if t == channel.Slack { // a token that is sent is checked even when approvals are off
			if app != "" && !slackAppTokenRE.MatchString(app) {
				return badRequest("bad_app_token", "The app-level token starts with xapp- and needs the connections:write scope. Copy it again from Basic Information.")
			}
			if bot != "" && !slackBotTokenRE.MatchString(bot) {
				return badRequest("bad_bot_token", "The bot token starts with xoxb-. Copy it from OAuth & Permissions after installing the app.")
			}
		}
		if t == channel.Slack && in.Approvals {
			if !slackChannelIDRE.MatchString(fields["channel_id"]) {
				return badRequest("bad_channel_id", "A Slack channel ID looks like C04ABCDEF12. Open the channel details in Slack and copy the ID at the bottom.")
			}
			if app == "" && cur.AppID == "" {
				return badRequest("secret_required", "Enter the app-level token (xapp-…). Approving in Slack needs Socket Mode.")
			}
			if bot == "" && cur.BotID == "" {
				return badRequest("secret_required", "Enter the bot token (xoxb-…). Approving in Slack needs it to read button presses and reply.")
			}
		}
		next := cur
		next.Configured, next.Enabled, next.Fields, next.MinSeverity, next.Approvals, next.LastTest = true, in.Enabled, fields, in.MinSeverity, in.Approvals, nil
		if secret != "" {
			if next.SecretID, next.SecretLast4, err = s.putSecret(ctx, tx, purposeSecret, cur.SecretID, secret); err != nil {
				return err
			}
		}
		if t == channel.Slack {
			if app != "" {
				if next.AppID, next.AppLast4, err = s.putSecret(ctx, tx, purposeAppToken, cur.AppID, app); err != nil {
					return err
				}
			}
			if bot != "" {
				if next.BotID, next.BotLast4, err = s.putSecret(ctx, tx, purposeBotToken, cur.BotID, bot); err != nil {
					return err
				}
			}
		}
		fj, err := json.Marshal(fields)
		if err != nil {
			return fmt.Errorf("notify: encode fields: %w", err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO notify_channel (`+channelCols+`, updated_at) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
			ON CONFLICT (type) DO UPDATE SET configured = 1, enabled = excluded.enabled, fields = excluded.fields, secret_id = excluded.secret_id,
			secret_last4 = excluded.secret_last4, app_token_secret_id = excluded.app_token_secret_id, app_token_last4 = excluded.app_token_last4,
			bot_token_secret_id = excluded.bot_token_secret_id, bot_token_last4 = excluded.bot_token_last4, min_severity = excluded.min_severity,
			approvals = excluded.approvals, last_test = NULL, rev = notify_channel.rev + 1, updated_at = excluded.updated_at`,
			string(t), boolInt(next.Enabled), string(fj), nullable(next.SecretID), nullable(next.SecretLast4), nullable(next.AppID), nullable(next.AppLast4),
			nullable(next.BotID), nullable(next.BotLast4), string(next.MinSeverity), boolInt(next.Approvals), cur.Rev+1, store.FormatTS(s.now()))
		if err != nil {
			return fmt.Errorf("notify: save channel %s: %w", t, err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM notify_approver WHERE channel_type = ?`, string(t)); err != nil {
			return fmt.Errorf("notify: save approvers: %w", err)
		}
		approvers := []Approver{}
		if in.Approvals {
			for _, a := range in.Approvers {
				a.Address = strings.TrimSpace(a.Address)
				if _, err := tx.ExecContext(ctx, `INSERT INTO notify_approver (channel_type, user_id, address) VALUES (?, ?, ?)`, string(t), a.UserID, a.Address); err != nil {
					return fmt.Errorf("notify: save approvers: %w", err)
				}
				approvers = append(approvers, a)
			}
		}
		detail := "off"
		if next.Enabled {
			detail = "on"
		}
		if in.Approvals {
			detail += fmt.Sprintf(", approvals on (%d approver%s)", len(approvers), map[bool]string{true: "", false: "s"}[len(approvers) == 1])
		}
		if err := s.record(ctx, tx, actor, "notify.channel_save", string(t), detail); err != nil {
			return err
		}
		ob.Add(events.Event{Name: "notify.channel.changed", Data: map[string]string{"type": string(t)}})
		out = next.view(approvers)
		return nil
	})
	if err != nil {
		return Channel{}, err
	}
	s.forget(t)
	s.flush(ctx, ob)
	return out, nil
}

// putSecret seals plaintext as a new secret, or replaces the one id. It returns the id and the last 4 characters ("" when too short to show).
//
// The last 4 characters are kept here, from the plaintext, not taken from core/secrets: core shows none for a short
// secret, and the settings page shows four for every saved secret (contract.ts). The secrets notify validates are far longer than four characters.
func (s *Service) putSecret(ctx context.Context, tx *sql.Tx, purpose, id, plaintext string) (newID, last4 string, err error) {
	if id == "" {
		newID, _, err = s.cfg.Secrets.Seal(ctx, tx, purpose, []byte(plaintext), true)
	} else {
		_, err = s.cfg.Secrets.Replace(ctx, tx, id, purpose, []byte(plaintext), true)
		newID = id
	}
	return newID, lastFour(plaintext), err
}

func lastFour(s string) string {
	r := []rune(s)
	if len(r) < 4 {
		return ""
	}
	return string(r[len(r)-4:])
}

// DeleteChannel removes the saved configuration and every secret of a channel, and with them a Zalo
// personal session (INV-12). The row stays, blank, so the API still lists six channels.
func (s *Service) DeleteChannel(ctx context.Context, actor string, t channel.Type) error {
	ob := &events.Outbox{}
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		cur, err := loadChannel(ctx, tx, t)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notify_channel (type, updated_at) VALUES (?, ?)
			ON CONFLICT (type) DO UPDATE SET configured = 0, enabled = 0, fields = '{}', secret_id = NULL, secret_last4 = NULL, app_token_secret_id = NULL,
			app_token_last4 = NULL, bot_token_secret_id = NULL, bot_token_last4 = NULL, min_severity = 'medium', approvals = 0, last_test = NULL,
			rev = notify_channel.rev + 1, updated_at = excluded.updated_at`, string(t), store.FormatTS(s.now())); err != nil {
			return fmt.Errorf("notify: reset channel %s: %w", t, err)
		}
		for _, id := range []string{cur.SecretID, cur.AppID, cur.BotID} {
			if id == "" {
				continue
			}
			if err := s.cfg.Secrets.Delete(ctx, tx, id); err != nil {
				return fmt.Errorf("notify: delete secret of %s: %w", t, err)
			}
		}
		for _, q := range []string{`DELETE FROM notify_approver WHERE channel_type = ?`, `DELETE FROM notify_pending WHERE channel = ?`} {
			if _, err := tx.ExecContext(ctx, q, string(t)); err != nil {
				return fmt.Errorf("notify: clear channel %s: %w", t, err)
			}
		}
		if err := s.record(ctx, tx, actor, "notify.channel_remove", string(t), "configuration and saved key deleted"); err != nil {
			return err
		}
		ob.Add(events.Event{Name: "notify.channel.changed", Data: map[string]string{"type": string(t)}})
		return nil
	})
	if err != nil {
		return err
	}
	s.forget(t)
	s.flush(ctx, ob)
	return nil
}

// userText is the text of err for people (see friendlyError): never the raw error of an adapter or a server.
func userText(err error) string { return friendlyError(err) }

const testTimeout = 45 * time.Second

// TestChannel sends a test message through the saved channel and records the result as last_test (INV-11).
// The result is not a history row: History lists incidents, vulnerabilities and approvals only.
func (s *Service) TestChannel(ctx context.Context, actor string, t channel.Type) (TestResult, error) {
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), t)
	if err != nil {
		return TestResult{}, err
	}
	if !c.Configured {
		return TestResult{}, badRequest("not_configured", "This channel has no saved configuration. Enter and save it before sending a test.")
	}
	res := TestResult{OK: false}
	snd, err := s.savedSender(ctx, c, nil)
	if err != nil {
		res.Detail = "The saved settings cannot be used: " + userText(err) + " Save the channel again."
	} else {
		tctx, cancel := context.WithTimeout(ctx, testTimeout)
		rcpt, err := snd.Send(tctx, channel.Message{ID: store.NewID("test"), Kind: "test", Severity: string(Info), Title: "Test message from Vedette",
			What: "If you can read this, this channel works. Nobody needs to do anything.", Link: s.link("/settings")})
		cancel()
		if err != nil {
			res.Detail = userText(err)
		} else {
			res.OK, res.Detail = true, rcpt.Detail
		}
	}
	ctx, stop := detached(ctx) // the result is written even when the request ended meanwhile
	defer stop()
	res.At = store.FormatTS(s.now())
	lt, err := json.Marshal(res)
	if err != nil {
		return res, fmt.Errorf("notify: encode test result: %w", err)
	}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		// rev is not bumped: a test does not change what is sent
		r, err := tx.ExecContext(ctx, `UPDATE notify_channel SET last_test = ? WHERE type = ? AND rev = ?`, string(lt), string(t), c.Rev)
		if err != nil {
			return fmt.Errorf("notify: save test result: %w", err)
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return nil // the channel was saved or deleted meanwhile: the result belongs to the old settings
		}
		out := "ok"
		if !res.OK {
			out = "failed"
		}
		return s.record(ctx, tx, actor, "notify.channel_test", string(t), out)
	})
	if err != nil {
		return res, err
	}
	return res, nil
}

// ---- rules ----

var (
	defaultQuiet    = Quiet{Enabled: false, From: "22:00", To: "06:30", AllowCritical: true}
	defaultGrouping = Grouping{Enabled: true, WindowMin: 60}
)

func loadRules(ctx context.Context, q dbtx) (Rules, error) {
	r := Rules{Quiet: defaultQuiet, Grouping: defaultGrouping}
	rows, err := q.QueryContext(ctx, `SELECT key, value FROM notify_setting`)
	if err != nil {
		return r, fmt.Errorf("notify: load rules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return r, fmt.Errorf("notify: load rules: %w", err)
		}
		switch k {
		case "quiet":
			err = json.Unmarshal([]byte(v), &r.Quiet)
		case "grouping":
			err = json.Unmarshal([]byte(v), &r.Grouping)
		}
		if err != nil {
			return r, fmt.Errorf("notify: stored rule %s: %w", k, err)
		}
	}
	return r, rows.Err()
}

// SaveRules stores quiet hours and grouping (PUT /notify/rules, INV-3, INV-5).
func (s *Service) SaveRules(ctx context.Context, actor string, r Rules) (Rules, error) {
	if _, err := minutes(r.Quiet.From); err != nil {
		return r, badRequest("bad_time", "Enter quiet hours like 22:00.")
	}
	if _, err := minutes(r.Quiet.To); err != nil {
		return r, badRequest("bad_time", "Enter quiet hours like 22:00.")
	}
	if r.Quiet.Validate() != nil {
		return r, badRequest("bad_quiet", "The start and end times must not be the same.")
	}
	if r.Grouping.Validate() != nil {
		return r, badRequest("bad_window", "The grouping window must be 15, 60 or 240 minutes.")
	}
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for k, v := range map[string]any{"quiet": r.Quiet, "grouping": r.Grouping} {
			j, err := json.Marshal(v)
			if err != nil {
				return fmt.Errorf("notify: encode rule %s: %w", k, err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO notify_setting (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
				ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
				k, string(j), store.FormatTS(s.now()), actor); err != nil {
				return fmt.Errorf("notify: save rule %s: %w", k, err)
			}
		}
		return s.record(ctx, tx, actor, "notify.rules_save", "quiet hours and grouping", "")
	})
	return r, err
}
