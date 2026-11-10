package notify

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Approvals from Telegram buttons (PRE-8, POST-8, D-96 (5), D-135, docs/specs/approval-tokens.md 6). notify owns the line and the
// platform check; the response module maps the person and keeps every gate. The listener is the job "telegram-listen": it runs only
// while the module is on (the scheduler cancels it when the module is turned off) and only while the Telegram channel is configured,
// enabled, takes approvals and the Decisions port is wired; it long-polls getUpdates (a connection out, no inbound port, FORBID-4).

const (
	telegramListenJob   = "telegram-listen"
	telegramListenEvery = 30 * time.Second // the pause before the listener starts again after it stopped (not ready, or an error)
	telegramPollWait    = 25 * time.Second // one long poll
	telegramWorkers     = 4                // presses decided at once; more get "busy" (the response module limits each sender, D-135 (5))
	decideBudget        = 5 * time.Second  // Decide records and returns (D-135 (9)); past this the press is answered as failed
	nonceBytes          = 8                // spec 6: 8 random bytes, 11 characters of base64url
	nonceLen            = 11
	maxButtonRequestID  = 64 - len("a:") - len(":") - nonceLen // callback_data is at most 64 bytes
	buttonKeep          = 7 * 24 * time.Hour
	// staleGap: when the listener starts again after more than this without a poll (or for the first time in the process), the presses
	// waiting at Telegram may be old (review of #172, L3), so they are answered and dropped, never decided.
	staleGap    = 60 * time.Second
	drainRounds = 10              // short polls to drop what waits (10 updates each); what is left after them is taken as new
	answerWait  = 3 * time.Second // one answerCallbackQuery: answers on the receive loop run one after the other (L6)

	answerInvalid = "This button is not valid. Open Vedette to decide."
	answerStale   = "This button was pressed while Vedette was not listening. Press it again."
	answerFailed  = "Vedette could not record your decision. Try again, or open Vedette to decide."
	answerBusy    = "Vedette is busy. Press the button again in a minute."
	answerRefused = "Vedette did not take this decision. Open Vedette to see why."
	answerTaken   = "Your decision was recorded."

	// EventApprovalDecided is published when a decision made in chat was recorded by the response module (POST-8).
	EventApprovalDecided = "notify.approval.decided"
)

var (
	nonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)
	// numericChatRE is a Telegram chat as a number (the form the channel adapter accepts). Approvals need it (review of #172, L1): a
	// public @name can be joined by anyone, and a released name can be taken by someone else, who would then get approval requests.
	numericChatRE = regexp.MustCompile(`^-?[0-9]{5,20}$`)
)

// approvalChat says whether the configured chat_id can take approvals.
func approvalChat(fields map[string]string) bool {
	return numericChatRE.MatchString(strings.TrimSpace(fields["chat_id"]))
}

// recordedDecision says whether a Status of the response module is a decision that was recorded (POST-8); every other value
// is the code of a refusal.
func recordedDecision(status string) bool {
	return status == "approved" || status == "pending" || status == "rejected"
}

func hashNonce(n string) string {
	h := sha256.Sum256([]byte(n))
	return hex.EncodeToString(h[:])
}

// telegramButtons makes the Approve and Reject buttons of a request and keeps the hash of their nonce before the message is sent.
// None when no one can take the decision (no Decisions port), when the request is in-app only (INV-16 of response: no button),
// when the request id does not fit the 64 bytes of callback_data, or when the chat is not a number (a @name saved before approvals
// needed one): the message then only says to open Vedette.
func (s *Service) telegramButtons(ctx context.Context, req ApprovalRequest, fields map[string]string) ([]channel.Button, error) {
	if s.cfg.Decisions == nil || req.InAppOnly || len(req.ID) > maxButtonRequestID || !approvalChat(fields) {
		return nil, nil
	}
	b := make([]byte, nonceBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+)
	nonce := base64.RawURLEncoding.EncodeToString(b)
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO notify_tg_button (request_id, nonce_hash, expires_at) VALUES (?, ?, ?)
			ON CONFLICT (request_id) DO UPDATE SET nonce_hash = excluded.nonce_hash, expires_at = excluded.expires_at,
				message_id = NULL, chat_id = NULL, state = 'none', tries = 0`,
			req.ID, hashNonce(nonce), store.FormatTS(req.Expires))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("notify: keep the telegram button nonce: %w", err)
	}
	return []channel.Button{{Text: "Approve", Data: "a:" + req.ID + ":" + nonce}, {Text: "Reject", Data: "r:" + req.ID + ":" + nonce}}, nil
}

// parseButtonData splits the callback_data notify made: "a" or "r", the request id, the nonce. Anything else is not a button of
// ours (ok=false). The request id may itself hold ":" (idRE allows it), so the nonce is cut from the end.
func parseButtonData(data string) (requestID, nonce string, approve, ok bool) {
	if len(data) < len("a:x:")+nonceLen || len(data) > 64 || (data[:2] != "a:" && data[:2] != "r:") || data[len(data)-nonceLen-1] != ':' {
		return "", "", false, false
	}
	requestID, nonce = data[2:len(data)-nonceLen-1], data[len(data)-nonceLen:]
	if !idRE.MatchString(requestID) || !nonceRE.MatchString(nonce) {
		return "", "", false, false
	}
	return requestID, nonce, data[0] == 'a', true
}

// checkButton says whether data is a button notify sent: its nonce matches the one kept for the request (constant time).
func (s *Service) checkButton(ctx context.Context, data string) (requestID string, approve, ok bool, err error) {
	requestID, nonce, approve, ok := parseButtonData(data)
	if !ok {
		return "", false, false, nil
	}
	var stored string
	err = s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT nonce_hash FROM notify_tg_button WHERE request_id = ?`, requestID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, fmt.Errorf("notify: read the telegram button nonce: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(hashNonce(nonce)), []byte(stored)) != 1 {
		return "", false, false, nil
	}
	return requestID, approve, true, nil
}

// pruneButtons forgets button nonces a week after their request ended (called with the hourly prune).
func pruneButtons(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM notify_tg_button WHERE expires_at < ?`, store.FormatTS(now.Add(-buttonKeep))); err != nil {
		return fmt.Errorf("notify: prune telegram button nonces: %w", err)
	}
	return nil
}

// telegramOffset is the next update to read, per bot (the number before ":" of its token, which is public: the bot's user id), and
// when the last poll ended. It lives as long as the process, so a listener that stopped and starts again confirms what it already read.
type telegramOffset struct {
	mu     sync.Mutex
	bot    string
	offset int64
	at     time.Time // when the last poll of this bot returned; zero = none in this process
}

func (o *telegramOffset) get(bot string) (int64, time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.bot != bot {
		return 0, time.Time{} // another bot: its update ids are its own
	}
	return o.offset, o.at
}

func (o *telegramOffset) set(bot string, offset int64, at time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.bot, o.offset, o.at = bot, offset, at
}

// dropWaiting answers and drops the presses waiting at Telegram (short polls, no wait), so none of them is decided (L3). Each round
// confirms the one before; it stops at an answer with nothing new, or after drainRounds.
func (s *Service) dropWaiting(ctx context.Context, bot *channel.TelegramBot, botID string, offset int64) error {
	for range drainRounds {
		presses, next, err := bot.Updates(ctx, offset, 0)
		if err != nil {
			return err
		}
		for _, p := range presses {
			s.answerPress(ctx, bot, p.QueryID, answerStale)
		}
		done := len(presses) == 0 && next == offset
		offset = next
		s.tgOffset.set(botID, offset, s.now())
		if done {
			break
		}
	}
	return nil
}

// listenTelegram is the Run of the job "telegram-listen". It returns nil when the channel is not ready (the scheduler starts it
// again after telegramListenEvery, so a channel turned on later is picked up) or when ctx ends, and an error when Telegram
// cannot be polled (never with the token in it). It waits for the presses it started before it returns.
func (s *Service) listenTelegram(ctx context.Context) error {
	if s.cfg.Decisions == nil {
		return nil
	}
	sem := make(chan struct{}, telegramWorkers)
	var wg sync.WaitGroup
	defer wg.Wait()
	for ctx.Err() == nil {
		c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Telegram)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("notify: telegram listener: %w", err)
		}
		if !c.Configured || !c.Enabled || !c.Approvals || !approvalChat(c.Fields) {
			return nil
		}
		token, err := s.openSecret(ctx, s.cfg.DB.Reader(), c.SecretID)
		if err != nil {
			if ctx.Err() != nil { // stopped while reading the key (it reads the database): a stop, not an unreadable key
				return nil
			}
			return fmt.Errorf("notify: telegram listener: %w", err)
		}
		bot, err := channel.NewTelegramBot(secrets.NewValue(token), s.cfg.HTTPClient)
		if err != nil {
			return fmt.Errorf("notify: telegram listener: %s", userText(err))
		}
		botID, _, _ := strings.Cut(strings.TrimSpace(token), ":")
		offset, at := s.tgOffset.get(botID)
		if at.IsZero() || s.now().Sub(at) > staleGap {
			if err := s.dropWaiting(ctx, bot, botID, offset); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("notify: telegram listener: %w", err)
			}
			continue
		}
		presses, next, err := bot.Updates(ctx, offset, telegramPollWait)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("notify: telegram listener: %w", err)
		}
		s.tgOffset.set(botID, next, s.now())
		chat := strings.TrimSpace(c.Fields["chat_id"])
		for _, p := range presses {
			s.takePress(ctx, bot, chat, p, sem, &wg)
		}
	}
	return nil
}

// chatMatches checks the press came from the configured chat (spec 6), by number: approvals need a numeric chat (L1).
func chatMatches(chat string, p channel.Callback) bool { return p.ChatID == chat }

// takePress checks one press on the receive loop (chat, then the nonce) and hands the decision to a worker, so a slow Decide never
// holds the loop. A press that is not ours to decide is answered at once and never reaches Decide.
func (s *Service) takePress(ctx context.Context, bot *channel.TelegramBot, chat string, p channel.Callback, sem chan struct{}, wg *sync.WaitGroup) {
	if p.Invalid { // a field out of form (data, chat, a bot): answered, never decided
		s.answerPress(ctx, bot, p.QueryID, answerInvalid)
		return
	}
	if !chatMatches(chat, p) {
		s.answerPress(ctx, bot, p.QueryID, "") // another chat (a forwarded message, the bot added elsewhere): only stop the progress indicator
		return
	}
	requestID, approve, ok, err := s.checkButton(ctx, p.Data)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "notify: telegram: a button could not be checked", "error", err.Error())
		s.answerPress(ctx, bot, p.QueryID, answerFailed)
		return
	}
	if !ok {
		s.answerPress(ctx, bot, p.QueryID, answerInvalid)
		return
	}
	select {
	case sem <- struct{}{}:
	default:
		s.answerPress(ctx, bot, p.QueryID, answerBusy)
		return
	}
	wg.Go(func() {
		defer func() { <-sem }()
		s.decidePress(ctx, bot, p, requestID, approve)
	})
}

// decidePress passes a checked press to the response module, answers the person privately with its Message (POST-8) and publishes
// notify.approval.decided when the decision was recorded. An error of Decide is an infrastructure error: the person gets a fixed
// text, never the error.
func (s *Service) decidePress(ctx context.Context, bot *channel.TelegramBot, p channel.Callback, requestID string, approve bool) {
	dctx, cancel := context.WithTimeout(ctx, decideBudget)
	res, err := s.cfg.Decisions.Decide(dctx, Decision{Channel: channel.Telegram, ExternalID: p.FromID, RequestID: requestID, Approve: approve})
	cancel()
	text := res.Message
	switch {
	case err != nil:
		s.cfg.Log.WarnContext(ctx, "notify: telegram: the decision could not be recorded", "request_id", requestID, "error", err.Error())
		text = answerFailed
	case text == "" && recordedDecision(res.Status):
		text = answerTaken
	case text == "":
		text = answerRefused
	}
	s.answerPress(ctx, bot, p.QueryID, text)
	if err == nil && recordedDecision(res.Status) {
		s.publishDecided(ctx, requestID, res.Status, p.FromID, channel.Telegram)
	}
}

// answerPress answers a press; it still runs when ctx ended (the module was turned off after the press was taken). Its deadline is
// short (answerWait): answers made on the receive loop run one after the other, and one Telegram does not answer must not hold the next.
func (s *Service) answerPress(ctx context.Context, bot *channel.TelegramBot, queryID, text string) {
	actx, stop := context.WithTimeout(context.WithoutCancel(ctx), answerWait)
	defer stop()
	if err := bot.Answer(actx, queryID, text); err != nil {
		s.cfg.Log.DebugContext(ctx, "notify: telegram: a button press could not be answered", "error", err.Error())
	}
}

// publishDecided publishes notify.approval.decided {request_id, decision, approver, channel}: decision is the Status of the response
// module (approved, pending or rejected), approver the id of the person on the platform.
func (s *Service) publishDecided(ctx context.Context, requestID, status, approver string, ch channel.Type) {
	if s.cfg.Bus == nil {
		return
	}
	pctx, stop := detached(ctx)
	defer stop()
	if err := s.cfg.Bus.Publish(pctx, events.Event{Name: EventApprovalDecided, Data: map[string]string{
		"request_id": requestID, "decision": status, "approver": approver, "channel": string(ch)}}); err != nil {
		s.cfg.Log.WarnContext(ctx, "notify: publish approval decided", "error", err.Error())
	}
}
