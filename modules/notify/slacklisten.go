package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Approvals from Slack buttons (PRE-8, POST-8, D-38, D-240, docs/specs/approval-tokens.md 5). The approval message is posted with
// the bot token (chat.postMessage) with Approve/Reject buttons; the job "slack-listen" opens a Socket Mode connection OUT with the app
// token (no inbound port, FORBID-4) and reads the presses. Like the Telegram listener it runs only while the module is on, the Slack
// channel is configured, enabled, takes approvals and has both tokens and the Decisions port is wired. notify checks the platform
// (workspace, channel, the message the press came from, the request not ended); the response module maps the person and keeps every gate.

const (
	slackListenJob   = "slack-listen"
	slackListenEvery = 30 * time.Second // the pause before the listener starts again after it stopped (not ready, or an error)
	slackWatchEvery  = 30 * time.Second // how often a live connection checks that its channel is unchanged
	slackWorkers     = telegramWorkers
	slackBackoffMax  = 30 * time.Second
	slackHealthy     = 10 * time.Second // a connection that lived this long was not a hot loop
)

var errSlackChanged = errors.New("notify: slack: the channel changed")

// slackReady says whether the Slack channel can take approvals now.
func slackReady(c channelRow) bool {
	return c.Configured && c.Enabled && c.Approvals && slackChannelIDRE.MatchString(c.Fields["channel_id"]) && c.AppID != "" && c.BotID != ""
}

// slackBot opens both tokens of the saved channel and returns the bot client.
func (s *Service) slackBot(ctx context.Context, q dbtx, c channelRow) (*channel.SlackBot, error) {
	bot, err := s.cfg.Secrets.Open(ctx, q, c.BotID, purposeBotToken)
	if err != nil {
		return nil, errSecretUnreadable
	}
	var app []byte
	if c.AppID != "" {
		if app, err = s.cfg.Secrets.Open(ctx, q, c.AppID, purposeAppToken); err != nil {
			return nil, errSecretUnreadable
		}
	}
	b, err := channel.NewSlackBot(secrets.NewValue(string(bot)), secrets.NewValue(string(app)), s.cfg.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("%s", userText(err))
	}
	return b, nil
}

// slackApprovalSender is the sender of an approval message with buttons, or nil when the channel cannot take presses (then the
// message goes through the webhook and only says to open Vedette). An unreadable token also gives nil: the message must still go out.
func (s *Service) slackApprovalSender(ctx context.Context, c channelRow, req ApprovalRequest) (channel.Sender, []channel.Button) {
	if s.cfg.Decisions == nil || !slackReady(c) || req.InAppOnly || len(req.ID) > 128 {
		return nil, nil
	}
	bot, err := s.slackBot(ctx, s.cfg.DB.Reader(), c)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "notify: slack: approval buttons skipped", "error", err.Error())
		return nil, nil
	}
	snd, err := channel.NewSlackApprovalSender(bot, c.Fields["channel_id"])
	if err != nil {
		return nil, nil
	}
	return snd, []channel.Button{{Text: "Approve", Data: "a:" + req.ID}, {Text: "Reject", Data: "r:" + req.ID}}
}

// slackButtonShown records the message with buttons of a request (in the transaction that records its send). When the final decision
// of the request arrived before (notify_slack_final), the message is marked for removal at once.
func slackButtonShown(ctx context.Context, tx *sql.Tx, requestID, channelID, ts string, expires time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO notify_slack_button (request_id, channel_id, ts, expires_at, state, outcome)
		SELECT ?, ?, ?, ?, CASE WHEN f.outcome IS NULL THEN 'shown' ELSE 'remove' END, f.outcome
		FROM (SELECT 1) LEFT JOIN notify_slack_final f ON f.request_id = ?`,
		requestID, channelID, ts, store.FormatTS(expires), requestID)
	if err != nil {
		return fmt.Errorf("notify: record the slack approval message: %w", err)
	}
	return nil
}

// checkSlackButton says whether the press came from a message notify posted for this request (channel and ts), the request has not
// ended and is not finally decided (its buttons are being removed).
func (s *Service) checkSlackButton(ctx context.Context, p channel.SlackPress) (bool, error) {
	if !idRE.MatchString(p.RequestID) {
		return false, nil
	}
	var one int
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT 1 FROM notify_slack_button WHERE request_id = ? AND channel_id = ? AND ts = ?
		AND state = 'shown' AND expires_at > ?`, p.RequestID, p.ChannelID, p.TS, store.FormatTS(s.now())).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("notify: read the slack approval message: %w", err)
	}
	return true, nil
}

// pruneSlackButtons forgets posted messages a week after their request ended, and final decisions a week after they arrived (called
// with the hourly prune).
func pruneSlackButtons(ctx context.Context, tx *sql.Tx, now time.Time) error {
	cut := store.FormatTS(now.Add(-buttonKeep))
	if _, err := tx.ExecContext(ctx, `DELETE FROM notify_slack_button WHERE expires_at < ?`, cut); err != nil {
		return fmt.Errorf("notify: prune slack approval messages: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM notify_slack_final WHERE at < ?`, cut); err != nil {
		return fmt.Errorf("notify: prune slack final decisions: %w", err)
	}
	return nil
}

// slackTeam returns the workspace id of the bot token at channel revision rev: the stored one, or learned with auth.test and stored.
func (s *Service) slackTeam(ctx context.Context, bot *channel.SlackBot, rev int64) (string, error) {
	var storedRev int64
	var team string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT rev, team_id FROM notify_slack_team WHERE id = 1`).Scan(&storedRev, &team)
	if err == nil && storedRev == rev {
		return team, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("notify: read the slack workspace: %w", err)
	}
	team, err = bot.AuthTest(ctx)
	if err != nil {
		return "", err
	}
	werr := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO notify_slack_team (id, rev, team_id) VALUES (1, ?, ?)
			ON CONFLICT (id) DO UPDATE SET rev = excluded.rev, team_id = excluded.team_id`, rev, team)
		return err
	})
	if werr != nil {
		return "", fmt.Errorf("notify: keep the slack workspace: %w", werr)
	}
	return team, nil
}

// listenSlack is the Run of the job "slack-listen". It returns nil when the channel is not ready or ctx ends, and an error (never
// with a token or the connection address in it) when Slack cannot be reached; the scheduler starts it again after slackListenEvery.
// A disconnect from Slack reconnects at once; a connection that keeps ending at once is slowed down (hot-loop guard).
func (s *Service) listenSlack(ctx context.Context) error {
	if s.cfg.Decisions == nil {
		return nil
	}
	sem := make(chan struct{}, slackWorkers)
	var wg sync.WaitGroup
	defer wg.Wait()
	quick := 0
	for ctx.Err() == nil {
		c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Slack)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("notify: slack listener: %w", err)
		}
		if !slackReady(c) {
			return nil
		}
		if quick > 1 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(min(time.Second<<(quick-1), slackBackoffMax)):
			}
		}
		started := time.Now()
		err = s.serveSlack(ctx, c, sem, &wg)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(started) >= slackHealthy {
			quick = 0
		} else {
			quick++
		}
		if err != nil && !errors.Is(err, errSlackChanged) && !errors.Is(err, errSlackDisconnect) {
			return fmt.Errorf("notify: slack listener: %w", err)
		}
	}
	return nil
}

var errSlackDisconnect = errors.New("notify: slack: asked to reconnect")

// serveSlack runs one Socket Mode connection until Slack asks to reconnect, the channel changes, ctx ends or the connection fails.
func (s *Service) serveSlack(ctx context.Context, c channelRow, sem chan struct{}, wg *sync.WaitGroup) error {
	bot, err := s.slackBot(ctx, s.cfg.DB.Reader(), c)
	if err != nil {
		return err
	}
	team, err := s.slackTeam(ctx, bot, c.Rev)
	if err != nil {
		return err
	}
	addr, err := bot.OpenConnection(ctx)
	if err != nil {
		return err
	}
	conn, err := bot.Dial(ctx, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	cctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	go s.watchSlack(cctx, cancel, c.Rev)
	seen := &seenEnvelopes{}
	for {
		env, err := conn.Read(cctx)
		if err != nil {
			if cause := context.Cause(cctx); ctx.Err() == nil && cause != nil && errors.Is(cause, errSlackChanged) {
				return errSlackChanged
			}
			return err
		}
		if env.EnvelopeID != "" { // at once, on the read loop: Slack sends the envelope again after 3 seconds
			if err := conn.Ack(cctx, env.EnvelopeID); err != nil {
				return err
			}
		}
		switch env.Kind {
		case channel.SlackDisconnect:
			return errSlackDisconnect
		case channel.SlackPressKind:
			if seen.add(env.EnvelopeID) { // Slack sends an envelope again when it was not acked in time: decide it once
				s.takeSlackPress(ctx, bot, c, team, env.Press, sem, wg)
			}
		}
	}
}

// watchSlack ends the connection when the channel is turned off or changed.
func (s *Service) watchSlack(ctx context.Context, cancel context.CancelCauseFunc, rev int64) {
	t := time.NewTicker(slackWatchEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Slack)
		if err == nil && (!slackReady(c) || c.Rev != rev) {
			cancel(errSlackChanged)
			return
		}
	}
}

// takeSlackPress checks one press on the read loop and hands the decision to a worker, so a slow Decide never holds the loop. A press
// of another workspace or channel is ignored (no reply: it is not ours to answer); one that is not ours to decide is answered "not
// valid" and never reaches Decide.
func (s *Service) takeSlackPress(ctx context.Context, bot *channel.SlackBot, c channelRow, team string, p channel.SlackPress, sem chan struct{}, wg *sync.WaitGroup) {
	// Replies are slow HTTP calls and Slack wants every ack within 3 seconds: none of them runs on the read loop (review: replies held acks).
	reply := func(text string) {
		if p.ResponseURL == "" {
			return
		}
		select {
		case sem <- struct{}{}:
			wg.Go(func() {
				defer func() { <-sem }()
				s.replySlack(ctx, bot, p.ResponseURL, text)
			})
		default: // every worker is busy: this private reply is dropped (best effort)
		}
	}
	if p.Invalid {
		reply(answerInvalid)
		return
	}
	if p.TeamID != team || p.ChannelID != c.Fields["channel_id"] {
		return
	}
	// The channel may have been turned off or changed since the connection opened (the watcher looks every 30 s): decide nothing then.
	now, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Slack)
	if err != nil || !slackReady(now) || now.Rev != c.Rev {
		return
	}
	ok, err := s.checkSlackButton(ctx, p)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "notify: slack: a button could not be checked", "error", err.Error())
		reply(answerFailed)
		return
	}
	if !ok {
		reply(answerInvalid)
		return
	}
	select {
	case sem <- struct{}{}:
	default:
		reply(answerBusy)
		return
	}
	wg.Go(func() {
		defer func() { <-sem }()
		s.decideSlackPress(ctx, bot, p)
	})
}

func (s *Service) decideSlackPress(ctx context.Context, bot *channel.SlackBot, p channel.SlackPress) {
	dctx, cancel := context.WithTimeout(ctx, decideBudget)
	res, err := s.cfg.Decisions.Decide(dctx, Decision{Channel: channel.Slack, ExternalID: p.UserID, RequestID: p.RequestID, Approve: p.Approve})
	cancel()
	text := res.Message
	switch {
	case err != nil:
		s.cfg.Log.WarnContext(ctx, "notify: slack: the decision could not be recorded", "request_id", p.RequestID, "error", err.Error())
		text = answerFailed
	case text == "" && recordedDecision(res.Status):
		text = answerTaken
	case text == "":
		text = answerRefused
	}
	s.replySlack(ctx, bot, p.ResponseURL, text)
	if err == nil && recordedDecision(res.Status) {
		s.publishDecided(ctx, p.RequestID, res.Status, p.UserID, channel.Slack)
	}
}

// replySlack answers a press privately through its response_url; it still runs when ctx ended. No address (it failed its check) = no reply.
func (s *Service) replySlack(ctx context.Context, bot *channel.SlackBot, responseURL, text string) {
	if responseURL == "" {
		return
	}
	actx, stop := context.WithTimeout(context.WithoutCancel(ctx), answerWait)
	defer stop()
	if err := bot.Respond(actx, responseURL, text); err != nil {
		s.cfg.Log.DebugContext(ctx, "notify: slack: a button press could not be answered", "error", err.Error())
	}
}

// seenEnvelopes remembers the last envelope ids of one connection.
type seenEnvelopes struct {
	ids [256]string
	n   int
}

// add reports whether id is new.
func (e *seenEnvelopes) add(id string) bool {
	for _, x := range e.ids {
		if x == id {
			return false
		}
	}
	e.ids[e.n%len(e.ids)] = id
	e.n++
	return true
}
