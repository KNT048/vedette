package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Removing the Approve/Reject buttons of a Slack approval message once its request is finally decided or has ended (slice 3b, D-241,
// spec approval-tokens.md 5 "cập nhật tin gốc (chat.update) để bỏ nút"). The Slack analogue of tgbuttons.go: the event handler only
// marks rows; the deliver job rewrites the messages with the bot token, keeping their text and adding one fixed line saying how the
// request ended. Who decided is not written: it would put a Vedette user's email into the Slack channel (the audit log has it).

// slackEndLines are the only lines written into a message: the outcome is one of a fixed set, never text from the event.
var slackEndLines = map[string]string{
	"approved":  "Approved.",
	"rejected":  "Rejected.",
	"expired":   "Expired. Nothing was changed.",
	"cancelled": "Cancelled.",
	"ended":     "This request has ended. Open Vedette to see the outcome.",
}

// slackOutcome maps the decision of response.decision.made to an outcome; anything else is "ended".
func slackOutcome(decision string) string {
	if _, ok := slackEndLines[decision]; ok && decision != "ended" {
		return decision
	}
	return "ended"
}

// slackFinal marks the Slack messages of a finally decided request for removal and remembers the decision for a message recorded
// later (notify_slack_final). A repeated event changes nothing.
func slackFinal(ctx context.Context, tx *sql.Tx, requestID, outcome string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE notify_slack_button SET state = 'remove', outcome = ? WHERE request_id = ? AND state = 'shown'`,
		outcome, requestID); err != nil {
		return fmt.Errorf("notify: mark slack buttons for removal: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO notify_slack_final (request_id, outcome, at) VALUES (?, ?, ?)`,
		requestID, outcome, store.FormatTS(now)); err != nil {
		return fmt.Errorf("notify: remember the final decision: %w", err)
	}
	return nil
}

type slackButtonRow struct {
	requestID, channelID, ts, outcome string
	tries                             int
}

// clearSlackButtons is the part of the deliver job that removes Slack buttons: it marks the messages of requests that ended, then
// rewrites at most buttonsPerRun marked messages. Slack refusing the edit (ok:false, or a 4xx other than 429) is final; a 429 or 5xx
// is tried again at the next run, at most buttonTries times in all. Slack not answering at all stops this run's removals at once
// (review of #198, L1: a Slack that swallows the requests holds the deliver job for one timeout, not one per message). Without the
// bot token nothing is sent (the rows are pruned a week after their request).
func (s *Service) clearSlackButtons(ctx context.Context, now time.Time) error {
	var rows []slackButtonRow
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE notify_slack_button SET state = 'remove', outcome = 'ended' WHERE state = 'shown' AND expires_at <= ?`,
			store.FormatTS(now)); err != nil {
			return fmt.Errorf("notify: mark ended slack requests: %w", err)
		}
		q, err := tx.QueryContext(ctx, `SELECT request_id, channel_id, ts, COALESCE(outcome, 'ended'), tries FROM notify_slack_button
			WHERE state = 'remove' ORDER BY expires_at LIMIT ?`, buttonsPerRun)
		if err != nil {
			return fmt.Errorf("notify: read slack buttons to remove: %w", err)
		}
		defer func() { _ = q.Close() }()
		rows = rows[:0]
		for q.Next() {
			var r slackButtonRow
			if err := q.Scan(&r.requestID, &r.channelID, &r.ts, &r.outcome, &r.tries); err != nil {
				return fmt.Errorf("notify: read slack buttons to remove: %w", err)
			}
			rows = append(rows, r)
		}
		return q.Err()
	})
	if err != nil || len(rows) == 0 {
		return err
	}
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Slack)
	if err != nil || !c.Configured || c.BotID == "" {
		return err
	}
	bot, err := s.slackBot(ctx, s.cfg.DB.Reader(), c)
	if err != nil {
		return nil // a token cannot be read: the channel shows it; nothing to edit with
	}
	for _, r := range rows {
		if ctx.Err() != nil {
			return nil
		}
		m, err := s.postedApproval(ctx, r.requestID)
		if err != nil {
			return err
		}
		err = bot.UpdateApproval(ctx, r.channelID, r.ts, m, slackEndLines[r.outcome])
		var se *channel.StatusError
		var pe *channel.ProviderError
		answered := errors.As(err, &se) || errors.As(err, &pe)
		done := err == nil || pe != nil || (se != nil && se.Code >= 400 && se.Code < 500 && se.Code != http.StatusTooManyRequests)
		state, tries := "remove", r.tries+1
		if done || tries >= buttonTries {
			state = "removed"
		}
		if err != nil && state == "removed" {
			s.cfg.Log.WarnContext(ctx, "notify: slack: the buttons of an approval message could not be removed", "request_id", r.requestID, "error", err.Error())
		}
		werr := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE notify_slack_button SET state = ?, tries = ? WHERE request_id = ? AND channel_id = ? AND ts = ?`,
				state, tries, r.requestID, r.channelID, r.ts)
			return err
		})
		if werr != nil {
			return fmt.Errorf("notify: record a slack button removal: %w", werr)
		}
		if err != nil && !answered {
			return nil // Slack did not answer: the rest wait for the next run
		}
	}
	return nil
}

// postedApproval is the approval message of a request as it was sent to Slack (the history copy, which never holds a token), or a
// zero Message when it is not kept any more.
func (s *Service) postedApproval(ctx context.Context, requestID string) (channel.Message, error) {
	var raw string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT message FROM notify_send WHERE kind = 'approval' AND ref_id = ? AND channel = ? AND ok = 1
		ORDER BY at DESC LIMIT 1`, requestID, string(channel.Slack)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return channel.Message{}, nil
	}
	if err != nil {
		return channel.Message{}, fmt.Errorf("notify: read the slack approval message: %w", err)
	}
	var m channel.Message
	if json.Unmarshal([]byte(raw), &m) != nil {
		return channel.Message{}, nil
	}
	m.Buttons = nil
	return m, nil
}
