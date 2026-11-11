package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Removing the Approve/Reject buttons of a Telegram approval message once its request is finally decided or has ended (slice 13b-8
// (2), spec approval-tokens.md 6). The event handler only marks the row (handlers write the database, the deliver job does the
// network); requests that ended are also marked by the job itself, because events are best effort (D-144).

// EventDecisionMade is the decision event of the response module (CONTRACT "Events": received).
const EventDecisionMade = "response.decision.made"

const (
	buttonTries   = 5  // removal attempts of one message, in all
	buttonsPerRun = 20 // removals per deliver run
)

// buttonsShown records where the message with buttons of a request is (in the transaction that records its send). A request that was
// decided before this ran keeps its "remove" mark.
func buttonsShown(ctx context.Context, tx *sql.Tx, requestID, chatID string, messageID int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE notify_tg_button SET message_id = ?, chat_id = ?, state = CASE state WHEN 'none' THEN 'shown' ELSE state END
		WHERE request_id = ?`, messageID, chatID, requestID)
	if err != nil {
		return fmt.Errorf("notify: record the telegram approval message: %w", err)
	}
	return nil
}

// decisionEvent marks the buttons of a request for removal when response.decision.made {request_id, final} says the request is
// finally decided (approved by the last person needed, rejected, expired or cancelled). final=false (the first of two approvals)
// leaves them for the second person. Anything not of that form, or about a request without buttons, changes nothing.
func (s *Service) decisionEvent(ctx context.Context, data any) error {
	var e struct {
		RequestID string `json:"request_id"`
		Final     bool   `json:"final"`
	}
	if decode(data, &e) != nil || !e.Final || !idRE.MatchString(e.RequestID) || len(e.RequestID) > maxButtonRequestID {
		return nil
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE notify_tg_button SET state = 'remove' WHERE request_id = ? AND state IN ('none', 'shown')`, e.RequestID); err != nil {
			return fmt.Errorf("notify: mark telegram buttons for removal: %w", err)
		}
		return nil
	})
}

type buttonRow struct {
	requestID, chatID string
	messageID         int64
	tries             int
}

// clearButtons is the part of the deliver job that removes buttons: it marks the messages of requests that ended, then removes the
// buttons of at most buttonsPerRun marked messages. A 400 from Telegram is final (gone already, deleted, too old); other failures are
// tried again at the next run, at most buttonTries times in all. Without a configured Telegram channel nothing is sent (the rows are
// pruned a week after their request).
func (s *Service) clearButtons(ctx context.Context, now time.Time) error {
	var rows []buttonRow
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE notify_tg_button SET state = 'remove' WHERE state = 'shown' AND expires_at <= ?`, store.FormatTS(now)); err != nil {
			return fmt.Errorf("notify: mark ended requests: %w", err)
		}
		q, err := tx.QueryContext(ctx, `SELECT request_id, chat_id, message_id, tries FROM notify_tg_button
			WHERE state = 'remove' AND message_id IS NOT NULL AND chat_id IS NOT NULL ORDER BY expires_at LIMIT ?`, buttonsPerRun)
		if err != nil {
			return fmt.Errorf("notify: read buttons to remove: %w", err)
		}
		defer func() { _ = q.Close() }()
		rows = rows[:0]
		for q.Next() {
			var r buttonRow
			if err := q.Scan(&r.requestID, &r.chatID, &r.messageID, &r.tries); err != nil {
				return fmt.Errorf("notify: read buttons to remove: %w", err)
			}
			rows = append(rows, r)
		}
		return q.Err()
	})
	if err != nil || len(rows) == 0 {
		return err
	}
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.Telegram)
	if err != nil || !c.Configured {
		return err
	}
	token, err := s.openSecret(ctx, s.cfg.DB.Reader(), c.SecretID)
	if err != nil {
		return nil // the saved token cannot be read: the channel shows it; nothing to remove with
	}
	bot, err := channel.NewTelegramBot(secrets.NewValue(token), s.cfg.HTTPClient)
	if err != nil {
		return nil
	}
	for _, r := range rows {
		if ctx.Err() != nil {
			return nil
		}
		err := bot.RemoveButtons(ctx, r.chatID, r.messageID)
		var se *channel.StatusError
		done := err == nil || (errors.As(err, &se) && se.Code == http.StatusBadRequest)
		state, tries := "remove", r.tries+1
		if done || tries >= buttonTries {
			state = "removed"
		}
		if !done && state == "removed" {
			s.cfg.Log.WarnContext(ctx, "notify: telegram: the buttons of an approval message could not be removed", "request_id", r.requestID, "error", err.Error())
		}
		werr := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE notify_tg_button SET state = ?, tries = ? WHERE request_id = ?`, state, tries, r.requestID)
			return err
		})
		if werr != nil {
			return fmt.Errorf("notify: record a button removal: %w", werr)
		}
	}
	return nil
}
