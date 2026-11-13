package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/modules/notify/channel"
)

// channelLabel is a channel's name as the Channels page shows it.
var channelLabel = map[channel.Type]string{
	channel.Telegram: "Telegram", channel.Slack: "Slack", channel.Zalo: "Zalo OA", channel.ZaloPersonal: "Zalo personal",
	channel.Email: "Email", channel.Webhook: "Webhook",
}

// withNotSent fills NotSent of the incidents that no channel received (INV-24, D-551). It reads, in this order: a message still
// waiting in the queue (queued, or held for quiet hours with the time it goes out), the failed attempts, the decision kept when the
// incident was opened (enqueue, or the queue dropping a held message), and for an incident opened before that decision was kept,
// the channels as they are now. Three small queries for the whole page, only for the incidents without a delivered message.
func (s *Service) withNotSent(ctx context.Context, q dbtx, list []Incident) error {
	var ids []any
	at := map[string]int{}
	for k, i := range list {
		if !reached(i.Sends) {
			at[i.ID] = k
			ids = append(ids, i.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")"
	type waiting struct {
		now   bool
		quiet string // the earliest release of a held message
	}
	queue := map[string]*waiting{}
	rows, err := q.QueryContext(ctx, `SELECT notice_id, reason, MIN(due_at) FROM notify_pending WHERE notice_id IN `+in+` GROUP BY notice_id, reason`, ids...)
	if err != nil {
		return fmt.Errorf("notify: read queued incidents: %w", err)
	}
	for rows.Next() {
		var id, reason, due string
		if err := rows.Scan(&id, &reason, &due); err != nil {
			_ = rows.Close()
			return fmt.Errorf("notify: read queued incidents: %w", err)
		}
		w := queue[id]
		if w == nil {
			w = &waiting{}
			queue[id] = w
		}
		if reason == "quiet" {
			w.quiet = due
		} else {
			w.now = true
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("notify: read queued incidents: %w", err)
	}
	type kept struct {
		why   sql.NullString
		floor sql.NullString
	}
	decided := map[string]kept{}
	rows, err = q.QueryContext(ctx, `SELECT id, unsent, unsent_floor FROM notify_incident WHERE id IN `+in, ids...)
	if err != nil {
		return fmt.Errorf("notify: read why incidents were not sent: %w", err)
	}
	for rows.Next() {
		var id string
		var k kept
		if err := rows.Scan(&id, &k.why, &k.floor); err != nil {
			_ = rows.Close()
			return fmt.Errorf("notify: read why incidents were not sent: %w", err)
		}
		decided[id] = k
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("notify: read why incidents were not sent: %w", err)
	}
	var today *[]channelNow // read once, only for an incident older than the kept decision
	loc := s.loc(ctx)
	for id, k := range at {
		i := &list[k]
		w, kd := queue[id], decided[id]
		switch {
		case w != nil && w.now:
			i.NotSent = notSent(UnsentQueued, i.Severity, "", "", "", loc)
		case w != nil:
			i.NotSent = notSent(UnsentQuietHours, i.Severity, "", "", w.quiet, loc)
		case len(i.Sends) > 0:
			last := i.Sends[len(i.Sends)-1] // sends are oldest first
			i.NotSent = notSent(UnsentFailed, i.Severity, "", last.Channel, last.Error, loc)
		case kd.why.Valid && kd.why.String != string(UnsentQueued) && kd.why.String != string(UnsentQuietHours):
			i.NotSent = notSent(NotSentReason(kd.why.String), i.Severity, Severity(kd.floor.String), "", "", loc)
		default: // opened by an older binary, or queued and then lost: the channels as they are now
			if today == nil {
				l, err := channelsNow(ctx, q)
				if err != nil {
					return err
				}
				today = &l
			}
			why, floor, ch := judgeNow(*today, i.Severity)
			i.NotSent = notSent(why, i.Severity, floor, ch, "", loc)
		}
	}
	return nil
}

// reached is true when a channel received the incident or is still trying (a send delayed by the provider's rate limit).
func reached(sends []SendView) bool {
	for _, sd := range sends {
		if sd.OK || sd.Delayed {
			return true
		}
	}
	return false
}

type channelNow struct {
	t     channel.Type
	on    bool
	floor Severity
}

func channelsNow(ctx context.Context, q dbtx) ([]channelNow, error) {
	rows, err := q.QueryContext(ctx, `SELECT type, enabled, min_severity FROM notify_channel WHERE configured = 1 ORDER BY type`)
	if err != nil {
		return nil, fmt.Errorf("notify: read channels: %w", err)
	}
	var out []channelNow
	for rows.Next() {
		var c channelNow
		var t, f string
		if err := rows.Scan(&t, &c.on, &f); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("notify: read channels: %w", err)
		}
		c.t, c.floor = channel.Type(t), Severity(f)
		out = append(out, c)
	}
	return out, errors.Join(rows.Err(), rows.Close())
}

// judgeNow is the reason today's channels give for an incident opened before the reason was kept; unknown when they would take it.
func judgeNow(list []channelNow, sev Severity) (NotSentReason, Severity, channel.Type) {
	if len(list) == 0 {
		return UnsentNoChannel, "", ""
	}
	var low *channelNow
	for k := range list {
		c := &list[k]
		if !c.on {
			continue
		}
		if MeetsMin(sev, c.floor) {
			return UnsentUnknown, "", ""
		}
		if low == nil || c.floor.rank() < low.floor.rank() {
			low = c
		}
	}
	if low == nil {
		return UnsentChannelsOff, "", ""
	}
	return UnsentBelowMin, low.floor, low.t
}

// notSent words a reason for the customer: plain English, no internal ids (INV-24).
func notSent(why NotSentReason, sev, floor Severity, ch channel.Type, detail string, loc *time.Location) *NotSent {
	n := &NotSent{Reason: why, Channel: ch}
	switch why {
	case UnsentQueued:
		n.Text = "Waiting to be sent: it goes out within a minute."
	case UnsentQuietHours:
		n.Text = "Held for quiet hours. It goes out by itself when they end."
		if t, err := time.Parse(time.RFC3339, detail); err == nil {
			n.Until = detail
			n.Text = fmt.Sprintf("Held for quiet hours until %s. It goes out by itself then.", t.In(loc).Format("15:04"))
		}
	case UnsentNoChannel:
		n.Text = "Not sent: no alert channel was set up."
	case UnsentChannelsOff:
		n.Text = "Not sent: the alert channels were turned off."
	case UnsentBelowMin:
		n.Text = fmt.Sprintf("Not sent: this incident is %s, and your channels only send %s and above.", sev, floor)
		if !floor.Valid() {
			n.Text = fmt.Sprintf("Not sent: this incident is %s, below the minimum severity of your channels.", sev)
		}
	case UnsentFailed:
		n.Text = fmt.Sprintf("Not delivered: %s failed.", channelLabel[ch])
		if detail = strings.TrimSpace(detail); detail != "" {
			n.Text += " " + detail
		}
	case UnsentDroppedStale:
		n.Text = "Not sent: alerts were off, and it was more than a day old when they came back on."
	case UnsentFirstRun:
		n.Text = "Not sent on its own: Vedette tells it in the hourly first-run summary."
	default:
		n.Reason = UnsentUnknown
		n.Text = "Not sent. It was opened before this version of Vedette kept the reason."
	}
	return n
}
