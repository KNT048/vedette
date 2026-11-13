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

// withNotSent fills NotSent of the incidents that no channel received (INV-24, D-551). It reads, in this order: a message still
// waiting in the queue (queued, or held for quiet hours with the time it goes out), a channel whose last attempt failed, the decision kept when the
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
		why, floor, ch sql.NullString
		summary, told  sql.NullString // first-run incidents (INV-23): the summary that tells it, and when a channel delivered that summary
	}
	decided := map[string]kept{}
	rows, err = q.QueryContext(ctx, `SELECT i.id, i.unsent, i.unsent_floor, i.unsent_channel, i.summary_id,
		(SELECT MIN(d.at) FROM notify_send d WHERE d.ref_id = i.summary_id AND d.ok = 1) FROM notify_incident i WHERE i.id IN `+in, ids...)
	if err != nil {
		return fmt.Errorf("notify: read why incidents were not sent: %w", err)
	}
	for rows.Next() {
		var id string
		var k kept
		if err := rows.Scan(&id, &k.why, &k.floor, &k.ch, &k.summary, &k.told); err != nil {
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
		case i.FirstRunSummary: // held by the first-run window (D-550, INV-23): never queued on its own, so unsent stays NULL
			detail := ""
			if kd.summary.Valid {
				detail = "pending"
			}
			if kd.told.Valid {
				detail = kd.told.String
			}
			i.NotSent = notSent(UnsentFirstRun, i.Severity, "", "", detail, loc)
		case w != nil && w.now:
			i.NotSent = notSent(UnsentQueued, i.Severity, "", "", "", loc)
		case w != nil:
			i.NotSent = notSent(UnsentQuietHours, i.Severity, "", "", w.quiet, loc)
		case failedLast(i.Sends) != nil:
			f := failedLast(i.Sends)
			i.NotSent = notSent(UnsentFailed, i.Severity, "", f.Channel, f.Error, loc)
		case kd.why.Valid && kd.why.String != string(UnsentQueued) && kd.why.String != string(UnsentQuietHours):
			i.NotSent = notSent(NotSentReason(kd.why.String), i.Severity, Severity(kd.floor.String), channel.Type(kd.ch.String), "", loc)
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

// lastPerChannel is the last attempt of each channel, in the order of those attempts (sends are oldest first). An earlier "Delayed"
// row says nothing once the message failed or was dropped: only the last attempt of a channel counts.
func lastPerChannel(sends []SendView) []SendView {
	last := map[channel.Type]int{}
	for k, sd := range sends {
		last[sd.Channel] = k
	}
	var out []SendView
	for k, sd := range sends {
		if last[sd.Channel] == k {
			out = append(out, sd)
		}
	}
	return out
}

// reached is true when any attempt delivered the incident: the customer got the alert, whatever a later Resend did (Opus r2). The last
// attempt of a channel only chooses between failed and dropped (failedLast).
func reached(sends []SendView) bool {
	for _, sd := range sends {
		if sd.OK {
			return true
		}
	}
	return false
}

// failedLast is the most recent channel whose last attempt failed (not a "Delayed" row: that one still waits in the queue or was
// dropped, and the queue keeps why), or nil.
func failedLast(sends []SendView) *SendView {
	l := lastPerChannel(sends)
	for k := len(l) - 1; k >= 0; k-- {
		if !l[k].OK && !l[k].Delayed {
			return &l[k]
		}
	}
	return nil
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
	case UnsentChannelOff:
		n.Text = "Not sent: the channel it was waiting for was turned off before it went out."
	case UnsentChannelGone:
		n.Text = "Not sent: the channel it was waiting for was removed before it went out."
	case UnsentBelowMin:
		n.Text = fmt.Sprintf("Not sent: this incident is %s, and your channels only send %s and above.", sev, floor)
		if !floor.Valid() {
			n.Text = fmt.Sprintf("Not sent: this incident is %s, below the minimum severity of your channels.", sev)
		}
	case UnsentFailed:
		n.Text = fmt.Sprintf("Not delivered. %s failed to deliver it.", channelName[ch])
		if detail = strings.TrimSpace(detail); detail != "" {
			n.Text += " " + detail
		}
	case UnsentDroppedStale:
		n.Text = "Not sent: alerts were off, and it was more than a day old when they came back on."
	case UnsentFirstRun: // detail: "" = not in a summary yet, "pending" = in one no channel delivered yet, else when one delivered it
		n.Text = "Not sent on its own: it goes out in the next first-run summary, within the hour."
		if t, err := time.Parse(time.RFC3339, detail); err == nil {
			n.Text = fmt.Sprintf("Not sent on its own: it was in the first-run summary sent at %s.", t.In(loc).Format("15:04"))
		} else if detail == "pending" {
			n.Text = "Not sent on its own: it is in the first-run summary, which no channel has delivered yet."
		}
	default:
		n.Reason = UnsentUnknown
		n.Text = "Not sent. It was opened before this version of Vedette kept the reason."
	}
	return n
}
