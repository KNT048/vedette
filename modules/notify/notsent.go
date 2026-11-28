package notify

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// withNotSent fills NotSent of the incidents that no channel received (INV-24). It reads, in this order: a message still
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
	// The notices of an incident: its own, and those of its raises (raiseIntrusion: <id>-raised-<severity>).
	noticeIDs := slices.Clone(ids)
	for _, id := range ids {
		for _, sev := range []Severity{Critical, High, Medium, Low, Info} {
			noticeIDs = append(noticeIDs, raisedNoticeID(id.(string), sev))
		}
	}
	nin := "(" + strings.TrimSuffix(strings.Repeat("?,", len(noticeIDs)), ",") + ")"
	rows, err := q.QueryContext(ctx, `SELECT notice_id, reason, MIN(due_at) FROM notify_pending WHERE notice_id IN `+nin+` GROUP BY notice_id, reason`, noticeIDs...)
	if err != nil {
		return fmt.Errorf("notify: read queued incidents: %w", err)
	}
	for rows.Next() {
		var id, reason, due string
		if err := rows.Scan(&id, &reason, &due); err != nil {
			_ = rows.Close()
			return fmt.Errorf("notify: read queued incidents: %w", err)
		}
		id = incidentOfNotice(id)
		w := queue[id]
		if w == nil {
			w = &waiting{}
			queue[id] = w
		}
		if reason == "quiet" {
			if w.quiet == "" || due < w.quiet {
				w.quiet = due
			}
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
		case i.FirstRunSummary: // held by the first-run window (INV-23): never queued on its own, so unsent stays NULL
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

// reached is true when any attempt delivered the incident: the customer got the alert, whatever a later Resend did. The last
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
			n.Text = fmt.Sprintf("Held for quiet hours until %s. It goes out by itself then.", orgtime.Clock(t, loc))
		}
	case UnsentGrouped:
		n.Text = "Waiting to go out with the other alerts about the same product. It goes out by itself."
		if t, err := time.Parse(time.RFC3339, detail); err == nil {
			n.Until = detail
			n.Text = fmt.Sprintf("Waiting to go out at %s with the other alerts about the same product (grouping). It goes out by itself then.", orgtime.Clock(t, loc))
		}
	case UnsentNoChannel: // said of the moment it opened: a channel set up later does not make it untrue
		n.Text = "Not sent: no alert channel was set up when it opened."
	case UnsentChannelsOff:
		n.Text = "Not sent: the alert channels were turned off when it opened."
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
			n.Text = fmt.Sprintf("Not sent on its own: it was in the first-run summary sent at %s.", orgtime.Clock(t, loc))
		} else if detail == "pending" {
			n.Text = "Not sent on its own: it is in the first-run summary, which no channel has delivered yet."
		}
	case UnsentTriggerOff:
		n.Text = "Not sent: alerts of this kind are turned off in the alert settings."
		if floor.Valid() && sev.Valid() {
			n.Text = fmt.Sprintf("Not sent: it is %s, and the alert settings send this kind only from %s.", sev, floor)
		}
	case UnsentNotExploited:
		n.Text = "No alert: only findings exploited in the wild send one. It is in the daily summary when that is on (Settings, Alert channels)."
	case UnsentLineLeftOut:
		n.Text = "Not named in the message that went out: its line was past what the message could hold."
	default:
		n.Reason = UnsentUnknown
		n.Text = "Not sent. It was opened before this version of Vedette kept the reason."
	}
	return n
}

// noticeNotSent words a reason for a vulnerability notice: the incident's words, said of a finding.
func noticeNotSent(why NotSentReason, sev, floor Severity, ch channel.Type, detail string, loc *time.Location) NotSent {
	n := *notSent(why, sev, floor, ch, detail, loc)
	switch why {
	case UnsentNoChannel:
		n.Text = "Not sent: no alert channel was set up when it was found."
	case UnsentChannelsOff:
		n.Text = "Not sent: the alert channels were turned off when it was found."
	case UnsentBelowMin:
		n.Text = fmt.Sprintf("Not sent: it is rated %s for alerts, and your channels only send %s and above.", sev, floor)
		if !floor.Valid() || !sev.Valid() {
			n.Text = "Not sent: it is below the minimum severity of your channels."
		}
	case UnsentQueued:
		n.Text = "Waiting to be sent: it goes out within a minute."
	case UnsentUnknown:
		n.Text = "Not sent when it was found. The version of Vedette that found it did not keep the reason."
	}
	return n
}

// notSentNotices lists the vulnerability notices made since a time that no channel delivered, newest first, each with why (History,
// INV-24 for notices): waiting in the queue (its grouping window, quiet hours, or within a minute), the last failed attempt, else the
// decision kept when it was queued or dropped. A notice whose line a delivered message carried is told (notify_send_notice links only
// the lines a message sent whole), so it is not listed. Three reads for the whole list.
func (s *Service) notSentNotices(ctx context.Context, q dbtx, since time.Time) ([]UnsentNotice, error) {
	rows, err := q.QueryContext(ctx, `SELECT n.id, n.created_at, n.event, n.product, n.cves, ifnull(n.title, ''), ifnull(n.severity, ''), ifnull(n.unsent, ''),
		ifnull(n.unsent_floor, ''), ifnull(n.unsent_channel, ''), (SELECT min(nf.finding_id) FROM notify_notice_finding nf WHERE nf.notice_id = n.id)
		FROM notify_notice n WHERE n.created_at >= ? AND NOT EXISTS (SELECT 1 FROM notify_send_notice sn JOIN notify_send d ON d.id = sn.send_id
		WHERE sn.notice_id = n.id AND d.ok = 1) ORDER BY n.created_at DESC, n.id LIMIT ?`, store.FormatTS(since), historyLimit)
	if err != nil {
		return nil, fmt.Errorf("notify: read notices not sent: %w", err)
	}
	type row struct {
		id, at, event, product, cves, title, sev, why, floor, ch string
		finding                                                  sql.NullString
	}
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.at, &r.event, &r.product, &r.cves, &r.title, &r.sev, &r.why, &r.floor, &r.ch, &r.finding); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("notify: read notices not sent: %w", err)
		}
		list = append(list, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("notify: read notices not sent: %w", err)
	}
	out := []UnsentNotice{}
	if len(list) == 0 {
		return out, nil
	}
	ids := make([]any, len(list))
	for k, r := range list {
		ids[k] = r.id
	}
	in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")"
	type waiting struct{ now, group, quiet string } // the earliest due time of each kind of queued row
	queue := map[string]*waiting{}
	rows, err = q.QueryContext(ctx, `SELECT notice_id, reason, min(due_at) FROM notify_pending WHERE notice_id IN `+in+` GROUP BY notice_id, reason`, ids...)
	if err != nil {
		return nil, fmt.Errorf("notify: read queued notices: %w", err)
	}
	for rows.Next() {
		var id, reason, due string
		if err := rows.Scan(&id, &reason, &due); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("notify: read queued notices: %w", err)
		}
		w := queue[id]
		if w == nil {
			w = &waiting{}
			queue[id] = w
		}
		switch reason {
		case "quiet":
			w.quiet = due
		case "group":
			w.group = due
		default:
			w.now = due
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("notify: read queued notices: %w", err)
	}
	failed := map[string]SendView{} // the last failed attempt of each notice (a "Delayed" row still waits in the queue)
	rows, err = q.QueryContext(ctx, `SELECT sn.notice_id, d.channel, d.error, d.at FROM notify_send_notice sn JOIN notify_send d ON d.id = sn.send_id
		WHERE sn.notice_id IN `+in+` AND d.ok = 0 AND d.delayed = 0 ORDER BY d.at`, ids...)
	if err != nil {
		return nil, fmt.Errorf("notify: read failed notices: %w", err)
	}
	for rows.Next() {
		var id, ch, at string
		var e sql.NullString
		if err := rows.Scan(&id, &ch, &e, &at); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("notify: read failed notices: %w", err)
		}
		failed[id] = SendView{Channel: channel.Type(ch), At: at, Error: e.String}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("notify: read failed notices: %w", err)
	}
	loc := s.loc(ctx)
	rules, err := loadRules(ctx, q)
	if err != nil {
		return nil, err
	}
	cache := map[string]findingNow{}
	for _, r := range list {
		sev := Severity(r.sev)
		var ns NotSent
		w, f := queue[r.id], failed[r.id]
		// Not sent lists what still needs telling: a notice whose findings were all handled since, are no longer urgent, or were told
		// by another message that arrived (a later rise, a summary, Send now of another row) leaves the list, as Send now would refuse it.
		// One still waiting in the queue stays: the queue drops it itself when its findings are handled.
		what := noticeWhat(r.title, r.event, r.product, r.cves)
		if w == nil && s.cfg.Findings != nil {
			ids, err := noticeFindings(ctx, q, r.id)
			if err != nil {
				return nil, err
			}
			keep, infos, _, err := s.untold(ctx, q, r.id, ids, cache)
			if err != nil {
				return nil, err
			}
			if len(ids) > 0 && len(keep) == 0 {
				continue
			}
			// A notice written before titles were kept names its product and CVE only: the device it is on is added, so two rows of
			// one CVE on two devices read differently.
			if r.title == "" && len(keep) > 0 && NoticeEvent(r.event) != NoticeFirstRun {
				if d := joinDevices(infos[keep[0]].Devices); d != "" {
					what = noticeWhatOn(r.product, r.cves, d)
				}
			}
		}
		switch {
		case w != nil && w.now != "":
			ns = noticeNotSent(UnsentQueued, sev, "", "", "", loc)
		case w != nil && w.group != "":
			// The queue releases no grouped batch during quiet hours: a window that ends inside them waits for their end.
			if due, err := time.Parse(time.RFC3339, w.group); err == nil && rules.Quiet.Active(due.In(loc)) {
				ns = noticeNotSent(UnsentQuietHours, sev, "", "", store.FormatTS(rules.Quiet.EndsAt(due.In(loc))), loc)
				break
			}
			ns = noticeNotSent(UnsentGrouped, sev, "", "", w.group, loc)
		case w != nil:
			ns = noticeNotSent(UnsentQuietHours, sev, "", "", w.quiet, loc)
		case f.Channel != "":
			ns = noticeNotSent(UnsentFailed, sev, "", f.Channel, f.Error, loc)
		case r.why != "" && r.why != string(UnsentQueued) && r.why != string(UnsentQuietHours):
			ns = noticeNotSent(NotSentReason(r.why), sev, Severity(r.floor), channel.Type(r.ch), "", loc)
		case r.why != "": // queued, and the message that went out left its line out ("and N more", a chat app's length limit)
			ns = noticeNotSent(UnsentLineLeftOut, sev, "", "", "", loc)
		default: // written by a build that kept no reason
			ns = noticeNotSent(UnsentUnknown, sev, "", "", "", loc)
		}
		out = append(out, UnsentNotice{ID: r.id, At: r.at, What: what, Link: noticeLink(r.event, r.finding), NotSent: ns})
	}
	return out, nil
}

// noticeWhat is the line that names a notice in the History: its title, or for a notice written before titles were kept, its product
// and CVEs.
func noticeWhat(title, event, product, cves string) string {
	if title != "" {
		return title
	}
	var list []string
	_ = json.Unmarshal([]byte(cves), &list)
	what := strings.Join(list, ", ")
	if p := strings.TrimSpace(product); p != "" {
		what = p + ": " + what
	}
	if NoticeEvent(event) == NoticeFirstRun {
		what = "First-run summary: " + what
	}
	return strings.TrimSuffix(strings.TrimSpace(what), ":")
}

// noticeWhatOn is the line of a notice written before titles were kept, with the device it is on: "<product> on <device>: <CVEs>".
func noticeWhatOn(product, cves, device string) string {
	var list []string
	_ = json.Unmarshal([]byte(cves), &list)
	what := cmp.Or(strings.TrimSpace(product), "A finding") + " on " + device
	if c := strings.Join(list, ", "); c != "" {
		what += ": " + c
	}
	return what
}

// noticeLink is where a notice of the History opens: its finding, or the urgent findings for a summary.
func noticeLink(event string, finding sql.NullString) string {
	if NoticeEvent(event) == NoticeFirstRun {
		return findingsListOf([]int{1, 2, 3, 4})
	}
	if !finding.Valid {
		return findingsList
	}
	return "/findings/" + finding.String
}
