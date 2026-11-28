package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/schedule"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// The daily summary (INV-32). Only a finding exploited in the wild sends an alert; everything else a person should still hear about
// goes into one optional message a day on every alert channel that is on: the findings of the day that are not exploited (their notices
// were recorded as not_exploited), the new findings with no sign of exploitation, what external scans found that is not exploited, the answers of the customer's AI waiting for review,
// and the tokens its research of CVEs used. Its time is a core/schedule owner (notify.summary), off until an administrator turns it on,
// like the periodic report. When it comes due, the schedule's transaction only writes a notify_summary row; the summary job builds and
// sends it, because sending talks to the channels. A summary with nothing to tell is not sent.

// SummaryScheduleKey is the owner key of the daily summary's schedule.
const SummaryScheduleKey = "notify.summary"

const (
	summaryJob   = "summary"
	summaryEvery = time.Minute
	// summaryCatchUp is how late the job still sends a summary that came due (the box or the module was off): a day-old summary is
	// replaced by the next one, which covers the same findings.
	summaryCatchUp = 24 * time.Hour
	// summaryFirstSpan is what the first summary covers: the day before its due time.
	summaryFirstSpan = 24 * time.Hour
)

// summaryLimits is what the summary's schedule allows: every day at a time, at any hour (it is not a scan).
var summaryLimits = schedule.Limits{Freqs: []schedule.Freq{schedule.Daily}, Windows: []schedule.WindowMode{schedule.WindowNone},
	Reason: "The summary covers one day."}

// SummarySources are what the daily summary reads outside notify. Each is optional: nil leaves its line out.
type SummarySources struct {
	// Updates counts the findings first seen in [from, to) that are open now with no sign of exploitation (update recommended), and the
	// devices they are on.
	Updates func(ctx context.Context, from, to time.Time) (findings, devices int, err error)
	// AIReview counts the answers of the customer's AI that wait for a person's review now.
	AIReview func(ctx context.Context) (int, error)
	// AITokens is how many tokens the AI's research of CVEs used in [from, to).
	AITokens func(ctx context.Context, from, to time.Time) (int, error)
	// Exposure counts what external scans found new in [from, to) that did not alert (no CVE exploited in the wild): the issues and
	// the open ports (exposure NewSince).
	Exposure func(ctx context.Context, from, to time.Time) (issues, ports int, err error)
}

// ScheduleOwner is what notify registers with core/schedule: the daily summary, off until an administrator turns it on, 08:00 in the
// organisation's zone by default.
func (s *Service) ScheduleOwner() schedule.Owner {
	return schedule.Owner{Module: ModuleID, Key: SummaryScheduleKey, AdminOnly: true, Limits: summaryLimits,
		Default: schedule.DailyAt("08:00"), DefaultOn: false, Start: s.startSummary}
}

// startSummary marks the summary for the summary job, inside the schedule's transaction; skipped, saying why, when no channel is on.
func (s *Service) startSummary(ctx context.Context, tx *sql.Tx, f schedule.Fire) (string, error) {
	var on int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM notify_channel WHERE configured = 1 AND enabled = 1`).Scan(&on); err != nil {
		return "", fmt.Errorf("notify: daily summary: %w", err)
	}
	if on == 0 {
		return "", schedule.Skip("No alert channel is on. Set one up in Settings, Alert channels.")
	}
	due := f.DueAt
	if due.IsZero() {
		due = s.now()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO notify_summary (id, due_at, state) VALUES (?, ?, 'due') ON CONFLICT (id) DO NOTHING`,
		"sum-"+due.UTC().Format("20060102T150405.000"), store.FormatTS(due)); err != nil {
		return "", fmt.Errorf("notify: daily summary: %w", err)
	}
	return "", nil
}

// summaryOf is what one daily summary tells.
type summaryOf struct {
	from, to time.Time
	ids      []string // the findings not exploited that were told for the summary, still open and urgent, most urgent first
	infos    map[string]FindingInfo
	notices  map[string][]string // finding id → the not_exploited notices that told it
	updates  int                 // new findings with no sign of exploitation
	devices  int                 // the devices of updates
	review   int                 // AI answers waiting for review
	tokens   int                 // tokens of the AI's research
	exIssues int                 // new exposure issues with no CVE exploited in the wild
	exPorts  int                 // new open ports found by external scans
}

func (m summaryOf) empty() bool {
	return len(m.ids) == 0 && m.updates == 0 && m.review == 0 && m.tokens == 0 && m.exIssues == 0 && m.exPorts == 0
}

// RunSummary is the body of the summary job: each summary the schedule marked is taken (sending, so a crash cannot send it twice),
// built and sent to every alert channel that is on, once. One found more than summaryCatchUp late is skipped.
func (s *Service) RunSummary(ctx context.Context) error {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, due_at FROM notify_summary WHERE state = 'due' ORDER BY due_at`)
	if err != nil {
		return fmt.Errorf("notify: daily summary: %w", err)
	}
	type due struct{ id, at string }
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.at); err != nil {
			_ = rows.Close()
			return fmt.Errorf("notify: daily summary: %w", err)
		}
		list = append(list, d)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("notify: daily summary: %w", err)
	}
	for _, d := range list {
		taken := false
		if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			r, err := tx.ExecContext(ctx, `UPDATE notify_summary SET state = 'sending' WHERE id = ? AND state = 'due'`, d.id)
			if err != nil {
				return fmt.Errorf("notify: daily summary: %w", err)
			}
			n, _ := r.RowsAffected()
			taken = n == 1
			return nil
		}); err != nil {
			return err
		}
		if !taken {
			continue
		}
		state, err := s.sendSummary(ctx, d.id, d.at)
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "notify: daily summary failed", "summary", d.id, "error", err)
			state = "skipped"
		}
		wctx, stop := detached(ctx)
		err = s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(wctx, `UPDATE notify_summary SET state = ?, done_at = ? WHERE id = ?`, state, store.FormatTS(s.now()), d.id)
			return err
		})
		stop()
		if err != nil {
			return fmt.Errorf("notify: daily summary: %w", err)
		}
	}
	return nil
}

// sendSummary builds the summary due at dueAt and sends it; the state it ends in (sent, empty, skipped).
func (s *Service) sendSummary(ctx context.Context, id, dueAt string) (string, error) {
	to, err := time.Parse(time.RFC3339, dueAt)
	if err != nil {
		return "", fmt.Errorf("notify: daily summary due time: %w", err)
	}
	if s.now().Sub(to) > summaryCatchUp {
		return "skipped", nil
	}
	from := to.Add(-summaryFirstSpan)
	var prev sql.NullString // the due time of the summary before: this one covers what came since
	if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT max(due_at) FROM notify_summary WHERE due_at < ? AND id <> ?`, dueAt, id).Scan(&prev); err != nil {
		return "", fmt.Errorf("notify: daily summary: %w", err)
	}
	if t, err := time.Parse(time.RFC3339, prev.String); prev.Valid && err == nil && t.After(from.Add(-summaryCatchUp)) {
		from = t
	}
	m, err := s.buildSummary(ctx, from, to)
	if err != nil {
		return "", err
	}
	if m.empty() {
		return "empty", nil
	}
	msg, listed := s.summaryMessage(ctx, id, m)
	types, err := s.onChannels(ctx)
	if err != nil {
		return "", err
	}
	if len(types) == 0 {
		return "skipped", nil
	}
	link := findingsListOf(summaryLayers(m))
	for _, t := range types {
		c, err := loadChannel(ctx, s.cfg.DB.Reader(), t)
		var rec SendRecord
		if err == nil {
			var snd channel.Sender
			if snd, err = s.savedSender(ctx, c, nil); err == nil {
				rec = Deliver(ctx, store.NewID("sd"), snd, msg, s.now)
			}
		}
		if err != nil {
			rec = SendRecord{ID: store.NewID("sd"), Channel: t, To: string(t), At: s.now(), Error: "The channel settings cannot be used: " + userText(err)}
		}
		// The notices of the findings whose line went out whole are told by this message (History, Not sent drops them); a failure is
		// linked to all it meant to name, as an alert's failure is.
		told := listed
		if rec.OK {
			told = listed[:min(len(listed), channel.Listed(t, msg))]
		}
		wctx, stop := detached(ctx)
		ob := &events.Outbox{}
		err = s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
			ob = &events.Outbox{}
			if err := insertSend(wctx, tx, rec, "vuln", id, msg.Title, link, "", msg); err != nil {
				return err
			}
			for _, f := range told {
				for _, n := range m.notices[f] {
					if _, err := tx.ExecContext(wctx, `INSERT INTO notify_send_notice (send_id, notice_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, rec.ID, n); err != nil {
						return fmt.Errorf("notify: link the summary to a notice: %w", err)
					}
				}
			}
			name := "notify.message.sent"
			if !rec.OK {
				name = "notify.message.failed"
			}
			ob.Add(events.Event{Name: name, Data: map[string]string{"id": rec.ID, "channel": string(rec.Channel)}})
			return nil
		})
		if err == nil {
			s.flush(wctx, ob)
		}
		stop()
		if err != nil {
			return "", err
		}
	}
	return "sent", nil
}

// onChannels lists the channels that are set up and on.
func (s *Service) onChannels(ctx context.Context) ([]channel.Type, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT type FROM notify_channel WHERE configured = 1 AND enabled = 1 ORDER BY type`)
	if err != nil {
		return nil, fmt.Errorf("notify: list channels: %w", err)
	}
	var out []channel.Type
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("notify: list channels: %w", err)
		}
		out = append(out, channel.Type(t))
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("notify: list channels: %w", err)
	}
	return out, nil
}

// buildSummary reads what the summary of [from, to) tells: the findings the not_exploited notices of the span told that are still open,
// urgent and not exploited (one that became exploited since had its own alert; one handled or no longer urgent needs nothing), then the
// counts of the other modules.
func (s *Service) buildSummary(ctx context.Context, from, to time.Time) (summaryOf, error) {
	m := summaryOf{from: from, to: to, infos: map[string]FindingInfo{}, notices: map[string][]string{}}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT n.id, nf.finding_id FROM notify_notice n JOIN notify_notice_finding nf ON nf.notice_id = n.id
		WHERE n.unsent = ? AND n.created_at >= ? AND n.created_at < ?
		AND NOT EXISTS (SELECT 1 FROM notify_send_notice sn JOIN notify_send d ON d.id = sn.send_id WHERE sn.notice_id = n.id AND d.ok = 1)
		ORDER BY n.created_at, nf.rowid`, string(UnsentNotExploited), store.FormatTS(from), store.FormatTS(to))
	if err != nil {
		return m, fmt.Errorf("notify: daily summary: %w", err)
	}
	var order []string
	for rows.Next() {
		var n, f string
		if err := rows.Scan(&n, &f); err != nil {
			_ = rows.Close()
			return m, fmt.Errorf("notify: daily summary: %w", err)
		}
		if _, seen := m.notices[f]; !seen {
			order = append(order, f)
		}
		m.notices[f] = append(m.notices[f], n)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return m, fmt.Errorf("notify: daily summary: %w", err)
	}
	if s.cfg.Findings != nil {
		for _, id := range order {
			f, ok, err := s.cfg.Findings.Finding(ctx, id)
			if err != nil {
				return m, err
			}
			if ok && f.Open && !exploitedLayer(f.Layer) && f.Layer < layerUpdate {
				m.ids, m.infos[id] = append(m.ids, id), f
			}
		}
	}
	slices.SortStableFunc(m.ids, func(a, b string) int { return m.infos[a].Layer - m.infos[b].Layer })
	src := s.cfg.Summary
	if src.Updates != nil {
		if m.updates, m.devices, err = src.Updates(ctx, from, to); err != nil {
			return m, fmt.Errorf("notify: daily summary, new findings: %w", err)
		}
	}
	if src.AIReview != nil {
		if m.review, err = src.AIReview(ctx); err != nil {
			return m, fmt.Errorf("notify: daily summary, AI answers: %w", err)
		}
	}
	if src.Exposure != nil {
		if m.exIssues, m.exPorts, err = src.Exposure(ctx, from, to); err != nil {
			return m, fmt.Errorf("notify: daily summary, external scans: %w", err)
		}
	}
	if src.AITokens != nil {
		if m.tokens, err = src.AITokens(ctx, from, to); err != nil {
			return m, fmt.Errorf("notify: daily summary, AI tokens: %w", err)
		}
	}
	return m, nil
}

// summaryLayers is the urgency layers the summary names (its findings', and update recommended for its new findings).
func summaryLayers(m summaryOf) []int {
	var out []int
	for _, id := range m.ids {
		out = append(out, m.infos[id].Layer)
	}
	if m.updates > 0 {
		out = append(out, layerUpdate)
	}
	return out
}

// summaryMessage words a summary: the counts in its text, one line per finding (as a digest line says it), the rest counted. listed is
// the findings it names, in the order of its lines.
func (s *Service) summaryMessage(ctx context.Context, id string, m summaryOf) (msg channel.Message, listed []string) {
	found := len(m.ids) + m.updates
	title := "Daily summary"
	switch {
	case found > 0:
		title += ": " + plural(found, "finding", "findings") + " not exploited in the wild"
	case m.exIssues+m.exPorts > 0:
		title += ": what external scans found, nothing exploited in the wild"
	case m.review > 0:
		title += ": " + plural(m.review, "AI answer waits", "AI answers wait") + " for your review"
	}
	loc := s.loc(ctx)
	what := []string{fmt.Sprintf("Since %s. Only findings exploited in the wild send an alert at once; this is the rest.", orgtime.Stamp(m.from, loc))}
	if n := len(m.ids); n > 0 {
		what = append(what, fmt.Sprintf("%s with a public exploit or critical on an edge device, not exploited yet.", plural(n, "finding is", "findings are")))
	}
	if m.updates > 0 {
		what = append(what, fmt.Sprintf("%s on %s with no sign of exploitation: update when you can.", plural(m.updates, "new finding", "new findings"), plural(max(m.devices, 1), "device", "devices")))
	}
	if m.exIssues+m.exPorts > 0 {
		what = append(what, fmt.Sprintf("External scans found %s and %s, none with a CVE exploited in the wild: see External exposure.",
			plural(m.exIssues, "new issue", "new issues"), plural(m.exPorts, "new open port", "new open ports")))
	}
	if m.review > 0 {
		what = append(what, plural(m.review, "answer of your AI waits", "answers of your AI wait")+" for your review in Findings.")
	}
	if m.tokens > 0 {
		what = append(what, fmt.Sprintf("Your AI used %s tokens researching CVEs.", groupDigits(m.tokens)))
	}
	msg = channel.Message{ID: id, Kind: channel.KindSummary, Severity: "info", Title: title, What: strings.Join(what, " "),
		Link: s.link(findingsListOf(summaryLayers(m)))}
	if len(m.ids) > 0 {
		msg.Action = "Plan these updates: none of them is known to be exploited yet."
	}
	for _, fid := range m.ids {
		if len(msg.Items) == channel.MaxItems {
			break
		}
		f := m.infos[fid]
		line := Notice{Product: f.Product, Devices: f.Devices, Reasons: f.Reasons, Status: f.Status, Verification: f.Verification}
		if f.CVE != "" {
			line.CVEs = []string{f.CVE}
		}
		msg.Items = append(msg.Items, itemLine(line, true))
		listed = append(listed, fid)
	}
	msg.More = len(m.ids) - len(msg.Items)
	return msg, listed
}

// groupDigits writes n with a comma between thousands (140,000).
func groupDigits(n int) string {
	s := fmt.Sprint(n)
	if n < 0 {
		return s
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return b.String()
}
