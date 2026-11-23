package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Home shows the first-run summary of the newest load (findings GET /findings/overview, wired by the binary): the box's own first look,
// a catalogue's or a source's first load. A summary is a vulnerability notice (INV-27), never an incident (INV-10).

// Summary states for Home.
const (
	SummarySent    = "sent"     // a channel delivered it
	SummaryWaiting = "waiting"  // queued: it waits for the rest of its load (settle), quiet hours, or the next deliver run
	SummaryNotSent = "not_sent" // no channel took it, or every channel that tried failed: Home shows it all the same
)

// FirstRunSummary is the summary of one load as Home shows it: its first summary (the one that says "Patch first: …"), and how many
// "N more" summaries of the same load came after it.
type FirstRunSummary struct {
	ID    string // the first summary's notice id
	Load  string // install, catalogue or source
	Title string
	At    time.Time // when the first summary was made (its load's first event)
	State string    // SummarySent, SummaryWaiting or SummaryNotSent
	// sent: the first delivery and the channels that delivered it.
	SentAt   time.Time
	Channels []channel.Type
	// waiting: when it goes out (the earliest queue row), and whether only quiet hours hold it.
	DueAt time.Time
	Quiet bool
	// not_sent: why, as the History page says it (INV-24).
	NotSent *NotSent
	// Link is the findings list of every summary of the load: /findings?tab=device&status=<the statuses they named>.
	Link string
	// Later counts the summaries of the same load made after the first ("N more urgent findings…"); LaterTitle is the newest one's title.
	Later      int
	LaterTitle string
}

// summaryStamp is the time suffix of a summary id (firstRunPass: prefix + at.Format("20060102T150405.000")).
const summaryStamp = len("20060102T150405.000")

// summaryLoad is the load kind of a summary id: "install", "catalogue" (catalogue-<day>) or "source" (<source>-<day>).
func summaryLoad(id string) (prefix, load string, ok bool) {
	const head = "nt-first-run-" // firstRunPrefix without its key
	if !strings.HasPrefix(id, head) || len(id) <= len(head)+summaryStamp+1 {
		return "", "", false
	}
	prefix = id[:len(id)-summaryStamp]
	key := strings.TrimSuffix(prefix[len(head):], "-")
	switch {
	case key == "install":
		load = "install"
	case strings.HasPrefix(key, "catalogue-"):
		load = "catalogue"
	default:
		load = "source"
	}
	return prefix, load, true
}

// FirstRunSummary is the summary of the newest load whose summary was made at or after since; nil when there is none. Five small reads:
// the newest summary, its load's summaries, the first one's deliveries and queue rows, the statuses the load named.
func (s *Service) FirstRunSummary(ctx context.Context, since time.Time) (*FirstRunSummary, error) {
	q := s.cfg.DB.Reader()
	var newest string
	err := q.QueryRowContext(ctx, `SELECT id FROM notify_notice WHERE event = ? AND created_at >= ? ORDER BY created_at DESC, id DESC LIMIT 1`,
		string(NoticeFirstRun), store.FormatTS(since)).Scan(&newest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("notify: read the first-run summary: %w", err)
	}
	prefix, load, ok := summaryLoad(newest)
	if !ok {
		return nil, nil
	}
	type notice struct {
		id, at, title, sev, why, floor, ch string
	}
	rows, err := q.QueryContext(ctx, `SELECT id, created_at, ifnull(title, ''), ifnull(severity, ''), ifnull(unsent, ''), ifnull(unsent_floor, ''),
		ifnull(unsent_channel, '') FROM notify_notice WHERE event = ? AND substr(id, 1, ?) = ? ORDER BY created_at, id`, string(NoticeFirstRun), len(prefix), prefix)
	if err != nil {
		return nil, fmt.Errorf("notify: read the first-run summary: %w", err)
	}
	var list []notice
	for rows.Next() {
		var n notice
		if err := rows.Scan(&n.id, &n.at, &n.title, &n.sev, &n.why, &n.floor, &n.ch); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("notify: read the first-run summary: %w", err)
		}
		list = append(list, n)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("notify: read the first-run summary: %w", err)
	}
	if len(list) == 0 {
		return nil, nil
	}
	first := list[0]
	at, err := time.Parse(time.RFC3339, first.at)
	if err != nil {
		return nil, fmt.Errorf("notify: read the first-run summary: %w", err)
	}
	out := &FirstRunSummary{ID: first.id, Load: load, Title: first.title, At: at, Later: len(list) - 1}
	if out.Title == "" {
		out.Title = noticeWhat("", string(NoticeFirstRun), "", "[]")
	}
	if out.Later > 0 {
		out.LaterTitle = list[len(list)-1].title
	}
	if err := s.summaryState(ctx, q, out, first.sev, first.why, first.floor, first.ch); err != nil {
		return nil, err
	}
	rows, err = q.QueryContext(ctx, `SELECT DISTINCT nf.layer FROM notify_notice_finding nf JOIN notify_notice n ON n.id = nf.notice_id
		WHERE n.event = ? AND substr(n.id, 1, ?) = ?`, string(NoticeFirstRun), len(prefix), prefix)
	if err != nil {
		return nil, fmt.Errorf("notify: read the first-run summary: %w", err)
	}
	var layers []int
	for rows.Next() {
		var l int
		if err := rows.Scan(&l); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("notify: read the first-run summary: %w", err)
		}
		layers = append(layers, l)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("notify: read the first-run summary: %w", err)
	}
	if len(layers) == 0 {
		layers = []int{1, 2, 3, 4}
	}
	out.Link = findingsListOf(layers)
	return out, nil
}

// summaryState fills the state of the summary out names: delivered (the first delivery and its channels), still in the queue (when it
// goes out), else why not, in the order of the History's "Not sent" list (the last failed attempt, then the decision kept at enqueue).
func (s *Service) summaryState(ctx context.Context, q dbtx, out *FirstRunSummary, sev, why, floor, ch string) error {
	// A summary goes as its own message (ref_id); notify_send_notice links the message to it too.
	const sends = `FROM notify_send d WHERE (d.ref_id = ? OR d.id IN (SELECT sn.send_id FROM notify_send_notice sn WHERE sn.notice_id = ?))`
	rows, err := q.QueryContext(ctx, `SELECT d.at, d.channel `+sends+` AND d.ok = 1 ORDER BY d.at, d.rowid`, out.ID, out.ID)
	if err != nil {
		return fmt.Errorf("notify: read the first-run summary's messages: %w", err)
	}
	for rows.Next() {
		var at, c string
		if err := rows.Scan(&at, &c); err != nil {
			_ = rows.Close()
			return fmt.Errorf("notify: read the first-run summary's messages: %w", err)
		}
		if out.SentAt.IsZero() {
			if out.SentAt, err = time.Parse(time.RFC3339, at); err != nil {
				_ = rows.Close()
				return fmt.Errorf("notify: read the first-run summary's messages: %w", err)
			}
		}
		if t := channel.Type(c); !slices.Contains(out.Channels, t) {
			out.Channels = append(out.Channels, t)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("notify: read the first-run summary's messages: %w", err)
	}
	if !out.SentAt.IsZero() {
		out.State = SummarySent
		return nil
	}
	var due sql.NullString
	var quietOnly bool
	if err := q.QueryRowContext(ctx, `SELECT min(due_at), ifnull(min(reason = 'quiet'), 0) FROM notify_pending WHERE notice_id = ?`, out.ID).Scan(&due, &quietOnly); err != nil {
		return fmt.Errorf("notify: read the first-run summary's queue: %w", err)
	}
	if due.Valid {
		out.State, out.Quiet = SummaryWaiting, quietOnly
		if t, err := time.Parse(time.RFC3339, due.String); err == nil {
			out.DueAt = t
		}
		return nil
	}
	out.State = SummaryNotSent
	loc := s.loc(ctx)
	var fch sql.NullString
	err = q.QueryRowContext(ctx, `SELECT d.channel `+sends+` AND d.ok = 0 AND d.delayed = 0 ORDER BY d.at DESC, d.rowid DESC LIMIT 1`, out.ID, out.ID).Scan(&fch)
	switch {
	case err == nil:
		// Home is read by every role: the failed channel only, never the error text (it can name the mail server or the webhook host);
		// the alert history, an administrator's page, has it.
		ns := noticeNotSent(UnsentFailed, Severity(sev), "", channel.Type(fch.String), "", loc)
		out.NotSent = &ns
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("notify: read the first-run summary's messages: %w", err)
	}
	reason := NotSentReason(why)
	if why == "" || reason == UnsentQueued || reason == UnsentQuietHours { // queued, then gone without a delivery: no reason was kept
		reason = UnsentUnknown
	}
	ns := noticeNotSent(reason, Severity(sev), Severity(floor), channel.Type(ch), "", loc)
	switch reason { // said of a summary, not of a finding
	case UnsentNoChannel:
		ns.Text = "Not sent: no alert channel was set up when it was made."
	case UnsentChannelsOff:
		ns.Text = "Not sent: the alert channels were turned off when it was made."
	case UnsentUnknown:
		ns.Text = "Not sent. No channel delivered it."
	}
	out.NotSent = &ns
	return nil
}
