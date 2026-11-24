package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
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

// FirstRunSummary is the summary of one load as Home shows it. Its headline is the load's first look: every summary of the load made
// before one was delivered (all of them while none was), as one title that counts each finding they told once ("Patch first: …"). A
// first look told in several summaries (no channel to wait in, a pass that came while the first one was being sent) is still one look.
// Only the summaries made after one was delivered are "N more" on Home.
type FirstRunSummary struct {
	ID    string // the load's first summary's notice id: it stays the same while later passes add summaries
	Load  string // install, catalogue or source
	Title string
	At    time.Time // when the first summary was made (its load's first event)
	State string    // SummarySent, SummaryWaiting or SummaryNotSent: of the first look's delivered summary, else of its newest
	// sent: the first delivery of a summary of the load and the channels that delivered it.
	SentAt   time.Time
	Channels []channel.Type
	// waiting: when it goes out (the earliest queue row), and whether only quiet hours hold it.
	DueAt time.Time
	Quiet bool
	// not_sent: why, as the History page says it (INV-24).
	NotSent *NotSent
	// Link is the findings list of every summary of the load: /findings?tab=device&status=<the statuses they named>.
	Link string
	// Later counts the summaries of the same load made after one was delivered ("N more urgent findings…"); LaterTitle is the newest one's title.
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

// FirstRunSummary is the summary of the newest load whose summary was made at or after since; nil when there is none. A few small reads:
// the newest summary, its load's summaries and their first deliveries, the state of the one Home speaks of, the statuses the load named;
// and, when the first look is told in several summaries, the findings they told.
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
	// Each summary of the load with its first delivery, if one: as its own message, or named by one (the messages summaryState reads),
	// each on its index (notify_send_ref_ix, notify_send_notice_ix).
	rows, err := q.QueryContext(ctx, `SELECT id, created_at, title, sev, why, floor, ch, min(coalesce(own, named), coalesce(named, own)) FROM (
		SELECT n.id, n.created_at, ifnull(n.title, '') AS title, ifnull(n.severity, '') AS sev, ifnull(n.unsent, '') AS why,
			ifnull(n.unsent_floor, '') AS floor, ifnull(n.unsent_channel, '') AS ch,
			(SELECT min(d.at) FROM notify_send d WHERE d.kind = 'vuln' AND d.ref_id = n.id AND d.ok = 1) AS own,
			(SELECT min(d.at) FROM notify_send_notice sn JOIN notify_send d ON d.id = sn.send_id WHERE sn.notice_id = n.id AND d.ok = 1) AS named
		FROM notify_notice n WHERE n.event = ? AND substr(n.id, 1, ?) = ?) ORDER BY created_at, id`, string(NoticeFirstRun), len(prefix), prefix)
	if err != nil {
		return nil, fmt.Errorf("notify: read the first-run summary: %w", err)
	}
	var list []summaryRow
	for rows.Next() {
		var n summaryRow
		var sent sql.NullString
		if err := rows.Scan(&n.id, &n.at, &n.title, &n.sev, &n.why, &n.floor, &n.ch, &sent); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("notify: read the first-run summary: %w", err)
		}
		n.sent = sent.String
		list = append(list, n)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("notify: read the first-run summary: %w", err)
	}
	if len(list) == 0 {
		return nil, nil
	}
	at, err := time.Parse(time.RFC3339, list[0].at)
	if err != nil {
		return nil, fmt.Errorf("notify: read the first-run summary: %w", err)
	}
	// The first look: every summary made up to the first delivery of one of them (store.FormatTS times compare as text), all of them
	// while none was delivered. The later ones are "Since then".
	delivered := -1
	for i, n := range list {
		if n.sent != "" && (delivered < 0 || n.sent < list[delivered].sent) {
			delivered = i
		}
	}
	look := list
	if delivered >= 0 {
		look = slices.DeleteFunc(slices.Clone(list), func(n summaryRow) bool { return n.at > list[delivered].sent })
	}
	out := &FirstRunSummary{ID: list[0].id, Load: load, Title: look[0].title, At: at, Later: len(list) - len(look)}
	if len(look) > 1 {
		if out.Title, err = s.firstLookTitle(ctx, q, look); err != nil {
			return nil, err
		}
	}
	if out.Title == "" {
		out.Title = noticeWhat("", string(NoticeFirstRun), "", "[]")
	}
	if out.Later > 0 {
		out.LaterTitle = list[len(list)-1].title
	}
	state := look[len(look)-1] // none delivered: the newest says where the first look stands now
	if delivered >= 0 {
		state = list[delivered]
	}
	if err := s.summaryState(ctx, q, out, state); err != nil {
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

// summaryRow is one summary of a load as notify_notice keeps it, with its first delivery ("" when none).
type summaryRow struct {
	id, at, title, sev, why, floor, ch, sent string
}

// firstLookLookups bounds how many findings the headline of a first look told in several summaries reads to count their devices.
const firstLookLookups = 200

// firstLookTitle is the headline of a first look told in several summaries: every finding they told, once, on how many devices, in the
// words of a first summary. The findings are the ones each summary recorded (notify_notice_finding), plus the ones its title counts
// without listing them; their devices are read from the finding directory, and are at least as many as any one summary counted.
//
// Home and the menu badge read it every minute for a week after a load, and each lookup reads the finding page's data: the headline is
// kept for the summaries it counted and counted again only when a pass adds one (or a restart forgets it).
func (s *Service) firstLookTitle(ctx context.Context, q dbtx, look []summaryRow) (string, error) {
	ids := make([]string, 0, len(look))
	for _, n := range look {
		ids = append(ids, n.id)
	}
	key := strings.Join(ids, "\n")
	s.firstLook.mu.Lock()
	memo, title := s.firstLook.key, s.firstLook.title
	s.firstLook.mu.Unlock()
	if memo == key {
		return title, nil
	}
	title, err := s.countFirstLook(ctx, q, look)
	if err != nil {
		return "", err
	}
	s.firstLook.mu.Lock()
	s.firstLook.key, s.firstLook.title = key, title
	s.firstLook.mu.Unlock()
	return title, nil
}

// firstLookMemo is the last first look firstLookTitle counted: its summaries' ids and its headline.
type firstLookMemo struct {
	mu         sync.Mutex
	key, title string
}

// countFirstLook counts the headline firstLookTitle keeps.
func (s *Service) countFirstLook(ctx context.Context, q dbtx, look []summaryRow) (string, error) {
	listed := map[string][]string{} // notice id → the findings it recorded
	ids := make([]any, 0, len(look))
	marks := make([]string, 0, len(look))
	for _, n := range look {
		ids, marks = append(ids, n.id), append(marks, "?")
	}
	rows, err := q.QueryContext(ctx, `SELECT notice_id, finding_id FROM notify_notice_finding WHERE notice_id IN (`+strings.Join(marks, ", ")+`)
		ORDER BY notice_id, finding_id`, ids...)
	if err != nil {
		return "", fmt.Errorf("notify: read the first-run summary's findings: %w", err)
	}
	for rows.Next() {
		var n, f string
		if err := rows.Scan(&n, &f); err != nil {
			_ = rows.Close()
			return "", fmt.Errorf("notify: read the first-run summary's findings: %w", err)
		}
		listed[n] = append(listed[n], f)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return "", fmt.Errorf("notify: read the first-run summary's findings: %w", err)
	}
	var findings []string
	unlisted, devices := 0, 0
	for _, n := range look {
		findings = append(findings, listed[n.id]...)
		if found, dev, ok := summaryCounts(n.title); ok {
			unlisted += max(found-len(listed[n.id]), 0)
			devices = max(devices, dev)
		}
	}
	findings = dedupe(findings)
	if s.cfg.Findings != nil {
		seen := map[string]bool{}
		for _, id := range findings[:min(len(findings), firstLookLookups)] {
			f, ok, err := s.cfg.Findings.Finding(ctx, id)
			if err != nil {
				return "", err
			}
			if !ok {
				continue
			}
			for _, d := range f.Devices {
				if d = strings.TrimSpace(d); d != "" {
					seen[d] = true
				}
			}
		}
		devices = max(devices, len(seen))
	}
	found := len(findings) + unlisted
	if found == 0 {
		return look[0].title, nil
	}
	return fmt.Sprintf(summaryFirstTitle, plural(found, "urgent finding", "urgent findings"), plural(max(devices, 1), "device", "devices")), nil
}

// summaryState fills out with the state of the summary n: delivered (the first delivery and its channels), still in the queue (when it
// goes out), else why not, in the order of the History's "Not sent" list (the last failed attempt, then the decision kept at enqueue).
func (s *Service) summaryState(ctx context.Context, q dbtx, out *FirstRunSummary, n summaryRow) error {
	id, sev, why, floor, ch := n.id, n.sev, n.why, n.floor, n.ch
	// A summary goes as its own message (ref_id); notify_send_notice links the message to it too.
	const sends = `FROM notify_send d WHERE (d.ref_id = ? OR d.id IN (SELECT sn.send_id FROM notify_send_notice sn WHERE sn.notice_id = ?))`
	rows, err := q.QueryContext(ctx, `SELECT d.at, d.channel `+sends+` AND d.ok = 1 ORDER BY d.at, d.rowid`, id, id)
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
	if err := q.QueryRowContext(ctx, `SELECT min(due_at), ifnull(min(reason = 'quiet'), 0) FROM notify_pending WHERE notice_id = ?`, id).Scan(&due, &quietOnly); err != nil {
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
	err = q.QueryRowContext(ctx, `SELECT d.channel `+sends+` AND d.ok = 0 AND d.delayed = 0 ORDER BY d.at DESC, d.rowid DESC LIMIT 1`, id, id).Scan(&fch)
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
