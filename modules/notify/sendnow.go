package notify

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// SendNow sends a vulnerability notice that no channel delivered (History, Not sent) to every channel that is on, now: a person decided
// it matters, so the channels' minimum severity, quiet hours and grouping do not hold it back. It is written again from its findings as
// findings shows them now (the status, the reasons and the verification line of today), keeps its id, so the message that delivers it
// takes it off the Not sent list, and goes out with the next run of the deliver job. Refused (409) when a message already delivered it
// or has told all its findings since at their status or a more urgent one (one alert per finding), when its findings are no longer open
// at an urgent status (1-4), or when no channel is on.
func (s *Service) SendNow(ctx context.Context, actor, id string) (UnsentNotice, error) {
	db := s.cfg.DB.Reader()
	var event, title, created string
	err := db.QueryRowContext(ctx, `SELECT event, ifnull(title, ''), created_at FROM notify_notice WHERE id = ?`, id).Scan(&event, &title, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return UnsentNotice{}, notFound("No such alert. It may have been removed from the history.")
	}
	if err != nil {
		return UnsentNotice{}, fmt.Errorf("notify: read alert: %w", err)
	}
	var delivered int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM notify_send_notice sn JOIN notify_send d ON d.id = sn.send_id WHERE sn.notice_id = ? AND d.ok = 1`, id).Scan(&delivered); err != nil {
		return UnsentNotice{}, fmt.Errorf("notify: read alert: %w", err)
	}
	if delivered > 0 {
		return UnsentNotice{}, apierr.New(http.StatusConflict, "already_sent", "A message that arrived already named this alert. Use Send again on that message instead.")
	}
	if s.cfg.Findings == nil {
		return UnsentNotice{}, apierr.New(http.StatusConflict, "nothing_to_send", "Vedette cannot read the findings of this alert now.")
	}
	ids, err := noticeFindings(ctx, db, id)
	if err != nil {
		return UnsentNotice{}, err
	}
	keep, infos, urgent, err := s.untold(ctx, db, id, ids, nil)
	if err != nil {
		return UnsentNotice{}, err
	}
	if urgent > 0 && len(keep) == 0 {
		return UnsentNotice{}, apierr.New(http.StatusConflict, "already_sent", "A message that arrived since already told its findings at this status. Use Send again on that message instead.")
	}
	if len(keep) == 0 {
		return UnsentNotice{}, apierr.New(http.StatusConflict, "nothing_to_send", "Its findings are handled, or no longer exploited or urgent, so there is nothing to send.")
	}
	var n Notice
	if NoticeEvent(event) == NoticeFirstRun {
		key := strings.TrimPrefix(strings.TrimPrefix(id, quietPrefix), "nt-first-run-")
		if k := strings.LastIndex(key, "-"); k > 0 {
			key = key[:k]
		}
		n = s.summaryNotice(key, keep, infos, 0, 0, 0, "")
	} else {
		f := infos[keep[0]]
		n = Notice{Kind: KindVuln, Severity: AlertSeverity(f.Severity, f.Layer), Product: f.Product, FindingIDs: keep[:1], Devices: f.Devices,
			Title: cmp.Or(title, titleOf(f, f.CVE, "")), What: whatOf(f), Action: f.Action, Reasons: f.Reasons, Status: f.Status, Verification: f.Verification,
			Layer: f.Layer, Link: s.link("/findings/" + keep[0])}
		if f.CVE != "" {
			n.CVEs = []string{f.CVE}
		}
	}
	n.ID, n.Event, n.Forced, n.At = id, NoticeEvent(event), true, s.now()
	if err := n.validate(); err != nil {
		return UnsentNotice{}, err
	}
	raw, err := json.Marshal(n)
	if err != nil {
		return UnsentNotice{}, fmt.Errorf("notify: encode notice: %w", err)
	}
	queued := 0
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		queued = 0
		rows, err := tx.QueryContext(ctx, `SELECT type FROM notify_channel WHERE configured = 1 AND enabled = 1 ORDER BY type`)
		if err != nil {
			return fmt.Errorf("notify: list channels: %w", err)
		}
		var on []string
		for rows.Next() {
			var t string
			if err := rows.Scan(&t); err != nil {
				_ = rows.Close()
				return fmt.Errorf("notify: list channels: %w", err)
			}
			on = append(on, t)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("notify: list channels: %w", err)
		}
		if len(on) == 0 {
			return apierr.New(http.StatusConflict, "channel_not_ready", "No alert channel is on. An administrator can set one up or turn one on in Settings, Alert channels.")
		}
		now := store.FormatTS(s.now())
		for _, t := range on {
			// A row still waiting (grouping, quiet hours) goes now with today's words, a row the provider asked to wait (rate limit) when
			// that wait is over; one a run already took is left to that run.
			r, err := tx.ExecContext(ctx, `INSERT INTO notify_pending (id, channel, notice_id, notice, reason, due_at, created_at) VALUES (?, ?, ?, ?, 'now', ?, ?)
				ON CONFLICT (channel, notice_id) DO UPDATE SET notice = excluded.notice, reason = 'now',
					due_at = CASE WHEN notify_pending.attempts > 0 THEN notify_pending.due_at ELSE excluded.due_at END WHERE notify_pending.state = 'pending'`,
				store.NewID("pq"), t, id, string(raw), now, now)
			if err != nil {
				return fmt.Errorf("notify: queue notice: %w", err)
			}
			if c, _ := r.RowsAffected(); c > 0 {
				queued++
			}
		}
		if err := markUnsent(ctx, tx, id, UnsentQueued, "", ""); err != nil {
			return err
		}
		return s.record(ctx, tx, actor, "notify.notice_send_now", id, fmt.Sprintf("%s: queued on %d channel(s)", clip(n.Title, 200), queued))
	})
	if err != nil {
		return UnsentNotice{}, err
	}
	return UnsentNotice{ID: id, At: created, What: n.Title, Link: noticeLinkOf(n), NotSent: noticeNotSent(UnsentQueued, n.Severity, "", "", "", s.loc(ctx))}, nil
}

// noticeLinkOf is where the History opens a notice: its finding, or for a summary the list of what it tells.
func noticeLinkOf(n Notice) string {
	_, _, link := refOf(n)
	return link
}

// noticeFindings are the findings a notice tells, in the order it was written with.
func noticeFindings(ctx context.Context, db dbtx, id string) ([]string, error) {
	var ids []string
	rows, err := db.QueryContext(ctx, `SELECT finding_id FROM notify_notice_finding WHERE notice_id = ? ORDER BY rowid`, id)
	if err != nil {
		return nil, fmt.Errorf("notify: read alert findings: %w", err)
	}
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("notify: read alert findings: %w", err)
		}
		ids = append(ids, f)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("notify: read alert findings: %w", err)
	}
	return ids, nil
}

// untold reads the findings of notice id as findings shows them now and keeps those still worth telling: open at an urgent status
// (1-4) and not told at that status or a more urgent one by another message that arrived (one alert per finding). urgent counts the
// open urgent ones, told or not. cache, when not nil, keeps what a finding read so a list reads each finding once.
func (s *Service) untold(ctx context.Context, db dbtx, id string, ids []string, cache map[string]findingNow) (keep []string, infos map[string]FindingInfo, urgent int, err error) {
	infos = map[string]FindingInfo{}
	for _, f := range ids {
		now, ok := cache[f]
		if !ok {
			info, found, err := s.cfg.Findings.Finding(ctx, f)
			if err != nil {
				return nil, nil, 0, err
			}
			now = findingNow{info: info, found: found}
			if cache != nil {
				cache[f] = now
			}
		}
		info := now.info
		if !now.found || !info.Open || info.Layer < 1 || info.Layer >= layerUpdate {
			continue
		}
		urgent++
		// One alert per finding: one a message that arrived already told at this status or a more urgent one (a later rise) is not
		// told again.
		var told int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM notify_notice_finding nf JOIN notify_send_notice sn ON sn.notice_id = nf.notice_id
			JOIN notify_send d ON d.id = sn.send_id WHERE nf.finding_id = ? AND nf.notice_id <> ? AND nf.layer BETWEEN 1 AND ? AND d.ok = 1`,
			f, id, info.Layer).Scan(&told); err != nil {
			return nil, nil, 0, fmt.Errorf("notify: read what a finding was told at: %w", err)
		}
		if told == 0 {
			infos[f] = info
			keep = append(keep, f)
		}
	}
	return keep, infos, urgent, nil
}

// findingNow is a finding as the directory read it during one request.
type findingNow struct {
	info  FindingInfo
	found bool
}
