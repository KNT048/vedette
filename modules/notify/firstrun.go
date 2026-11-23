package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/modules/notify/channel"
)

// A first load (the box's own first look, a signal source's or the catalogue's) rates many findings urgent at once. Findings tells them
// as findings.urgency.first_run events, one per write of a pass, so one load makes several events within seconds or minutes (a pass per
// device after a match, a pass in chunks). Notify tells them as one summary message:
//   - a summary waits firstRunSettle in the queue (reason "settle"), at most firstRunSettleMax after the first event it tells;
//   - an event of the same load that comes while a summary of that load still waits replaces it with one that tells both;
//   - once a summary of the load went out, the next one says "N more" since the time it was sent; never before.
//
// Each line of a summary is a finding as a digest line says it: the status and its reasons, then the verification line.
const (
	firstRunSettle    = 2 * time.Minute
	firstRunSettleMax = 10 * time.Minute
)

// settleDue is when a first-run summary made at now goes out when its load's first summary event was at first.
func settleDue(now, first time.Time) time.Time {
	due := now.Add(firstRunSettle)
	if last := first.Add(firstRunSettleMax); last.Before(due) {
		due = last
	}
	if due.Before(now) {
		return now
	}
	return due
}

// firstRunPrefix starts the id of every summary of one load: "nt-first-run-<key>-".
func firstRunPrefix(key string) string { return "nt-first-run-" + clip(key, 80) + "-" }

// waitingSummaryWhere selects a first-run summary that no channel has taken yet: queued on at least one channel, every row still pending
// (none claimed or being sent), no attempt recorded, no message named it.
const waitingSummaryWhere = `EXISTS (SELECT 1 FROM notify_pending p WHERE p.notice_id = n.id)
	AND NOT EXISTS (SELECT 1 FROM notify_pending p WHERE p.notice_id = n.id AND p.state <> 'pending')
	AND NOT EXISTS (SELECT 1 FROM notify_send d WHERE d.kind = 'vuln' AND d.ref_id = n.id)
	AND NOT EXISTS (SELECT 1 FROM notify_send_notice sn WHERE sn.notice_id = n.id)`

// waitingSummary is the summary of the load (its id prefix) still waiting in the queue, as it was queued; nil when there is none.
func waitingSummary(ctx context.Context, q dbtx, prefix string) (*Notice, error) {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT (SELECT p.notice FROM notify_pending p WHERE p.notice_id = n.id ORDER BY p.rowid LIMIT 1)
		FROM notify_notice n WHERE substr(n.id, 1, ?) = ? AND n.event = ? AND `+waitingSummaryWhere+` ORDER BY n.created_at DESC, n.id DESC LIMIT 1`,
		len(prefix), prefix, string(NoticeFirstRun)).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("notify: read the waiting first-run summary: %w", err)
	}
	var n Notice
	if json.Unmarshal([]byte(raw), &n) != nil {
		return nil, nil // cannot be rebuilt: the queue drops it; the new summary stands alone
	}
	return &n, nil
}

// stillWaiting says whether a summary read before the write still waits (no run took it meanwhile).
func stillWaiting(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	var one int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM notify_notice n WHERE n.id = ? AND `+waitingSummaryWhere, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("notify: read the waiting first-run summary: %w", err)
	}
	return true, nil
}

// dropNotice removes a notice that never reached a channel, with its queue rows and the record of what it told.
func dropNotice(ctx context.Context, tx *sql.Tx, id string) error {
	for _, q := range []string{`DELETE FROM notify_pending WHERE notice_id = ?`, `DELETE FROM notify_notice_finding WHERE notice_id = ?`, `DELETE FROM notify_notice WHERE id = ?`} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return fmt.Errorf("notify: replace the waiting first-run summary: %w", err)
		}
	}
	return nil
}

// toldAtExcept is toldAt without what one notice told (the summary about to be replaced).
func toldAtExcept(ctx context.Context, q querier, findingID, except string) (int, error) {
	var layer sql.NullInt64
	if err := q.QueryRowContext(ctx, `SELECT min(layer) FROM notify_notice_finding WHERE finding_id = ? AND layer > 0 AND notice_id <> ?`, findingID, except).Scan(&layer); err != nil {
		return 0, fmt.Errorf("notify: read what a finding was told at: %w", err)
	}
	return int(layer.Int64), nil
}

// urgencyFirstRun turns findings.urgency.first_run into the summary of its load: what the load rated urgent on the devices, one line per
// finding, instead of one alert each. It tells only the findings still open at layer 1-4 and not already told at that layer or a more
// urgent one; each is recorded at its layer, so a later rise of it is told only when it is to a more urgent one.
func (s *Service) urgencyFirstRun(ctx context.Context, data any) error {
	var e struct {
		Key        string   `json:"key"`
		At         string   `json:"at"`
		Findings   int      `json:"findings"`
		Devices    int      `json:"devices"`
		Layer      int      `json:"layer"`
		FindingIDs []string `json:"finding_ids"`
		CVEList    []string `json:"cve_list"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.Findings <= 0 || IsBaseline(ctx) {
		return nil
	}
	if s.cfg.Findings == nil {
		s.cfg.Log.WarnContext(ctx, "finding summary skipped: no finding directory is wired")
		return nil
	}
	at, err := time.Parse(time.RFC3339Nano, e.At)
	if err != nil {
		at = s.now()
	}
	prefix := firstRunPrefix(e.Key)
	waiting, err := waitingSummary(ctx, s.cfg.DB.Reader(), prefix)
	if err != nil {
		return err
	}
	// The findings as findings shows them now, read before the write: the waiting summary's and the event's.
	var ids []string
	if waiting != nil {
		ids = append(ids, waiting.FindingIDs...)
	}
	ids = dedupe(append(ids, e.FindingIDs...))
	infos := make(map[string]FindingInfo, len(ids))
	for _, id := range ids {
		f, ok, err := s.cfg.Findings.Finding(ctx, id)
		if err != nil {
			return err
		}
		if ok && f.Open && f.Layer >= 1 && f.Layer < layerUpdate { // handled since, or dropped to "update recommended": not told
			infos[id] = f
		}
	}
	unlisted := max(e.Findings-len(e.FindingIDs), 0) // the event counts more findings than it lists
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		w := waiting
		if w != nil {
			if still, err := stillWaiting(ctx, tx, w.ID); err != nil {
				return err
			} else if !still {
				w = nil // a run took it meanwhile: this summary tells only what came since
			}
		}
		except := ""
		if w != nil {
			except = w.ID
		}
		var keep []string
		add := func(id string) error {
			f, ok := infos[id]
			if !ok || slices.Contains(keep, id) || len(keep) == maxNoticeItems {
				return nil
			}
			told, err := toldAtExcept(ctx, tx, id, except)
			if err != nil {
				return err
			}
			if told == 0 || told > f.Layer {
				keep = append(keep, id)
			}
			return nil
		}
		if w != nil {
			for _, id := range w.FindingIDs {
				if err := add(id); err != nil {
					return err
				}
			}
			unlisted += max(len(w.Lines)+w.More-len(w.FindingIDs), 0)
		}
		before := len(keep)
		for _, id := range e.FindingIDs {
			if err := add(id); err != nil {
				return err
			}
		}
		if len(keep) == before {
			return nil // nothing new to tell: the waiting summary, if any, stands as it is
		}
		var sent sql.NullString // the last summary of this load a channel delivered
		if err := tx.QueryRowContext(ctx, `SELECT max(at) FROM notify_send WHERE kind = 'vuln' AND ok = 1 AND substr(ref_id, 1, ?) = ?`, len(prefix), prefix).Scan(&sent); err != nil {
			return fmt.Errorf("notify: read first-run summaries: %w", err)
		}
		first := at
		if w != nil {
			if err := dropNotice(ctx, tx, w.ID); err != nil {
				return err
			}
			first = w.At
		}
		n := s.summaryNotice(ctx, e.Key, keep, infos, unlisted, e.Devices, e.Layer, sent)
		n.ID, n.At = prefix+at.UTC().Format("20060102T150405.000"), first
		return s.enqueue(ctx, tx, n)
	})
}

// summaryNotice words the summary of a load's findings keep (in that order of reading): most urgent first, one line each. unlisted
// findings are counted but not named (eventDevices and eventLayer then count them too); sent is when the last summary of the load was
// delivered, if one was.
func (s *Service) summaryNotice(ctx context.Context, key string, keep []string, infos map[string]FindingInfo, unlisted, eventDevices, eventLayer int,
	sent sql.NullString) Notice {
	keep = slices.Clone(keep)
	slices.SortStableFunc(keep, func(a, b string) int { return infos[a].Layer - infos[b].Layer })
	n := Notice{Kind: KindVuln, Event: NoticeFirstRun, Action: "Patch them from the top of this list: the most urgent come first."}
	seenDevice, seenCVE := map[string]bool{}, map[string]bool{}
	devices := 0
	for _, id := range keep {
		f := infos[id]
		n.FindingIDs = append(n.FindingIDs, id)
		n.FindingLayers = append(n.FindingLayers, f.Layer)
		if n.Layer == 0 || f.Layer < n.Layer {
			n.Layer = f.Layer
		}
		for _, d := range f.Devices {
			if d = strings.TrimSpace(d); d != "" && !seenDevice[d] {
				seenDevice[d] = true
				devices++
				if len(n.Devices) < maxNoticeItems {
					n.Devices = append(n.Devices, d)
				}
			}
		}
		if f.CVE != "" && !seenCVE[f.CVE] && len(n.CVEs) < maxNoticeItems {
			seenCVE[f.CVE] = true
			n.CVEs = append(n.CVEs, f.CVE)
		}
		if len(n.Lines) < channel.MaxItems {
			line := Notice{Product: f.Product, Devices: f.Devices, Reasons: f.Reasons, Status: f.Status, Verification: f.Verification}
			if f.CVE != "" {
				line.CVEs = []string{f.CVE}
			}
			n.Lines = append(n.Lines, itemLine(line, true))
		}
	}
	found := len(keep) + unlisted
	if unlisted > 0 {
		devices = max(devices, eventDevices)
		if eventLayer >= 1 && eventLayer < n.Layer {
			n.Layer = eventLayer
		}
	}
	n.More = found - len(n.Lines)
	n.Severity = AlertSeverity(Medium, n.Layer)
	n.Link = s.link(findingsListOf(append(slices.Clone(n.FindingLayers), n.Layer)))
	const urgent = "as exploited, with a public exploit or critical on an edge device"
	if t, err := time.Parse(time.RFC3339, sent.String); sent.Valid && err == nil {
		why := "Like those, they come from the first load of a source of exploitation news, so they are listed together here instead of one alert each."
		switch {
		case key == "install":
			why = "Like those, they are flaws known before Vedette was installed that it found in its first 36 hours, so they are listed together here instead of one alert each."
		case strings.HasPrefix(key, "catalogue-"):
			why = "Like those, they come from the first load of its catalogue of vulnerabilities, so they are listed together here instead of one alert each."
		}
		n.Title = fmt.Sprintf("%s on %s to patch first", plural(found, "more urgent finding", "more urgent findings"), plural(devices, "device", "devices"))
		n.What = fmt.Sprintf("Since the summary sent at %s, Vedette rated %s on %s %s. %s", orgtime.Stamp(t, s.loc(ctx)),
			plural(found, "more finding", "more findings"), plural(devices, "device", "devices"), urgent, why)
		return n
	}
	lead := "Vedette has just loaded a source of exploitation news for the first time"
	switch {
	case key == "install":
		lead = "This is Vedette's first look at your network and at its sources of exploitation news"
	case strings.HasPrefix(key, "catalogue-"):
		lead = "Vedette has just loaded its catalogue of vulnerabilities for the first time"
	}
	n.Title = fmt.Sprintf("Patch first: %s on %s", plural(found, "urgent finding", "urgent findings"), plural(devices, "device", "devices"))
	n.What = fmt.Sprintf("%s, so instead of one alert each, the %s it rated %s are listed together here, most urgent first.", lead,
		plural(found, "finding", "findings"), urgent)
	return n
}
