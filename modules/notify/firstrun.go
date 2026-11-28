package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
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

// quietPrefix starts the id of the notice of a load's findings that are not exploited (INV-32): "nt-quiet-first-run-<key>-<time>", so
// no reader of the load's summaries (Home's first look, the waiting summary, "N more") counts it as one.
const quietPrefix = "nt-quiet-"

// firstRunPrefix starts the id of every summary of one load: "nt-first-run-<key>-".
func firstRunPrefix(key string) string { return "nt-first-run-" + clip(key, 80) + "-" }

// waitingSummaryWhere selects a first-run summary that no channel has taken yet: queued on at least one channel, every row still pending
// (none claimed or being sent), none queued to go now (a person's Send now: it goes as they asked, not into a summary a channel's minimum
// severity drops), no attempt recorded, no message named it.
const waitingSummaryWhere = `EXISTS (SELECT 1 FROM notify_pending p WHERE p.notice_id = n.id)
	AND NOT EXISTS (SELECT 1 FROM notify_pending p WHERE p.notice_id = n.id AND (p.state <> 'pending' OR p.reason = 'now'))
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

// waitingSummaryID is the id of the summary of the load (its id prefix) that waits in the queue now, read inside the write; "" when none.
func waitingSummaryID(ctx context.Context, tx *sql.Tx, prefix string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT n.id FROM notify_notice n WHERE substr(n.id, 1, ?) = ? AND n.event = ? AND `+waitingSummaryWhere+`
		ORDER BY n.created_at DESC, n.id DESC LIMIT 1`, len(prefix), prefix, string(NoticeFirstRun)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("notify: read the waiting first-run summary: %w", err)
	}
	return id, nil
}

// errSummaryMoved: another pass of the same load queued or replaced its waiting summary between the reads and the write.
var errSummaryMoved = errors.New("notify: the waiting first-run summary changed meanwhile")

// firstRunTries bounds how often a pass reads again after another pass of its load wrote in between.
const firstRunTries = 5

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
		Exploited  int      `json:"exploited"`
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
	// Passes of one load may be told at the same time (several devices rated at once): a pass that finds the waiting summary changed
	// when it comes to write reads again, so it joins the summary the other pass wrote instead of queuing a second one beside it.
	for try := 1; ; try++ {
		err := s.firstRunPass(ctx, e.Key, prefix, at, e.Findings, e.Exploited, e.Devices, e.Layer, e.FindingIDs, try < firstRunTries)
		if !errors.Is(err, errSummaryMoved) {
			return err
		}
	}
}

// firstRunPass is one try of urgencyFirstRun for the event of a load (its key and id prefix): eventFindings counted (eventExploited of
// them exploited), ids listed.
// retry: return errSummaryMoved when the waiting summary changed between the reads and the write (else tell what this pass has alone).
func (s *Service) firstRunPass(ctx context.Context, key, prefix string, at time.Time, eventFindings, eventExploited, eventDevices, eventLayer int, eventIDs []string,
	retry bool) error {
	waiting, err := waitingSummary(ctx, s.cfg.DB.Reader(), prefix)
	if err != nil {
		return err
	}
	// The findings as findings shows them now, read before the write: the waiting summary's and the event's.
	var ids []string
	if waiting != nil {
		ids = append(ids, waiting.FindingIDs...)
	}
	ids = dedupe(append(ids, eventIDs...))
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
	// Only a finding exploited in the wild is told in the summary (INV-32): the others of the load are one notice recorded for the
	// daily summary, which no channel takes as an alert.
	quiet := map[string]FindingInfo{}
	var quietIDs []string
	listedExploited := 0
	for _, id := range ids {
		f, ok := infos[id]
		switch {
		case !ok:
		case !f.Exploited:
			quiet[id] = f
			quietIDs = append(quietIDs, id)
			delete(infos, id)
		case slices.Contains(eventIDs, id):
			listedExploited++
		}
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		// a finding a quiet notice already told at its layer is not told again (it would be in two daily summaries)
		var fresh []string
		for _, id := range quietIDs {
			told, err := s.toldAt(ctx, tx, id)
			if err != nil {
				return err
			}
			if told == 0 || told > quiet[id].Layer {
				fresh = append(fresh, id)
			}
		}
		quietIDs := fresh
		if len(quietIDs) > 0 {
			q := s.summaryNotice(key, quietIDs, quiet, 0, 0, 0, "")
			q.ID, q.At = quietPrefix+strings.TrimPrefix(prefix, "nt-")+at.UTC().Format("20060102T150405.000"), at
			q.Title = plural(len(quietIDs), "finding", "findings") + " not exploited in the wild, for the daily summary"
			if err := s.enqueue(ctx, tx, q); err != nil {
				return err
			}
		}
		unlisted := 0 // the event counts more findings than it lists: only its exploited ones are told here
		if eventFindings > len(eventIDs) {
			unlisted = max(eventExploited-listedExploited, 0)
		}
		w := waiting
		cur, err := waitingSummaryID(ctx, tx, prefix)
		if err != nil {
			return err
		}
		switch {
		case w != nil && cur == w.ID: // still waits: this pass replaces it
		case cur != "" && retry:
			return errSummaryMoved // another pass of the load queued or replaced it meanwhile: read again
		default:
			w = nil // a run took it meanwhile: this summary tells only what came since
		}
		except := ""
		if w != nil {
			except = w.ID
		}
		// What is left to tell: the waiting summary's findings, then the event's new ones (still open at layer 1-4, not told at that
		// layer or a more urgent one by another notice).
		var waitKeep, eventKeep []string
		add := func(id string, into *[]string) error {
			f, ok := infos[id]
			if !ok || slices.Contains(waitKeep, id) || slices.Contains(eventKeep, id) {
				return nil
			}
			told, err := toldAtExcept(ctx, tx, id, except)
			if err != nil {
				return err
			}
			if told == 0 || told > f.Layer {
				*into = append(*into, id)
			}
			return nil
		}
		if w != nil {
			for _, id := range w.FindingIDs {
				if err := add(id, &waitKeep); err != nil {
					return err
				}
			}
			unlisted += max(len(w.Lines)+w.More-len(w.FindingIDs), 0)
		}
		for _, id := range eventIDs {
			if err := add(id, &eventKeep); err != nil {
				return err
			}
		}
		if len(eventKeep) == 0 {
			return nil // nothing new to tell: the waiting summary, if any, stands as it is
		}
		keep := append(waitKeep, eventKeep...)
		devices := eventDevices
		if len(keep) > maxNoticeItems { // the most urgent are listed, the rest counted
			slices.SortStableFunc(keep, func(a, b string) int { return infos[a].Layer - infos[b].Layer })
			seen := map[string]bool{}
			for _, id := range keep {
				for _, d := range infos[id].Devices {
					seen[strings.TrimSpace(d)] = true
				}
			}
			devices = max(devices, len(seen))
			unlisted += len(keep) - maxNoticeItems
			keep = keep[:maxNoticeItems]
		}
		prior, err := s.priorSummary(ctx, tx, prefix)
		if err != nil {
			return err
		}
		first := at
		if w != nil {
			if err := dropNotice(ctx, tx, w.ID); err != nil {
				return err
			}
			first = w.At
		}
		n := s.summaryNotice(key, keep, infos, unlisted, devices, eventLayer, prior)
		n.ID, n.At = prefix+at.UTC().Format("20060102T150405.000"), first
		return s.enqueue(ctx, tx, n)
	})
}

// priorSummary names the summary of the load (its id prefix) the customer already got, or is getting, for the words of the next one
// ("Since the summary sent at 10:03"; "Since the previous summary" while a delivery run is sending it); "" when there is none: the next
// summary is then the load's first look ("Patch first: …"). A summary waiting in the queue is not one: the next pass replaces it.
func (s *Service) priorSummary(ctx context.Context, tx *sql.Tx, prefix string) (string, error) {
	var sent sql.NullString // the last summary of this load a channel delivered
	if err := tx.QueryRowContext(ctx, `SELECT max(at) FROM notify_send WHERE kind = 'vuln' AND ok = 1 AND substr(ref_id, 1, ?) = ?`, len(prefix), prefix).Scan(&sent); err != nil {
		return "", fmt.Errorf("notify: read first-run summaries: %w", err)
	}
	if t, err := time.Parse(time.RFC3339, sent.String); sent.Valid && err == nil {
		return "the summary sent at " + orgtime.Stamp(t, s.loc(ctx)), nil
	}
	// Claimed or being sent by a delivery run, or queued to go now (Send now, a rate-limited retry): it is on its way.
	var going bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM notify_pending WHERE substr(notice_id, 1, ?) = ? AND (state <> 'pending' OR reason = 'now'))`,
		len(prefix), prefix).Scan(&going); err != nil {
		return "", fmt.Errorf("notify: read first-run summaries: %w", err)
	}
	if going {
		return "the previous summary", nil
	}
	return "", nil
}

// The titles of a first-run summary: the load's first look, and a later one of the same load. summaryCounts reads the counts back.
const (
	summaryFirstTitle = "Patch first: %s on %s"
	summaryMoreTitle  = "%s on %s to patch first"
)

var summaryTitleCounts = regexp.MustCompile(`^(?:Patch first: )?(\d+) (?:more )?urgent findings? on (\d+) devices?(?: to patch first)?$`)

// summaryCounts is how many findings on how many devices a first-run summary's title counts (summaryFirstTitle, summaryMoreTitle), the
// ones it lists and the ones it only counts; ok is false for a title of another form.
func summaryCounts(title string) (found, devices int, ok bool) {
	m := summaryTitleCounts.FindStringSubmatch(title)
	if m == nil {
		return 0, 0, false
	}
	found, err1 := strconv.Atoi(m[1])
	devices, err2 := strconv.Atoi(m[2])
	return found, devices, err1 == nil && err2 == nil
}

// summaryNotice words the summary of a load's findings keep (in that order of reading): most urgent first, one line each. unlisted
// findings are counted but not named (eventDevices and eventLayer then count them too); prior names the summary of the load the customer
// got or is getting (priorSummary), "" when there is none.
func (s *Service) summaryNotice(key string, keep []string, infos map[string]FindingInfo, unlisted, eventDevices, eventLayer int,
	prior string) Notice {
	keep = slices.Clone(keep)
	slices.SortStableFunc(keep, func(a, b string) int { return infos[a].Layer - infos[b].Layer })
	n := Notice{Kind: KindVuln, Event: NoticeFirstRun, Action: "Patch them from the top of this list: the most urgent come first."}
	seenDevice, seenCVE := map[string]bool{}, map[string]bool{}
	devices := 0
	for _, id := range keep {
		f := infos[id]
		n.FindingIDs = append(n.FindingIDs, id)
		n.FindingLayers = append(n.FindingLayers, f.Layer)
		n.Exploited = n.Exploited || f.Exploited
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
		n.Exploited = true // the unlisted ones are the event's exploited findings
		devices = max(devices, eventDevices)
		if eventLayer >= 1 && eventLayer < n.Layer {
			n.Layer = eventLayer
		}
	}
	n.More = found - len(n.Lines)
	n.Severity = AlertSeverity(Medium, n.Exploited)
	n.Link = s.link(findingsListOf(append(slices.Clone(n.FindingLayers), n.Layer)))
	const urgent = "as exploited in the wild" // only those are in a summary (INV-32)
	if prior != "" {
		why := "Like those, they come from the first load of a source of exploitation news, so they are listed together here instead of one alert each."
		switch {
		case key == "install":
			why = "Like those, they are flaws known before Vedette was installed that it found in its first 36 hours, so they are listed together here instead of one alert each."
		case strings.HasPrefix(key, "catalogue-"):
			why = "Like those, they come from the first load of its catalogue of vulnerabilities, so they are listed together here instead of one alert each."
		}
		n.Title = fmt.Sprintf(summaryMoreTitle, plural(found, "more urgent finding", "more urgent findings"), plural(devices, "device", "devices"))
		n.What = fmt.Sprintf("Since %s, Vedette rated %s on %s %s. %s", prior,
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
	n.Title = fmt.Sprintf(summaryFirstTitle, plural(found, "urgent finding", "urgent findings"), plural(devices, "device", "devices"))
	n.What = fmt.Sprintf("%s, so instead of one alert each, the %s it rated %s are listed together here, most urgent first.", lead,
		plural(found, "finding", "findings"), urgent)
	return n
}
