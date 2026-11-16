package findings

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/store"
)

// GET /findings/summary (#825): Home at a glance in one read. Home is opened many times a day on a small box (the N100 shares four
// cores with the scanners), so the answer is computed from what the box already holds, kept in memory, and dropped at every change of a
// finding (Service.gen) or after summaryTTL (the device and alert counts and the feeds data change outside this module).

// SummaryTop and SummaryDays are contract.ts SUMMARY_TOP and SUMMARY_DAYS.
const (
	SummaryTop  = 5
	SummaryDays = 30
	summaryTTL  = 60 * time.Second
	// alertDays is the window of the "alerts sent" count.
	alertDays = 7
)

// NotifyModule is the id of the module whose sent messages Home counts.
const NotifyModule = "notify"

// HomeSources are the counts of other modules GET /findings/summary carries, wired by the binary (findings imports neither inventory nor
// notify). Devices is inventory's "All" and "To review" counts; Alerts is notify's sent and failed alert messages since a time;
// Incidents is notify's open and urgent (high, critical) incidents. A nil Devices counts the devices from Inventory.AssetIDs with no
// "to review"; a nil Alerts or Incidents, or notify off, answers null for it.
type HomeSources struct {
	Devices   func(ctx context.Context) (total, pending int, err error)
	Alerts    func(ctx context.Context, since time.Time) (sent, failed int, err error)
	Incidents func(ctx context.Context) (open, urgent int, err error)
}

// SetHome registers the sources of the device and alert counts (the binary, at start-up).
func (h *FindingHandlers) SetHome(src HomeSources) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.home = src
	h.sum.val = nil
}

// Summary is contract.ts HomeSummary.
type Summary struct {
	Open        SummaryOpen       `json:"open"`
	Top         []SummaryItem     `json:"top"`
	Trend       []int             `json:"trend"`
	Devices     SummaryDevices    `json:"devices"`
	Alerts      *SummaryAlerts    `json:"alerts"`
	Incidents   *SummaryIncidents `json:"incidents"`
	GeneratedAt string            `json:"generated_at"`
}

// SummaryOpen counts the open findings.
type SummaryOpen struct {
	Total      int `json:"total"`
	Confirmed  int `json:"confirmed"`
	Devices    int `json:"devices"`
	Ransomware int `json:"ransomware"`
}

// SummaryItem is one finding of "Fix first".
type SummaryItem struct {
	ID         string     `json:"id"`
	CVE        string     `json:"cve"`
	Status     Status     `json:"status"`
	Severity   Severity   `json:"severity"`
	Asset      *AssetView `json:"asset"`
	Product    string     `json:"product"`
	Ransomware bool       `json:"ransomware"`
	Source     *string    `json:"source"`
	CVSS       *CVSS      `json:"cvss"`
	FirstSeen  string     `json:"first_seen"`
}

// SummaryDevices is inventory's counts.
type SummaryDevices struct {
	Total   int `json:"total"`
	Pending int `json:"pending"`
}

// SummaryAlerts is notify's counts over the last Days days.
type SummaryAlerts struct {
	Sent   int `json:"sent"`
	Failed int `json:"failed"`
	Days   int `json:"days"`
}

// SummaryIncidents is notify's open incidents (new or acknowledged) and, of them, the high and critical ones.
type SummaryIncidents struct {
	Open   int `json:"open"`
	Urgent int `json:"urgent"`
}

// summaryCache is the last answer, the change counter and the Notifications switch it was computed under, and when.
type summaryCache struct {
	val      *Summary
	gen      uint64
	notifyOn bool
	at       time.Time
}

// FindingsGetFindingsSummary implements findings_get_findings_summary.
func (h *FindingHandlers) FindingsGetFindingsSummary(ctx context.Context) (*oas.FindingsGetFindingsSummaryOK, error) {
	s, err := h.Summary(ctx)
	if err != nil {
		return nil, err
	}
	return Into[oas.FindingsGetFindingsSummaryOK](s)
}

// Summary returns the cached answer while no finding changed, the Notifications switch did not move and the answer is younger than
// summaryTTL, else computes it again. Concurrent
// callers wait for the one computation (sumMu), so a burst of Home views costs one.
func (h *FindingHandlers) Summary(ctx context.Context) (*Summary, error) {
	h.sumMu.Lock()
	defer h.sumMu.Unlock()
	now := h.svc.now()
	gen := h.svc.gen.Load()
	notifyOn := h.gate == nil || h.gate.Enabled(NotifyModule)
	h.mu.RLock()
	c := h.sum
	src := h.home
	h.mu.RUnlock()
	if c.val != nil && c.gen == gen && c.notifyOn == notifyOn && now.Sub(c.at) < summaryTTL && now.Sub(c.at) >= 0 {
		return c.val, nil
	}
	s, err := h.computeSummary(ctx, src, notifyOn, now)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.sum = summaryCache{val: s, gen: gen, notifyOn: notifyOn, at: now}
	h.mu.Unlock()
	return s, nil
}

func (h *FindingHandlers) computeSummary(ctx context.Context, src HomeSources, notifyOn bool, now time.Time) (*Summary, error) {
	open, trend, err := h.svc.summaryData(ctx, now)
	if err != nil {
		return nil, err
	}
	s := &Summary{Top: []SummaryItem{}, Trend: trend, GeneratedAt: store.FormatTS(now)}
	cves := make([]string, 0, len(open))
	seen := map[string]bool{}
	devices := map[string]bool{}
	for _, r := range open {
		devices[r.assetID] = true
		if r.status == StatusConfirmed {
			s.Open.Confirmed++
		}
		if !seen[r.cve] {
			seen[r.cve] = true
			cves = append(cves, r.cve)
		}
	}
	s.Open.Total, s.Open.Devices = len(open), len(devices)
	var kev map[string]KevInfo
	var scores map[string]CVSS
	if len(cves) > 0 {
		if kev, err = h.feed.KevInfo(ctx, cves); err != nil {
			return nil, fmt.Errorf("findings: summary: reading KEV entries: %w", err)
		}
		if scores, err = h.feed.CVSS(ctx, cves); err != nil {
			return nil, fmt.Errorf("findings: summary: reading CVSS scores: %w", err)
		}
	}
	for _, r := range open {
		if kev[r.cve].Ransomware {
			s.Open.Ransomware++
		}
	}
	top := rankOpen(open, kev, scores)
	ids := make([]string, 0, len(top))
	for _, r := range top {
		ids = append(ids, r.assetID)
	}
	var assets map[string]AssetView
	if len(ids) > 0 {
		if assets, err = h.inv.Assets(ctx, ids); err != nil {
			return nil, fmt.Errorf("findings: summary: reading devices: %w", err)
		}
	}
	for _, r := range top {
		it := SummaryItem{ID: r.id, CVE: r.cve, Status: r.status, Severity: r.severity, FirstSeen: store.FormatTS(r.firstSeen)}
		if a, ok := assets[r.assetID]; ok {
			a = shownAsset(a)
			it.Asset = &a
		}
		if k, ok := kev[r.cve]; ok {
			it.Product, it.Ransomware = productOf(k), k.Ransomware
			list := cmp.Or(k.Source, "cisa-kev")
			it.Source = &list
		}
		if c, ok := scores[r.cve]; ok {
			it.CVSS = &c
		}
		s.Top = append(s.Top, it)
	}
	if src.Devices != nil {
		if s.Devices.Total, s.Devices.Pending, err = src.Devices(ctx); err != nil {
			return nil, fmt.Errorf("findings: summary: counting devices: %w", err)
		}
	} else {
		all, err := h.inv.AssetIDs(ctx)
		if err != nil {
			return nil, fmt.Errorf("findings: summary: counting devices: %w", err)
		}
		s.Devices.Total = len(all)
	}
	if src.Alerts != nil && notifyOn {
		sent, failed, err := src.Alerts(ctx, now.Add(-alertDays*24*time.Hour))
		if err != nil {
			return nil, fmt.Errorf("findings: summary: counting alerts: %w", err)
		}
		s.Alerts = &SummaryAlerts{Sent: sent, Failed: failed, Days: alertDays}
	}
	if src.Incidents != nil && notifyOn {
		open, urgent, err := src.Incidents(ctx)
		if err != nil {
			return nil, fmt.Errorf("findings: summary: counting incidents: %w", err)
		}
		s.Incidents = &SummaryIncidents{Open: open, Urgent: urgent}
	}
	return s, nil
}

// productOf names the product as the findings list does: KEV's display name, else "<vendor> <product>".
func productOf(k KevInfo) string {
	if k.Display != "" {
		return k.Display
	}
	return k.Vendor + " " + k.Product
}

// rankOpen returns the first SummaryTop open findings: confirmed before suspected, then those ransomware campaigns use, then the highest
// CVSS (no score last), then the newest, then the id (a stable order between two reads).
func rankOpen(open []summaryRow, kev map[string]KevInfo, scores map[string]CVSS) []summaryRow {
	score := func(r summaryRow) float64 {
		if c, ok := scores[r.cve]; ok {
			return c.Score
		}
		return -1
	}
	b2i := func(b bool) int {
		if b {
			return 0
		}
		return 1
	}
	sorted := slices.Clone(open)
	slices.SortFunc(sorted, func(a, b summaryRow) int {
		return cmp.Or(
			cmp.Compare(b2i(a.status == StatusConfirmed), b2i(b.status == StatusConfirmed)),
			cmp.Compare(b2i(kev[a.cve].Ransomware), b2i(kev[b.cve].Ransomware)),
			cmp.Compare(score(b), score(a)),
			b.firstSeen.Compare(a.firstSeen),
			cmp.Compare(a.id, b.id),
		)
	})
	return sorted[:min(len(sorted), SummaryTop)]
}

// summaryRow is an open finding as the summary needs it.
type summaryRow struct {
	id, assetID, cve string
	status           Status
	severity         Severity
	firstSeen        time.Time
}

// summaryData reads the open findings and the trend: at the end of each of the last SummaryDays UTC days (the last is now), how many
// findings had been first seen and were not closed yet. Two reads: the open rows (status index), and the first_seen/resolved_at of the
// rows closed inside the window, one range per closed status on fnd_finding_status_resolved_idx (the statuses are listed so the index
// serves it; rows closed before the window count on no day). The last point is the open count. A finding reopened after a close
// counts as open since its first sighting (fnd_finding keeps one resolved_at): the line is a trend, the tile's number is exact.
func (s *Service) summaryData(ctx context.Context, now time.Time) ([]summaryRow, []int, error) {
	db := s.cfg.DB.Reader()
	now = now.UTC()
	start := now.Truncate(24*time.Hour).AddDate(0, 0, -(SummaryDays - 1)) // midnight UTC of the first day
	ends := make([]time.Time, SummaryDays)
	for i := range ends {
		ends[i] = start.AddDate(0, 0, i+1)
	}
	ends[SummaryDays-1] = now
	trend := make([]int, SummaryDays)
	count := func(first, resolved time.Time) {
		if resolved.After(now) { // a close stamped after now (the clock was set back) counts as closed now: the last point stays exact
			resolved = now
		}
		for i, e := range ends {
			if !first.After(e) && (resolved.IsZero() || resolved.After(e)) {
				trend[i]++
			}
		}
	}
	rows, err := db.QueryContext(ctx, `SELECT id, asset_id, cve, status, severity, first_seen FROM fnd_finding WHERE status IN ('confirmed', 'suspected')`)
	if err != nil {
		return nil, nil, fmt.Errorf("findings: summary: open findings: %w", err)
	}
	var open []summaryRow
	for rows.Next() {
		var r summaryRow
		var fs string
		if err := rows.Scan(&r.id, &r.assetID, &r.cve, &r.status, &r.severity, &fs); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("findings: summary: open findings: %w", err)
		}
		if r.firstSeen, err = time.Parse(time.RFC3339, fs); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("findings: summary: open findings: %w", err)
		}
		count(r.firstSeen, time.Time{})
		open = append(open, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, nil, fmt.Errorf("findings: summary: open findings: %w", err)
	}
	rows, err = db.QueryContext(ctx, `SELECT first_seen, resolved_at FROM fnd_finding
		WHERE status IN ('mitigated', 'patched', 'false_positive', 'not_relevant', 'risk_accepted') AND resolved_at >= ? AND first_seen <= ?`,
		store.FormatTS(start), store.FormatTS(now))
	if err != nil {
		return nil, nil, fmt.Errorf("findings: summary: trend: %w", err)
	}
	for rows.Next() {
		var fs string
		var rs sql.NullString
		if err := rows.Scan(&fs, &rs); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("findings: summary: trend: %w", err)
		}
		first, err1 := time.Parse(time.RFC3339, fs)
		resolved, err2 := time.Parse(time.RFC3339, rs.String)
		if err := errors.Join(err1, err2); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("findings: summary: trend: %w", err)
		}
		count(first, resolved)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, nil, fmt.Errorf("findings: summary: trend: %w", err)
	}
	trend[SummaryDays-1] = len(open) // now: exactly the open findings, also one first seen "after now" (clock set back)
	return open, trend, nil
}

// summaryState is the part of FindingHandlers that holds the summary: sumMu serialises the computations.
type summaryState struct {
	sumMu sync.Mutex
	sum   summaryCache
	home  HomeSources
}
