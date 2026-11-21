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
	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/store"
)

// GET /findings/summary (#825): Home at a glance in one read. Home is opened many times a day on a small box (it may share four
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
	Open      SummaryOpen       `json:"open"`
	Top       []SummaryItem     `json:"top"`
	Trend     []int             `json:"trend"`
	Devices   SummaryDevices    `json:"devices"`
	Alerts    *SummaryAlerts    `json:"alerts"`
	Incidents *SummaryIncidents `json:"incidents"`
	// Unchecked is the Findings "could not be checked" counts (#910 phase 1): distinct CVEs and devices of GET /findings `unchecked`.
	Unchecked   SummaryUnchecked `json:"unchecked"`
	GeneratedAt string           `json:"generated_at"`
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
	Software   string     `json:"software"` // n73: the device's software row the KEV entry is keyed to (matchedOn), "" when unknown
	Ransomware bool       `json:"ransomware"`
	Source     *string    `json:"source"` // the exploited list that names the CVE; null when it is on none
	CVSS       *CVSS      `json:"cvss"`
	FirstSeen  string     `json:"first_seen"`
	// Urgency is the finding's layer, 1 under attack here .. 5 update recommended.
	Urgency int `json:"urgency"`
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

// SummaryUnchecked counts the distinct exploited CVEs and the devices of the unchecked list (#910 phase 1).
type SummaryUnchecked struct {
	CVEs    int `json:"cves"`
	Devices int `json:"devices"`
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
		return h.withIncidents(ctx, c.val, src, notifyOn)
	}
	s, err := h.computeSummary(ctx, src, notifyOn, now)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.sum = summaryCache{val: s, gen: gen, notifyOn: notifyOn, at: now}
	h.mu.Unlock()
	return h.withIncidents(ctx, s, src, notifyOn)
}

// withIncidents is the summary with notify's open incidents read now, never from the cache (the nav badge once said 9 urgent incidents
// after every incident was resolved, because the cache follows changes of findings only). It is one count query, the same one notify
// uses for its own list (OpenIncidents), so the Incidents page, Home and the badge agree. The cached answer is not changed.
func (h *FindingHandlers) withIncidents(ctx context.Context, cached *Summary, src HomeSources, notifyOn bool) (*Summary, error) {
	if src.Incidents == nil || !notifyOn {
		return cached, nil
	}
	open, urgent, err := src.Incidents(ctx)
	if err != nil {
		return nil, fmt.Errorf("findings: summary: counting incidents: %w", err)
	}
	s := *cached
	s.Incidents = &SummaryIncidents{Open: open, Urgent: urgent}
	return &s, nil
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
	// n73: Fix first names the software, not only the KEV group ("Windows PCs and servers" on all five rows): the device's row the
	// entry is keyed to, as the finding's page names it (matchedOn). At most SummaryTop devices are read; a failed read only leaves
	// the name out. The stored entries are read once.
	var vulns []Vuln
	vulnsRead := false
	softwareOf := func(r summaryRow, k KevInfo) string {
		a, ok, err := h.inv.MatchInput(ctx, r.assetID)
		if err != nil || !ok {
			return ""
		}
		// the stored entry lets matchedOn name the matcher's row: a "Multiple Products" entry, or one reached only through NVD's list
		// (#910: no row is keyed to it), names the same row as the finding's page (review r2 M1 of #913)
		if !vulnsRead {
			vulnsRead = true
			vulns, _ = h.feed.Vulns(ctx)
		}
		var v *Vuln
		for i := range vulns {
			if vulns[i].CVE == r.cve {
				v = &vulns[i]
				break
			}
		}
		return matchedOn(a, k, v)
	}
	for _, r := range top {
		it := SummaryItem{ID: r.id, CVE: r.cve, Status: r.status, Severity: SeverityMedium, FirstSeen: store.FormatTS(r.firstSeen), Urgency: r.urgency}
		if a, ok := assets[r.assetID]; ok {
			a = shownAsset(a)
			it.Asset = &a
		}
		if k, ok := kev[r.cve]; ok {
			it.Product, it.Ransomware = productOf(k), k.Ransomware
			if it.Asset != nil {
				it.Software = softwareOf(r, k)
			}
			list := cmp.Or(k.Source, "cisa-kev")
			it.Source = &list
		}
		if c, ok := scores[r.cve]; ok {
			it.CVSS, it.Severity = &c, bandOf(c) // the CVE's CVSS band, as every reader of a finding shows it
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
	unchecked, err := h.unchecked(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("findings: summary: %w", err)
	}
	s.Unchecked = uncheckedCounts(unchecked)
	if src.Alerts != nil && notifyOn {
		sent, failed, err := src.Alerts(ctx, now.Add(-alertDays*24*time.Hour))
		if err != nil {
			return nil, fmt.Errorf("findings: summary: counting alerts: %w", err)
		}
		s.Alerts = &SummaryAlerts{Sent: sent, Failed: failed, Days: alertDays}
	}
	return s, nil // the incidents are added by withIncidents, read at every call
}

// productOf names the product as the findings list does: KEV's display name, else "<vendor> <product>".
func productOf(k KevInfo) string {
	if k.Display != "" {
		return k.Display
	}
	return k.Vendor + " " + k.Product
}

// rankOpen returns the first SummaryTop open findings: the most urgent layer first (under attack here before an update nobody attacks),
// then confirmed before suspected, then those ransomware campaigns use, then the highest
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
			cmp.Compare(a.urgency, b.urgency),
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
	firstSeen        time.Time
	urgency          int
}

// summaryData reads the open findings and the trend: at the end of each of the last SummaryDays days of the organization's time zone
// (ServiceConfig.Zone, the days Home's chart names; the last is now), how many
// findings had been first seen and were not closed yet. Two reads: the open rows (status index), and the first_seen/resolved_at of the
// rows handled inside the window (fnd_finding_resolved_ix; rows handled before the window count on no day). The last point is the open count. A finding reopened after a close
// counts as open since its first sighting (fnd_finding keeps one resolved_at): the line is a trend, the tile's number is exact.
func (s *Service) summaryData(ctx context.Context, now time.Time) ([]summaryRow, []int, error) {
	db := s.cfg.DB.Reader()
	ignored, err := s.ignoredDevices(ctx) // a person's ignored devices are left out of Home
	if err != nil {
		return nil, nil, fmt.Errorf("findings: summary: %w", err)
	}
	loc := orgtime.At(ctx, s.cfg.Zone)
	now = now.UTC()
	y, m, d := now.In(loc).Date()
	start := time.Date(y, m, d-(SummaryDays-1), 0, 0, 0, 0, loc) // midnight of the first day, in the organization's zone
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
	rows, err := db.QueryContext(ctx, `SELECT id, asset_id, cve, CASE WHEN verified = 'no' THEN 'suspected' ELSE 'confirmed' END, first_seen, urgency FROM fnd_finding WHERE state = 'open'`)
	if err != nil {
		return nil, nil, fmt.Errorf("findings: summary: open findings: %w", err)
	}
	var open []summaryRow
	for rows.Next() {
		var r summaryRow
		var fs string
		if err := rows.Scan(&r.id, &r.assetID, &r.cve, &r.status, &fs, &r.urgency); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("findings: summary: open findings: %w", err)
		}
		if r.firstSeen, err = time.Parse(time.RFC3339, fs); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("findings: summary: open findings: %w", err)
		}
		if ignored[r.assetID] {
			continue
		}
		count(r.firstSeen, time.Time{})
		open = append(open, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, nil, fmt.Errorf("findings: summary: open findings: %w", err)
	}
	rows, err = db.QueryContext(ctx, `SELECT asset_id, first_seen, resolved_at FROM fnd_finding
		WHERE state = 'handled' AND resolved_at >= ? AND first_seen <= ?`,
		store.FormatTS(start), store.FormatTS(now))
	if err != nil {
		return nil, nil, fmt.Errorf("findings: summary: trend: %w", err)
	}
	for rows.Next() {
		var asset, fs string
		var rs sql.NullString
		if err := rows.Scan(&asset, &fs, &rs); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("findings: summary: trend: %w", err)
		}
		first, err1 := time.Parse(time.RFC3339, fs)
		resolved, err2 := time.Parse(time.RFC3339, rs.String)
		if err := errors.Join(err1, err2); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("findings: summary: trend: %w", err)
		}
		if !ignored[asset] {
			count(first, resolved)
		}
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
