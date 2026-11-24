package ids

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// Windows of the alert list.
var windows = map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

// PageMax is the largest page of the alert list.
const PageMax = 200

// AttackWindow is how recent an alert must be for its CVE to count as attacked here (layer 1 of a finding's urgency).
const AttackWindow = 14 * 24 * time.Hour

var cveQueryRE = regexp.MustCompile(`^(?i:CVE)-\d{4}-\d{4,}$`)

// Alert is one intrusion alert as the API shows it (contract Alert).
type Alert struct {
	ID         string          `json:"id"`
	Source     string          `json:"source"`
	SID        *int64          `json:"sid"`
	Signature  string          `json:"signature"`
	Category   string          `json:"category"`
	Priority   int             `json:"priority"`
	Severity   string          `json:"severity"`
	SrcIP      string          `json:"src_ip"`
	SrcDevice  *DeviceRef      `json:"src_device"`
	DstIP      string          `json:"dst_ip"`
	DstPort    *int            `json:"dst_port"`
	Proto      string          `json:"proto"`
	DstDevice  *DeviceRef      `json:"dst_device"`
	CVEs       []string        `json:"cves"`
	Findings   []FindingLink   `json:"findings"`
	FirstSeen  string          `json:"first_seen"`
	LastSeen   string          `json:"last_seen"`
	Count      int             `json:"count"`
	Incident   *IncidentRefAPI `json:"incident"`
	srcAssetID string
	dstAssetID string
	lastTS     time.Time
}

// FindingLink is a linked finding as the API shows it.
type FindingLink struct {
	ID     string    `json:"id"`
	CVE    string    `json:"cve"`
	Device DeviceRef `json:"device"`
	Status string    `json:"status"`
}

// IncidentRefAPI is the incident of an alert as the API shows it.
type IncidentRefAPI struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// AlertsView is the answer of GET /detection/alerts.
type AlertsView struct {
	Items []Alert `json:"items"`
	Total int     `json:"total"`
}

// Query is the filter of the alert list.
type Query struct {
	Window, Q, Device, CVE, Sort string
	Offset, Limit                int
}

// affected says whether the attacked device is affected by a CVE the alert names: an open linked finding.
func (a Alert) affected(fs []LinkedFinding) bool {
	for _, f := range fs {
		if f.Affected {
			return true
		}
	}
	return false
}

// load reads the alerts whose last event is at or after since, with their CVE ids, newest first. where/args narrow it further.
func (s *Service) load(ctx context.Context, since time.Time, where string, args ...any) ([]Alert, error) {
	q := `SELECT id, source, sid, signature, category, priority, src_ip, dst_ip, dst_port, proto, coalesce(src_asset_id, ''), coalesce(dst_asset_id, ''),
		first_ts, last_ts, count, (SELECT group_concat(cve, ',') FROM (SELECT cve FROM ids_alert_cve c WHERE c.alert_id = a.id ORDER BY cve))
		FROM ids_alert a WHERE last_ts >= ?` + where + ` ORDER BY last_ts DESC, id LIMIT ?`
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, q, append(append([]any{store.FormatTS(since)}, args...), MaxAlerts)...)
	if err != nil {
		return nil, fmt.Errorf("ids: reading alerts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Alert
	for rows.Next() {
		var a Alert
		var sid, port sql.NullInt64
		var cves sql.NullString
		if err := rows.Scan(&a.ID, &a.Source, &sid, &a.Signature, &a.Category, &a.Priority, &a.SrcIP, &a.DstIP, &port, &a.Proto, &a.srcAssetID, &a.dstAssetID,
			&a.FirstSeen, &a.LastSeen, &a.Count, &cves); err != nil {
			return nil, fmt.Errorf("ids: reading alerts: %w", err)
		}
		if sid.Valid {
			v := sid.Int64
			a.SID = &v
		}
		if port.Valid {
			v := int(port.Int64)
			a.DstPort = &v
		}
		a.CVEs = []string{}
		if cves.Valid && cves.String != "" {
			a.CVEs = strings.Split(cves.String, ",")
			slices.SortFunc(a.CVEs, cmpCVE)
		}
		a.lastTS, _ = time.Parse(time.RFC3339Nano, a.LastSeen)
		a.Findings = []FindingLink{}
		out = append(out, a)
	}
	return out, rows.Err()
}

// alertKey is what one row of the alert list stands for: one signature (with the CVE ids its events name) from one source address to
// one destination address and port. The table keeps one row per hour of it (dedupe_key, so an alert's count and incident stay
// per-hour facts); a person reads the same attack repeated over hours as one alert with its count.
type alertKey struct {
	sid                 int64
	signature, src, dst string
	port                int
	proto, cves         string
}

func keyOf(a Alert) alertKey {
	k := alertKey{sid: -1, port: -1, signature: a.Signature, src: a.SrcIP, dst: a.DstIP, proto: a.Proto, cves: strings.Join(a.CVEs, ",")}
	if a.SID != nil {
		k.sid = *a.SID
	}
	if a.DstPort != nil {
		k.port = *a.DstPort
	}
	return k
}

// fold makes one row of each alert repeated over several hours: the newest hour stands for it (its id, source, category and devices),
// with the events of every hour counted, the earliest first event, and the most urgent priority. Alerts come newest first (load) and
// stay in that order.
func fold(alerts []Alert) []Alert {
	at := map[alertKey]int{}
	out := alerts[:0:0]
	for _, a := range alerts {
		k := keyOf(a)
		i, ok := at[k]
		if !ok {
			at[k] = len(out)
			out = append(out, a)
			continue
		}
		g := &out[i]
		g.Count += a.Count
		if a.FirstSeen < g.FirstSeen {
			g.FirstSeen = a.FirstSeen
		}
		if a.LastSeen > g.LastSeen {
			g.LastSeen, g.lastTS = a.LastSeen, a.lastTS
		}
		g.Priority = min(g.Priority, a.Priority)
	}
	return out
}

// cmpCVE orders CVE ids by year, then number (CVE-2021-9999 before CVE-2021-10000).
func cmpCVE(a, b string) int {
	ya, na, _ := strings.Cut(strings.TrimPrefix(a, "CVE-"), "-")
	yb, nb, _ := strings.Cut(strings.TrimPrefix(b, "CVE-"), "-")
	return cmp.Or(strings.Compare(ya, yb), cmp.Compare(len(na), len(nb)), strings.Compare(na, nb))
}

// name fills the device references of the alerts from the inventory (names are read now, so a rename shows at once).
func (s *Service) name(ctx context.Context, alerts []Alert) error {
	if s.cfg.Inventory == nil {
		return nil
	}
	set := map[string]bool{}
	for _, a := range alerts {
		for _, id := range []string{a.srcAssetID, a.dstAssetID} {
			if id != "" {
				set[id] = true
			}
		}
	}
	if len(set) == 0 {
		return nil
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	names, err := s.cfg.Inventory.Names(ctx, ids)
	if err != nil {
		return err
	}
	for i := range alerts {
		a := &alerts[i]
		if n, ok := names[a.srcAssetID]; ok && a.srcAssetID != "" {
			a.SrcDevice = &DeviceRef{ID: a.srcAssetID, Name: n}
		}
		if n, ok := names[a.dstAssetID]; ok && a.dstAssetID != "" {
			a.DstDevice = &DeviceRef{ID: a.dstAssetID, Name: n}
		}
	}
	return nil
}

// link fills the findings and the severity of the alerts and, withIncident, the incident of each.
func (s *Service) link(ctx context.Context, alerts []Alert, withIncident bool) error {
	type pair struct{ asset, cve string }
	byAsset := map[string][]string{}
	for _, a := range alerts {
		if a.DstDevice != nil && len(a.CVEs) > 0 {
			byAsset[a.dstAssetID] = append(byAsset[a.dstAssetID], a.CVEs...)
		}
	}
	found := map[pair][]LinkedFinding{}
	if s.cfg.Findings != nil && len(byAsset) > 0 {
		for asset, cves := range byAsset {
			slices.Sort(cves)
			byAsset[asset] = slices.Compact(cves)
		}
		all, err := s.cfg.Findings.Linked(ctx, byAsset) // one read for the whole page
		if err != nil {
			return err
		}
		for asset, fs := range all {
			for _, f := range fs {
				found[pair{asset, f.CVE}] = append(found[pair{asset, f.CVE}], f)
			}
		}
	}
	for i := range alerts {
		a := &alerts[i]
		var linked []LinkedFinding
		if a.DstDevice != nil {
			for _, c := range a.CVEs {
				linked = append(linked, found[pair{a.dstAssetID, c}]...)
			}
		}
		slices.SortFunc(linked, func(x, y LinkedFinding) int { return cmp.Or(cmpCVE(x.CVE, y.CVE), strings.Compare(x.ID, y.ID)) })
		for _, f := range linked {
			a.Findings = append(a.Findings, FindingLink{ID: f.ID, CVE: f.CVE, Device: *a.DstDevice, Status: f.Status})
		}
		a.Severity = prioritySeverity(a.Priority)
		if a.affected(linked) {
			a.Severity = "critical"
		}
		if withIncident && s.cfg.Incidents != nil {
			sid := int64(-1)
			if a.SID != nil {
				sid = *a.SID
			}
			source, target := IncidentKey(a.SrcIP, a.CVEs, sid, a.Signature)
			ref, ok, err := s.cfg.Incidents.Intrusion(ctx, source, target, a.lastTS)
			if err != nil {
				return err
			}
			if ok {
				a.Incident = &IncidentRefAPI{ID: ref.ID, Status: ref.Status}
			}
		}
	}
	return nil
}

func badWindow() error {
	return apierr.New(400, "bad_window", "The time range must be 24h, 7d or 30d.")
}

// List answers GET /detection/alerts: the alerts with activity in the window, filtered by a device (source or destination), a CVE
// and a search over the signature, category, addresses, device names and CVE ids; sorted by the newest last event or the most events,
// ties by id; paged.
func (s *Service) List(ctx context.Context, q Query) (AlertsView, error) {
	span, ok := windows[q.Window]
	if !ok {
		return AlertsView{}, badWindow()
	}
	where, args := "", []any{}
	if c := strings.TrimSpace(q.CVE); c != "" {
		if !cveQueryRE.MatchString(c) {
			return AlertsView{}, apierr.New(400, "invalid_cve", "A CVE ID looks like CVE-2022-27593.")
		}
		where += ` AND id IN (SELECT alert_id FROM ids_alert_cve WHERE cve = ?)`
		args = append(args, strings.ToUpper(c))
	}
	if d := q.Device; d != "" {
		where += ` AND (src_asset_id = ? OR dst_asset_id = ?)`
		args = append(args, d, d)
	}
	rows, err := s.load(ctx, s.now().Add(-span), where, args...)
	if err != nil {
		return AlertsView{}, err
	}
	rows = fold(rows)
	if err := s.name(ctx, rows); err != nil {
		return AlertsView{}, err
	}
	if needle := strings.ToLower(strings.TrimSpace(q.Q)); needle != "" {
		rows = slices.DeleteFunc(rows, func(a Alert) bool { return !a.matches(needle) })
	}
	if q.Sort == "count" {
		slices.SortStableFunc(rows, func(x, y Alert) int { return cmp.Or(cmp.Compare(y.Count, x.Count), strings.Compare(x.ID, y.ID)) })
	} else {
		slices.SortStableFunc(rows, func(x, y Alert) int {
			return cmp.Or(strings.Compare(y.LastSeen, x.LastSeen), strings.Compare(x.ID, y.ID))
		})
	}
	total := len(rows)
	limit := q.Limit
	if limit <= 0 || limit > PageMax {
		limit = PageMax
	}
	off := min(max(q.Offset, 0), total)
	page := rows[off:min(off+limit, total)]
	if err := s.link(ctx, page, true); err != nil {
		return AlertsView{}, err
	}
	return AlertsView{Items: slices.Clip(page), Total: total}, nil
}

func (a Alert) matches(needle string) bool {
	hay := []string{a.Signature, a.Category, a.SrcIP, a.DstIP}
	if a.SrcDevice != nil {
		hay = append(hay, a.SrcDevice.Name)
	}
	if a.DstDevice != nil {
		hay = append(hay, a.DstDevice.Name)
	}
	hay = append(hay, a.CVEs...)
	for _, h := range hay {
		if strings.Contains(strings.ToLower(h), needle) {
			return true
		}
	}
	return false
}

// Get answers GET /detection/alerts/{id}: the alert as the list shows it, every hour of it folded into one (fold), whichever of its
// hours the id names.
func (s *Service) Get(ctx context.Context, id string) (Alert, error) {
	one, err := s.load(ctx, time.Time{}, ` AND id = ?`, id)
	if err != nil {
		return Alert{}, err
	}
	if len(one) == 0 {
		return Alert{}, apierr.New(404, "not_found", "This alert no longer exists.")
	}
	a := one[0]
	same, err := s.load(ctx, time.Time{}, ` AND signature = ? AND sid IS ? AND src_ip = ? AND dst_ip = ? AND dst_port IS ? AND proto = ?`,
		a.Signature, a.SID, a.SrcIP, a.DstIP, a.DstPort, a.Proto)
	if err != nil {
		return Alert{}, err
	}
	rows := slices.DeleteFunc(fold(same), func(x Alert) bool { return keyOf(x) != keyOf(a) })
	if len(rows) == 0 {
		rows = one
	}
	if err := s.name(ctx, rows); err != nil {
		return Alert{}, err
	}
	if err := s.link(ctx, rows, true); err != nil {
		return Alert{}, err
	}
	return rows[0], nil
}

// Attack is one CVE fired at one address, as the alerts since a time saw it: the input of layer 1 of a finding's urgency ("under
// attack here"). DstAssetID is the device that had the address when the events arrived ("" when none did).
type Attack struct {
	CVE         string
	DstIP       string
	DstAssetID  string
	FirstSeen   time.Time
	LastSeen    time.Time
	Events      int
	LastAlertID string
}

// Attacked is the port findings reads: which CVEs were attacked here, against which address and device, and when, for the alerts
// with an event at or after since (one row per CVE and destination address, newest first). Findings decides what that means for a
// finding (layer 1: an attack in the last AttackWindow aimed at the device, or at any address while the device is affected).
func (s *Service) Attacked(ctx context.Context, since time.Time) ([]Attack, error) {
	return ReadAttacked(ctx, s.cfg.DB.Reader(), since)
}

// ReadAttacked is Attacked through q, the service's reader or a read-only handle on the same file (the selfcheck recomputes stored
// urgencies with it).
func ReadAttacked(ctx context.Context, q *sql.DB, since time.Time) ([]Attack, error) {
	rows, err := q.QueryContext(ctx, `SELECT c.cve, a.dst_ip, coalesce(max(a.dst_asset_id), ''), min(a.first_ts), max(a.last_ts), sum(a.count),
			(SELECT b.id FROM ids_alert b JOIN ids_alert_cve d ON d.alert_id = b.id WHERE d.cve = c.cve AND b.dst_ip = a.dst_ip ORDER BY b.last_ts DESC, b.id LIMIT 1)
		FROM ids_alert a JOIN ids_alert_cve c ON c.alert_id = a.id WHERE a.last_ts >= ?
		GROUP BY c.cve, a.dst_ip ORDER BY max(a.last_ts) DESC, c.cve, a.dst_ip LIMIT ?`, store.FormatTS(since), MaxAlerts)
	if err != nil {
		return nil, fmt.Errorf("ids: reading attacked CVEs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Attack
	for rows.Next() {
		var a Attack
		var first, last string
		if err := rows.Scan(&a.CVE, &a.DstIP, &a.DstAssetID, &first, &last, &a.Events, &a.LastAlertID); err != nil {
			return nil, fmt.Errorf("ids: reading attacked CVEs: %w", err)
		}
		a.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
		a.LastSeen, _ = time.Parse(time.RFC3339Nano, last)
		out = append(out, a)
	}
	return out, rows.Err()
}

// Summary is what the Intrusion detection overview shows of the module.
type Summary struct {
	Alerts, Affected int       // alerts with activity in the window, and those whose attacked device is affected by a CVE they name
	LastEvent        time.Time // the newest event of any alert (zero when none)
}

// Summarize counts the alerts with activity since a time.
func (s *Service) Summarize(ctx context.Context, since time.Time) (Summary, error) {
	rows, err := s.load(ctx, since, "")
	if err != nil {
		return Summary{}, err
	}
	rows = fold(rows)
	var sum Summary
	sum.Alerts = len(rows)
	var last string
	if err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT coalesce(max(last_ts), '') FROM ids_alert`).Scan(&last); err != nil {
		return Summary{}, fmt.Errorf("ids: reading the last alert: %w", err)
	}
	if last != "" {
		sum.LastEvent, _ = time.Parse(time.RFC3339Nano, last)
	}
	if in := s.lastInput(); in.After(sum.LastEvent) {
		sum.LastEvent = in
	}
	// Only alerts naming a CVE at a known device can be affected: link only those.
	var cand []Alert
	for _, a := range rows {
		if a.dstAssetID != "" && len(a.CVEs) > 0 {
			cand = append(cand, a)
		}
	}
	if len(cand) == 0 || s.cfg.Findings == nil {
		return sum, nil
	}
	if err := s.name(ctx, cand); err != nil {
		return Summary{}, err
	}
	if err := s.link(ctx, cand, false); err != nil { // the incident of each alert is not needed for a count
		return Summary{}, err
	}
	for _, a := range cand {
		if a.Severity == "critical" {
			sum.Affected++
		}
	}
	return sum, nil
}
