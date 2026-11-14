package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
)

// Names of the events notify listens to. core/events wants <module>.<object>.<verb>, so the two-part
// names of the CONTRACT (honeypot.hit, logs.anomaly, logs.bad_address) are spelled with a verb here;
// the producers must publish these names (see CONTRACT "Events").
const (
	EventFindingCreated       = "findings.finding.created"
	EventFindingStatusChanged = "findings.finding.status_changed"
	EventFindingRaised        = "findings.finding.severity_raised"
	EventAssetDiscovered      = "inventory.asset.discovered"
	EventAssetDeleted         = "inventory.asset.deleted"
	EventAssetApproved        = "inventory.asset.approved" // B9 (D-474): {asset_id, actor}
	EventAssetUpdated         = "inventory.asset.updated"  // {asset_id}: also what a person's Approve publishes today (D-552)
	EventAssetMerged          = "inventory.asset.merged"   // {from, into}: inventory joined two rows of one device (D-515, D-554)
	EventNewKEV               = "feeds.vuln.new_kev"
	EventHoneypotHit          = "honeypot.hit.created"
	EventLogAnomaly           = "logs.anomaly.detected"
	EventLogBadAddress        = "logs.bad_address.detected"
)

// decode reads event data, whatever Go type the producer used, through its JSON form: notify does not
// import the producing modules, only the field names they document.
func decode(data any, into any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("notify: read event data: %w", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("notify: read event data: %w", err)
	}
	return nil
}

// Subscribe registers the event handlers on bus and returns a function that removes them all. Handlers
// only record and queue (a database write); sending is the job's work, so a handler never holds the
// publisher on the network. Events are not persisted: a missed one is not replayed.
func (s *Service) Subscribe(bus Bus) (unsubscribe func()) {
	var undo []func()
	on := func(name string, fn func(ctx context.Context, data any) error) {
		undo = append(undo, bus.Subscribe(name, func(ctx context.Context, e events.Event) error {
			if !s.on() {
				return nil
			}
			return fn(ctx, e.Data)
		}))
	}
	on(EventFindingCreated, func(ctx context.Context, d any) error { return s.findingEvent(ctx, d, false) })
	on(EventFindingStatusChanged, func(ctx context.Context, d any) error { return s.findingEvent(ctx, d, true) })
	on(EventFindingRaised, s.findingRaised)
	on(EventNewKEV, s.kevEvent)
	on(EventAssetDiscovered, s.assetEvent)
	on(EventAssetDeleted, s.assetDeleted)
	on(EventAssetApproved, s.assetApproved)
	on(EventAssetUpdated, s.assetUpdated)
	on(EventAssetMerged, s.assetMerged)
	on(EventHoneypotHit, s.hitEvent)
	on(EventLogAnomaly, func(ctx context.Context, d any) error { return s.logEvent(ctx, d, IncidentLogAnomaly) })
	on(EventLogBadAddress, func(ctx context.Context, d any) error { return s.logEvent(ctx, d, IncidentBadAddress) })
	on(EventDecisionMade, s.decisionEvent)
	return func() {
		for _, u := range undo {
			u()
		}
	}
}

// kevEvent remembers an exploited vulnerability the box has just heard of (feeds.vuln.new_kev). Until a finding
// matches it to a device (findings.finding.created) it counts as one that matched nothing: HistoryView.suppressed.
func (s *Service) kevEvent(ctx context.Context, data any) error {
	var e struct {
		CVE string `json:"cve"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if kevKey(e.CVE) == "" {
		return nil
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return markKEV(ctx, tx, []string{e.CVE}, s.now(), false) })
}

// findingEvent turns findings.finding.created, and a finding that a scan has confirmed
// (status_changed to "confirmed"), into a vulnerability notice. A notice for a finding that matched
// no device is counted, not sent (INV-2).
func (s *Service) findingEvent(ctx context.Context, data any, statusChange bool) error {
	var e struct {
		FindingID string `json:"finding_id"`
		CVE       string `json:"cve"`
		Severity  string `json:"severity"`
		To        string `json:"to"`
		Reason    string `json:"reason"`
		// acceptance_expired only (D-498): who accepted the risk and its last day (YYYY-MM-DD)
		AcceptedBy    string `json:"accepted_by"`
		AcceptedUntil string `json:"accepted_until"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.FindingID == "" {
		return nil
	}
	if statusChange && e.Reason == "matches_again" { // Vedette reopened a finding it had closed as not affected (D-530)
		if IsBaseline(ctx) {
			return nil
		}
		return s.findingChange(ctx, e.FindingID, e.CVE, "", func(f FindingInfo, cve string, n *Notice) {
			n.ID += "-reopened-" + n.At.UTC().Format("20060102") // one notice per UTC day: a version that flaps between scans does not send one each time
			n.Change = "reopened, it matches again"
			n.Title = "Vedette reopened " + about(cve, f) + ": it matches again"
			n.What = "Vedette had closed this finding as not affected, and the device matches the entry again. " + f.What
		})
	}
	if statusChange && e.Reason == "acceptance_expired" { // a risk a person accepted until a day is open again (D-498, INV-21)
		if IsBaseline(ctx) {
			return nil
		}
		return s.findingChange(ctx, e.FindingID, e.CVE, "", func(f FindingInfo, cve string, n *Notice) {
			n.ID += "-expired-" + n.At.UTC().Format("20060102") // its own id: a matches_again reopen the same day is a different notice (D-498)
			n.Change = "risk acceptance ended, open again"
			n.Title = "Risk acceptance ended: " + about(cve, f) + " is open again"
			n.What = acceptedText(e.AcceptedBy, e.AcceptedUntil) + "; that date has passed. " + f.What
		})
	}
	if !statusChange && kevKey(e.CVE) != "" { // a finding exists: a device matched this CVE, so it is no longer one that matched nothing
		if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return markKEV(ctx, tx, []string{e.CVE}, s.now(), true) }); err != nil {
			return err
		}
	}
	if statusChange && e.To != "confirmed" {
		return nil
	}
	if !statusChange && IsBaseline(ctx) { // the re-match after the first CISA pull (D-78): nothing is queued, so nothing can leak later
		s.cfg.Log.DebugContext(ctx, "finding event ignored: it belongs to the first CISA pull", "finding", e.FindingID)
		return nil
	}
	if s.cfg.Findings == nil {
		s.cfg.Log.WarnContext(ctx, "finding event skipped: no finding directory is wired")
		return nil
	}
	f, ok, err := s.cfg.Findings.Finding(ctx, e.FindingID)
	if err != nil || !ok {
		return err
	}
	sev := f.Severity
	if !sev.Valid() {
		sev = Severity(e.Severity)
	}
	cve := f.CVE
	if cve == "" {
		cve = e.CVE
	}
	n := Notice{ID: "nt-" + e.FindingID, Kind: KindVuln, Severity: sev, Product: f.Product, FindingIDs: []string{e.FindingID}, Devices: f.Devices,
		Title: f.Title, What: f.What, Action: f.Action, Link: s.link("/findings/" + e.FindingID), At: s.now()}
	if cve != "" {
		n.CVEs = []string{cve}
	}
	if statusChange {
		n.ID += "-confirmed"
		n.What = "A scan confirmed that this flaw is present. " + n.What
	}
	return s.Publish(ctx, n)
}

// findingRaised turns findings.finding.severity_raised (a re-match found the finding more serious: the installed version is
// in the affected range, or ransomware / a high EPSS made it critical) into a notice, as for a new finding. The id carries the
// new severity, so the same raise is sent once and a later raise to a higher level is told again. The text is derived from the
// event only: the two severities and the basis.
func (s *Service) findingRaised(ctx context.Context, data any) error {
	var e struct {
		FindingID    string `json:"finding_id"`
		CVE          string `json:"cve"`
		FromSeverity string `json:"from_severity"`
		ToSeverity   string `json:"to_severity"`
		Basis        string `json:"basis"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	to := Severity(e.ToSeverity)
	if e.FindingID == "" || !to.Valid() {
		return nil
	}
	if IsBaseline(ctx) {
		return nil
	}
	return s.findingChange(ctx, e.FindingID, e.CVE, to, func(f FindingInfo, cve string, n *Notice) {
		n.ID += "-raised-" + string(to)
		was := ""
		if Severity(e.FromSeverity).Valid() {
			was = " (was " + e.FromSeverity + ")"
		}
		n.Change = "now " + string(to) + was
		n.Title = about(cve, f) + " is now " + string(to) + was
		why := "Vedette checked again and found stronger evidence that this device is affected."
		if e.Basis == "version" {
			why = "The installed version is in the range that the vendor lists as affected."
		}
		n.What = why + " " + f.What
	})
}

// acceptedText is "<who> accepted this risk until <12 Feb 2027>" from the event's fields, each optional.
func acceptedText(by, until string) string {
	who := strings.TrimSpace(by)
	if who == "" || len(who) > 320 {
		who = "Someone"
	}
	out := who + " accepted this risk"
	if d, err := time.Parse(time.DateOnly, until); err == nil {
		out += " until " + d.Format("2 Jan 2006")
	}
	return out
}

// about names a finding in a sentence: "CVE-2026-1 on NAS-01".
func about(cve string, f FindingInfo) string {
	out := cve
	if out == "" {
		out = "A finding"
	}
	if len(f.Devices) > 0 {
		out += " on " + strings.Join(f.Devices, ", ")
	}
	return out
}

// findingChange builds the notice of a finding that changed (raised, reopened) the way findingEvent builds a new one: same
// directory lookup, device names, severity (override when not empty), link and path through Publish; shape sets the id suffix and text.
func (s *Service) findingChange(ctx context.Context, id, eventCVE string, override Severity, shape func(f FindingInfo, cve string, n *Notice)) error {
	if s.cfg.Findings == nil {
		s.cfg.Log.WarnContext(ctx, "finding event skipped: no finding directory is wired")
		return nil
	}
	f, ok, err := s.cfg.Findings.Finding(ctx, id)
	if err != nil || !ok {
		return err
	}
	sev := override
	if !sev.Valid() {
		sev = f.Severity
	}
	if !sev.Valid() {
		return nil
	}
	cve := f.CVE
	if cve == "" {
		cve = eventCVE
	}
	n := Notice{ID: "nt-" + id, Kind: KindVuln, Severity: sev, Product: f.Product, FindingIDs: []string{id}, Devices: f.Devices,
		Title: f.Title, What: f.What, Action: f.Action, Link: s.link("/findings/" + id), At: s.now()}
	if cve != "" {
		n.CVEs = []string{cve}
	}
	shape(f, cve, &n)
	return s.Publish(ctx, n)
}

// assetEvent opens an unknown_device incident for a newly discovered device when the notify_new setting
// of inventory was on at that moment (the event says so). During the first discovery every device is new, so they go into one
// summary incident instead (firstDiscovery, D-483); so does a device that a sensor found while it was learning the network (learning:
// its source first reported to the box less than 36 hours ago, inventory INV-28, D-554), whenever that sensor was added.
func (s *Service) assetEvent(ctx context.Context, data any) error {
	var e struct {
		AssetID  string `json:"asset_id"`
		Notify   bool   `json:"notify"`
		Learning bool   `json:"learning"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if !e.Notify || e.AssetID == "" {
		return nil
	}
	name := e.AssetID
	if s.cfg.Devices != nil {
		states, err := s.cfg.Devices.DeviceStates(ctx, []string{e.AssetID})
		if err != nil {
			return err
		}
		if st, ok := states[e.AssetID]; ok && st.Name != "" {
			name = deviceLabel(st)
		}
	}
	first := e.Learning
	if !first {
		var err error
		if first, err = s.firstDiscovery(ctx); err != nil {
			return err
		}
	}
	if first {
		return s.discoveryIncident(ctx, Device{ID: e.AssetID, Name: name})
	}
	title, what := newDeviceTexts(name)
	_, _, err := s.OpenIncident(ctx, IncidentInput{Kind: IncidentUnknownDevice, Source: e.AssetID, Title: title, Severity: Medium, What: what,
		Action: "Find out whose device it is. Add it to the inventory if it belongs to you, otherwise remove it from the network.",
		Link:   "/devices/" + e.AssetID, Devices: []Device{{ID: e.AssetID, Name: name}}})
	return err
}

// deviceLabel names a device on its new-device incidents (D-552, W8-2): the name the Devices page shows (inventory's one naming rule,
// so a host name learnt later or a name typed by hand shows), then its address when that is not the name already: "byn
// (192.168.18.181)", "Hon Hai Precision Ind. Co.,Ltd. (192.168.18.181)", "192.168.18.254".
func deviceLabel(st DeviceState) string {
	if st.Address != "" && st.Address != st.Name {
		return clip(st.Name+" ("+st.Address+")", 200)
	}
	return clip(st.Name, 200)
}

// newDeviceTexts are the title and what of a device's own new-device incident; the title is cut to the 200 characters OpenIncident takes.
func newDeviceTexts(label string) (title, what string) {
	return clip("A new unknown device appeared: "+label, 200), "A device that is not in your inventory joined the network: " + label + "."
}

// approvedInDevices closes a device's new-device incident when inventory.asset.updated shows the device approved (D-552): that event
// does not say who approved it.
const approvedInDevices = "Closed by Vedette: the device was approved in Devices."

// assetUpdated follows a device that changed in Devices (inventory.asset.updated {asset_id}, D-552): a person's Approve publishes it
// (B9's inventory.asset.approved is not published yet). When the device is on an open new-device incident, the incident takes the
// name Devices shows now, and an approved device leaves it as INV-22 (1) says (approvedInDevices). An update of a device on no open
// new-device incident, the usual case, costs one indexed read and no inventory read; nothing changed means no write. A deleted
// device is INV-20's.
func (s *Service) assetUpdated(ctx context.Context, data any) error {
	var e struct {
		AssetID string `json:"asset_id"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.AssetID == "" || s.cfg.Devices == nil {
		return nil
	}
	rows, err := s.openDeviceRows(ctx, e.AssetID)
	if err != nil || len(rows) == 0 {
		return err
	}
	states, err := s.cfg.Devices.DeviceStates(ctx, []string{e.AssetID})
	if err != nil {
		return err
	}
	st, ok := states[e.AssetID]
	if !ok || !needsFollow(st, rows) {
		return nil
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return s.followDevice(ctx, tx, e.AssetID, st) })
}

// newDeviceKey is the dedupe key of a device's own new-device incident (source = asset id) or, for firstDiscoverySource, of the
// first-discovery summary: the open one is found through the unique index on open keys.
func newDeviceKey(source string) string {
	return dedupeKey(IncidentInput{Kind: IncidentUnknownDevice, Source: source})
}

// openDeviceRow is one device line of an open new-device incident (its own incident, or the first-discovery summary: link /devices).
type openDeviceRow struct {
	asset, link, title, name string
	firstSeen, active        string // active: when the box last saw it or a person reopened it (INV-22)
}

// openDeviceRows reads the device lines of the open new-device incidents: of one device (through the open dedupe keys of its own
// incident and of the summary, an indexed read), or of every device when assetID is "", oldest incident first.
func (s *Service) openDeviceRows(ctx context.Context, assetID string) ([]openDeviceRow, error) {
	q := `SELECT d.asset_id, i.link, i.title, d.name, i.first_seen, COALESCE(i.active_at, i.last_seen) FROM notify_incident i
		JOIN notify_incident_device d ON d.incident_id = i.id WHERE i.kind = ? AND i.status <> 'resolved'`
	args := []any{string(IncidentUnknownDevice)}
	if assetID != "" {
		q += ` AND i.dedupe_key IN (?, ?) AND d.asset_id = ?`
		args = append(args, newDeviceKey(assetID), newDeviceKey(firstDiscoverySource), assetID)
	}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, q+` ORDER BY i.first_seen, d.asset_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("notify: find the incidents of a device: %w", err)
	}
	var out []openDeviceRow
	for rows.Next() {
		var r openDeviceRow
		if err := rows.Scan(&r.asset, &r.link, &r.title, &r.name, &r.firstSeen, &r.active); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("notify: find the incidents of a device: %w", err)
		}
		out = append(out, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("notify: find the incidents of a device: %w", err)
	}
	return out, nil
}

// reopenedSinceApproval says whether a device's own new-device incident showed life after the device was approved: a person reopened
// it (active_at), or the device was found again. Vedette then leaves it open: the person took it back (Opus review LOW-2 of D-552).
// Approved at an unknown time (before D-471), any reopen counts.
func reopenedSinceApproval(approvedAt time.Time, firstSeen, active string) bool {
	since := firstSeen
	if !approvedAt.IsZero() {
		since = max(since, store.FormatTS(approvedAt))
	}
	return active > since
}

// needsFollow says whether followDevice would change anything for these device lines: a label that differs from the one Devices
// gives now, or an approved device on an incident Vedette may close. Nothing to change means no write transaction.
func needsFollow(st DeviceState, rows []openDeviceRow) bool {
	label := deviceLabel(st)
	title, _ := newDeviceTexts(label)
	for _, r := range rows {
		own := r.link != "/devices"
		if st.Name != "" && (r.name != label || (own && r.title != title)) {
			return true
		}
		if st.Approved && (!own || !reopenedSinceApproval(st.ApprovedAt, r.firstSeen, r.active)) {
			return true
		}
	}
	return false
}

// followDevice brings the open new-device incidents of a device up to date with Devices (D-552): the device's own incident and its
// entry on the first-discovery summary take its current label, and an approved device leaves them (leaveDevice, INV-22), except an
// own incident a person reopened after the approval. Nothing is sent; a renamed incident keeps its history.
func (s *Service) followDevice(ctx context.Context, tx *sql.Tx, assetID string, st DeviceState) error {
	if st.Name != "" {
		label := deviceLabel(st)
		title, what := newDeviceTexts(label)
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET title = ?, what = ? WHERE dedupe_key = ? AND status <> 'resolved' AND (title <> ? OR what <> ?)`,
			title, what, newDeviceKey(assetID), title, what); err != nil {
			return fmt.Errorf("notify: rename a new-device incident: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident_device SET name = ? WHERE asset_id = ? AND name <> ? AND incident_id IN
			(SELECT id FROM notify_incident WHERE dedupe_key IN (?, ?) AND status <> 'resolved')`,
			label, assetID, label, newDeviceKey(assetID), newDeviceKey(firstDiscoverySource)); err != nil {
			return fmt.Errorf("notify: rename a discovered device: %w", err)
		}
	}
	if !st.Approved {
		return nil
	}
	return s.leaveDevice(ctx, tx, assetID, approvedInDevices, &st.ApprovedAt)
}

// assetDeleted takes a device deleted in Devices off the open new-device incidents (W6-3, D-497, INV-20): see leaveDeviceIncidents.
func (s *Service) assetDeleted(ctx context.Context, data any) error {
	var e struct {
		AssetID string `json:"asset_id"`
		Actor   string `json:"actor"` // B9 (D-474) adds who deleted it; older producers leave it out
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	return s.leaveDeviceIncidents(ctx, e.AssetID, deletedInDevices+byActor(e.Actor)+".")
}

// assetApproved takes a device a person approved in Devices (inventory.asset.approved {asset_id, actor}, B9 / D-474) off the open
// new-device incidents the way a delete does (D-550, INV-22): there is nothing left to approve.
func (s *Service) assetApproved(ctx context.Context, data any) error {
	var e struct {
		AssetID string `json:"asset_id"`
		Actor   string `json:"actor"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	by := byActor(e.Actor)
	if err := s.leaveDeviceIncidents(ctx, e.AssetID, "Closed by Vedette: the device was approved"+by+"."); err != nil || by == "" {
		return err
	}
	// The inventory.asset.updated of the same approval may have come first and closed the incident without the person (D-552): name
	// them in its reason now. No second close and no second audit row; only a close of the last minute, so an old approval is never
	// credited to whoever approves the device again later.
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET resolved_reason = replace(resolved_reason, ?, ?) WHERE dedupe_key = ? AND status = 'resolved'
			AND handled_by = ? AND handled_at >= ? AND substr(resolved_reason, 1, ?) = ?`,
			"the device was approved in Devices", "the device was approved"+by, newDeviceKey(e.AssetID), systemUser,
			store.FormatTS(s.now().Add(-time.Minute)), len(approvedInDevices)-1, strings.TrimSuffix(approvedInDevices, ".")); err != nil {
			return fmt.Errorf("notify: name who approved a device: %w", err)
		}
		return nil
	})
}

// deletedInDevices starts the reason of a device's own new-device incident closed by inventory.asset.deleted (assetDeleted).
const deletedInDevices = "Closed by Vedette: the device was deleted in Devices"

// assetMerged takes the row inventory joined into another device (inventory.asset.merged {from, into}, D-515) off the open new-device
// incidents like a delete (INV-20), with the reason that says where it went (D-554): "Closed by Vedette: merged into <name>.". The
// device it joined keeps its own incident: it is still to approve. Inventory also publishes inventory.asset.deleted for from, in
// either order: when the delete came first and closed from's own incident (within the last minute), only its reason is rewritten, so
// there is one close and one audit row, as the approver rewrite of D-552 does.
func (s *Service) assetMerged(ctx context.Context, data any) error {
	var e struct {
		From string `json:"from"`
		Into string `json:"into"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.From == "" || e.From == e.Into {
		return nil
	}
	into := "another device in Devices"
	if s.cfg.Devices != nil && e.Into != "" {
		states, err := s.cfg.Devices.DeviceStates(ctx, []string{e.Into})
		if err != nil {
			return err
		}
		if st, ok := states[e.Into]; ok && st.Name != "" {
			into = deviceLabel(st)
		}
	}
	reason := "Closed by Vedette: merged into " + into + "."
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := s.leaveDevice(ctx, tx, e.From, reason, nil); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET resolved_reason = ? WHERE dedupe_key = ? AND status = 'resolved'
			AND handled_by = ? AND handled_at >= ? AND substr(resolved_reason, 1, ?) = ?`,
			clip(reason, maxNote), newDeviceKey(e.From), systemUser, store.FormatTS(s.now().Add(-time.Minute)), len(deletedInDevices), deletedInDevices); err != nil {
			return fmt.Errorf("notify: say where a merged device went: %w", err)
		}
		return nil
	})
}

// byActor is " by <who>" from an event's actor (a user name or email that inventory sends), cut to size and stripped of control
// characters; "" when there is none.
func byActor(actor string) string {
	who := strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) { // Cf: bidi overrides (U+202E) and other invisible format characters
			return -1
		}
		return r
	}, actor))
	if who == "" {
		return ""
	}
	return " by " + clip(who, 120)
}

// leaveDeviceIncidents takes a device off the open new-device incidents (INV-20, INV-22): the first-discovery summary drops it from
// its list and its count (and is resolved when no device is left), and the device's own "new unknown device" incident is resolved
// by Vedette with reason. Resolved incidents and the other kinds keep the device: they are history. Nothing is sent.
func (s *Service) leaveDeviceIncidents(ctx context.Context, assetID, reason string) error {
	if assetID == "" {
		return nil
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return s.leaveDevice(ctx, tx, assetID, reason, nil) })
}

// leaveDevice is leaveDeviceIncidents inside a transaction. With approvedAt (the device's approval as an update showed it, D-552), the
// device's own incident stays open when a person reopened it after that approval (reopenedSinceApproval).
func (s *Service) leaveDevice(ctx context.Context, tx *sql.Tx, assetID, reason string, approvedAt *time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT i.id, i.title, i.link, i.first_seen, COALESCE(i.active_at, i.last_seen) FROM notify_incident i JOIN notify_incident_device d ON d.incident_id = i.id
		WHERE i.kind = ? AND i.status <> 'resolved' AND d.asset_id = ?`, string(IncidentUnknownDevice), assetID)
	if err != nil {
		return fmt.Errorf("notify: find the incidents of a device: %w", err)
	}
	type open struct{ id, title, link, firstSeen, active string }
	var list []open
	for rows.Next() {
		var o open
		if err := rows.Scan(&o.id, &o.title, &o.link, &o.firstSeen, &o.active); err != nil {
			_ = rows.Close()
			return fmt.Errorf("notify: find the incidents of a device: %w", err)
		}
		list = append(list, o)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("notify: find the incidents of a device: %w", err)
	}
	for _, o := range list {
		if o.link != "/devices" { // the device's own incident: nothing is left to approve
			if approvedAt != nil && reopenedSinceApproval(*approvedAt, o.firstSeen, o.active) {
				continue
			}
			if err := s.closeBySystem(ctx, tx, o.id, o.title, reason); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM notify_incident_device WHERE incident_id = ? AND asset_id = ?`, o.id, assetID); err != nil {
			return fmt.Errorf("notify: take a device off the summary: %w", err)
		}
		var n, count int // count can be above the listed rows: the list stops at maxDiscoveryDevices
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM notify_incident_device WHERE incident_id = ?), count FROM notify_incident WHERE id = ?`, o.id, o.id).Scan(&n, &count); err != nil {
			return fmt.Errorf("notify: count discovered devices: %w", err)
		}
		n = max(n, count-1)
		if n == 0 {
			if err := s.closeBySystem(ctx, tx, o.id, o.title, "Closed by Vedette: every device on it was approved or deleted in Devices."); err != nil {
				return err
			}
			continue
		}
		title := fmt.Sprintf("%d devices found on your network: approve them in Devices", n)
		if n == 1 {
			title = "1 device found on your network: approve it in Devices"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET title = ?, count = ? WHERE id = ?`, title, n, o.id); err != nil {
			return fmt.Errorf("notify: name discovered devices: %w", err)
		}
	}
	return nil
}

const (
	// firstDiscoveryWindow is how long after notify first ran on the box new devices go into the one summary (D-483): the passive
	// sensor finds most devices in the first hours, the active sensor (23:00-05:00 by default) the rest the first night.
	firstDiscoveryWindow = 36 * time.Hour
	firstDiscoverySource = "first-discovery" // the source of the summary incident: one per box while it is open
	maxDiscoveryDevices  = 500               // devices listed on the summary; the count goes on
	discoveryUpdateEvery = time.Hour         // the summary tells people again when it grew, at most this often
)

// firstDiscovery reports whether a new device belongs to the first discovery: notify first ran on this box (notify_box, migration
// 0011: an upgraded box takes its earliest notify record) less than firstDiscoveryWindow ago. A box that turns new-device alerts on
// later, or whose incidents passed retention, never opens the window again. A sensor's own first 36 hours come from inventory instead
// (AssetEvent.Learning, D-554), so a setup finished days after the install, or a sensor added later, still folds its first sweep.
func (s *Service) firstDiscovery(ctx context.Context) (bool, error) {
	var first string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT first_run_at FROM notify_box WHERE id = 1`).Scan(&first)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("notify: read first discovery: %w", err)
	}
	at, err := time.Parse(time.RFC3339Nano, first)
	if err != nil {
		return false, nil
	}
	return s.now().Sub(at) < firstDiscoveryWindow, nil
}

// discoveryIncident adds a device to the summary incident of the first discovery: the first device opens it (and its one message goes
// out, if the channels take medium), the next ones add to its list and count, and its title says how many there are. When it grew
// since its last message and that was at least discoveryUpdateEvery ago, it tells people again with the new count, so a device found
// at hour 20 is not silent. ponytail: the update goes with a new device, so devices found within the hour after an update wait for the
// next one (they are on the incident at once); upgrade path: a due update row in notify_pending.
func (s *Service) discoveryIncident(ctx context.Context, d Device) error {
	id, created, err := s.OpenIncident(ctx, IncidentInput{Kind: IncidentUnknownDevice, Source: firstDiscoverySource, Severity: Medium,
		Title: "Devices found on your network: approve them in Devices",
		What: "This is the first look of Vedette or of one of its sensors at your network, so every device it finds is new. Instead of one alert per " +
			"device, the devices found in the first 36 hours are listed together here.",
		Action: "Open Devices, approve the devices you know, and find out about the ones you do not.",
		Link:   "/devices", Devices: []Device{d}})
	if err != nil || id == "" {
		return err
	}
	now := s.now()
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM notify_incident_device WHERE incident_id = ?`, id).Scan(&n); err != nil {
			return fmt.Errorf("notify: count discovered devices: %w", err)
		}
		if n < maxDiscoveryDevices {
			r, err := tx.ExecContext(ctx, `INSERT INTO notify_incident_device (incident_id, asset_id, name) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, id, d.ID, d.Name)
			if err != nil {
				return fmt.Errorf("notify: add discovered device: %w", err)
			}
			if c, _ := r.RowsAffected(); c == 1 {
				n++
			}
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count FROM notify_incident WHERE id = ?`, id).Scan(&count); err != nil {
			return fmt.Errorf("notify: count discovered devices: %w", err)
		}
		count = max(n, count)
		title := fmt.Sprintf("%d devices found on your network: approve them in Devices", count)
		if count == 1 {
			title = "1 device found on your network: approve it in Devices"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET title = ? WHERE id = ?`, title, id); err != nil {
			return fmt.Errorf("notify: name discovered devices: %w", err)
		}
		if created { // its first message is queued by OpenIncident
			_, err := tx.ExecContext(ctx, `UPDATE notify_box SET discovery_told_at = ?, discovery_told_count = ? WHERE id = 1`, store.FormatTS(now), count)
			return err
		}
		var toldAt sql.NullString
		var told int
		if err := tx.QueryRowContext(ctx, `SELECT discovery_told_at, discovery_told_count FROM notify_box WHERE id = 1`).Scan(&toldAt, &told); err != nil {
			return fmt.Errorf("notify: read discovery updates: %w", err)
		}
		last, _ := time.Parse(time.RFC3339Nano, toldAt.String)
		if count <= told || now.Sub(last) < discoveryUpdateEvery {
			return nil
		}
		if err := s.enqueue(ctx, tx, Notice{ID: id, Kind: KindIncident, IncidentKind: string(IncidentUnknownDevice), Severity: Medium, Title: title,
			What:   fmt.Sprintf("%s since the last message. Vedette lists the devices of a first look at your network together for 36 hours.", plural(count-told, "more device found", "more devices found")),
			Action: "Open Devices, approve the devices you know, and find out about the ones you do not.", Link: s.link("/incidents/" + id), At: now}); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE notify_box SET discovery_told_at = ?, discovery_told_count = ? WHERE id = 1`, store.FormatTS(now), count)
		return err
	})
}

// hitEvent opens a trap incident for a honeypot hit (S-HP-1). Every text from the event is data from the
// network: it is cut to size and rendered as plain text by the adapters.
func (s *Service) hitEvent(ctx context.Context, data any) error {
	var e struct {
		ID         string `json:"id"`
		TS         string `json:"ts"`
		Kind       string `json:"kind"`
		Service    string `json:"service"`
		SrcIP      string `json:"src_ip"`
		Label      string `json:"label"`
		Decoy      string `json:"decoy"`
		SrcAssetID string `json:"src_asset_id"`
		SrcName    string `json:"src_name"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.ID == "" || e.SrcIP == "" {
		return nil
	}
	src, label := clip(strings.TrimSpace(e.SrcIP), 45), clip(strings.TrimSpace(e.Label), 120)
	if label == "" {
		label = "honeypot"
	}
	title := src + " touched the " + label + " trap"
	what := src + " connected to the trap " + label + ". Nobody uses this trap, so it usually means a machine is infected or someone is probing the network."
	if e.Kind == "token" { // a honey token: the label is "URL token <name>", "File token <name>", ... (honeypot tokenLabel)
		verb := "used"
		if strings.HasPrefix(label, "URL token ") || strings.HasPrefix(label, "File token ") {
			verb = "opened"
		}
		title = src + " " + verb + " the " + label
		what = src + " " + verb + " the " + label + ". It is bait nobody has a reason to touch, so someone is reading where it was planted, or a machine there is infected."
	}
	var devs []Device // W1-13: the incident names the source device the inventory knew when the hit was stored
	if id, name := clip(strings.TrimSpace(e.SrcAssetID), 64), clip(strings.TrimSpace(e.SrcName), 120); id != "" && name != "" {
		devs = []Device{{ID: id, Name: name}}
	}
	at, _ := time.Parse(time.RFC3339, e.TS) // zero = now
	in := IncidentInput{Kind: IncidentTrap, Source: src, Target: label + "|" + e.Service,
		Title: title, Severity: Critical, What: what,
		Action: "Take the machine off the network (unplug the cable, turn off Wi-Fi), then ask its user what they were doing. Do not change passwords from that machine.",
		Link:   "/honeypot/hits/" + e.ID, Devices: devs, At: at}
	if e.Kind == "scan" { // W1-13: one High incident per scanning source while it is open; the touches themselves stay Critical
		decoys := clip(strings.TrimSpace(e.Decoy), 120)
		in.Target, in.Severity = "scan", High
		in.Title = src + " scanned the Trap IPs"
		in.What = src + " touched several Trap IPs within a minute (" + decoys + "). Nobody uses them, so a machine is mapping your network: often malware looking for its next target, or someone probing."
	}
	_, _, err := s.OpenIncident(ctx, in)
	return err
}

// logEvent opens an incident from a logs event. The logs module sends the description ready-made
// (it knows the logs): source and target make the dedupe key.
func (s *Service) logEvent(ctx context.Context, data any, kind IncidentKind) error {
	var e struct {
		Source   string   `json:"source"`
		Target   string   `json:"target"`
		Title    string   `json:"title"`
		What     string   `json:"what"`
		Action   string   `json:"action"`
		Severity Severity `json:"severity"`
		Devices  []Device `json:"devices"`
		Blocked  bool     `json:"blocked"` // logs.bad_address.detected only: the device that logged it blocked the connection (D-227)
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if utf8.RuneCountInString(e.Title) > 200 || e.Title == "" {
		return fmt.Errorf("%w: a logs event needs a title of at most 200 characters", ErrInvalidNotice)
	}
	_, _, err := s.OpenIncident(ctx, IncidentInput{Kind: kind, Source: e.Source, Target: e.Target, Title: e.Title, Severity: e.Severity, What: e.What, Action: e.Action,
		Link: "/logs", Devices: e.Devices, Attempt: e.Blocked && kind == IncidentBadAddress})
	return err
}

// Jobs returns the scheduler jobs of the module: "deliver" sends what is due (held notices when quiet
// hours end, grouped batches at their DueAt, the rest at once); "autoclose" sends the first-run summary and closes quiet incidents
// (autoclose.go); "telegram-listen" and "slack-listen" take approval button presses
// while the Telegram / Slack channel takes approvals (tglisten.go, slacklisten.go). The five above run only while the module is on: `deliver` sends and its deletes are queue upkeep, not a customer retention, so it is not housekeeping (D-160). "retention" is Housekeeping (retention.go).
func (s *Service) Jobs() []jobs.Job {
	return []jobs.Job{
		{Module: ModuleID, Name: "deliver", Every: flushEvery, Run: s.Flush},
		{Module: ModuleID, Name: telegramListenJob, Every: telegramListenEvery, Run: s.listenTelegram},
		{Module: ModuleID, Name: slackListenJob, Every: slackListenEvery, Run: s.listenSlack},
		{Module: ModuleID, Name: zaloListenJob, Every: zaloListenEvery, Run: s.listenZalo},
		{Module: ModuleID, Name: autoCloseJob, Every: autoCloseEvery, Run: s.runAutoClose},                     // INV-22, INV-23: a normal job, only while notify is on
		{Module: ModuleID, Name: retentionJob, Every: retentionEvery, Housekeeping: true, Run: s.RunRetention}, // D-160: deletes history past 1 year, also while the module is off
	}
}

// plural is "1 <one>" or "<n> <many>".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
