package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
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
// summary incident instead (firstDiscovery, D-483).
func (s *Service) assetEvent(ctx context.Context, data any) error {
	var e struct {
		AssetID string `json:"asset_id"`
		Notify  bool   `json:"notify"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if !e.Notify || e.AssetID == "" {
		return nil
	}
	name := e.AssetID
	if s.cfg.Devices != nil {
		if n, ok, err := s.cfg.Devices.DeviceLabel(ctx, e.AssetID); err != nil {
			return err
		} else if ok && n != "" {
			name = n
		}
	}
	name = clip(name, 160) // a host name can be 200 characters; the title may not be longer than that (OpenIncident)
	first, err := s.firstDiscovery(ctx)
	if err != nil {
		return err
	}
	if first {
		return s.discoveryIncident(ctx, Device{ID: e.AssetID, Name: name})
	}
	_, _, err = s.OpenIncident(ctx, IncidentInput{Kind: IncidentUnknownDevice, Source: e.AssetID, Title: "A new unknown device appeared: " + name, Severity: Medium,
		What:   "A device that is not in your inventory joined the network: " + name + ".",
		Action: "Find out whose device it is. Add it to the inventory if it belongs to you, otherwise remove it from the network.",
		Link:   "/devices/" + e.AssetID, Devices: []Device{{ID: e.AssetID, Name: name}}})
	return err
}

// assetDeleted takes a device deleted in Devices off the open new-device incidents (W6-3, D-497): the first-discovery summary drops it
// from its list and its count (and is resolved when no device is left), and the device's own "new unknown device" incident is
// resolved, since there is nothing left to approve. Resolved incidents and the other kinds keep the device: they are history.
func (s *Service) assetDeleted(ctx context.Context, data any) error {
	var e struct {
		AssetID string `json:"asset_id"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.AssetID == "" {
		return nil
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT i.id, i.link, d.name FROM notify_incident i JOIN notify_incident_device d ON d.incident_id = i.id
			WHERE i.kind = ? AND i.status <> 'resolved' AND d.asset_id = ?`, string(IncidentUnknownDevice), e.AssetID)
		if err != nil {
			return fmt.Errorf("notify: find the incidents of a deleted device: %w", err)
		}
		type open struct{ id, link, name string }
		var list []open
		for rows.Next() {
			var o open
			if err := rows.Scan(&o.id, &o.link, &o.name); err != nil {
				_ = rows.Close()
				return fmt.Errorf("notify: find the incidents of a deleted device: %w", err)
			}
			list = append(list, o)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("notify: find the incidents of a deleted device: %w", err)
		}
		at := store.FormatTS(s.now())
		resolve := func(id, title, note string) error {
			if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET status = 'resolved', handled_by = ?, handled_at = ?, note = ? WHERE id = ?`, systemUser, at, note, id); err != nil {
				return fmt.Errorf("notify: resolve the incident of a deleted device: %w", err)
			}
			return s.record(ctx, tx, systemUser, "notify.incident_status", clip(title, 400), "resolved: "+note)
		}
		for _, o := range list {
			if o.link != "/devices" { // the device's own incident: nothing is left to approve
				if err := resolve(o.id, "A new unknown device appeared: "+o.name, "The device was deleted in Devices."); err != nil {
					return err
				}
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM notify_incident_device WHERE incident_id = ? AND asset_id = ?`, o.id, e.AssetID); err != nil {
				return fmt.Errorf("notify: take a deleted device off the summary: %w", err)
			}
			var n, count int // count can be above the listed rows: the list stops at maxDiscoveryDevices
			if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM notify_incident_device WHERE incident_id = ?), count FROM notify_incident WHERE id = ?`, o.id, o.id).Scan(&n, &count); err != nil {
				return fmt.Errorf("notify: count discovered devices: %w", err)
			}
			n = max(n, count-1)
			if n == 0 {
				if err := resolve(o.id, "Devices found on your network", "Every device on it was deleted in Devices."); err != nil {
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
	})
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
// later, or whose incidents passed retention, never opens the window again. ponytail: the start is notify's first run, not the first
// contact of a sensor (inventory does not say; deferred line); a setup finished more than a day after the install gets one
// incident per device, as before.
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
		What: "This is Vedette's first look at your network, so every device on it is new. Instead of one alert per device, the devices found in the first " +
			"36 hours are listed together here.",
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
			What:   fmt.Sprintf("%s since the last message. Vedette lists the devices of its first look at your network together for 36 hours.", plural(count-told, "more device found", "more devices found")),
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
// hours end, grouped batches at their DueAt, the rest at once); "telegram-listen" and "slack-listen" take approval button presses
// while the Telegram / Slack channel takes approvals (tglisten.go, slacklisten.go). The four above run only while the module is on: `deliver` sends and its deletes are queue upkeep, not a customer retention, so it is not housekeeping (D-160). "retention" is Housekeeping (retention.go).
func (s *Service) Jobs() []jobs.Job {
	return []jobs.Job{
		{Module: ModuleID, Name: "deliver", Every: flushEvery, Run: s.Flush},
		{Module: ModuleID, Name: telegramListenJob, Every: telegramListenEvery, Run: s.listenTelegram},
		{Module: ModuleID, Name: slackListenJob, Every: slackListenEvery, Run: s.listenSlack},
		{Module: ModuleID, Name: zaloListenJob, Every: zaloListenEvery, Run: s.listenZalo},
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
