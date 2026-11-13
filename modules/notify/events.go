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
	EventAssetDiscovered      = "inventory.asset.discovered"
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
	on(EventNewKEV, s.kevEvent)
	on(EventAssetDiscovered, s.assetEvent)
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
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.FindingID == "" {
		return nil
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
		ID      string `json:"id"`
		TS      string `json:"ts"`
		Service string `json:"service"`
		SrcIP   string `json:"src_ip"`
		Label   string `json:"label"`
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
	at, _ := time.Parse(time.RFC3339, e.TS) // zero = now
	_, _, err := s.OpenIncident(ctx, IncidentInput{Kind: IncidentTrap, Source: src, Target: label + "|" + e.Service,
		Title: src + " touched the " + label + " trap", Severity: Critical,
		What:   src + " connected to the trap " + label + ". Nobody uses this trap, so it usually means a machine is infected or someone is probing the network.",
		Action: "Take the machine off the network (unplug the cable, turn off Wi-Fi), then ask its user what they were doing. Do not change passwords from that machine.",
		Link:   "/honeypot/hits/" + e.ID, At: at})
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
