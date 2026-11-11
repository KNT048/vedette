package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
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
// of inventory was on at that moment (the event says so).
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
		if n, ok, err := s.cfg.Devices.DeviceName(ctx, e.AssetID); err != nil {
			return err
		} else if ok && n != "" {
			name = n
		}
	}
	_, _, err := s.OpenIncident(ctx, IncidentInput{Kind: IncidentUnknownDevice, Source: e.AssetID, Title: "A new unknown device appeared: " + name, Severity: Medium,
		What:   "A device that is not in your inventory joined the network: " + name + ".",
		Action: "Find out whose device it is. Add it to the inventory if it belongs to you, otherwise remove it from the network.",
		Link:   "/devices/" + e.AssetID, Devices: []Device{{ID: e.AssetID, Name: name}}})
	return err
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
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if utf8.RuneCountInString(e.Title) > 200 || e.Title == "" {
		return fmt.Errorf("%w: a logs event needs a title of at most 200 characters", ErrInvalidNotice)
	}
	_, _, err := s.OpenIncident(ctx, IncidentInput{Kind: kind, Source: e.Source, Target: e.Target, Title: e.Title, Severity: e.Severity, What: e.What, Action: e.Action,
		Link: "/logs", Devices: e.Devices})
	return err
}

// Jobs returns the scheduler jobs of the module: "deliver" sends what is due (held notices when quiet
// hours end, grouped batches at their DueAt, the rest at once); "telegram-listen" and "slack-listen" take approval button presses
// while the Telegram / Slack channel takes approvals (tglisten.go, slacklisten.go). They run only while the module is on: `deliver` sends and its deletes are queue upkeep, not a customer retention, so it is not housekeeping (D-160).
func (s *Service) Jobs() []jobs.Job {
	return []jobs.Job{
		{Module: ModuleID, Name: "deliver", Every: flushEvery, Run: s.Flush},
		{Module: ModuleID, Name: telegramListenJob, Every: telegramListenEvery, Run: s.listenTelegram},
		{Module: ModuleID, Name: slackListenJob, Every: slackListenEvery, Run: s.listenSlack},
	}
}
