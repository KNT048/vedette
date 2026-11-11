package response

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
)

// Events this module publishes, after the transaction that caused them committed (payloads: CONTRACT "Events").
const (
	EventRequestCreated   = "response.request.created"
	EventDecisionMade     = "response.decision.made"
	EventActionExecuted   = "response.action.executed"
	EventActionRolledBack = "response.action.rolled_back"
	EventBreakerTripped   = "response.breaker.tripped"
)

// RequestEvent is the payload of response.request.created: an approval request exists (notify may send it to the approvers, part 13b).
type RequestEvent struct {
	RequestID string `json:"request_id"`
	Source    string `json:"source"`
	Title     string `json:"title"`
	Risk      string `json:"risk"`
	Items     int    `json:"items"`
	ExpiresAt string `json:"expires_at"`
	Approvals int    `json:"approvals"` // how many different approvers it needs
}

// DecisionEvent is the payload of response.decision.made. Decision is approved, rejected, expired or cancelled; Final is false for the first of two approvals.
type DecisionEvent struct {
	RequestID string `json:"request_id"`
	Decision  string `json:"decision"`
	By        string `json:"by"`
	Final     bool   `json:"final"`
}

// ExecutedEvent is the payload of response.action.executed: one item ran and was recorded as executed.
type ExecutedEvent struct {
	RequestID string `json:"request_id"`
	ItemID    string `json:"item_id"`
	ActionID  string `json:"action_id"`
	Device    bool   `json:"device"` // false for a box action (block list, message, webhook)
}

// RolledBackEvent is the payload of response.action.rolled_back. Auto is true when the undo time ended.
type RolledBackEvent struct {
	RequestID string `json:"request_id"`
	ItemID    string `json:"item_id"`
	ActionID  string `json:"action_id"`
	Auto      bool   `json:"auto"`
}

// BreakerEvent is the payload of response.breaker.tripped.
type BreakerEvent struct {
	MaxPerHour int    `json:"max_per_hour"`
	TrippedAt  string `json:"tripped_at"`
}

// Events this module listens to. The names of the later triggers are listed so the producers know what to publish; this
// part subscribes to the modules that exist and to nothing else:
//
//	findings.finding.created, findings.finding.status_changed (to confirmed) -> trigger finding
//	inventory.asset.discovered (a device that is not approved)               -> trigger unknown_device
//	honeypot.hit.created (a real hit; a test hit publishes nothing)          -> trigger honeypot
//	logs.ioc_hit.detected                                                    -> trigger ioc_connection (module not built yet)
//	(no event) logs.Counts read by PollLogs every minute                    -> trigger log_threshold (#332, D-287)
//	exposure.port.opened                                                     -> trigger new_port (module not built yet)
const (
	EventFindingCreated       = "findings.finding.created"
	EventFindingStatusChanged = "findings.finding.status_changed"
	EventAssetDiscovered      = "inventory.asset.discovered"
	EventHoneypotHit          = "honeypot.hit.created"
)

// decode reads event data, whatever Go type the producer used, through its JSON form: this module does not import the
// producing modules, only the field names they document.
func decode(data any, into any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("response: read event data: %w", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("response: read event data: %w", err)
	}
	return nil
}

// Subscribe registers the event handlers on bus and returns a function that removes them. A handler only records the
// event (a database write); the rules run in the evaluate job, so a handler never holds the publisher while it works.
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
	on(EventAssetDiscovered, s.assetEvent)
	on(EventHoneypotHit, s.honeypotEvent)
	return func() {
		for _, u := range undo {
			u()
		}
	}
}

func openStatus(st string) bool { return st == "confirmed" || st == "suspected" }

func (s *Service) findingEvent(ctx context.Context, data any, statusChange bool) error {
	var e struct {
		FindingID string `json:"finding_id"`
		To        string `json:"to"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.FindingID == "" || (statusChange && e.To != "confirmed") {
		return nil
	}
	if s.cfg.Directory == nil {
		s.cfg.Log.WarnContext(ctx, "response: finding event skipped: no directory is wired")
		return nil
	}
	f, ok, err := s.cfg.Directory.Finding(ctx, e.FindingID)
	if err != nil || !ok || !openStatus(f.Status) {
		return err
	}
	d, ok, err := s.cfg.Directory.Device(ctx, f.AssetID)
	if err != nil || !ok {
		return err
	}
	sev := f.Severity
	switch sev {
	case "critical", "high", "medium", "low":
	default:
		sev = "low"
	}
	id := "finding:" + f.ID
	if statusChange {
		id += ":confirmed"
	}
	return s.StoreEvent(ctx, Det{ID: id, Trigger: "finding", TS: s.ts(), DeviceKind: d.Kind, AssetID: d.ID, FindingID: f.ID, CVE: f.CVE,
		Summary: oneLine(d.Name+": "+f.CVE+" ("+sev+")", 300),
		Fields:  map[string]string{"device": oneLine(d.Name, 100), "ip": d.IP, "cve": f.CVE, "severity": sev, "kev": fmt.Sprint(f.KEV), "exposed_via_nat": "false", "vip": ""}})
}

func (s *Service) assetEvent(ctx context.Context, data any) error {
	var e struct {
		AssetID string `json:"asset_id"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.AssetID == "" || s.cfg.Directory == nil {
		return nil
	}
	d, ok, err := s.cfg.Directory.Device(ctx, e.AssetID)
	if err != nil || !ok || d.Approved {
		return err
	}
	vendor, kind := d.Vendor, d.Kind
	if vendor == "" {
		vendor = "Unknown vendor"
	}
	if !s.isDeviceKind(kind) {
		kind = "unknown"
	}
	ts := d.Seen
	if ts.IsZero() {
		ts = s.now()
	}
	who := d.MAC
	if who == "" {
		who = d.IP
	}
	return s.StoreEvent(ctx, Det{ID: "device:" + d.ID, Trigger: "unknown_device", TS: store2(ts), DeviceKind: d.Kind, AssetID: d.ID,
		Summary: oneLine("Unknown device "+who+" ("+vendor+") at "+d.IP, 300),
		Fields:  map[string]string{"ip": d.IP, "mac": d.MAC, "vendor": oneLine(vendor, 80), "kind": kind}})
}

// honeypotEvent records a real trap hit for the honeypot trigger (S-RESP-3). Every field came from the network: the source is
// kept only as a parsed address, the kind only from its three values, the decoy name as one cut line; anything else drops the event.
// The source device is the one the honeypot named, read again from the inventory.
func (s *Service) honeypotEvent(ctx context.Context, data any) error {
	var e struct {
		ID         string `json:"id"`
		TS         string `json:"ts"`
		Kind       string `json:"kind"`
		SrcIP      string `json:"src_ip"`
		Decoy      string `json:"decoy"`
		SrcAssetID string `json:"src_asset_id"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	ip, err := netip.ParseAddr(e.SrcIP)
	switch {
	case e.ID == "" || len(e.ID) > 64 || err != nil || ip.Zone() != "":
		s.cfg.Log.WarnContext(ctx, "response: honeypot hit skipped: no id or no valid source address")
		return nil
	case e.Kind != "service" && e.Kind != "token" && e.Kind != "scan":
		s.cfg.Log.WarnContext(ctx, "response: honeypot hit skipped: unknown kind")
		return nil
	}
	ip = ip.Unmap()
	if e.Kind == "scan" && !s.scanRoom(ctx) {
		return nil
	}
	var dev DeviceInfo
	if e.SrcAssetID != "" && s.cfg.Directory != nil {
		d, ok, err := s.cfg.Directory.Device(ctx, e.SrcAssetID)
		switch {
		case err != nil: // the hit still counts; it only names no device
			s.cfg.Log.WarnContext(ctx, "response: honeypot hit: the source device could not be read", "error", err)
		case ok && d.IP == ip.String(): // the device may have moved since the hit was stored
			dev = d
		}
	}
	name := oneLine(dev.Name, 100)
	who := name
	if who == "" {
		who = ip.String()
	}
	decoy := oneLine(e.Decoy, 100)
	if decoy == "" {
		decoy = "decoy"
	}
	ts := s.ts()
	if t, err := time.Parse(time.RFC3339Nano, e.TS); err == nil {
		ts = store2(t)
	}
	return s.StoreEvent(ctx, Det{ID: "honeypot:" + e.ID, Trigger: "honeypot", TS: ts, DeviceKind: dev.Kind, AssetID: dev.ID,
		Summary: oneLine(who+" touched a trap ("+decoy+", "+e.Kind+")", 300),
		Fields:  map[string]string{"source_ip": ip.String(), "source_device": name, "decoy": decoy, "kind": e.Kind, "switch_port": ""}})
}

// maxScansPerHour bounds the port-scan hits that reach the rules in one clock hour. A scan hit's source can be forged, so a LAN
// host can make up to the honeypot's own cap (2000 new hits an hour) of them, and every hit a rule sees writes permanent lines to
// the append-only logs. Service and token hits need a connection from the real address and are not counted, so a flood of scans
// never hides a later login on a trap. ponytail: a flat cap per hour, one log line when it is reached; upgrade path: coalesce the
// per-rule lines.
const maxScansPerHour = 60

// scanRoom counts a scan hit against this hour's cap and reports whether it may reach the rules. The first scan over the cap
// writes one line to the response log (never a silent loss); the hits stay on the honeypot page.
func (s *Service) scanRoom(ctx context.Context) bool {
	hour := s.now().Truncate(time.Hour)
	s.hpMu.Lock()
	if !s.hpHour.Equal(hour) {
		s.hpHour, s.hpCount = hour, 0
	}
	s.hpCount++
	n := s.hpCount
	s.hpMu.Unlock()
	if n <= maxScansPerHour {
		return true
	}
	if n == maxScansPerHour+1 {
		s.cfg.Log.WarnContext(ctx, "response: more honeypot scan hits than the hourly cap; the rest of this hour's scans do not reach the rules", "cap", maxScansPerHour)
		if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			return s.step(ctx, tx, "response.events_dropped", "response", LogRefused, "honeypot_cap: more than "+itoa(maxScansPerHour)+" honeypot port scans this hour; the rest of this hour's scans are on the Honeypot page but do not run the rules (logins and tokens still do).", "system")
		}); err != nil {
			s.cfg.Log.WarnContext(ctx, "response: log the honeypot cap", "error", err)
		}
	}
	return false
}

// message sends a notice to the alert channels, best effort: a failure is logged, never returned.
func (s *Service) message(ctx context.Context, id, title, text string) {
	if s.cfg.Notifier == nil {
		return
	}
	if err := s.cfg.Notifier.Message(ctx, id, title, text); err != nil {
		s.cfg.Log.WarnContext(ctx, "response: a notice could not be queued", "error", err)
	}
}

// channelNames are the labels of the configured, enabled alert channels, or "the app".
func (s *Service) channelNames(ctx context.Context) []string {
	out := []string{}
	if s.cfg.Notifier != nil {
		if l, err := s.cfg.Notifier.Channels(ctx); err == nil {
			for _, c := range l {
				if c.Configured && c.Enabled {
					out = append(out, c.Label)
				}
			}
		}
	}
	if len(out) == 0 {
		return []string{"the app"}
	}
	return out
}

// Jobs returns the jobs of the module: "evaluate" runs the rules on new events and the due schedules; "sweep" expires old
// requests and undoes changes whose undo time ended. "evaluate" also polls the Logs counts for the log_threshold rules (PollLogs). Both run only while the module is on (SYS-5).
func (s *Service) Jobs() []jobs.Job {
	return []jobs.Job{
		{Module: ModuleID, Name: "evaluate", Every: 10 * time.Second, Run: func(ctx context.Context) error {
			if err := s.PollLogs(ctx); err != nil {
				return err
			}
			if _, err := s.Evaluate(ctx); err != nil {
				return err
			}
			return s.RunSchedules(ctx)
		}},
		{Module: ModuleID, Name: "sweep", Every: 30 * time.Second, Run: s.Sweep},
		s.planJob(),
	}
}
