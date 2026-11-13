package response

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/modules/logs/signature"
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

// Events this module listens to (it imports none of their producers; of logs only the stdlib-only address check of logs/signature):
//
//	findings.finding.created, findings.finding.status_changed (to confirmed) -> trigger finding
//	inventory.asset.discovered (a device that is not approved)               -> trigger unknown_device
//	honeypot.hit.created (a real hit; a test hit publishes nothing)          -> trigger honeypot
//	logs.ioc_hit.detected (logs L4, D-213)                                   -> trigger ioc_connection (D-335)
//	(no event) logs.Counts read by PollLogs every minute                    -> trigger log_threshold (#332, D-287)
//	exposure.port.opened (cmd/vedette, from exposure's own Diff, D-384)     -> trigger new_port
const (
	EventFindingCreated       = "findings.finding.created"
	EventFindingStatusChanged = "findings.finding.status_changed"
	EventAssetDiscovered      = "inventory.asset.discovered"
	EventHoneypotHit          = "honeypot.hit.created"
	EventIocHit               = "logs.ioc_hit.detected"
	EventPortOpened           = "exposure.port.opened"
)

// PortOpenedEvent is the payload of exposure.port.opened (D-384): one port that a scan of an exposure target saw open and the
// previous scan day of that target did not. cmd/vedette publishes it from exposure's own Diff; the exposure module does not know
// the name.
type PortOpenedEvent struct {
	TargetID string `json:"target_id"`
	Date     string `json:"date"` // the scan day that saw it, YYYY-MM-DD
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
}

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
	on(EventIocHit, s.iocEvent)
	on(EventPortOpened, s.portEvent)
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
		// Unconfirmed: the hit completed no handshake (a UDP trap, honeypot D-467), so its source may be forged, as a scan's.
		Unconfirmed bool `json:"unconfirmed"`
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
	if (e.Kind == "scan" || e.Unconfirmed) && !s.scanRoom(ctx) { // forgeable hits share the scan budget (honeypot D-467 review M1)
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
	fields := map[string]string{"source_ip": ip.String(), "source_device": name, "decoy": decoy, "kind": e.Kind, "switch_port": ""}
	if e.Unconfirmed {
		fields["unconfirmed"] = "1"
	}
	return s.StoreEvent(ctx, Det{ID: "honeypot:" + e.ID, Trigger: "honeypot", TS: ts, DeviceKind: dev.Kind, AssetID: dev.ID,
		Summary: oneLine(who+" touched a trap ("+decoy+", "+e.Kind+")", 300), Fields: fields})
}

// maxScansPerHour bounds the scan and UDP hits (unconfirmed: no handshake) that reach the rules in one clock hour. Their source can be forged, so a LAN
// host can make up to the honeypot's own cap (2000 new hits an hour) of them, and every hit a rule sees writes permanent lines to
// the append-only logs. TCP service and token hits need a connection from the real address and are not counted, so a flood of scans
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
		s.cfg.Log.WarnContext(ctx, "response: more honeypot scan or UDP hits than the hourly cap; the rest of this hour's do not reach the rules", "cap", maxScansPerHour)
		if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			return s.step(ctx, tx, "response.events_dropped", "response", LogRefused, "honeypot_cap: more than "+itoa(maxScansPerHour)+" honeypot scans or UDP requests (source unconfirmed) this hour; the rest of this hour's are on the Honeypot page but do not run the rules (logins and tokens still do).", "system")
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

// maxIocPerHour bounds the known-bad connection hits that reach the rules in one clock hour (D-339). A hit is read from a syslog line,
// which any LAN host can forge over UDP; logs makes one hit per device and destination per 24 hours, but a forger can vary the
// destination over every listed address, and each hit a rule sees writes permanent lines to the append-only logs. The first hit over
// the cap writes one line to the response log; the hits stay on the Logs page. ponytail: a flat cap per hour, as maxScansPerHour.
const maxIocPerHour = 60

// iocEvent records a logs.ioc_hit.detected (the IocHit of logs, D-213) as an ioc_connection event (D-335). Every field is checked at
// the edge, as the honeypot hit is: an id, a private source address, a destination of its kind (an address or a domain), a
// public destination address, a confidence from 0 to 1. Anything else is skipped with a warning. Of the line's text only the
// destination reaches a rule, after that check; the feed names and the device name come from feeds and the inventory.
func (s *Service) iocEvent(ctx context.Context, data any) error {
	var e struct {
		ID         string   `json:"id"`
		TS         string   `json:"ts"`
		AssetID    *string  `json:"asset_id"`
		AssetName  *string  `json:"asset_name"`
		SrcIP      string   `json:"src_ip"`
		Dest       string   `json:"dest"`
		DestKind   string   `json:"dest_kind"`
		Feeds      []string `json:"feeds"`
		Confidence float64  `json:"confidence"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	src, srcOK := CheckValue(PIP, e.SrcIP)
	var dest string
	destOK := false
	switch e.DestKind {
	case "ip": // a listed address is a public one by logs' own rule (it refuses the rest): a feed listing private, carrier-grade NAT
		// (a Tailscale peer), documentation or benchmarking space must not make a rule block a host the customer reaches
		dest, destOK = CheckValue(PIP, e.Dest)
		destOK = destOK && signature.PublicDest(addrOf(dest))
	case "domain":
		dest, destOK = CheckValue(PDomain, e.Dest)
	}
	switch {
	case e.ID == "" || len(e.ID) > 64 || cleanLine(e.ID) != e.ID:
		s.cfg.Log.WarnContext(ctx, "response: known-bad connection skipped: no valid id")
		return nil
	case !srcOK || !signature.LocalOK(addrOf(src).Unmap()): // logs' own LAN-device rule: RFC 1918 or 100.64/10 (D-461)
		s.cfg.Log.WarnContext(ctx, "response: known-bad connection skipped: the device address is not a private address")
		return nil
	case !destOK:
		s.cfg.Log.WarnContext(ctx, "response: known-bad connection skipped: the destination is not an address or a domain of its kind")
		return nil
	case math.IsNaN(e.Confidence) || e.Confidence < 0 || e.Confidence > 1:
		s.cfg.Log.WarnContext(ctx, "response: known-bad connection skipped: confidence is not between 0 and 1")
		return nil
	}
	if !s.iocRoom(ctx) {
		return nil
	}
	var dev DeviceInfo
	if e.AssetID != nil && *e.AssetID != "" && s.cfg.Directory != nil {
		d, ok, err := s.cfg.Directory.Device(ctx, *e.AssetID)
		switch {
		case err != nil: // the hit still counts; it only names no device
			s.cfg.Log.WarnContext(ctx, "response: known-bad connection: the device could not be read", "error", err)
		case ok && d.IP == src: // the device may have moved since the hit was made
			dev = d
		}
	}
	name := oneLine(dev.Name, 100)
	if name == "" && e.AssetName != nil && (e.AssetID == nil || *e.AssetID == "" || s.cfg.Directory == nil) {
		name = oneLine(*e.AssetName, 100) // the hit's own name only when the directory could not be asked: a moved device is not named
	}
	who := name
	if who == "" {
		who = src
	}
	var feeds []string
	for _, f := range e.Feeds {
		if f = oneLine(f, 60); f != "" && len(feeds) < 10 {
			feeds = append(feeds, f)
		}
	}
	fields := map[string]string{"src_ip": src, "device": name, "dest": dest, "dest_kind": e.DestKind, "dest_ip": "", "dest_domain": "",
		"feeds": strings.Join(feeds, ", "), "confidence": strconv.FormatFloat(e.Confidence, 'f', -1, 64), "switch_port": ""}
	if e.DestKind == "ip" {
		fields["dest_ip"] = dest
	} else {
		fields["dest_domain"] = dest
	}
	ts := s.ts()
	if t, err := time.Parse(time.RFC3339Nano, e.TS); err == nil {
		ts = store2(t)
	}
	return s.StoreEvent(ctx, Det{ID: "ioc:" + e.ID, Trigger: "ioc_connection", TS: ts, DeviceKind: dev.Kind, AssetID: dev.ID,
		Summary: oneLine(who+" connected to "+dest+", listed by "+firstNonEmpty(fields["feeds"], "a feed"), 300), Fields: fields})
}

// iocRoom counts a known-bad connection against this hour's cap and reports whether it may reach the rules.
func (s *Service) iocRoom(ctx context.Context) bool {
	hour := s.now().Truncate(time.Hour)
	s.hpMu.Lock()
	if !s.iocHour.Equal(hour) {
		s.iocHour, s.iocCount = hour, 0
	}
	s.iocCount++
	n := s.iocCount
	s.hpMu.Unlock()
	if n <= maxIocPerHour {
		return true
	}
	if n == maxIocPerHour+1 {
		if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			return s.step(ctx, tx, "response.events_dropped", "response", LogRefused, "ioc_cap: more than "+itoa(maxIocPerHour)+" known-bad connections this hour; the rest of this hour's hits are on the Logs page but do not run the rules.", "system")
		}); err != nil {
			s.cfg.Log.ErrorContext(ctx, "response: log the known-bad connection cap", "error", err)
		}
	}
	return false
}

// portEvent records an exposure.port.opened as a new_port event (D-384). The scan was of the customer's own verified target, but its
// text came from the network (the service guess is read from a banner), so every field is checked at the edge as for the other
// triggers: an id-like target, a scan day, a public address, a port 1..65535, a one-line service guess. Anything
// else is skipped with a warning. The event id is the target, the day, the address and the port, so a second scan on the same day
// (it replaces that day's snapshot) never runs a rule twice for one port; a port that closes and opens again on a later day does.
func (s *Service) portEvent(ctx context.Context, data any) error {
	var e PortOpenedEvent
	if err := decode(data, &e); err != nil {
		return err
	}
	ip, ipOK := CheckValue(PIP, e.IP)
	_, dateErr := time.Parse(time.DateOnly, e.Date)
	switch {
	case !nameRE.MatchString(e.TargetID):
		s.cfg.Log.WarnContext(ctx, "response: new port skipped: no valid target id")
		return nil
	case dateErr != nil:
		s.cfg.Log.WarnContext(ctx, "response: new port skipped: no valid scan day")
		return nil
	case !ipOK || !publishable(addrOf(ip)): // the block list's own "public": not CGNAT, 198.18/15, 6to4…; IPv4 documentation kept (D-88 L4)
		s.cfg.Log.WarnContext(ctx, "response: new port skipped: the address is not a public address")
		return nil
	case e.Port < 1 || e.Port > 65535:
		s.cfg.Log.WarnContext(ctx, "response: new port skipped: the port is not between 1 and 65535")
		return nil
	}
	port := strconv.Itoa(e.Port)
	service := oneLine(cleanLine(e.Service), 60) // cleanLine also drops bidi and other invisible characters a banner may carry
	summary := "New open port " + port + " on public IP " + ip
	if service != "" {
		summary += " (" + service + ")"
	}
	return s.StoreEvent(ctx, Det{ID: "port:" + e.TargetID + ":" + e.Date + ":" + ip + ":" + port, Trigger: "new_port", TS: s.ts(),
		Summary: oneLine(summary, 300), Fields: map[string]string{"ip": ip, "port": port, "service": service, "device": ""}})
}

func addrOf(s string) netip.Addr { a, _ := netip.ParseAddr(s); return a }
