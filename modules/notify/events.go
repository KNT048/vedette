package notify

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/store"
)

// Names of the events notify listens to. core/events wants <module>.<object>.<verb>, so the two-part
// names of the CONTRACT (honeypot.hit, logs.anomaly, logs.bad_address) are spelled with a verb here;
// the producers must publish these names (see CONTRACT "Events").
const (
	EventFindingCreated       = "findings.finding.created"
	EventFindingStatusChanged = "findings.finding.status_changed"
	// EventUrgencyRaised: an open finding rose into a more urgent layer of 1–4 {finding_id, cve, severity, from, to, at}: one notice per
	// escalation (a finding is told again only at a more urgent layer than any it was told at).
	EventUrgencyRaised = "findings.finding.urgency_raised"
	// EventFirstRun: the rises of a first-run window in one pass {key, at, findings, devices, layer, finding_ids, cve_list}: one summary
	// notice each, the later ones of a window saying "N more".
	EventFirstRun        = "findings.urgency.first_run"
	EventAssetDiscovered = "inventory.asset.discovered"
	EventAssetApproved   = "inventory.asset.approved" // B9: {asset_id, actor}
	EventAssetIgnored    = "inventory.asset.ignored"  // {asset_id, actor}: a person said the device needs no watching
	EventAssetUpdated    = "inventory.asset.updated"  // {asset_id}: also what a person's Approve publishes today
	EventHoneypotHit     = "honeypot.hit.created"
	EventLogAnomaly      = "logs.anomaly.detected"
	EventLogBadAddress   = "logs.bad_address.detected"
	EventIntrusion       = "ids.alert.detected" // {alert_id, source, target, title, what, action, severity, link, at, devices}
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
	on(EventFindingCreated, s.findingCreated)
	on(EventFindingStatusChanged, s.findingStatus)
	on(EventUrgencyRaised, s.urgencyRaised)
	on(EventFirstRun, s.urgencyFirstRun)
	on(EventAssetDiscovered, s.assetEvent)
	on(EventAssetApproved, s.assetApproved)
	on(EventAssetIgnored, s.assetIgnored)
	on(EventAssetUpdated, s.assetUpdated)
	on(EventHoneypotHit, s.hitEvent)
	on(EventLogAnomaly, func(ctx context.Context, d any) error { return s.logEvent(ctx, d, IncidentLogAnomaly) })
	on(EventLogBadAddress, func(ctx context.Context, d any) error { return s.logEvent(ctx, d, IncidentBadAddress) })
	on(EventIntrusion, s.intrusionEvent)
	on(EventDecisionMade, s.decisionEvent)
	return func() {
		for _, u := range undo {
			u()
		}
	}
}

// The finding events a vulnerability notice tells (Notice.Event, notify_notice.event): the kinds of the findings module's own history that
// a person has to know, and the summary of a first load. An open vocabulary.
const (
	NoticeCreated           NoticeEvent = "created"
	NoticeUrgencyChanged    NoticeEvent = "urgency_changed"
	NoticeReopened          NoticeEvent = "reopened"
	NoticeAcceptanceExpired NoticeEvent = "acceptance_expired"
	NoticeFirstRun          NoticeEvent = "first_run"
)

// NoticeEvent is the finding event a vulnerability notice tells. The column is an open vocabulary (a shape check); these are the ones notify
// writes, and "" is a notice that tells none.
type NoticeEvent string

// NoticeEvents lists every event notify writes.
var NoticeEvents = []NoticeEvent{NoticeCreated, NoticeUrgencyChanged, NoticeReopened, NoticeAcceptanceExpired, NoticeFirstRun}

// Valid reports whether e is "" or one of NoticeEvents.
func (e NoticeEvent) Valid() bool { return e == "" || slices.Contains(NoticeEvents, e) }

// findingCreated turns findings.finding.created (a new finding at an urgency of 1–4) into a notice.
func (s *Service) findingCreated(ctx context.Context, data any) error {
	var e struct {
		FindingID string `json:"finding_id"`
		CVE       string `json:"cve"`
		Severity  string `json:"severity"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.FindingID == "" {
		return nil
	}
	if IsBaseline(ctx) { // the re-match after the first CISA pull: nothing is queued, so nothing can leak later
		s.cfg.Log.DebugContext(ctx, "finding event ignored: it belongs to the first CISA pull", "finding", e.FindingID)
		return nil
	}
	return s.findingNotice(ctx, e.FindingID, e.CVE, Severity(e.Severity), NoticeCreated, nil)
}

// findingStatus turns the two status changes that a person has to know into notices: a finding Vedette reopened because the device
// matches it again (reopened), and a risk acceptance that ran out (acceptance_expired). Every other change of a status is only history.
func (s *Service) findingStatus(ctx context.Context, data any) error {
	var e struct {
		FindingID string `json:"finding_id"`
		CVE       string `json:"cve"`
		Severity  string `json:"severity"`
		Reason    string `json:"reason"`
		// acceptance_expired only: who accepted the risk and its last day (YYYY-MM-DD)
		AcceptedBy    string `json:"accepted_by"`
		AcceptedUntil string `json:"accepted_until"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.FindingID == "" || IsBaseline(ctx) {
		return nil
	}
	switch e.Reason {
	case "matches_again": // Vedette had closed the finding as not affected, and the device matches the entry again
		return s.findingNotice(ctx, e.FindingID, e.CVE, Severity(e.Severity), NoticeReopened, func(f FindingInfo, cve string, n *Notice) {
			n.ID += "-" + n.At.UTC().Format("20060102") // one notice per UTC day: a version that flaps between scans does not send one each time
			n.Change = "reopened, it matches again"
			n.Title = "Vedette reopened " + about(cve, f) + ": it matches again"
			n.What = "Vedette had closed this finding by itself, and the device matches the entry again. " + n.What
		})
	case "still_detected": // a person marked it patched, and a newer reading of the device still shows the flaw
		return s.findingNotice(ctx, e.FindingID, e.CVE, Severity(e.Severity), NoticeReopened, func(f FindingInfo, cve string, n *Notice) {
			n.ID += "-" + n.At.UTC().Format("20060102")
			n.Change = "reopened, still detected"
			n.Title = "Vedette reopened " + about(cve, f) + ": it is still detected"
			n.What = "It was marked patched, but a newer reading of the device still shows the flaw. " + n.What
		})
	case "acceptance_expired": // a risk a person accepted until a day is open again (INV-21)
		return s.findingNotice(ctx, e.FindingID, e.CVE, Severity(e.Severity), NoticeAcceptanceExpired, func(f FindingInfo, cve string, n *Notice) {
			n.ID += "-" + n.At.UTC().Format("20060102")
			n.Change = "risk acceptance ended, open again"
			n.Title = "Risk acceptance ended: " + about(cve, f) + " is open again"
			n.What = acceptedText(e.AcceptedBy, e.AcceptedUntil) + "; that date has passed. " + n.What
		})
	}
	return nil
}

// urgencyRaised turns findings.finding.urgency_raised (an open finding rose into a more urgent layer of 1–4) into a notice with the
// status the finding page shows now. The notice is told once per layer: Publish does not send a finding again at the layer it was told at
// or at a less urgent one. Old news (the Backlog mark) is only counted, never sent.
func (s *Service) urgencyRaised(ctx context.Context, data any) error {
	var e struct {
		FindingID string `json:"finding_id"`
		CVE       string `json:"cve"`
		Severity  string `json:"severity"`
		To        int    `json:"to"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.FindingID == "" || e.To < 1 || e.To >= layerUpdate || IsBaseline(ctx) {
		return nil
	}
	return s.findingNotice(ctx, e.FindingID, e.CVE, Severity(e.Severity), NoticeUrgencyChanged, func(f FindingInfo, cve string, n *Notice) {
		n.ID += fmt.Sprintf("-%d", f.Layer) // its own notice for each layer it rises to
		n.Title = titleOf(f, cve, "now ")
		n.Change = "now " + lowerFirst(f.Status)
	})
}

// findingNotice builds the vulnerability notice of one finding event from the finding as the directory reads it now, and publishes it.
// Only an open finding at an urgency of 1–4 is told (layer 5 never alerts); a finding that was handled or dropped since the event is not.
// The id is the finding's and the event's; frame changes the default texts and the id for the kinds that need it. The default texts are
// the status name, its meaning and the reasons, all from findings.
func (s *Service) findingNotice(ctx context.Context, id, eventCVE string, eventSeverity Severity, event NoticeEvent, frame func(f FindingInfo, cve string, n *Notice)) error {
	if s.cfg.Findings == nil {
		s.cfg.Log.WarnContext(ctx, "finding event skipped: no finding directory is wired")
		return nil
	}
	f, ok, err := s.cfg.Findings.Finding(ctx, id)
	if err != nil || !ok {
		return err
	}
	if !f.Open || f.Layer < 1 || f.Layer >= layerUpdate {
		return nil
	}
	sev := f.Severity
	if !sev.Valid() {
		sev = eventSeverity
	}
	cve := cmp.Or(f.CVE, eventCVE)
	n := Notice{ID: "nt-" + id + "-" + string(event), Event: event, Kind: KindVuln, Severity: AlertSeverity(sev, f.Layer), Product: f.Product, FindingIDs: []string{id},
		Devices: f.Devices, Title: titleOf(f, cve, ""), What: whatOf(f), Action: f.Action, Reasons: f.Reasons, Status: f.Status, Verification: f.Verification, Layer: f.Layer, Link: s.link("/findings/" + id), At: s.now()}
	if cve != "" {
		n.CVEs = []string{cve}
	}
	if frame != nil {
		frame(f, cve, &n)
	}
	return s.Publish(ctx, n)
}

// AlertSeverity is the severity a channel judges a finding's notice at (its min_severity, quiet hours, grouping): the finding's CVSS
// band raised to the floor of its urgency layer. Layers 1–4 are the ones Vedette alerts for, so none of them is below High; a flaw
// attackers use (under attack here, exploited in the wild) is Critical whatever its CVSS score, as the exploit-aware ratings of the
// large scanners rate a flaw on CISA's list. So a channel on the default "Medium and above", or on "High and above", gets every finding
// that enters layers 1–4; "Critical only" gets the exploited ones and the critical scores. An unknown band takes the floor.
func AlertSeverity(cvss Severity, layer int) Severity {
	floor := High
	if exploitedLayer(layer) {
		floor = Critical
	}
	if cvss.Valid() && cvss.rank() > floor.rank() {
		return cvss
	}
	return floor
}

// titleOf is the title of a finding's notice: "FortiOS on fw01: public exploit available (CVE-2026-1)", lead being "now " for a rise.
func titleOf(f FindingInfo, cve, lead string) string {
	out := cmp.Or(f.Product, "A finding")
	if len(f.Devices) > 0 {
		out += " on " + strings.Join(f.Devices, ", ")
	}
	out += ": " + lead + lowerFirst(f.Status)
	if cve != "" {
		out += " (" + cve + ")"
	}
	return out
}

// whatOf is the body of a finding's notice: what its status asks of a person, the note about its device, and why it has that status.
func whatOf(f FindingInfo) string {
	out := f.Meaning
	if f.Note != "" {
		out += " " + f.Note
	}
	if f.Reasons != "" {
		out += " Why: " + f.Reasons + "."
	}
	if f.Verification != "" {
		out += " " + f.Verification + "."
	}
	return out
}

// lowerFirst starts a status name in lower case, to continue a sentence ("Public exploit available" -> "public exploit available").
func lowerFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return string(unicode.ToLower(r)) + s[n:]
}

// acceptedText is "<who> accepted this risk until <12 Feb 2027>" from the event's fields, each optional.
func acceptedText(by, until string) string {
	who := strings.TrimSpace(by)
	if who == "" || len(who) > 320 {
		who = "Someone"
	}
	out := who + " accepted this risk"
	if d, err := time.Parse(time.DateOnly, until); err == nil {
		out += " until " + orgtime.CalendarDay(d)
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

// assetEvent opens an unknown_device incident for a newly discovered device when the notify_new setting
// of inventory was on at that moment (the event says so). During the first discovery every device is new, so they go into one
// summary incident instead (firstDiscovery); so does a device that a sensor found while it was learning the network (learning:
// its source first reported to the box less than 36 hours ago, inventory INV-28), whenever that sensor was added.
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
	inWindow, err := s.firstDiscovery(ctx)
	if err != nil {
		return err
	}
	if inWindow || e.Learning {
		return s.discoveryIncident(ctx, Device{ID: e.AssetID, Name: name}, !inWindow)
	}
	title, what := newDeviceTexts(name)
	_, _, err = s.OpenIncident(ctx, IncidentInput{Kind: IncidentUnknownDevice, Source: e.AssetID, Title: title, Severity: Medium, What: what,
		Action: "Find out whose device it is. Add it to the inventory if it belongs to you, otherwise remove it from the network.",
		Link:   "/devices/" + e.AssetID, Devices: []Device{{ID: e.AssetID, Name: name}}})
	return err
}

// deviceLabel names a device on its new-device incidents: the name the Devices page shows (inventory's one naming rule,
// so a host name learnt later or a name typed by hand shows), then its address when that is not the name already: "byn
// (192.168.142.181)", "Hon Hai Precision Ind. Co.,Ltd. (192.168.142.181)", "192.168.142.254".
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

// approvedInDevices closes a device's new-device incident when inventory.asset.updated shows the device approved: that event
// does not say who approved it.
const approvedInDevices = "Closed by Vedette: the device was approved in Devices."

// assetUpdated follows a device that changed in Devices (inventory.asset.updated {asset_id}): a person's Approve publishes it
// (B9's inventory.asset.approved is not published yet). When the device is on an open new-device incident, the incident takes the
// name Devices shows now, and an approved device leaves it as INV-22 (1) says (approvedInDevices). An update of a device on no open
// new-device incident, the usual case, costs one indexed read and no inventory read; nothing changed means no write. A deleted
// device is INV-20's.
func (s *Service) assetUpdated(ctx context.Context, data any) error {
	var e struct {
		AssetID string `json:"asset_id"`
		Notify  bool   `json:"notify"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.Notify { // a quiet device (a private Wi-Fi address nobody looked at) earned its new-device notice: inventory INV-49
		return s.assetEvent(ctx, data)
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
// it (active_at), or the device was found again. Vedette then leaves it open: the person took it back.
// Approved at an unknown time (recorded by an older release), any reopen counts.
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

// followDevice brings the open new-device incidents of a device up to date with Devices: the device's own incident and its
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

// DeviceDeleted is notify's part of deleting a device (core/lifecycle, inside the inventory's write): the device leaves the open
// new-device incidents (INV-20, see leaveDevice), with who deleted it in the reason. Resolved incidents and the other kinds keep it
// with the name they stored: they are history. Nothing is sent.
func (s *Service) DeviceDeleted(ctx context.Context, tx *sql.Tx, d lifecycle.Delete) error {
	if d.Device == "" {
		return nil
	}
	return s.leaveDevice(ctx, tx, d.Device, deletedInDevices+byActor(d.Actor)+".", nil)
}

// assetApproved takes a device a person approved in Devices (inventory.asset.approved {asset_id, actor}) off the open
// new-device incidents the way a delete does (INV-22): there is nothing left to approve.
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
	// The inventory.asset.updated of the same approval may have come first and closed the incident without the person: name
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

// assetIgnored takes a device a person ignored in Devices (inventory.asset.ignored {asset_id, actor}: a staff phone, known and
// not watched) off the open new-device incidents the way an approval does: there is nothing left to review. Only the new-device
// incidents: a trap hit or an intrusion-detection incident from the device stays open and new ones still come.
func (s *Service) assetIgnored(ctx context.Context, data any) error {
	var e struct {
		AssetID string `json:"asset_id"`
		Actor   string `json:"actor"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	return s.leaveDeviceIncidents(ctx, e.AssetID, "Closed by Vedette: the device was ignored"+byActor(e.Actor)+".")
}

// deletedInDevices starts the reason of a device's own new-device incident closed by its delete (DeviceDeleted).
const deletedInDevices = "Closed by Vedette: the device was deleted in Devices"

// FindingFolded is notify's part of a merge that folds finding f.From into f.Into (core/lifecycle, inside the inventory's write): the
// notices sent for the folded finding are listed on the one that stays, so "who was told" keeps them and an old alert's link to the
// finding still opens. A notice that already lists the kept finding keeps its row.
func (s *Service) FindingFolded(ctx context.Context, tx *sql.Tx, f lifecycle.FindingFold) error {
	for _, q := range []string{
		`UPDATE OR IGNORE notify_notice_finding SET finding_id = ?2 WHERE finding_id = ?1`,
		`DELETE FROM notify_notice_finding WHERE finding_id = ?1`,
	} {
		if _, err := tx.ExecContext(ctx, q, f.From, f.Into); err != nil {
			return fmt.Errorf("notify: follow a folded finding: %w", err)
		}
	}
	return nil
}

// mergedInto starts the reason of a device inventory joined into another (DeviceMerged).
const mergedInto = "Closed by Vedette: merged into "

// DeviceMerged is notify's part of a merge (core/lifecycle, inside the inventory's write): the row inventory joined into another
// device leaves the open new-device incidents like a delete (INV-20), with the reason that says where it went: "Closed by Vedette:
// merged into <name>.". The device it joined keeps its own incident: it is still to approve. Every other incident that lists the row
// (a trap hit, a bad connection, a resolved one) lists the device it joined instead, with the name it stored; one that already lists
// that device keeps its row.
func (s *Service) DeviceMerged(ctx context.Context, tx *sql.Tx, m lifecycle.Merge) error {
	if m.From == "" || m.Into == "" || m.From == m.Into {
		return nil
	}
	into := clip(cmp.Or(m.IntoName, "another device in Devices"), 200) // the name the inventory passes: no read outside the write
	if err := s.leaveDevice(ctx, tx, m.From, mergedInto+into+".", nil); err != nil {
		return err
	}
	for _, q := range []string{
		`UPDATE OR IGNORE notify_incident_device SET asset_id = ?2 WHERE asset_id = ?1`,
		`DELETE FROM notify_incident_device WHERE asset_id = ?1`, // an incident that lists both: into's row stays
	} {
		if _, err := tx.ExecContext(ctx, q, m.From, m.Into); err != nil {
			return fmt.Errorf("notify: move the incidents of a merged device: %w", err)
		}
	}
	return nil
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

// leaveDevice is leaveDeviceIncidents inside a transaction. With approvedAt (the device's approval as an update showed it), the
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
		// Was the device told? The untold devices are the newest ones (count above notify_box.discovery_told_count); the rows are
		// added in order, so the device was told unless it is among the newest untold listed rows (rowid order). A told device leaving
		// lowers the told count, so the devices added after the last message stay untold (tellDiscovery). ponytail: a list that hit
		// maxDiscoveryDevices and then lost rows lists later devices out of order; the guess can then be off by the devices it skipped.
		var rows, newer, count, told int // count can be above the listed rows: the list stops at maxDiscoveryDevices
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM notify_incident_device WHERE incident_id = ?),
			(SELECT COUNT(*) FROM notify_incident_device WHERE incident_id = ? AND rowid > (SELECT rowid FROM notify_incident_device WHERE incident_id = ? AND asset_id = ?)),
			i.count, b.discovery_told_count FROM notify_incident i, notify_box b WHERE i.id = ? AND b.id = 1`,
			o.id, o.id, o.id, assetID, o.id).Scan(&rows, &newer, &count, &told); err != nil {
			return fmt.Errorf("notify: count discovered devices: %w", err)
		}
		listedUntold := max(0, max(rows, count)-told-max(0, count-rows))
		if newer >= listedUntold && told > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE notify_box SET discovery_told_count = ? WHERE id = 1`, told-1); err != nil {
				return fmt.Errorf("notify: count told devices: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM notify_incident_device WHERE incident_id = ? AND asset_id = ?`, o.id, assetID); err != nil {
			return fmt.Errorf("notify: take a device off the summary: %w", err)
		}
		n := max(rows-1, count-1)
		if n == 0 {
			why := "Closed by Vedette: every device on it was added, ignored or deleted in Devices."
			if strings.HasPrefix(reason, mergedInto) { // the last one was merged: say where it went
				why = "Closed by Vedette: every device on it was added, ignored or deleted in Devices, the last one " + strings.TrimPrefix(reason, "Closed by Vedette: ")
			}
			if err := s.closeBySystem(ctx, tx, o.id, o.title, why); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET title = ?, count = ? WHERE id = ?`, discoveryTitle(n), n, o.id); err != nil {
			return fmt.Errorf("notify: name discovered devices: %w", err)
		}
	}
	return nil
}

const (
	// firstDiscoveryWindow is how long after notify first ran on the box new devices go into the one summary: the passive
	// sensor finds most devices in the first hours, the active sensor (23:00-05:00 by default) the rest the first night.
	firstDiscoveryWindow = 36 * time.Hour
	firstDiscoverySource = "first-discovery" // the source of the summary incident: one per box while it is open
	maxDiscoveryDevices  = 500               // devices listed on the summary; the count goes on
	discoveryUpdateEvery = time.Hour         // the summary tells people again when it grew, at most this often
)

// firstDiscovery reports whether a new device belongs to the first discovery: notify first ran on this box (notify_box, migration
// 0011: an upgraded box takes its earliest notify record) less than firstDiscoveryWindow ago. A box that turns new-device alerts on
// later, or whose incidents passed retention, never opens the window again. A sensor's own first 36 hours come from inventory instead
// (AssetEvent.Learning), so a setup finished days after the install, or a sensor added later, still folds its first sweep.
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

// FirstRunAt is when the box first ran (notify_box.first_run_at: its install); zero when not known. Findings folds the urgency rises
// its first look brings into one summary.
func (s *Service) FirstRunAt(ctx context.Context) (time.Time, error) {
	var first string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT first_run_at FROM notify_box WHERE id = 1`).Scan(&first)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return time.Time{}, nil
	case err != nil:
		return time.Time{}, fmt.Errorf("notify: read first run: %w", err)
	}
	at, err := time.Parse(time.RFC3339Nano, first)
	if err != nil {
		return time.Time{}, nil
	}
	return at, nil
}

// discoveryIncident adds a device to the summary incident of the first discovery or of a sensor's learning: the first
// device opens it (and its one message goes out, if the channels take medium), the next ones add to its list and count, and its title
// says how many there are. An acknowledged summary that takes a new device goes back to New: a person acknowledged the devices they
// saw, not this one. Devices added since its last message are told again (tellDiscovery) with the device, and by the hourly autoclose
// job when they came within the hour after a message, so no device found by a burst stays untold.
func (s *Service) discoveryIncident(ctx context.Context, d Device, learning bool) error {
	what := "This is Vedette's first look at your network, so every device on it is new. Instead of one alert per device, the devices found in " +
		"its first 36 hours are listed together here."
	if learning {
		what = "A sensor started watching your network less than 36 hours ago, so every device it finds is new to Vedette. Instead of one alert " +
			"per device, the devices it finds while it learns the network are listed together here."
	}
	id, created, err := s.OpenIncident(ctx, IncidentInput{Kind: IncidentUnknownDevice, Source: firstDiscoverySource, Severity: Medium,
		Title: "Devices found on your network: add them in Devices", What: what,
		Action: "Open Devices, add the devices you know, and find out about the ones you do not.",
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
		var status, title string
		if err := tx.QueryRowContext(ctx, `SELECT count, status, title FROM notify_incident WHERE id = ?`, id).Scan(&count, &status, &title); err != nil {
			return fmt.Errorf("notify: count discovered devices: %w", err)
		}
		count = max(n, count)
		if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET title = ? WHERE id = ?`, discoveryTitle(count), id); err != nil {
			return fmt.Errorf("notify: name discovered devices: %w", err)
		}
		if created { // its first message is queued by OpenIncident
			_, err := tx.ExecContext(ctx, `UPDATE notify_box SET discovery_told_at = ?, discovery_told_count = ? WHERE id = 1`, store.FormatTS(now), count)
			return err
		}
		if status == string(StatusAcknowledged) {
			if _, err := tx.ExecContext(ctx, `UPDATE notify_incident SET status = 'new', handled_by = NULL, handled_at = NULL, active_at = ? WHERE id = ?`,
				store.FormatTS(now), id); err != nil {
				return fmt.Errorf("notify: reopen the discovery summary: %w", err)
			}
			if err := s.record(ctx, tx, systemUser, "notify.incident_status", clip(title, 400), "new: a new device was found"); err != nil {
				return err
			}
		}
		return s.tellDiscovery(ctx, tx, id, count, now)
	})
}

// discoveryTitle is the title of the discovery summary with count devices.
func discoveryTitle(count int) string {
	if count == 1 {
		return "1 device found on your network: add it in Devices"
	}
	return fmt.Sprintf("%d devices found on your network: add them in Devices", count)
}

// tellDiscovery queues the short "N more devices found" update of the discovery summary id when devices were added since its last
// message (count above notify_box.discovery_told_count; leaveDevice lowers that count when a told device leaves) and that message
// is at least discoveryUpdateEvery old.
func (s *Service) tellDiscovery(ctx context.Context, tx *sql.Tx, id string, count int, now time.Time) error {
	var toldAt sql.NullString
	var told int
	if err := tx.QueryRowContext(ctx, `SELECT discovery_told_at, discovery_told_count FROM notify_box WHERE id = 1`).Scan(&toldAt, &told); err != nil {
		return fmt.Errorf("notify: read discovery updates: %w", err)
	}
	last, _ := time.Parse(time.RFC3339Nano, toldAt.String)
	if count <= told || now.Sub(last) < discoveryUpdateEvery {
		return nil
	}
	if err := s.enqueue(ctx, tx, Notice{ID: id, Kind: KindIncident, IncidentKind: string(IncidentUnknownDevice), Severity: Medium, Title: discoveryTitle(count),
		What:   plural(count-told, "more device found", "more devices found") + " since the last message. Devices found while Vedette or a new sensor learns your network are listed together for 36 hours.",
		Action: "Open Devices, add the devices you know, and find out about the ones you do not.", Link: s.link("/incidents/" + id), At: now}); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE notify_box SET discovery_told_at = ?, discovery_told_count = ? WHERE id = 1`, store.FormatTS(now), count)
	return err
}

// discoveryUpdate is the hourly part of tellDiscovery (autoclose job): devices that came within the hour after the summary's last
// message, with no device after them, are told now. An open summary with nothing untold costs one read and no write.
func (s *Service) discoveryUpdate(ctx context.Context) error {
	var id string
	var count, told int
	switch err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT i.id, i.count, b.discovery_told_count FROM notify_incident i, notify_box b
		WHERE b.id = 1 AND i.dedupe_key = ? AND i.status <> 'resolved'`, newDeviceKey(firstDiscoverySource)).Scan(&id, &count, &told); {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("notify: read the discovery summary: %w", err)
	}
	if count <= told {
		return nil
	}
	now := s.now()
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return s.tellDiscovery(ctx, tx, id, count, now) })
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
	var devs []Device // The incident names the source device the inventory knew when the hit was stored
	if id, name := clip(strings.TrimSpace(e.SrcAssetID), 64), clip(strings.TrimSpace(e.SrcName), 120); id != "" && name != "" {
		devs = []Device{{ID: id, Name: name}}
	}
	at, _ := time.Parse(time.RFC3339, e.TS) // zero = now
	in := IncidentInput{Kind: IncidentTrap, Source: src, Target: label + "|" + e.Service,
		Title: title, Severity: Critical, What: what,
		Action: "Take the machine off the network (unplug the cable, turn off Wi-Fi), then ask its user what they were doing. Do not change passwords from that machine.",
		Link:   "/honeypot/hits/" + e.ID, Devices: devs, At: at}
	if e.Kind == "scan" { // One High incident per scanning source while it is open; the touches themselves stay Critical
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
		Blocked  bool     `json:"blocked"` // logs.bad_address.detected only: the device that logged it blocked the connection
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

// intrusionEvent opens or counts the incident of kind intrusion of an IPS or IDS alert (ids.alert.detected). The ids module sends the
// description ready-made; source (the attacking address) and target (the CVE ids or the rule) make the dedupe key, and the link is the
// alert's page (or /detection for the hourly summary). A repeat with a higher severity raises the open incident (OpenIncident).
func (s *Service) intrusionEvent(ctx context.Context, data any) error {
	var e struct {
		Source   string    `json:"source"`
		Target   string    `json:"target"`
		Title    string    `json:"title"`
		What     string    `json:"what"`
		Action   string    `json:"action"`
		Severity Severity  `json:"severity"`
		Link     string    `json:"link"`
		At       time.Time `json:"at"`
		Devices  []Device  `json:"devices"`
	}
	if err := decode(data, &e); err != nil {
		return err
	}
	if e.Link != "/detection" && !strings.HasPrefix(e.Link, "/detection/") {
		return fmt.Errorf("%w: an intrusion event links to its alert or to /detection", ErrInvalidNotice)
	}
	_, _, err := s.OpenIncident(ctx, IncidentInput{Kind: IncidentIntrusion, Source: e.Source, Target: e.Target, Title: e.Title, Severity: e.Severity,
		What: e.What, Action: e.Action, Link: e.Link, Devices: e.Devices, At: e.At})
	return err
}

// Jobs returns the scheduler jobs of the module: "deliver" sends what is due (held notices when quiet
// hours end, grouped batches at their DueAt, the rest at once); "autoclose" sends the first-run summary and closes quiet incidents
// (autoclose.go); "telegram-listen" and "slack-listen" take approval button presses
// while the Telegram / Slack channel takes approvals (tglisten.go, slacklisten.go). The five above run only while the module is on: `deliver` sends and its deletes are queue upkeep, not a customer retention, so it is not housekeeping. "retention" is Housekeeping (retention.go).
func (s *Service) Jobs() []jobs.Job {
	return []jobs.Job{
		{Module: ModuleID, Name: "deliver", Every: flushEvery, Run: s.Flush},
		{Module: ModuleID, Name: telegramListenJob, Every: telegramListenEvery, Run: s.listenTelegram},
		{Module: ModuleID, Name: slackListenJob, Every: slackListenEvery, Run: s.listenSlack},
		{Module: ModuleID, Name: zaloListenJob, Every: zaloListenEvery, Run: s.listenZalo},
		{Module: ModuleID, Name: autoCloseJob, Every: autoCloseEvery, Run: s.runAutoClose},                     // INV-22, INV-23: a normal job, only while notify is on
		{Module: ModuleID, Name: retentionJob, Every: retentionEvery, Housekeeping: true, Run: s.RunRetention}, // deletes history past 1 year, also while the module is off
	}
}

// plural is "1 <one>" or "<n> <many>".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
