package ids

import (
	"cmp"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/store"
)

// ModuleID is the id of the module in its MANIFEST.
const ModuleID = "ids"

// SourceLog is the source of an alert read from an IPS or IDS event in a log line a device sent to the box.
const SourceLog = "log"

// EventAlertDetected is published after an alert's events are stored (new, or more of them): notify opens or counts the incident
// of kind intrusion from it.
const EventAlertDetected = "ids.alert.detected"

// Bounds of what a flood of events can make the module hold or write (SYS-6).
const (
	// MaxPending is how many distinct alerts (signature, source, destination, hour) wait in memory for the next flush; the events of
	// more are dropped and counted.
	MaxPending = 2000
	// MaxAlerts is how many alert rows are kept; the oldest go first.
	MaxAlerts = 50000
	// RetentionDays is how long an alert is kept after its last event.
	RetentionDays = 90
	// AlertEventsPerHour is how many announcements of alerts notify gets in a clock hour (like the logs module's IocEventsPerHour): a
	// flood of distinct sources (UDP syslog can be forged on the LAN) cannot make thousands of incidents. Past it, the alerts are stored
	// and shown, and one summary incident a clock hour says that more came. The most severe alerts are announced first.
	AlertEventsPerHour = 100
	// FlushEvery is the pause between two flushes of the events received.
	FlushEvery = 5 * time.Second
)

// Line is a log line the logs module stored, with the kind of the source that sent it.
type Line struct {
	SourceID, SourceName, Kind string
	At                         time.Time
	Text                       string
}

// Inventory is what the module needs of the inventory: the device that has an address, and device names.
type Inventory interface {
	// DevicesAt maps each address to the one device that has it; an address no device or more than one device has is left out.
	DevicesAt(ctx context.Context, ips []string) (map[string]string, error)
	// Names gives the display name of each device id; a device that is gone is left out.
	Names(ctx context.Context, ids []string) (map[string]string, error)
}

// LinkedFinding is a finding of the attacked device for a CVE an alert names, with the findings module's one status.
type LinkedFinding struct {
	ID, CVE, Status string
	// Affected: the finding is open, so the device is affected by the CVE (not patched, mitigated, accepted or dismissed), and the flaw
	// can be exploited over the network: an alert naming a flaw that needs local or physical access is not an attack on it.
	Affected bool
}

// Findings is what the module needs of the findings module: the findings of some devices for some CVEs, read once for all of them
// (device id -> the CVEs an alert at it names; the answer is keyed by device id).
type Findings interface {
	Linked(ctx context.Context, cvesByDevice map[string][]string) (map[string][]LinkedFinding, error)
}

// IncidentRef is the incident of kind intrusion that groups an alert.
type IncidentRef struct{ ID, Status string }

// Incidents reads notify's intrusion incidents. Intrusion finds the incident opened for an incident key (source and target, as the
// event gave them) that existed at a time. ResolvedSince says whether the incident an announcement of ev would count on was resolved
// at or after since and none of its key is open: a repeat announced at since and held back since then must be announced again, as a
// new incident (notify ResolvedSince).
type Incidents interface {
	Intrusion(ctx context.Context, source, target string, at time.Time) (IncidentRef, bool, error)
	ResolvedSince(ctx context.Context, ev AlertEvent, since time.Time) (bool, error)
}

// Publisher publishes events after a commit.
type Publisher interface {
	Publish(ctx context.Context, e events.Event) error
}

// Modules says whether a module is on.
type Modules interface{ Enabled(id string) bool }

// Config is what the service needs. DB is required; every port may be nil (no names, no linked findings, no incidents, no events).
type Config struct {
	DB        *store.DB
	Inventory Inventory
	Findings  Findings
	Incidents Incidents
	Events    Publisher
	Modules   Modules // nil: the module counts as on
	Log       *slog.Logger
	Clock     func() time.Time
}

// pending is the events of one alert received since the last flush.
type pending struct {
	key         string
	ev          Event
	sourceName  string
	first, last time.Time
	count       int
}

// Service owns ids_alert and ids_alert_cve.
type Service struct {
	cfg Config

	mu      sync.Mutex
	buf     map[string]*pending
	dropped int64 // events dropped because MaxPending alerts were waiting
	lastIn  time.Time

	// The hourly announcement budget, read and written by the flush job only (one run at a time) under annMu: the clock hour, how many
	// were announced in it, the severity each incident key was last announced with in it and when (a repeat at the same or a lower
	// severity is not announced again while its incident is open; a rise is), and the summary of the hour.
	annMu      sync.Mutex
	annHour    int64
	annSent    int
	annTold    map[string]told
	annLeft    int       // alerts of the hour not announced one by one
	annSumRank int       // the severity the hour's summary was announced with; -1 = none yet
	annSumAt   time.Time // when it was
}

// told is the last announcement of an incident key in the hour: its severity rank and the time.
type told struct {
	rank int
	at   time.Time
}

// NewService checks the config and returns the service.
func NewService(cfg Config) (*Service, error) {
	if cfg.DB == nil {
		return nil, errors.New("ids: a database is required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Service{cfg: cfg, buf: map[string]*pending{}, annSumRank: -1}, nil
}

func (s *Service) on() bool { return s.cfg.Modules == nil || s.cfg.Modules.Enabled(ModuleID) }

func (s *Service) now() time.Time { return s.cfg.Clock().UTC().Truncate(time.Millisecond) }

// dedupeKey is the alert an event belongs to: one per source, signature (with the CVE ids the event names, at most MaxCVEs), source
// address, destination address and hour. The CVE ids are part of it, so an alert's CVE ids never change after it is made (and its
// incident key with them).
func dedupeKey(source string, e Event, at time.Time) string {
	h := sha256.Sum256([]byte(strings.Join([]string{source, e.Profile, strconv.FormatInt(e.SID, 10), e.Signature, strings.Join(e.CVEs, ","), e.Src.String(), e.Dst.String(),
		at.UTC().Truncate(time.Hour).Format(time.RFC3339)}, "\x00")))
	return hex.EncodeToString(h[:])
}

// Offer reads stored log lines for IPS events and keeps them for the next flush. It never blocks on the database (the logs module
// calls it after a batch is stored, and a syslog flood must not wait for the main database's writer): it only parses and counts in
// memory, bounded by MaxPending alerts. While the module is off it does nothing.
func (s *Service) Offer(_ context.Context, lines []Line) {
	if !s.on() {
		return
	}
	now := s.now()
	type found struct {
		ev   Event
		line Line
	}
	var got []found
	for _, l := range lines {
		if !Reads(l.Kind) {
			continue
		}
		if e, ok := Parse(l.Kind, l.Text); ok {
			got = append(got, found{e, l})
		}
	}
	if len(got) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range got {
		at := f.line.At.UTC().Truncate(time.Millisecond)
		if at.IsZero() || at.After(now) {
			at = now
		}
		key := dedupeKey(SourceLog, f.ev, at)
		p := s.buf[key]
		if p == nil {
			if len(s.buf) >= MaxPending {
				s.dropped++
				continue
			}
			p = &pending{key: key, ev: f.ev, sourceName: f.line.SourceName, first: at, last: at}
			s.buf[key] = p
		}
		p.count++
		p.first, p.last = minTime(p.first, at), maxTime(p.last, at)
		if f.ev.DstPort >= 0 && p.ev.DstPort < 0 {
			p.ev.DstPort = f.ev.DstPort
		}
		if at.After(s.lastIn) {
			s.lastIn = at
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// Jobs are the module's jobs: flush (stores what Offer kept, while the module is on) and purge (Housekeeping: deletes the alerts past
// RetentionDays and over MaxAlerts, also while the module is off).
func (s *Service) Jobs() []jobs.Job {
	return []jobs.Job{
		{Module: ModuleID, Name: "flush", Every: FlushEvery, Run: s.Flush},
		{Module: ModuleID, Name: "purge", Every: time.Hour, Run: s.Purge, Housekeeping: true},
	}
}

// stored is an alert row a flush wrote, as the incident event needs it.
type stored struct {
	id, srcAsset, dstAsset string
	p                      *pending
}

// Flush stores the alerts Offer kept, in one transaction, and then announces them. Dropped events are logged once per flush.
func (s *Service) Flush(ctx context.Context) error {
	s.mu.Lock()
	batch, dropped := s.buf, s.dropped
	s.buf, s.dropped = map[string]*pending{}, 0
	s.mu.Unlock()
	if dropped > 0 {
		s.cfg.Log.WarnContext(ctx, "ids: too many distinct IPS events at once; some were not stored", "dropped", dropped)
	}
	if len(batch) == 0 {
		return nil
	}
	devices := map[string]string{}
	if s.cfg.Inventory != nil {
		ips := make([]string, 0, 2*len(batch))
		for _, p := range batch {
			ips = append(ips, p.ev.Src.String(), p.ev.Dst.String())
		}
		d, err := s.cfg.Inventory.DevicesAt(ctx, ips)
		if err != nil { // the alerts are stored without devices rather than lost
			s.cfg.Log.WarnContext(ctx, "ids: the devices of the addresses could not be read", "err", err)
		} else {
			devices = d
		}
	}
	var out []stored
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		out = out[:0]
		for _, p := range batch {
			st, err := upsert(ctx, tx, p, devices[p.ev.Src.String()], devices[p.ev.Dst.String()])
			if err != nil {
				return err
			}
			out = append(out, st)
		}
		return trim(ctx, tx, s.now())
	})
	if err != nil {
		s.requeue(batch) // the next flush tries again, within MaxPending
		return err
	}
	s.announce(ctx, out)
	return nil
}

// requeue puts back the alerts of a flush whose write failed, merged with what arrived since, within MaxPending (the rest are counted
// as dropped).
func (s *Service) requeue(batch map[string]*pending) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range batch {
		if cur := s.buf[k]; cur != nil {
			cur.count += p.count
			cur.first, cur.last = minTime(cur.first, p.first), maxTime(cur.last, p.last)
			continue
		}
		if len(s.buf) >= MaxPending {
			s.dropped += int64(p.count)
			continue
		}
		s.buf[k] = p
	}
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(n int64) any {
	if n < 0 {
		return nil
	}
	return n
}

// upsert adds the events of p to their alert row, made when it is the first of its key.
func upsert(ctx context.Context, tx *sql.Tx, p *pending, srcAsset, dstAsset string) (stored, error) {
	e := p.ev
	var id string
	var src, dst sql.NullString
	err := tx.QueryRowContext(ctx, `INSERT INTO ids_alert (id, source, sid, signature, category, priority, src_ip, dst_ip, dst_port, proto, src_asset_id, dst_asset_id, first_ts, last_ts, count, dedupe_key)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (dedupe_key) DO UPDATE SET count = count + excluded.count, first_ts = min(first_ts, excluded.first_ts), last_ts = max(last_ts, excluded.last_ts),
			dst_port = coalesce(dst_port, excluded.dst_port), src_asset_id = coalesce(excluded.src_asset_id, src_asset_id), dst_asset_id = coalesce(excluded.dst_asset_id, dst_asset_id)
		RETURNING id, src_asset_id, dst_asset_id`,
		store.NewID("ida"), SourceLog, nullInt(e.SID), e.Signature, e.Category, e.Priority, e.Src.String(), e.Dst.String(), nullInt(int64(e.DstPort)), e.Proto,
		nullable(srcAsset), nullable(dstAsset), store.FormatTS(p.first), store.FormatTS(p.last), p.count, p.key).Scan(&id, &src, &dst)
	if err != nil {
		return stored{}, fmt.Errorf("ids: storing an alert: %w", err)
	}
	for _, c := range e.CVEs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ids_alert_cve (alert_id, cve) SELECT ?1, ?2 WHERE (SELECT count(*) FROM ids_alert_cve WHERE alert_id = ?1) < ?3
			ON CONFLICT DO NOTHING`, id, c, MaxCVEs); err != nil {
			return stored{}, fmt.Errorf("ids: storing the CVE of an alert: %w", err)
		}
	}
	return stored{id: id, srcAsset: src.String, dstAsset: dst.String, p: p}, nil
}

// trim deletes the alerts past the retention and the oldest over MaxAlerts.
func trim(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM ids_alert WHERE last_ts < ?`, store.FormatTS(now.AddDate(0, 0, -RetentionDays))); err != nil {
		return fmt.Errorf("ids: deleting old alerts: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ids_alert WHERE id IN (SELECT id FROM ids_alert ORDER BY last_ts DESC, id DESC LIMIT -1 OFFSET ?)`, MaxAlerts); err != nil {
		return fmt.Errorf("ids: deleting the oldest alerts: %w", err)
	}
	return nil
}

// Purge deletes the alerts past RetentionDays and over MaxAlerts (the Housekeeping job).
func (s *Service) Purge(ctx context.Context) error {
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return trim(ctx, tx, s.now()) })
}

// IncidentKey is the source and target of the intrusion incident an alert counts on: one incident per (CVE ids or rule, source
// address) while it repeats.
func IncidentKey(srcIP string, cves []string, sid int64, signature string) (source, target string) {
	switch {
	case len(cves) > 0:
		return srcIP, "cve:" + strings.Join(cves, ",")
	case sid >= 0:
		return srcIP, "rule:" + strconv.FormatInt(sid, 10) + ":" + clipText(signature, 150)
	}
	return srcIP, "rule:" + clipText(signature, 190)
}

// DeviceRef is a device as an event or the API names it.
type DeviceRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AlertEvent is the data of ids.alert.detected: notify opens or counts the incident of kind intrusion from it (source and target are
// its key). Every string is derived from an untrusted log line; notify shows it as plain text.
type AlertEvent struct {
	AlertID  string      `json:"alert_id"`
	Source   string      `json:"source"`
	Target   string      `json:"target"`
	Title    string      `json:"title"`
	What     string      `json:"what"`
	Action   string      `json:"action"`
	Severity string      `json:"severity"`
	Link     string      `json:"link"`
	At       time.Time   `json:"at"`
	Devices  []DeviceRef `json:"devices"`
}

// prioritySeverity is the severity of an alert from its rule's priority.
func prioritySeverity(p int) string {
	switch p {
	case 1:
		return "high"
	case 2:
		return "medium"
	case 3:
		return "low"
	}
	return "info"
}

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// summaryTarget is the start of the target of the summary incident of an hour in which alerts went past AlertEventsPerHour; the clock
// hour is appended, so each hour that overflows is its own incident.
const summaryTarget = "more intrusion alerts"

// announce publishes ids.alert.detected for the alerts a flush stored, in a fixed order: the most severe first (critical: the attacked
// device is affected by a CVE the alert names), then the newest, then by source address, incident target and alert. An incident key already announced in this clock hour with
// the same or a higher severity is not announced again while its incident is open (its alert row counts the events); once a person or
// Vedette resolved that incident, the repeat is a new incident and is announced again. One whose severity rose is, so notify raises
// the incident. At most AlertEventsPerHour announcements a clock hour; past it, one summary incident for the hour with the highest
// severity left out.
func (s *Service) announce(ctx context.Context, rows []stored) {
	if s.cfg.Events == nil || len(rows) == 0 {
		return
	}
	ctx = context.WithoutCancel(ctx)
	evs := s.alertEvents(ctx, rows)
	slices.SortFunc(evs, func(a, b AlertEvent) int {
		return cmp.Or(cmp.Compare(severityRank[b.Severity], severityRank[a.Severity]), b.At.Compare(a.At), strings.Compare(a.Source, b.Source),
			strings.Compare(a.Target, b.Target), strings.Compare(a.Link, b.Link))
	})
	s.annMu.Lock()
	now := s.now()
	hour := now.Unix() / 3600
	if hour != s.annHour {
		s.annHour, s.annSent, s.annTold, s.annLeft, s.annSumRank = hour, 0, map[string]told{}, 0, -1
	}
	var send []AlertEvent
	left, leftSev := 0, "info"
	sent := map[string]bool{}  // the keys announced in this flush
	again := map[string]bool{} // whether the incident of a key was resolved since its announcement, asked once a flush
	for _, ev := range evs {
		key := ev.Source + "\x00" + ev.Target
		rank := severityRank[ev.Severity]
		if t, ok := s.annTold[key]; ok && t.rank >= rank {
			// A repeat waits while its incident is open; once the incident was resolved since the announcement, the repeat is a new
			// incident and is announced again (within the budget below). A key announced in this flush is not asked again.
			if sent[key] {
				continue
			}
			res, asked := again[key]
			if !asked {
				res = s.resolvedSince(ctx, ev, t.at)
				again[key] = res
			}
			if !res {
				continue
			}
		}
		if s.annSent >= AlertEventsPerHour {
			left++
			if rank > severityRank[leftSev] {
				leftSev = ev.Severity
			}
			continue
		}
		s.annSent++
		s.annTold[key], sent[key] = told{rank, now}, true
		send = append(send, ev)
	}
	if severityRank[leftSev] < severityRank["medium"] {
		leftSev = "medium"
	}
	// The hour's summary goes out once, and again whenever what was left out is more severe than it said (an attack on an affected
	// device after the budget ran out): notify raises the summary incident and sends that raise.
	// A summary a person resolved while the flood goes on is announced again, once per resolve, like any other repeat.
	s.annLeft += left
	total := s.annLeft
	sum := s.summaryEvent(hour, total, leftSev)
	summary := left > 0 && (severityRank[leftSev] > s.annSumRank || s.annSumRank >= 0 && s.resolvedSince(ctx, sum, s.annSumAt))
	if summary { // after a resolve the summary is a new incident: it says the severity of what was left out since
		s.annSumRank, s.annSumAt = severityRank[leftSev], now
	}
	s.annMu.Unlock()
	for _, ev := range send {
		if err := s.cfg.Events.Publish(ctx, events.Event{Name: EventAlertDetected, Data: ev}); err != nil {
			s.cfg.Log.WarnContext(ctx, "ids: announcing an alert", "err", err)
		}
	}
	if left == 0 {
		return
	}
	s.cfg.Log.WarnContext(ctx, "ids: more intrusion alerts than the hourly limit of announcements; they are stored and shown on the Intrusion detection page", "not_announced", left, "limit", AlertEventsPerHour)
	if !summary {
		return
	}
	if err := s.cfg.Events.Publish(ctx, events.Event{Name: EventAlertDetected, Data: sum}); err != nil {
		s.cfg.Log.WarnContext(ctx, "ids: announcing the summary of the alerts not announced", "err", err)
	}
}

// summaryEvent is the summary incident of an hour in which total alerts were not announced one by one, at severity sev.
func (s *Service) summaryEvent(hour int64, total int, sev string) AlertEvent {
	title := "At least " + strconv.Itoa(total) + " more intrusion alerts this hour, not announced one by one"
	what := "The limit of " + strconv.Itoa(AlertEventsPerHour) + " announced intrusion alerts an hour was reached; more IPS events were received and are not announced one by one. A flood of events from many addresses can also be forged on the LAN when the firewall sends its logs over UDP."
	if sev == "critical" {
		title = "At least " + strconv.Itoa(total) + " more intrusion alerts this hour, including attacks on affected devices"
		what += " Among them are attacks on devices affected by the CVE the attack names."
	}
	return AlertEvent{Source: "ids", Target: summaryTarget + " " + strconv.FormatInt(hour, 10), Title: title, What: what,
		Action:   "Open Intrusion detection and read the alerts of the last 24 hours, the most severe first.",
		Severity: sev, Link: "/detection", At: s.now(), Devices: []DeviceRef{}}
}

// resolvedSince asks notify whether the incident of ev was resolved at or after since with none of its key open (Incidents.ResolvedSince).
// Without the port, or when the read fails, the repeat stays held back: a failed read never turns into a flood of announcements.
func (s *Service) resolvedSince(ctx context.Context, ev AlertEvent, since time.Time) bool {
	if s.cfg.Incidents == nil {
		return false
	}
	ok, err := s.cfg.Incidents.ResolvedSince(ctx, ev, since)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "ids: reading whether an incident was resolved", "err", err)
		return false
	}
	return ok
}

// alertEvents describes the stored alerts for their incidents. The devices' names and findings are read once for all of them; an alert
// whose attacked device is affected by a CVE it names is critical.
func (s *Service) alertEvents(ctx context.Context, rows []stored) []AlertEvent {
	set := map[string]bool{}
	cves := map[string][]string{}
	for _, r := range rows {
		for _, id := range []string{r.dstAsset, r.srcAsset} {
			if id != "" {
				set[id] = true
			}
		}
		if r.dstAsset != "" && len(r.p.ev.CVEs) > 0 {
			cves[r.dstAsset] = append(cves[r.dstAsset], r.p.ev.CVEs...)
		}
	}
	names := map[string]string{}
	if s.cfg.Inventory != nil && len(set) > 0 {
		idList := make([]string, 0, len(set))
		for id := range set {
			idList = append(idList, id)
		}
		slices.Sort(idList)
		if n, err := s.cfg.Inventory.Names(ctx, idList); err == nil {
			names = n
		}
	}
	linked := map[string][]LinkedFinding{}
	if s.cfg.Findings != nil && len(cves) > 0 {
		for id, c := range cves {
			slices.Sort(c)
			cves[id] = slices.Compact(c)
		}
		if l, err := s.cfg.Findings.Linked(ctx, cves); err == nil {
			linked = l
		} else {
			s.cfg.Log.WarnContext(ctx, "ids: the findings of the attacked devices could not be read", "err", err)
		}
	}
	out := make([]AlertEvent, 0, len(rows))
	for _, r := range rows {
		out = append(out, alertEvent(r, names, linked[r.dstAsset]))
	}
	return out
}

// alertEvent describes one alert for its incident.
func alertEvent(r stored, names map[string]string, linked []LinkedFinding) AlertEvent {
	e := r.p.ev
	var devices []DeviceRef
	for _, id := range []string{r.dstAsset, r.srcAsset} {
		if n := names[id]; id != "" && n != "" {
			devices = append(devices, DeviceRef{ID: id, Name: n})
		}
	}
	dst := e.Dst.String()
	if n := names[r.dstAsset]; n != "" {
		dst = n + " (" + e.Dst.String() + ")"
	}
	severity := prioritySeverity(e.Priority)
	var affected []string
	for _, f := range linked {
		if f.Affected && slices.Contains(e.CVEs, f.CVE) && !slices.Contains(affected, f.CVE) {
			affected = append(affected, f.CVE)
		}
	}
	slices.SortFunc(affected, cmpCVE)
	if len(affected) > 0 {
		severity = "critical"
	}
	source, target := IncidentKey(e.Src.String(), e.CVEs, e.SID, e.Signature)
	title := clipText(e.Src.String()+" fired "+clipText(e.Signature, 120)+" at "+dst, 200)
	var what strings.Builder
	what.WriteString("An IPS event")
	if r.p.sourceName != "" {
		what.WriteString(" in the log of " + r.p.sourceName)
	}
	what.WriteString(": " + e.Signature)
	if e.SID >= 0 {
		what.WriteString(" (rule " + strconv.FormatInt(e.SID, 10) + ")")
	}
	what.WriteString(", from " + e.Src.String() + " to " + dst)
	if e.DstPort >= 0 {
		what.WriteString(" port " + strconv.Itoa(e.DstPort))
	}
	what.WriteString(".")
	if len(e.CVEs) > 0 {
		what.WriteString(" It names " + strings.Join(e.CVEs, ", ") + ".")
	}
	action := "Check whether the device runs what the rule targets and is up to date. If " + e.Src.String() + " is not yours and keeps trying, block it at the firewall."
	if len(affected) > 0 {
		what.WriteString(" " + dst + " is affected by " + strings.Join(affected, ", ") + ".")
		action = "The attacked device is affected by " + strings.Join(affected, ", ") + ": patch it now, or isolate it until it is patched."
	}
	if devices == nil {
		devices = []DeviceRef{}
	}
	return AlertEvent{AlertID: r.id, Source: source, Target: target, Title: title, What: clipText(what.String(), 1000), Action: action,
		Severity: severity, Link: "/detection/alerts/" + r.id, At: r.p.last, Devices: devices}
}

// DeviceMerged moves the alerts of the merged device to the device it joined, in the inventory's transaction.
// (A deleted device needs nothing: the foreign keys set its alerts' device to NULL.)
func (s *Service) DeviceMerged(ctx context.Context, tx *sql.Tx, m lifecycle.Merge) error {
	if _, err := tx.ExecContext(ctx, `UPDATE ids_alert SET src_asset_id = ? WHERE src_asset_id = ?`, m.Into, m.From); err != nil {
		return fmt.Errorf("ids: moving the alerts of a merged device: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ids_alert SET dst_asset_id = ? WHERE dst_asset_id = ?`, m.Into, m.From); err != nil {
		return fmt.Errorf("ids: moving the alerts of a merged device: %w", err)
	}
	return nil
}

// LastInput is when the module last read an IPS event in a log line since the process started (zero when none); the stored alerts give
// the time before that.
func (s *Service) lastInput() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastIn
}
