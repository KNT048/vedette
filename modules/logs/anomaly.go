package logs

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
)

// The baseline (INV-6). Counters are per UTC day, so the last 24 hours are estimated the way a sliding-window rate limiter does:
// today's lines plus the part of yesterday's that is still inside the window. The baseline is the 7 full days before
// yesterday, so that neither the window nor its edge is part of what it is compared with.
const (
	// BaselineDays is the length of the baseline (baseline_days of the digest).
	BaselineDays = 7
	// WarmUp is how long a source is silent after its first line: no "new", no spike and no event (the D-78 lesson: the first
	// pull is not news). A kind of line seen during it belongs to the baseline.
	WarmUp = 24 * time.Hour
	// SpikeFloor and SpikeFactor: a spike is at least max(SpikeFloor, SpikeFactor x baseline_per_day) lines in 24 hours.
	SpikeFloor  = 20
	SpikeFactor = 5
	// DigestMax is how many new items and how many spikes the digest lists (in the order of rank: bounded first, then the rarest new).
	DigestMax = 20
	// EventsPerHour is the most logs.anomaly.detected events one source can send in an hour in each class: signatures of shipped data (bounded) and the rest.
	EventsPerHour = 20
	// MaxAnomaliesPerPass is how many unannounced anomalies of one source one pass looks at one by one (the best ranked first); the others of
	// the pass are counted in the summary event.
	MaxAnomaliesPerPass = 200
	// SummaryTarget is the start of the target of the flood summary of an hour when it carries new kinds of message ("new kinds of
	// message 2026-11-12T14": different every hour, so notify opens a new incident each time); a summary of spikes only says
	// "spiking kinds of message", both "new and spiking kinds of message". BacklogTarget is the same for the bounded backlog summary.
	SummaryTarget = "new kinds of message"
	// BoundedPrefix starts the target of every event of a bounded signature ("sig:<signature>"): its own namespace in notify's
	// dedupe key (kind, source, target), so a mined incident aimed at the same destination can never absorb it. A mined target is an
	// address or a masked text and cannot hold "sig:" followed by a bounded signature: those keep digits, which the miner always
	// masks, and contain spaces, which a destination cannot have.
	BoundedPrefix = "sig:"
	BacklogTarget = "waiting events"
	// MaxEventText, MaxEventKey, MaxEventTitle, MaxDeviceID and MaxDeviceName are what notify accepts (modules/notify/incidents.go
	// validate): what and action at most 1,000 characters, source and target 200, the title 200, a device id 96 bytes and a name 253.
	MaxEventText  = 1000
	MaxEventKey   = 200
	MaxEventTitle = 200
	MaxDeviceID   = 96
	MaxDeviceName = 253
	// DetectEvery is how often the anomaly job looks.
	// ponytail: a full read of the last 10 days of counters every 5 minutes (measured in TestMeasureDigestCost: see D-206);
	// past about 200,000 rows read only today and yesterday and keep the baseline in memory.
	DetectEvery = 5 * time.Minute
	// EventAnomalyDetected is the event notify opens an incident from (notify/events.go).
	EventAnomalyDetected = "logs.anomaly.detected"

	day = 24 * time.Hour
)

// AnomalyEvent is the data of logs.anomaly.detected. Source and Target are the key notify groups incidents by (the same kind, source
// and target still open count up instead of opening another), so one event stands for every anomaly of a source that aims at the
// same target. Every string comes from a device's log (untrusted): notify cuts it and shows it as plain text.
type AnomalyEvent struct {
	Source   string       `json:"source"`   // the name of the log source
	Target   string       `json:"target"`   // the address the lines are about, or the signature when they have none
	Title    string       `json:"title"`    // one English sentence, at most 200 characters
	What     string       `json:"what"`     // the signatures with their counts and one example line
	Action   string       `json:"action"`   // what to do
	Severity string       `json:"severity"` // low for a new kind of line, medium for a spike
	Devices  []DeviceInfo `json:"devices"`  // the inventory devices that match (may be empty)
}

// DeviceInfo is a device of AnomalyEvent.
type DeviceInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// anomaly is one new or spiking signature of one source.
type anomaly struct {
	Kind      string // "new" or "spike"
	SourceID  string
	Signature string
	Count     int       // lines in the 24 hours (an estimate for a spike)
	Base      float64   // baseline_per_day (spike)
	First     time.Time // first time seen (new)
	Bounded   bool      // the signature comes from a vocabulary of shipped data (a known log id or event id)
}

// ponytail: a spike's ref is the UTC day, so a bounded spike is announced or named best effort within the day it is seen (a spike that goes
// on is evaluated again the next day); upgrade path: key the ref on the day the spike started.
//
// rank orders anomalies for the digest and for the events. A signature that shipped data can name comes before one that the miner made
// (a log id or an event id the product knows is what a person needs to see; what the miner made can be a list of user names), and
// then the rarest first: a burst of new kinds of line (a brute force, a scan) is many signatures of about the same count, and the one
// real event is the one with one line. A spike is the opposite: the one with most lines first. So the order is: bounded new, bounded
// spike, mined new (the rarest first), mined spike (the most lines first), and last the text, so that the order is fixed. Bounded new items are the exception to "rarest first": the one first seen last goes first whatever its
// count, so a real event of 2 or 50 lines is not behind a flood of 1-line items; for the mined new items it breaks ties.
func rank(a, b anomaly) int {
	switch {
	case a.Bounded != b.Bounded:
		if a.Bounded {
			return -1
		}
		return 1
	case a.Kind != b.Kind:
		if a.Kind == "new" {
			return -1
		}
		return 1
	case a.Bounded && a.Kind == "new" && !a.First.Equal(b.First): // bounded new: the newest first whatever the count (a flood of 1-line items must not delay a real event of 2 or 50 lines)
		if a.First.After(b.First) {
			return -1
		}
		return 1
	case a.Count != b.Count && a.Kind == "new":
		return a.Count - b.Count
	case a.Count != b.Count:
		return b.Count - a.Count
	case a.Kind == "new" && !a.First.Equal(b.First): // equal counts: the one first seen last goes first, so a real new event is not behind a flood
		if a.First.After(b.First) {
			return -1
		}
		return 1
	}
	return strings.Compare(a.SourceID+"\x00"+a.Signature, b.SourceID+"\x00"+b.Signature)
}

// anomalies reads the last 9 days of counters, per signature and day, and returns every new kind of line and every spike of the sources that are past
// their warm-up. names maps a declared source to its row; counters of a source that is not declared are not read as news.
func (s *Service) anomalies(ctx context.Context, now time.Time) ([]anomaly, map[string]sourceRow, error) {
	srcs, err := s.loadSources(ctx)
	if err != nil {
		return nil, nil, err
	}
	names := make(map[string]sourceRow, len(srcs))
	for _, r := range srcs {
		names[r.ID] = r
	}
	now = now.UTC()
	today := now.Truncate(day)
	dayStr := func(t time.Time) string { return t.Format("2006-01-02") }
	baseFrom, baseTo := today.Add(-(BaselineDays+1)*day), today.Add(-2*day)
	// The counters are kept for BaselineDays+2 days: the oldest day is read only to know when each source started (the baseline needs
	// the full 7 days after it), not for "new" or the baseline itself.
	rows, err := s.cfg.Volume.Reader().QueryContext(ctx, `SELECT source_id, signature, day, count, first_seen, mined
		FROM logs_signature_daily WHERE day >= ? AND signature <> ?`, dayStr(today.Add(-(BaselineDays+2)*day)), OtherSignature)
	if err != nil {
		return nil, nil, fmt.Errorf("logs: reading signature counters: %w", err)
	}
	defer func() { _ = rows.Close() }()
	type key struct{ source, sig string }
	const span = BaselineDays + 3 // today, yesterday and the 8 days before: back = 0..9
	type sigRow struct {
		n     [span]int // lines of the day that many days back
		first string    // the earliest first_seen of the days from baseFrom on (a fixed-width text: it sorts as time does)
		mined bool
	}
	back := make(map[string]int, span)
	for i := 0; i < span; i++ {
		back[dayStr(today.Add(-time.Duration(i)*day))] = i
	}
	all := map[key]*sigRow{}
	startedAt := map[string]string{} // when each source was first heard from, as far as the counters read go back
	for rows.Next() {
		var k key
		var d, first string
		var n, mined int
		if err := rows.Scan(&k.source, &k.sig, &d, &n, &first, &mined); err != nil {
			return nil, nil, fmt.Errorf("logs: reading signature counters: %w", err)
		}
		if t, ok := startedAt[k.source]; !ok || first < t {
			startedAt[k.source] = first
		}
		i, ok := back[d]
		if !ok || i > BaselineDays+1 {
			continue // the oldest day is read only for the start of the source
		}
		r := all[k]
		if r == nil {
			r = &sigRow{first: first, mined: mined == 1}
			all[k] = r
		}
		if first < r.first {
			r.first = first
		}
		r.n[i] = n
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("logs: reading signature counters: %w", err)
	}
	started := make(map[string]time.Time, len(startedAt))
	for id, ts := range startedAt {
		t, err := time.Parse("2006-01-02T15:04:05.000Z", ts)
		if err != nil {
			return nil, nil, fmt.Errorf("logs: reading signature counters: %w", err)
		}
		started[id] = t
	}
	for _, r := range srcs { // a change of kind or sender starts the source again: its signatures mean something else now
		if t, ok := started[r.ID]; ok && r.Since.After(t) {
			started[r.ID] = r.Since
		}
	}
	frac := float64(now.Sub(today)) / float64(day)
	var out []anomaly
	for k, r := range all {
		if _, ok := names[k.source]; !ok {
			continue
		}
		warmEnd := started[k.source].Add(WarmUp)
		if now.Before(warmEnd) {
			continue // the source is still warming up
		}
		first, err := time.Parse("2006-01-02T15:04:05.000Z", r.first)
		if err != nil {
			return nil, nil, fmt.Errorf("logs: reading signature counters: %w", err)
		}
		if !first.Before(now.Add(-day)) && !first.Before(warmEnd) { // not seen before this window, and not during the warm-up
			out = append(out, anomaly{Kind: "new", SourceID: k.source, Signature: k.sig, Count: r.n[0] + r.n[1], First: first, Bounded: !r.mined})
			continue
		}
		// The baseline: the full days the source existed, among the 7 before yesterday (the day it started is partial and left out).
		lo := baseFrom
		if f := started[k.source].Truncate(day).Add(day); f.After(lo) {
			lo = f
		}
		if lo.After(baseTo) {
			continue // no full day to compare with yet
		}
		n, sum := 0, 0
		for d := lo; !d.After(baseTo); d = d.Add(day) {
			n++
			sum += r.n[back[dayStr(d)]]
		}
		est := float64(r.n[0]) + float64(r.n[1])*(1-frac)
		perDay := float64(sum) / float64(n)
		if est >= math.Max(SpikeFloor, SpikeFactor*perDay) {
			out = append(out, anomaly{Kind: "spike", SourceID: k.source, Signature: k.sig, Count: int(math.Round(est)), Base: math.Round(perDay*10) / 10, Bounded: !r.mined})
		}
	}
	return out, names, nil
}

// detail is what the counters know about one signature of one source, besides its count: where its lines were aimed and an example.
type detail struct {
	dest   string // the destination of the latest line
	sample string // the sample of the newest row
}

// detailOf reads where the latest line of a signature was aimed and its newest sample, over the counters kept (one lookup on the
// index of the source and signature: at most 10 rows, not a read of the source).
func (s *Service) detailOf(ctx context.Context, source, sig string, now time.Time) (detail, error) {
	m, err := s.detailsOf(ctx, source, []string{sig}, now)
	return m[sig], err
}

// detailChunk is how many signatures one detailsOf query names (SQLite allows far more bound values; this keeps a statement small).
const detailChunk = 200

// detailsOf is detailOf for many signatures of one source, one query per detailChunk of them instead of one per signature: a pass
// over a flood (MaxAnomaliesPerPass items) made hundreds of lookups every five minutes.
func (s *Service) detailsOf(ctx context.Context, source string, sigs []string, now time.Time) (map[string]detail, error) {
	out := make(map[string]detail, len(sigs))
	since := now.UTC().Add(-(BaselineDays + 2) * day).Format("2006-01-02")
	for part := range slices.Chunk(sigs, detailChunk) {
		args := make([]any, 0, len(part)+2)
		args = append(args, source, since)
		for _, sig := range part {
			args = append(args, sig)
		}
		rows, err := s.cfg.Volume.Reader().QueryContext(ctx, `SELECT signature, dest, sample FROM logs_signature_daily WHERE source_id = ? AND day >= ? AND signature IN (?`+
			strings.Repeat(", ?", len(part)-1)+`) ORDER BY signature, day`, args...)
		if err != nil {
			return nil, fmt.Errorf("logs: reading signature details: %w", err)
		}
		for rows.Next() { // oldest day first within a signature, so the newest non-empty value wins
			var sig, dest, sample string
			if err := rows.Scan(&sig, &dest, &sample); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("logs: reading signature details: %w", err)
			}
			d := out[sig]
			if dest != "" {
				d.dest = dest
			}
			if sample != "" {
				d.sample = sample
			}
			out[sig] = d
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, fmt.Errorf("logs: reading signature details: %w", err)
		}
	}
	return out, nil
}

// digestItems turns the anomalies into the lists of the digest: at most DigestMax of each, taken round-robin across the sources (the
// best ranked of each source first, then the second of each, and so on), so that one source's flood cannot hide another source's
// items; within a source the order of rank (bounded first, the rarest new first).
func (s *Service) digestItems(ctx context.Context, found []anomaly, names map[string]sourceRow) ([]NewItem, []SpikeItem, error) {
	news, spikes := []NewItem{}, []SpikeItem{}
	if len(found) == 0 {
		return news, spikes, nil
	}
	now := s.now()
	for _, a := range roundRobin(found, "new", DigestMax) {
		d, err := s.detailOf(ctx, a.SourceID, a.Signature, now)
		if err != nil {
			return nil, nil, err
		}
		news = append(news, NewItem{ID: "n-" + itemID(a), Signature: a.Signature, SourceID: a.SourceID, SourceName: names[a.SourceID].Name, Count: a.Count, FirstSeen: a.First, Sample: d.sample})
	}
	for _, a := range roundRobin(found, "spike", DigestMax) {
		d, err := s.detailOf(ctx, a.SourceID, a.Signature, now)
		if err != nil {
			return nil, nil, err
		}
		spikes = append(spikes, SpikeItem{ID: "s-" + itemID(a), Signature: a.Signature, SourceID: a.SourceID, SourceName: names[a.SourceID].Name, Count: a.Count, BaselinePerDay: a.Base, Sample: d.sample})
	}
	return news, spikes, nil
}

// roundRobin picks up to limit anomalies of one kind: each source's items in the order of rank, the sources in the order of their id,
// one item of each source in turn.
func roundRobin(found []anomaly, kind string, limit int) []anomaly {
	by := map[string][]anomaly{}
	for _, a := range found { // found is the shared snapshot: it is read here, never sorted in place
		if a.Kind == kind {
			by[a.SourceID] = append(by[a.SourceID], a)
		}
	}
	ids := make([]string, 0, len(by))
	for id := range by {
		slices.SortFunc(by[id], rank)
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var out []anomaly
	for i := 0; len(out) < limit; i++ {
		added := false
		for _, id := range ids {
			if i < len(by[id]) && len(out) < limit {
				out = append(out, by[id][i])
				added = true
			}
		}
		if !added {
			break
		}
	}
	return out
}

func itemID(a anomaly) string {
	h := sha256.Sum256([]byte(a.SourceID + "\x00" + a.Signature))
	return hex.EncodeToString(h[:6])
}

// group is the anomalies of one source that aim at one target: one event.
type group struct {
	target  string
	dest    string // where the lines were aimed (the latest line), for the text and the device lookup; target is the key notify groups by
	items   []anomaly
	latest  time.Time // the newest first_seen of its items
	count   int
	rarest  int // the fewest lines of an item
	spike   bool
	bounded bool
}

// detect announces the anomalies that have not been announced: grouped by source and target, at most EventsPerHour events an hour
// per source (what is held back goes out when the hour has room; it is not lost, and is dropped only when it is no longer an
// anomaly). Nothing is announced for a source in its warm-up (anomalies does not return it). It runs only as the job "anomaly",
// which core/jobs does not start while the module is off (SYS-5).
func (s *Service) detect(ctx context.Context) error {
	if s.cfg.Events == nil {
		return nil
	}
	now := s.now().UTC()
	gen := s.snapshotGen()
	found, names, err := s.anomalies(ctx, now)
	if err != nil {
		return err
	}
	s.storeSnapshotIfCurrent(gen, now, found, names) // the digest and the events are one reading
	if len(found) == 0 {
		return nil
	}
	bySource := map[string][]anomaly{}
	for _, a := range found {
		bySource[a.SourceID] = append(bySource[a.SourceID], a)
	}
	ids := make([]string, 0, len(bySource))
	for id := range bySource {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var errs []error
	for _, id := range ids {
		if err := s.detectSource(ctx, now, names[id], bySource[id]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// sentKey is the key of what logs_anomaly_sent holds in the maps of detectSource.
func sentKey(kind, sig, ref string) string { return kind + "\x00" + sig + "\x00" + ref }

func (s *Service) detectSource(ctx context.Context, now time.Time, src sourceRow, items []anomaly) error {
	sent, covered, err := s.readSent(ctx, src.ID)
	if err != nil {
		return err
	}
	ref := func(a anomaly) string {
		if a.Kind == "new" {
			return store.FormatTS(a.First)
		}
		return now.Format("2006-01-02")
	}
	var bounded, mined []anomaly // the two classes have a room of their own (D-206)
	for _, a := range items {
		switch {
		case sent[sentKey(a.Kind, a.Signature, ref(a))]:
		case a.Bounded:
			bounded = append(bounded, a)
		default:
			mined = append(mined, a)
		}
	}
	if len(bounded)+len(mined) == 0 {
		return nil
	}
	// The sender of the log is looked up once for every event of the source in this pass, and not at all when nothing is announced.
	var baseDevices []DeviceInfo
	haveBase := false
	base := func() []DeviceInfo {
		if !haveBase {
			baseDevices, haveBase = s.devicesOf(ctx, src), true
		}
		return baseDevices
	}
	hour := now.Format("2006-01-02T15")
	pass := &sourcePass{s: s, src: src, now: now, hour: hour, ref: ref, sent: sent, covered: covered, base: base}
	return errors.Join(pass.bounded(ctx, bounded), pass.mined(ctx, mined))
}

// readSent reads what has been announced for a source: sent is every row by (kind, signature, ref), covered is the items that a summary
// has named (kind "covered", key signature + ref).
func (s *Service) readSent(ctx context.Context, source string) (sent, covered map[string]bool, err error) {
	sent, covered = map[string]bool{}, map[string]bool{}
	rows, err := s.cfg.Volume.Reader().QueryContext(ctx, `SELECT kind, signature, ref FROM logs_anomaly_sent WHERE source_id = ?`, source)
	if err != nil {
		return nil, nil, fmt.Errorf("logs: reading what was announced: %w", err)
	}
	for rows.Next() {
		var k, sig, ref string
		if err := rows.Scan(&k, &sig, &ref); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("logs: reading what was announced: %w", err)
		}
		if k == "covered" {
			covered[sig+"\x00"+ref] = true
		} else {
			sent[sentKey(k, sig, ref)] = true
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, nil, fmt.Errorf("logs: reading what was announced: %w", err)
	}
	return sent, covered, nil
}

// sourcePass is one pass of detect over one source.
type sourcePass struct {
	s       *Service
	src     sourceRow
	now     time.Time
	hour    string
	ref     func(anomaly) string
	sent    map[string]bool
	covered map[string]bool
	base    func() []DeviceInfo
}

func (p *sourcePass) isCovered(a anomaly) bool { return p.covered[a.Signature+"\x00"+p.ref(a)] }

func (p *sourcePass) uncovered(items []anomaly) []anomaly {
	var out []anomaly
	for _, a := range items {
		if !p.isCovered(a) {
			out = append(out, a)
		}
	}
	return out
}

// bounded announces the signatures of shipped data (at most about 540 exist): each its own event, with a target of its own
// ("sig:<signature>"), never in a mined summary. When more wait than the hour has room for, room-1 go out one by one (the best
// ranked: the rarest, and among equals the newest) and the last place of the hour is ONE backlog summary of the source, naming the
// waiting items that no earlier summary has named, so that none ages out unannounced; what a summary names is still announced one
// by one when there is room (it is not marked as sent).
func (p *sourcePass) bounded(ctx context.Context, waiting []anomaly) error {
	if len(waiting) == 0 {
		return nil
	}
	inHour, err := p.s.sentInHour(ctx, p.src.ID, p.now, true)
	if err != nil {
		return err
	}
	room := EventsPerHour - inHour
	if room <= 0 {
		return nil
	}
	slices.SortFunc(waiting, rank)
	n := min(room, len(waiting))
	var fresh []anomaly
	if len(waiting) > room && room >= 2 && !p.sent[sentKey("summary", BacklogTarget, p.hour)] {
		if fresh = p.uncovered(waiting[room-1:]); len(fresh) > 0 {
			n = room - 1
		}
	}
	send := waiting[:n:n]
	if len(fresh) > 0 && room >= 3 {
		// With a summary going out, one individual place is for the item that has been named longest and still waits (first in, first
		// out), so under a steady trickle of fresh items a named one still gets its own event.
		var oldest []anomaly
		for _, a := range waiting[room-2:] {
			if a.Kind == "new" && p.isCovered(a) && (oldest == nil || a.First.Before(oldest[0].First)) {
				oldest = []anomaly{a}
			}
		}
		if oldest != nil {
			n = room - 2
			send = append(waiting[:n:n], oldest...)
		}
	}
	var errs []error
	for _, a := range send {
		d, err := p.s.detailOf(ctx, p.src.ID, a.Signature, p.now)
		if err != nil {
			return errors.Join(append(errs, err)...)
		}
		g := &group{target: clipRunes(BoundedPrefix+a.Signature, MaxEventKey), dest: d.dest, items: []anomaly{a}, count: a.Count, rarest: a.Count, spike: a.Kind == "spike", bounded: true, latest: a.First}
		errs = append(errs, p.s.announce(ctx, p.src, p.now, p.ref, g, p.s.eventFor(ctx, p.src, g, map[string]detail{a.Signature: d}, p.base()), true))
	}
	if len(fresh) > 0 {
		errs = append(errs, p.backlog(ctx, fresh, len(waiting)-len(send)))
	}
	return errors.Join(errs...)
}

// backlog announces the backlog summary of the hour: how many bounded events are waiting, and the rarest of those no summary has named.
func (p *sourcePass) backlog(ctx context.Context, fresh []anomaly, waiting int) error {
	ev, named := backlogEvent(p.src, p.hour, fresh, waiting, p.base())
	if err := p.s.cfg.Events.Publish(ctx, events.Event{Name: EventAnomalyDetected, Data: ev}); err != nil {
		return fmt.Errorf("logs: announcing a backlog: %w", err)
	}
	return p.s.cfg.Volume.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO logs_anomaly_sent (source_id, kind, signature, ref, target, sent_at, bounded) VALUES (?, 'summary', ?, ?, ?, ?, 1)`,
			p.src.ID, BacklogTarget, p.hour, ev.Target, store.FormatTS(p.now)); err != nil {
			return fmt.Errorf("logs: recording a backlog: %w", err)
		}
		return markCovered(ctx, tx, p.src.ID, named, p.ref, p.now, true)
	})
}

// markCovered records that a summary has named the items (kind "covered"): the next summary leaves them out, and they are still
// announced one by one when there is room.
func markCovered(ctx context.Context, tx *sql.Tx, source string, items []anomaly, ref func(anomaly) string, now time.Time, bounded bool) error {
	for _, a := range items {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO logs_anomaly_sent (source_id, kind, signature, ref, target, sent_at, bounded) VALUES (?, 'covered', ?, ?, '', ?, ?)`,
			source, a.Signature, ref(a), store.FormatTS(now), flag(bounded)); err != nil {
			return fmt.Errorf("logs: recording a summary: %w", err)
		}
	}
	return nil
}

// mined is best effort for everything the miner made (spikes included): one event for each group when there are few, and when there
// are more groups than the hour has room for (a brute force, a scan, a device that sends a different line every time) ONE summary of
// the source, with a target that is different every hour so that notify opens a new incident. A summary covers only the items that
// no earlier summary has covered (a one-off burst of 21 kinds is one summary, not one every hour); when the flood is over and the
// rest fit in the room, they are announced one by one. Once this hour's summary has gone out the pass does nothing.
func (p *sourcePass) mined(ctx context.Context, waiting []anomaly) error {
	if len(waiting) == 0 || p.sent[sentKey("summary", SummaryTarget, p.hour)] {
		return nil
	}
	inHour, err := p.s.sentInHour(ctx, p.src.ID, p.now, false)
	if err != nil {
		return err
	}
	room := EventsPerHour - inHour
	if room <= 0 {
		return nil
	}
	slices.SortFunc(waiting, rank)
	fresh := p.uncovered(waiting) // in the order of rank
	if len(fresh) == 0 && len(waiting) > MaxAnomaliesPerPass {
		return nil // all named by an earlier summary and too many to announce one by one: the loop below would end the same, after reading details
	}
	picks := [][]anomaly{waiting}
	if len(fresh) > 0 && len(fresh) < len(waiting) { // all of it, or only what no summary has named
		picks = append(picks, fresh)
	} else if len(fresh) == 0 {
		picks = picks[:1]
	}
	for i, pick := range picks {
		var tail []anomaly // past the best MaxAnomaliesPerPass: counted in the summary, not looked at one by one
		if len(pick) > MaxAnomaliesPerPass {
			tail, pick = pick[MaxAnomaliesPerPass:], pick[:MaxAnomaliesPerPass]
		}
		groups, det, err := p.s.groupsOf(ctx, p.src, p.now, pick)
		if err != nil {
			return err
		}
		if len(groups) <= room && len(tail) == 0 {
			var errs []error
			for _, g := range groups {
				errs = append(errs, p.s.announce(ctx, p.src, p.now, p.ref, g, p.s.eventFor(ctx, p.src, g, det, p.base()), false))
			}
			return errors.Join(errs...)
		}
		if i < len(picks)-1 {
			continue
		}
		all := append([]anomaly(nil), tail...)
		for _, g := range groups {
			all = append(all, g.items...)
		}
		if len(p.uncovered(all)) == 0 {
			return nil // everything was named by an earlier summary
		}
		slices.SortFunc(all, rank)
		return p.summary(ctx, all, det)
	}
	return nil
}

// summary announces the flood summary of the hour and covers what it carries.
func (p *sourcePass) summary(ctx context.Context, all []anomaly, det map[string]detail) error {
	ev, target := summaryEvent(p.src, p.hour, all, det, p.base())
	if err := p.s.cfg.Events.Publish(ctx, events.Event{Name: EventAnomalyDetected, Data: ev}); err != nil {
		return fmt.Errorf("logs: announcing a flood: %w", err)
	}
	return p.s.cfg.Volume.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO logs_anomaly_sent (source_id, kind, signature, ref, target, sent_at, bounded) VALUES (?, 'summary', ?, ?, ?, ?, 0)`,
			p.src.ID, SummaryTarget, p.hour, target, store.FormatTS(p.now)); err != nil {
			return fmt.Errorf("logs: recording a summary: %w", err)
		}
		return markCovered(ctx, tx, p.src.ID, all, p.ref, p.now, false)
	})
}

// sentInHour counts the events a source has sent in the last hour in one class (bounded, or the rest including the summaries).
func (s *Service) sentInHour(ctx context.Context, source string, now time.Time, bounded bool) (int, error) {
	var n int
	err := s.cfg.Volume.Reader().QueryRowContext(ctx, `SELECT count(*) FROM (SELECT DISTINCT target, sent_at FROM logs_anomaly_sent WHERE source_id = ? AND bounded = ? AND kind <> 'covered' AND sent_at > ?)`,
		source, flag(bounded), store.FormatTS(now.Add(-time.Hour))).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("logs: counting what was announced: %w", err)
	}
	return n, nil
}

// groupsOf looks up where each anomaly was aimed and groups them by target (the address, or the signature when there is none), in the
// order of the events: spikes after new, the rarest first, the text last.
func (s *Service) groupsOf(ctx context.Context, src sourceRow, now time.Time, items []anomaly) ([]*group, map[string]detail, error) {
	sigs := make([]string, len(items))
	for i, a := range items {
		sigs[i] = a.Signature
	}
	det, err := s.detailsOf(ctx, src.ID, sigs, now)
	if err != nil {
		return nil, nil, err
	}
	groups := map[string]*group{}
	for _, a := range items {
		d := det[a.Signature]
		target := d.dest
		if target == "" {
			target = a.Signature
		}
		g := groups[target]
		if g == nil {
			g = &group{target: target, dest: d.dest}
			groups[target] = g
		}
		if a.First.After(g.latest) {
			g.latest = a.First
		}
		g.items = append(g.items, a)
		g.count += a.Count
		g.spike = g.spike || a.Kind == "spike"
		g.bounded = g.bounded || a.Bounded
		if g.rarest == 0 || a.Count < g.rarest {
			g.rarest = a.Count
		}
	}
	order := make([]*group, 0, len(groups))
	for _, g := range groups {
		order = append(order, g)
	}
	slices.SortFunc(order, func(a, b *group) int { // the order of rank: new before spike, then the rarest, then the text
		switch {
		case a.spike != b.spike:
			if a.spike {
				return 1
			}
			return -1
		case a.rarest != b.rarest:
			return a.rarest - b.rarest
		case !a.latest.Equal(b.latest): // equal counts: the newest first, as rank does
			if a.latest.After(b.latest) {
				return -1
			}
			return 1
		}
		return strings.Compare(a.target, b.target)
	})
	return order, det, nil
}

// announce publishes the event of a group and, when that worked, records its signatures as announced.
func (s *Service) announce(ctx context.Context, src sourceRow, now time.Time, ref func(anomaly) string, g *group, ev AnomalyEvent, bounded bool) error {
	if err := s.cfg.Events.Publish(ctx, events.Event{Name: EventAnomalyDetected, Data: ev}); err != nil {
		return fmt.Errorf("logs: announcing an anomaly: %w", err) // not recorded: the next pass tries again
	}
	return s.cfg.Volume.Write(ctx, func(tx *sql.Tx) error {
		for _, a := range g.items {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO logs_anomaly_sent (source_id, kind, signature, ref, target, sent_at, bounded) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				src.ID, a.Kind, a.Signature, ref(a), g.target, store.FormatTS(now), flag(bounded)); err != nil {
				return fmt.Errorf("logs: recording an announcement: %w", err)
			}
		}
		return nil
	})
}

// summaryEvent is the one event that stands for the flood of an hour, and the target it was sent with. The target is different every
// hour, so notify opens a new incident for each (the same target would be counted up in an old one, silently). Title and target say
// what it carries (new kinds of message, spikes, or both) and the real span: "since <time of the first new kind>" and "in the last 24
// hours" for a spike (the estimate is over 24 hours). items is in the order of rank (the rarest first).
func summaryEvent(src sourceRow, hour string, items []anomaly, det map[string]detail, base []DeviceInfo) (AnomalyEvent, string) {
	news, spikes := 0, 0
	var since time.Time
	for _, a := range items {
		if a.Kind == "new" {
			news++
			if since.IsZero() || a.First.Before(since) {
				since = a.First
			}
		} else {
			spikes++
		}
	}
	const why = "(possible brute force or scan)"
	from := since.UTC().Format("2006-01-02 15:04") + " UTC"
	var title, target string
	switch {
	case spikes == 0:
		title, target = fmt.Sprintf("%s logged %d new kinds of message since %s %s", src.Name, news, from, why), SummaryTarget
	case news == 0:
		title, target = fmt.Sprintf("%s: %d kinds of message spiked in the last 24 hours %s", src.Name, spikes, why), "spiking kinds of message"
	default:
		title, target = fmt.Sprintf("%s logged %d new kinds of message since %s and %d spikes in the last 24 hours %s", src.Name, news, from, spikes, why), "new and spiking kinds of message"
	}
	target += " " + hour
	var what strings.Builder
	for i, a := range items {
		if i == 3 {
			fmt.Fprintf(&what, "and %d more.\n", len(items)-3)
			break
		}
		what.WriteString(clipRunes(fmt.Sprintf("%s: %s (%d lines)", map[string]string{"new": "New", "spike": "Spike"}[a.Kind], a.Signature, a.Count), 250) + "\n")
	}
	if sample := det[items[0].Signature].sample; sample != "" {
		what.WriteString("Example line: " + clipRunes(sample, 300))
	}
	sev := "low"
	if spikes > 0 {
		sev = "medium"
	}
	return AnomalyEvent{Source: clipRunes(src.Name, MaxEventKey), Target: clipRunes(target, MaxEventKey), Title: clipRunes(title, MaxEventTitle),
		What:   clipRunes(strings.TrimSpace(what.String()), MaxEventText),
		Action: "Open Logs, search for this device, and check whether a scan or a brute force is aimed at it.", Severity: sev, Devices: base}, target
}

// backlogEvent is the summary of the bounded events that are waiting for room: waiting is how many there are in all, fresh the ones
// no earlier summary has named (in the order of rank). It names as many as fit in the text, taken from the END of the order, the ones
// that would wait longest (the head is announced one by one as the room comes), and lists them rarest first; it returns the ones it
// named. Its target is in the bounded namespace and different every hour.
func backlogEvent(src sourceRow, hour string, fresh []anomaly, waiting int, base []DeviceInfo) (AnomalyEvent, []anomaly) {
	var lines []string
	size := 0
	for i := len(fresh) - 1; i >= 0; i-- {
		a := fresh[i]
		line := clipRunes(fmt.Sprintf("%s: %s (%d lines)\n", map[string]string{"new": "New", "spike": "Spike"}[a.Kind], a.Signature, a.Count), 120)
		if size+len(line)+60 > MaxEventText {
			break
		}
		lines, size = append(lines, line), size+len(line)
	}
	named := fresh[len(fresh)-len(lines):]
	slices.Reverse(lines)
	var what strings.Builder
	for _, l := range lines {
		what.WriteString(l)
	}
	if rest := waiting - len(named); rest > 0 {
		fmt.Fprintf(&what, "and %d more waiting.", rest)
	}
	target := BoundedPrefix + BacklogTarget + " " + hour
	return AnomalyEvent{Source: clipRunes(src.Name, MaxEventKey), Target: clipRunes(target, MaxEventKey),
		Title:  clipRunes(fmt.Sprintf("%s has %d more events of known kinds waiting to be announced", src.Name, waiting), MaxEventTitle),
		What:   clipRunes(strings.TrimSpace(what.String()), MaxEventText),
		Action: "Open Logs and read the digest: these events are announced one by one as the hourly limit allows.", Severity: "low", Devices: base}, named
}

// eventFor writes the event of a group (never of a summary: see summaryEvent). base is the device that sends the log.
func (s *Service) eventFor(ctx context.Context, src sourceRow, g *group, det map[string]detail, base []DeviceInfo) AnomalyEvent {
	slices.SortFunc(g.items, rank)
	first := g.items[0]
	var title string
	switch {
	case len(g.items) > 1:
		title = fmt.Sprintf("%s logged %d unusual kinds of message about %s", src.Name, len(g.items), g.target)
	case first.Kind == "new":
		title = fmt.Sprintf("%s logged a kind of message it has not logged before: %s", src.Name, first.Signature)
	default:
		title = fmt.Sprintf("%s logged %q %d times in 24 hours, far more than the usual %g a day", src.Name, first.Signature, first.Count, first.Base)
	}
	// notify refuses a "what" of more than 1,000 characters (and the bus would swallow the refusal), so the text is built from parts
	// that each have a budget: at most 3 signatures of 250 characters, an example of 300, and the whole is cut at 1,000.
	var what strings.Builder
	for i, a := range g.items {
		if i == 3 {
			fmt.Fprintf(&what, "and %d more.\n", len(g.items)-3)
			break
		}
		if a.Kind == "new" {
			what.WriteString(clipRunes(fmt.Sprintf("New: %s (%d lines)", a.Signature, a.Count), 250) + "\n")
		} else {
			what.WriteString(clipRunes(fmt.Sprintf("Spike: %s (%d lines, usually %g a day)", a.Signature, a.Count, a.Base), 250) + "\n")
		}
	}
	if g.bounded && g.dest != "" { // the target of a bounded event is its signature: where the lines went is said here
		what.WriteString("Destination: " + clipRunes(g.dest, 64) + "\n")
	}
	if sample := det[first.Signature].sample; sample != "" {
		what.WriteString("Example line: " + clipRunes(sample, 300))
	}
	sev := "low"
	if g.spike {
		sev = "medium"
	}
	devices := base
	if a, err := netip.ParseAddr(g.dest); err == nil && a.Is4() && a.String() != src.SenderIP { // the device that has the address, too
		devices = append(append([]DeviceInfo(nil), base...), s.devicesAt(ctx, a.String(), base)...)
	}
	return AnomalyEvent{Source: clipRunes(src.Name, MaxEventKey), Target: clipRunes(g.target, MaxEventKey), Title: clipRunes(title, MaxEventTitle), What: clipRunes(strings.TrimSpace(what.String()), MaxEventText), Severity: sev,
		Action:  "Open Logs, search for this device and address, and check that the change is expected.",
		Devices: devices}
}

// devicesOf returns the inventory device that sends the log of a source (nil Inventory or a failed read: none; the event is still worth sending).
func (s *Service) devicesOf(ctx context.Context, src sourceRow) []DeviceInfo {
	return s.devicesByIP(ctx, []string{src.SenderIP}, nil)
}

// devicesAt is the device that has one more address, without those already in have.
func (s *Service) devicesAt(ctx context.Context, ip string, have []DeviceInfo) []DeviceInfo {
	return s.devicesByIP(ctx, []string{ip}, have)
}

func (s *Service) devicesByIP(ctx context.Context, ips []string, have []DeviceInfo) []DeviceInfo {
	out := []DeviceInfo{}
	if s.cfg.Inventory == nil {
		return out
	}
	found, err := s.cfg.Inventory.DevicesByIP(ctx, ips)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "logs: could not look up the devices of an anomaly", "err", err)
		return out
	}
	seen := map[string]bool{}
	for _, h := range have {
		seen[h.ID] = true
	}
	for _, ip := range ips {
		if d, ok := found[ip]; ok && !seen[d.ID] && d.ID != "" && len(d.ID) <= MaxDeviceID && strings.TrimSpace(d.Name) != "" { // a device notify would refuse makes the whole incident fail
			seen[d.ID] = true
			out = append(out, DeviceInfo{ID: d.ID, Name: clipRunes(d.Name, MaxDeviceName)})
		}
	}
	return out
}

func clipRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// anomalyJob is the job of the module that announces anomalies. Not Housekeeping: with the module off it does not run (SYS-5).
func anomalyJob(svc *Service) jobs.Job {
	return jobs.Job{Module: ModuleID, Name: "anomaly", Every: DetectEvery, Run: svc.detect}
}

// snapshot is one reading of the counters (anomalies), shared by the digest and the events: detect stores it after every pass and the
// digest serves it while it is at most DetectEvery old, so the page never shows what the events did not say and the box reads the
// counters once for both. Any change of the sources drops it.
type snapshot struct {
	at    time.Time
	found []anomaly
	names map[string]sourceRow
}

// snapshotGen is the generation of the sources: a reading made after it was taken is current until dropSnapshot makes the next one.
func (s *Service) snapshotGen() uint64 {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	return s.snapGen
}

// storeSnapshotIfCurrent stores a reading unless the sources changed (dropSnapshot) since gen was taken: a reading that was already
// being made when a source changed must not be served as if it had come after.
func (s *Service) storeSnapshotIfCurrent(gen uint64, at time.Time, found []anomaly, names map[string]sourceRow) {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	if gen == s.snapGen {
		s.snap = &snapshot{at: at, found: found, names: names}
	}
}

// dropSnapshot forgets the stored reading.
func (s *Service) dropSnapshot() {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	s.snap = nil
	s.snapGen++
}

// snapshotted returns the stored reading when it is at most DetectEvery old (a clock that went back makes it older, not younger),
// else reads the counters once and stores the result.
func (s *Service) snapshotted(ctx context.Context) ([]anomaly, map[string]sourceRow, error) {
	now := s.now().UTC()
	s.snapMu.Lock()
	gen := s.snapGen
	if sn := s.snap; sn != nil && now.Sub(sn.at) >= 0 && now.Sub(sn.at) <= DetectEvery {
		s.snapMu.Unlock()
		return sn.found, sn.names, nil
	}
	s.snapMu.Unlock()
	found, names, err := s.anomalies(ctx, now)
	if err != nil {
		return nil, nil, err
	}
	s.storeSnapshotIfCurrent(gen, now, found, names)
	return found, names, nil
}
