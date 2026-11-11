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
	// SummaryTarget is the start of the target of the flood summary of an hour ("new kinds of message 2026-11-12T14": different every hour, so
	// notify opens a new incident each time).
	SummaryTarget = "new kinds of message"
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

// rank orders anomalies for the digest and for the events. A signature that shipped data can name comes before one that the miner made
// (a log id or an event id the product knows is what a person needs to see; what the miner made can be a list of user names), and
// then the rarest first: a burst of new kinds of line (a brute force, a scan) is many signatures of about the same count, and the one
// real event is the one with one line. A spike is the opposite: the one with most lines first. So the order is: bounded new, bounded
// spike, mined new (the rarest first), mined spike (the most lines first), and last the text, so that the order is fixed.
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
	case a.Count != b.Count && a.Kind == "new":
		return a.Count - b.Count
	case a.Count != b.Count:
		return b.Count - a.Count
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
	rows, err := s.cfg.Volume.Reader().QueryContext(ctx, `SELECT dest, sample FROM logs_signature_daily WHERE source_id = ? AND signature = ? AND day >= ? ORDER BY day`,
		source, sig, now.UTC().Add(-(BaselineDays+2)*day).Format("2006-01-02"))
	if err != nil {
		return detail{}, fmt.Errorf("logs: reading signature details: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var d detail
	for rows.Next() { // oldest day first, so the newest non-empty value wins
		var dest, sample string
		if err := rows.Scan(&dest, &sample); err != nil {
			return detail{}, fmt.Errorf("logs: reading signature details: %w", err)
		}
		if dest != "" {
			d.dest = dest
		}
		if sample != "" {
			d.sample = sample
		}
	}
	return d, rows.Err()
}

// digestItems turns the anomalies into the lists of the digest: at most DigestMax of each, in the order of rank (bounded first, the rarest new first).
func (s *Service) digestItems(ctx context.Context, found []anomaly, names map[string]sourceRow) ([]NewItem, []SpikeItem, error) {
	news, spikes := []NewItem{}, []SpikeItem{}
	if len(found) == 0 {
		return news, spikes, nil
	}
	found = slices.Clone(found) // the snapshot is shared: it is sorted here, not in place
	slices.SortFunc(found, rank)
	now := s.now()
	for _, a := range found {
		if a.Kind == "new" && len(news) >= DigestMax || a.Kind == "spike" && len(spikes) >= DigestMax {
			continue
		}
		d, err := s.detailOf(ctx, a.SourceID, a.Signature, now)
		if err != nil {
			return nil, nil, err
		}
		id := itemID(a)
		if a.Kind == "new" {
			news = append(news, NewItem{ID: "n-" + id, Signature: a.Signature, SourceID: a.SourceID, SourceName: names[a.SourceID].Name, Count: a.Count, FirstSeen: a.First, Sample: d.sample})
		} else {
			spikes = append(spikes, SpikeItem{ID: "s-" + id, Signature: a.Signature, SourceID: a.SourceID, SourceName: names[a.SourceID].Name, Count: a.Count, BaselinePerDay: a.Base, Sample: d.sample})
		}
	}
	return news, spikes, nil
}

func itemID(a anomaly) string {
	h := sha256.Sum256([]byte(a.SourceID + "\x00" + a.Signature))
	return hex.EncodeToString(h[:6])
}

// group is the anomalies of one source that aim at one target: one event.
type group struct {
	target  string
	items   []anomaly
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

func (s *Service) detectSource(ctx context.Context, now time.Time, src sourceRow, items []anomaly) error {
	vol := s.cfg.Volume
	sent := map[string]bool{}
	rows, err := vol.Reader().QueryContext(ctx, `SELECT kind, signature, ref FROM logs_anomaly_sent WHERE source_id = ?`, src.ID)
	if err != nil {
		return fmt.Errorf("logs: reading what was announced: %w", err)
	}
	for rows.Next() {
		var k, sig, ref string
		if err := rows.Scan(&k, &sig, &ref); err != nil {
			_ = rows.Close()
			return fmt.Errorf("logs: reading what was announced: %w", err)
		}
		sent[k+"\x00"+sig+"\x00"+ref] = true
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("logs: reading what was announced: %w", err)
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
		case sent[a.Kind+"\x00"+a.Signature+"\x00"+ref(a)]:
		case a.Bounded:
			bounded = append(bounded, a)
		default:
			mined = append(mined, a)
		}
	}
	if len(bounded)+len(mined) == 0 {
		return nil
	}
	// The sender of the log is looked up once for every event of the source in this pass.
	base := s.devicesOf(ctx, src, "")
	var errs []error
	// Signatures of shipped data (at most about 500 exist): each its own event, never in a summary; what does not fit in the room of the
	// hour waits for the next one.
	if len(bounded) > 0 {
		inHour, err := s.sentInHour(ctx, src.ID, now, true)
		if err != nil {
			return err
		}
		if room := EventsPerHour - inHour; room > 0 {
			slices.SortFunc(bounded, rank)
			if len(bounded) > MaxAnomaliesPerPass {
				bounded = bounded[:MaxAnomaliesPerPass]
			}
			groups, det, err := s.groupsOf(ctx, src, now, bounded)
			if err != nil {
				return err
			}
			for _, g := range groups[:min(room, len(groups))] {
				errs = append(errs, s.announce(ctx, src, now, ref, g, s.eventFor(ctx, src, g, det, base), true))
			}
		}
	}
	// Everything else is best effort: one event for each group when there are few, and when there are more groups than the hour has room
	// for (a brute force, a scan, a device that sends a different line every time) ONE summary of the source, with a target that is
	// different every hour so that notify opens a new incident, listing the rarest items. What a summary covers is not marked as
	// announced: when the flood is over the items that are still new are announced one by one.
	if len(mined) > 0 {
		inHour, err := s.sentInHour(ctx, src.ID, now, false)
		if err != nil {
			return err
		}
		room := EventsPerHour - inHour
		slices.SortFunc(mined, rank)
		var tail []anomaly // past the best MaxAnomaliesPerPass: counted in the summary, not looked at one by one
		if len(mined) > MaxAnomaliesPerPass {
			tail, mined = mined[MaxAnomaliesPerPass:], mined[:MaxAnomaliesPerPass]
		}
		groups, det, err := s.groupsOf(ctx, src, now, mined)
		if err != nil {
			return err
		}
		if len(groups) <= room && len(tail) == 0 {
			for _, g := range groups {
				errs = append(errs, s.announce(ctx, src, now, ref, g, s.eventFor(ctx, src, g, det, base), false))
			}
		} else if room > 0 {
			hour := now.Format("2006-01-02T15")
			if !sent["summary\x00"+SummaryTarget+"\x00"+hour] {
				all := append([]anomaly(nil), tail...)
				for _, g := range groups {
					all = append(all, g.items...)
				}
				slices.SortFunc(all, rank)
				sum := &group{target: SummaryTarget + " " + hour, items: all}
				errs = append(errs, s.announceSummary(ctx, src, now, hour, sum, det, base))
			}
		}
	}
	return errors.Join(errs...)
}

// sentInHour counts the events a source has sent in the last hour in one class (bounded, or the rest including the summaries).
func (s *Service) sentInHour(ctx context.Context, source string, now time.Time, bounded bool) (int, error) {
	var n int
	err := s.cfg.Volume.Reader().QueryRowContext(ctx, `SELECT count(*) FROM (SELECT DISTINCT target, sent_at FROM logs_anomaly_sent WHERE source_id = ? AND bounded = ? AND sent_at > ?)`,
		source, flag(bounded), store.FormatTS(now.Add(-time.Hour))).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("logs: counting what was announced: %w", err)
	}
	return n, nil
}

// groupsOf looks up where each anomaly was aimed and groups them by target (the address, or the signature when there is none), in the
// order of the events: spikes after new, the rarest first, the text last.
func (s *Service) groupsOf(ctx context.Context, src sourceRow, now time.Time, items []anomaly) ([]*group, map[string]detail, error) {
	det := map[string]detail{}
	groups := map[string]*group{}
	for _, a := range items {
		d, err := s.detailOf(ctx, src.ID, a.Signature, now)
		if err != nil {
			return nil, nil, err
		}
		det[a.Signature] = d
		target := d.dest
		if target == "" {
			target = a.Signature
		}
		g := groups[target]
		if g == nil {
			g = &group{target: target}
			groups[target] = g
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

// announceSummary publishes the summary of a flood and records that this hour has had its summary, and nothing about the items.
func (s *Service) announceSummary(ctx context.Context, src sourceRow, now time.Time, hour string, g *group, det map[string]detail, base []DeviceInfo) error {
	if err := s.cfg.Events.Publish(ctx, events.Event{Name: EventAnomalyDetected, Data: s.summaryEvent(src, g, det, base)}); err != nil {
		return fmt.Errorf("logs: announcing a flood: %w", err)
	}
	return s.cfg.Volume.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO logs_anomaly_sent (source_id, kind, signature, ref, target, sent_at, bounded) VALUES (?, 'summary', ?, ?, ?, ?, 0)`,
			src.ID, SummaryTarget, hour, g.target, store.FormatTS(now))
		if err != nil {
			return fmt.Errorf("logs: recording a summary: %w", err)
		}
		return nil
	})
}

// summaryEvent is the one event that stands for the flood of an hour. Its target is different every hour, so notify opens a new incident
// for each (the same target would be counted up in an old one, silently). The title says what it carries: new kinds of message, spikes, or
// both; the text lists the rarest items first (g.items is in the order of rank).
func (s *Service) summaryEvent(src sourceRow, g *group, det map[string]detail, base []DeviceInfo) AnomalyEvent {
	news, spikes := 0, 0
	for _, a := range g.items {
		if a.Kind == "new" {
			news++
		} else {
			spikes++
		}
	}
	const why = "in the last hour (possible brute force or scan)"
	var title string
	switch {
	case spikes == 0:
		title = fmt.Sprintf("%s logged %d new kinds of message %s", src.Name, news, why)
	case news == 0:
		title = fmt.Sprintf("%s: %d kinds of message spiked %s", src.Name, spikes, why)
	default:
		title = fmt.Sprintf("%s logged %d new kinds of message and %d spikes %s", src.Name, news, spikes, why)
	}
	var what strings.Builder
	for i, a := range g.items {
		if i == 3 {
			fmt.Fprintf(&what, "and %d more.\n", len(g.items)-3)
			break
		}
		what.WriteString(clipRunes(fmt.Sprintf("%s: %s (%d lines)", map[string]string{"new": "New", "spike": "Spike"}[a.Kind], a.Signature, a.Count), 250) + "\n")
	}
	if sample := det[g.items[0].Signature].sample; sample != "" {
		what.WriteString("Example line: " + clipRunes(sample, 300))
	}
	sev := "low"
	if spikes > 0 {
		sev = "medium"
	}
	return AnomalyEvent{Source: clipRunes(src.Name, MaxEventKey), Target: clipRunes(g.target, MaxEventKey), Title: clipRunes(title, MaxEventTitle),
		What:   clipRunes(strings.TrimSpace(what.String()), MaxEventText),
		Action: "Open Logs, search for this device, and check whether a scan or a brute force is aimed at it.", Severity: sev, Devices: base}
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
	if sample := det[first.Signature].sample; sample != "" {
		what.WriteString("Example line: " + clipRunes(sample, 300))
	}
	sev := "low"
	if g.spike {
		sev = "medium"
	}
	devices := base
	if a, err := netip.ParseAddr(g.target); err == nil && a.Is4() && a.String() != src.SenderIP { // the device that has the address, too
		devices = append(append([]DeviceInfo(nil), base...), s.devicesAt(ctx, a.String(), base)...)
	}
	return AnomalyEvent{Source: clipRunes(src.Name, MaxEventKey), Target: clipRunes(g.target, MaxEventKey), Title: clipRunes(title, MaxEventTitle), What: clipRunes(strings.TrimSpace(what.String()), MaxEventText), Severity: sev,
		Action:  "Open Logs, search for this device and address, and check that the change is expected.",
		Devices: devices}
}

// devicesOf returns the inventory device that sends the log of a source (nil Inventory or a failed read: none; the event is still worth sending).
func (s *Service) devicesOf(ctx context.Context, src sourceRow, _ string) []DeviceInfo {
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
