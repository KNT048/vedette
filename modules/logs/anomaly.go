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
	// DigestMax is how many new items and how many spikes the digest lists (the most frequent first).
	DigestMax = 20
	// EventsPerHour is the most logs.anomaly.detected events one source can send in an hour.
	EventsPerHour = 20
	// DetectEvery is how often the anomaly job looks.
	// ponytail: a full read of the last 9 days of counters (a few thousand rows on a small box) every 5 minutes; past about
	// 500,000 rows read only today and yesterday and keep the baseline in memory.
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
	rows, err := s.cfg.Volume.Reader().QueryContext(ctx, `SELECT source_id, signature, day, sum(count), min(first_seen)
		FROM logs_signature_daily WHERE day >= ? GROUP BY source_id, signature, day`, dayStr(baseFrom))
	if err != nil {
		return nil, nil, fmt.Errorf("logs: reading signature counters: %w", err)
	}
	defer func() { _ = rows.Close() }()
	type key struct{ source, sig string }
	type sigRow struct {
		today, yest int
		perDay      map[string]int // lines of each earlier day
		first       time.Time
	}
	all := map[key]*sigRow{}
	started := map[string]time.Time{} // when each source was first heard from, as far as the counters read go back
	for rows.Next() {
		var k key
		var d, first string
		var n int
		if err := rows.Scan(&k.source, &k.sig, &d, &n, &first); err != nil {
			return nil, nil, fmt.Errorf("logs: reading signature counters: %w", err)
		}
		ft, err := time.Parse("2006-01-02T15:04:05.000Z", first)
		if err != nil {
			return nil, nil, fmt.Errorf("logs: reading signature counters: %w", err)
		}
		if t, ok := started[k.source]; !ok || ft.Before(t) {
			started[k.source] = ft
		}
		r := all[k]
		if r == nil {
			r = &sigRow{perDay: map[string]int{}, first: ft}
			all[k] = r
		}
		if ft.Before(r.first) {
			r.first = ft
		}
		switch d {
		case dayStr(today):
			r.today = n
		case dayStr(today.Add(-day)):
			r.yest = n
		}
		r.perDay[d] = n
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("logs: reading signature counters: %w", err)
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
		if !r.first.Before(now.Add(-day)) && !r.first.Before(warmEnd) { // not seen before this window, and not during the warm-up
			out = append(out, anomaly{Kind: "new", SourceID: k.source, Signature: k.sig, Count: r.today + r.yest, First: r.first})
			continue
		}
		// The baseline: the full days the source existed, among the 7 before yesterday (the day it started is partial and left out).
		lo := baseFrom
		if first := started[k.source].Truncate(day).Add(day); first.After(lo) {
			lo = first
		}
		if lo.After(baseTo) {
			continue // no full day to compare with yet
		}
		n, sum := 0, 0
		for d := lo; !d.After(baseTo); d = d.Add(day) {
			n++
			sum += r.perDay[dayStr(d)]
		}
		est := float64(r.today) + float64(r.yest)*(1-frac)
		perDay := float64(sum) / float64(n)
		if est >= math.Max(SpikeFloor, SpikeFactor*perDay) {
			out = append(out, anomaly{Kind: "spike", SourceID: k.source, Signature: k.sig, Count: int(math.Round(est)), Base: math.Round(perDay*10) / 10})
		}
	}
	return out, names, nil
}

// detail is what the counters know about one signature of one source, besides its count: where its lines were aimed and an example.
type detail struct {
	dest   string // the destination with the most lines
	sample string // the sample of the newest row
}

// details reads, for one source, the destination and the sample of every signature over the last 9 days.
func (s *Service) details(ctx context.Context, source string, now time.Time) (map[string]detail, error) {
	rows, err := s.cfg.Volume.Reader().QueryContext(ctx, `SELECT signature, dest, count, sample FROM logs_signature_daily WHERE day >= ? AND source_id = ? ORDER BY day`,
		now.UTC().Add(-(BaselineDays+1)*day).Format("2006-01-02"), source)
	if err != nil {
		return nil, fmt.Errorf("logs: reading signature details: %w", err)
	}
	defer func() { _ = rows.Close() }()
	type dk struct{ sig, dest string }
	tally := map[dk]int{}
	out := map[string]detail{}
	for rows.Next() {
		var sig, dest, sample string
		var n int
		if err := rows.Scan(&sig, &dest, &n, &sample); err != nil {
			return nil, fmt.Errorf("logs: reading signature details: %w", err)
		}
		d := out[sig]
		if sample != "" {
			d.sample = sample
		}
		out[sig] = d
		if dest != "" {
			tally[dk{sig, dest}] += n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("logs: reading signature details: %w", err)
	}
	best := map[string]int{}
	for k, n := range tally {
		if d := out[k.sig]; n > best[k.sig] || n == best[k.sig] && k.dest < d.dest {
			best[k.sig] = n
			d.dest = k.dest
			out[k.sig] = d
		}
	}
	return out, nil
}

// digestItems turns the anomalies into the lists of the digest: at most DigestMax of each, the most frequent first.
func (s *Service) digestItems(ctx context.Context, found []anomaly, names map[string]sourceRow) ([]NewItem, []SpikeItem, error) {
	news, spikes := []NewItem{}, []SpikeItem{}
	if len(found) == 0 {
		return news, spikes, nil
	}
	slices.SortFunc(found, func(a, b anomaly) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.SourceID+a.Signature, b.SourceID+b.Signature)
	})
	now := s.now()
	info := map[string]map[string]detail{}
	for _, a := range found {
		if a.Kind == "new" && len(news) >= DigestMax || a.Kind == "spike" && len(spikes) >= DigestMax {
			continue
		}
		d, ok := info[a.SourceID]
		if !ok {
			var err error
			if d, err = s.details(ctx, a.SourceID, now); err != nil {
				return nil, nil, err
			}
			info[a.SourceID] = d
		}
		id := itemID(a)
		if a.Kind == "new" {
			news = append(news, NewItem{ID: "n-" + id, Signature: a.Signature, SourceID: a.SourceID, SourceName: names[a.SourceID].Name, Count: a.Count, FirstSeen: a.First, Sample: d[a.Signature].sample})
		} else {
			spikes = append(spikes, SpikeItem{ID: "s-" + id, Signature: a.Signature, SourceID: a.SourceID, SourceName: names[a.SourceID].Name, Count: a.Count, BaselinePerDay: a.Base, Sample: d[a.Signature].sample})
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
	target string
	items  []anomaly
	count  int
	spike  bool
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
	found, names, err := s.anomalies(ctx, now)
	if err != nil || len(found) == 0 {
		return err
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
	var fresh []anomaly
	for _, a := range items {
		if !sent[a.Kind+"\x00"+a.Signature+"\x00"+ref(a)] {
			fresh = append(fresh, a)
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	var inHour int
	if err := vol.Reader().QueryRowContext(ctx, `SELECT count(*) FROM (SELECT DISTINCT target, sent_at FROM logs_anomaly_sent WHERE source_id = ? AND sent_at > ?)`, src.ID, store.FormatTS(now.Add(-time.Hour))).Scan(&inHour); err != nil {
		return fmt.Errorf("logs: counting what was announced: %w", err)
	}
	room := EventsPerHour - inHour
	if room <= 0 {
		return nil
	}
	det, err := s.details(ctx, src.ID, now)
	if err != nil {
		return err
	}
	groups := map[string]*group{}
	for _, a := range fresh {
		target := det[a.Signature].dest
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
	}
	order := make([]*group, 0, len(groups))
	for _, g := range groups {
		order = append(order, g)
	}
	slices.SortFunc(order, func(a, b *group) int { // spikes first, then the most lines, then by target: a fixed order
		switch {
		case a.spike != b.spike:
			if a.spike {
				return -1
			}
			return 1
		case a.count != b.count:
			return b.count - a.count
		}
		return strings.Compare(a.target, b.target)
	})
	var errs []error
	for _, g := range order {
		if room <= 0 {
			break
		}
		ev := s.eventFor(ctx, src, g, det)
		if err := s.cfg.Events.Publish(ctx, events.Event{Name: EventAnomalyDetected, Data: ev}); err != nil {
			errs = append(errs, fmt.Errorf("logs: announcing an anomaly: %w", err))
			continue // not recorded: the next pass tries again
		}
		room--
		err := vol.Write(ctx, func(tx *sql.Tx) error {
			for _, a := range g.items {
				if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO logs_anomaly_sent (source_id, kind, signature, ref, target, sent_at) VALUES (?, ?, ?, ?, ?, ?)`,
					src.ID, a.Kind, a.Signature, ref(a), g.target, store.FormatTS(now)); err != nil {
					return fmt.Errorf("logs: recording an announcement: %w", err)
				}
			}
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// eventFor writes the event of a group.
func (s *Service) eventFor(ctx context.Context, src sourceRow, g *group, det map[string]detail) AnomalyEvent {
	slices.SortFunc(g.items, func(a, b anomaly) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.Signature, b.Signature)
	})
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
	var what strings.Builder
	for i, a := range g.items {
		if i == 3 {
			fmt.Fprintf(&what, "and %d more.\n", len(g.items)-3)
			break
		}
		if a.Kind == "new" {
			fmt.Fprintf(&what, "New: %s (%d lines)\n", a.Signature, a.Count)
		} else {
			fmt.Fprintf(&what, "Spike: %s (%d lines, usually %g a day)\n", a.Signature, a.Count, a.Base)
		}
	}
	if sample := det[first.Signature].sample; sample != "" {
		fmt.Fprintf(&what, "Example line: %s", sample)
	}
	sev := "low"
	if g.spike {
		sev = "medium"
	}
	return AnomalyEvent{Source: src.Name, Target: clipRunes(g.target, 200), Title: clipRunes(title, 200), What: strings.TrimSpace(what.String()), Severity: sev,
		Action:  "Open Logs, search for this device and address, and check that the change is expected.",
		Devices: s.devicesOf(ctx, src, g.target)}
}

// devicesOf returns the inventory devices that the event is about: the device that sends the log and, when the target is an address,
// the device that has it. A failed read is logged and gives none: the event is still worth sending.
func (s *Service) devicesOf(ctx context.Context, src sourceRow, target string) []DeviceInfo {
	out := []DeviceInfo{}
	if s.cfg.Inventory == nil {
		return out
	}
	ips := []string{src.SenderIP}
	if a, err := netip.ParseAddr(target); err == nil && a.Is4() && a.String() != src.SenderIP {
		ips = append(ips, a.String())
	}
	found, err := s.cfg.Inventory.DevicesByIP(ctx, ips)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "logs: could not look up the devices of an anomaly", "err", err)
		return out
	}
	seen := map[string]bool{}
	for _, ip := range ips {
		if d, ok := found[ip]; ok && !seen[d.ID] {
			seen[d.ID] = true
			out = append(out, DeviceInfo{ID: d.ID, Name: d.Name})
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
