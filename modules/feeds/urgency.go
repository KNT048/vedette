package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// UrgencySignal is a signal row as the urgency of a finding reads it. FirstLoad says the row came with the first load of its source on
// this box (stored no later than the end of the source's first good pull, LoadedAt), so its date says nothing about when the box learned it.
type UrgencySignal struct {
	Signal
	FirstLoad bool
	LoadedAt  time.Time
}

// UrgencyFacts is what the box holds about one CVE that the urgency of its findings reads: its signals of the feeds that are on (an
// exploited list's entry is one: the list writes its signal row with the entry), the CVSS score PickCVSS picks, CISA's SSVC
// "automatable" and the publication day.
type UrgencyFacts struct {
	Signals     []UrgencySignal
	CVSS        *CVSS
	Automatable string // "" when not given
	Published   *time.Time
}

// sourceLoad is what the urgency reads of a signal source: whether it is on, and when its first load ended.
type sourceLoad struct {
	off      bool
	loadedAt string // "" when unknown
}

// UrgencyReader reads urgency facts through q, the store's reader or a read-only handle on the same file (the selfcheck recomputes stored
// urgencies with it). It keeps what it reads of the sources until a feed pulls again or is switched (the sources' stamp).
type UrgencyReader struct {
	q     *sql.DB
	mu    sync.Mutex
	stamp string
	loads map[string]sourceLoad
}

// NewUrgencyReader returns a reader on q.
func NewUrgencyReader(q *sql.DB) *UrgencyReader { return &UrgencyReader{q: q} }

// ReadUrgencyFacts reads the urgency facts of these CVEs through q once (NewUrgencyReader(q).Facts).
func ReadUrgencyFacts(ctx context.Context, q *sql.DB, cves []string) (map[string]UrgencyFacts, error) {
	return NewUrgencyReader(q).Facts(ctx, cves)
}

// Facts reads the urgency facts of these CVEs. A CVE the box holds nothing of is absent. The signals of a feed that is off are left out
// (an exploited list's own rows stay: the list's entries are what the match pass reads, whatever the switch).
func (r *UrgencyReader) Facts(ctx context.Context, cves []string) (map[string]UrgencyFacts, error) {
	loads, err := r.sourceLoads(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]UrgencyFacts{}
	for chunk := range slices.Chunk(cves, 500) {
		part, err := json.Marshal(chunk) // one parameter: the CVEs as a JSON array (json_each)
		if err != nil {
			return nil, fmt.Errorf("feeds: urgency facts: %w", err)
		}
		if err := readUrgencySignals(ctx, r.q, string(part), loads, out); err != nil {
			return nil, err
		}
		if err := readUrgencyCVEs(ctx, r.q, string(part), out); err != nil {
			return nil, err
		}
		if err := readUrgencyLists(ctx, r.q, string(part), out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// sourceLoads reads, once per sources' stamp, each signal source's switch and the end of its first load: the first good pull the fetch
// log holds, or the earliest stored row when that is earlier (the log keeps 90 days; the rows of the first pull may be gone). The scan
// of every signal row runs only when a feed pulled or was switched.
func (r *UrgencyReader) sourceLoads(ctx context.Context) (map[string]sourceLoad, error) {
	var stamp string
	if err := r.q.QueryRowContext(ctx, `SELECT count(*) || '|' || ifnull(max(last_success), '') || '|' || ifnull(sum(enabled), 0) || '|' || ifnull(max(last_fetch), '')
	|| '|' || ifnull(sum(rev), 0) FROM feeds_source`).Scan(&stamp); err != nil { // rev moves on every switch, so off-and-on of two feeds is seen
		return nil, fmt.Errorf("feeds: urgency facts: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loads != nil && r.stamp == stamp {
		return r.loads, nil
	}
	loads := map[string]sourceLoad{}
	rows, err := r.q.QueryContext(ctx, `SELECT g.source, min(g.stored_at), s.enabled,
	(SELECT min(l.finished_at) FROM feeds_fetch_log l WHERE l.source_id = g.source AND l.status = 'ok')
FROM feeds_signal g LEFT JOIN feeds_source s ON s.id = g.source GROUP BY g.source`)
	if err != nil {
		return nil, fmt.Errorf("feeds: urgency facts: %w", err)
	}
	for rows.Next() {
		var (
			src, first string
			enabled    sql.NullBool
			logged     sql.NullString
		)
		if err := rows.Scan(&src, &first, &enabled, &logged); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("feeds: urgency facts: %w", err)
		}
		at := first // the first pull's rows share its stamp
		if logged.Valid {
			// the log's first good pull ends the first load, unless the log no longer holds it (it ended well after the earliest row)
			if f, err1 := parseTS(first); err1 == nil {
				if l, err2 := parseTS(logged.String); err2 == nil && l.Before(f.Add(24*time.Hour)) {
					at = logged.String
				}
			}
		}
		loads[src] = sourceLoad{off: enabled.Valid && !enabled.Bool && !isKEVSource(src), loadedAt: at}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("feeds: urgency facts: %w", err)
	}
	r.stamp, r.loads = stamp, loads
	return loads, nil
}

func readUrgencySignals(ctx context.Context, q *sql.DB, cves string, loads map[string]sourceLoad, out map[string]UrgencyFacts) error {
	rows, err := q.QueryContext(ctx, `SELECT cve, kind, source, first_seen, stored_at, last_seen, qualifies, url, detail FROM feeds_signal
WHERE cve IN (SELECT value FROM json_each(?)) ORDER BY cve, first_seen, kind, source`, cves)
	if err != nil {
		return fmt.Errorf("feeds: urgency facts: %w", err)
	}
	for rows.Next() {
		var (
			g          UrgencySignal
			fs, sa, ls string
			detail     sql.NullString
		)
		if err := rows.Scan(&g.CVE, &g.Kind, &g.Source, &fs, &sa, &ls, &g.Qualifies, &g.URL, &detail); err != nil {
			_ = rows.Close()
			return fmt.Errorf("feeds: urgency facts: %w", err)
		}
		var e1, e2, e3 error
		g.FirstSeen, e1 = parseTS(fs)
		g.StoredAt, e2 = parseTS(sa)
		g.LastSeen, e3 = parseTS(ls)
		if err := errors.Join(e1, e2, e3); err != nil {
			_ = rows.Close()
			return fmt.Errorf("feeds: urgency facts: %w", err)
		}
		if detail.Valid {
			g.Detail = json.RawMessage(detail.String)
		}
		l := loads[g.Source]
		if l.off {
			continue
		}
		if l.loadedAt != "" {
			g.FirstLoad = sa <= l.loadedAt && fs <= sa
			g.LoadedAt, _ = parseTS(l.loadedAt)
		}
		f := out[g.CVE]
		f.Signals = append(f.Signals, g)
		out[g.CVE] = f
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("feeds: urgency facts: %w", err)
	}
	return nil
}

func readUrgencyCVEs(ctx context.Context, q *sql.DB, cves string, out map[string]UrgencyFacts) error {
	rows, err := q.QueryContext(ctx, `SELECT c.cve, c.published, c.ssvc_automatable, m.source, m.version, m.score, m.vector
FROM feeds_cve c LEFT JOIN feeds_cve_metric m ON m.cve = c.cve WHERE c.cve IN (SELECT value FROM json_each(?))`, cves)
	if err != nil {
		return fmt.Errorf("feeds: urgency facts: %w", err)
	}
	metrics := map[string][]Metric{}
	for rows.Next() {
		var (
			cve                     string
			pub, auto, src, ver, vc sql.NullString
			score                   sql.NullFloat64
		)
		if err := rows.Scan(&cve, &pub, &auto, &src, &ver, &score, &vc); err != nil {
			_ = rows.Close()
			return fmt.Errorf("feeds: urgency facts: %w", err)
		}
		f := out[cve]
		f.Published, f.Automatable = optTime(pub), auto.String
		out[cve] = f
		if src.Valid {
			metrics[cve] = append(metrics[cve], Metric{Source: src.String, Version: ver.String, Score: score.Float64, Vector: vc.String})
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("feeds: urgency facts: %w", err)
	}
	for cve, ms := range metrics {
		if c, ok := PickCVSS(ms); ok {
			f := out[cve]
			f.CVSS = &c
			out[cve] = f
		}
	}
	return nil
}

// readUrgencyLists adds an exploited list's entry whose signal row is missing as the signal the list writes with it (kind exploited,
// the list's source, dated by its date added), so a listed CVE always rates as exploited, as the match pass starts it.
func readUrgencyLists(ctx context.Context, q *sql.DB, cves string, out map[string]UrgencyFacts) error {
	rows, err := q.QueryContext(ctx, `SELECT k.cve, k.source_id, k.date_added FROM feeds_kev k WHERE k.cve IN (SELECT value FROM json_each(?)) AND `+kevSources+`
AND NOT EXISTS (SELECT 1 FROM feeds_signal s WHERE s.cve = k.cve AND s.kind = 'exploited' AND s.source = k.source_id)`, cves)
	if err != nil {
		return fmt.Errorf("feeds: urgency facts: %w", err)
	}
	for rows.Next() {
		var cve, src, added string
		if err := rows.Scan(&cve, &src, &added); err != nil {
			_ = rows.Close()
			return fmt.Errorf("feeds: urgency facts: %w", err)
		}
		day, _ := time.Parse(time.DateOnly, added) // an unreadable date stays zero: never news
		f := out[cve]
		f.Signals = append(f.Signals, UrgencySignal{Signal: Signal{CVE: cve, Kind: SignalExploited, Source: src, FirstSeen: day, StoredAt: day, LastSeen: day,
			Qualifies: true, URL: kevListURL[src]}})
		out[cve] = f
	}
	return errors.Join(rows.Err(), rows.Close())
}

// ReadSourceNames reads the name people see of every feed (feeds_source.name), by id: a reasons line names its sources this way, never
// by id.
func ReadSourceNames(ctx context.Context, q *sql.DB) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, name FROM feeds_source`)
	if err != nil {
		return nil, fmt.Errorf("feeds: source names: %w", err)
	}
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("feeds: source names: %w", err)
		}
		out[id] = name
	}
	return out, errors.Join(rows.Err(), rows.Close())
}

// CatalogueLoaded is when the catalogue's first load ended: the later of the first good pulls of the catalogue's two feeds (NVD's CVEs
// of the last 12 months, the CVE records) that have one; zero before either has. A device's findings of old flaws appear then.
func (r *UrgencyReader) CatalogueLoaded(ctx context.Context) (time.Time, error) {
	var at sql.NullString
	if err := r.q.QueryRowContext(ctx, `SELECT max(f) FROM (SELECT min(finished_at) AS f FROM feeds_fetch_log WHERE source_id IN (?, ?) AND status = 'ok'
GROUP BY source_id)`, recentFeedID, cveOrgFeedID).Scan(&at); err != nil {
		return time.Time{}, fmt.Errorf("feeds: catalogue load: %w", err)
	}
	if !at.Valid {
		return time.Time{}, nil
	}
	t, err := parseTS(at.String)
	if err != nil {
		return time.Time{}, nil //nolint:nilerr // an unreadable time is no known load
	}
	return t, nil
}
