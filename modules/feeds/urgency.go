package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// UrgencySignal is a signal row as the urgency of a finding reads it: FirstLoad says the row came with the first load of its source on
// this box (it was stored in the source's first pull and is not dated after it), so its date says nothing about when the box learned it.
type UrgencySignal struct {
	Signal
	FirstLoad bool
}

// UrgencyFacts is what the box holds about one CVE that the urgency of its findings reads: its signals (an exploited list's entry is
// one: the list writes its signal row with the entry), the CVSS score PickCVSS picks, CISA's SSVC "automatable" and the publication day.
type UrgencyFacts struct {
	Signals     []UrgencySignal
	CVSS        *CVSS
	Automatable string // "" when not given
	Published   *time.Time
}

// UrgencyFacts reads the urgency facts of these CVEs (ReadUrgencyFacts) through the store's reader.
func (s *Store) UrgencyFacts(ctx context.Context, cves []string) (map[string]UrgencyFacts, error) {
	return ReadUrgencyFacts(ctx, s.db.Reader(), cves)
}

// ReadUrgencyFacts reads the urgency facts of these CVEs through q, the store's reader or a read-only handle on the same file (the
// selfcheck recomputes stored urgencies with it). A CVE the box holds nothing of is absent.
func ReadUrgencyFacts(ctx context.Context, q *sql.DB, cves []string) (map[string]UrgencyFacts, error) {
	firstLoad := map[string]string{} // source → the stamp of its first stored row
	rows, err := q.QueryContext(ctx, `SELECT source, min(stored_at) FROM feeds_signal GROUP BY source`)
	if err != nil {
		return nil, fmt.Errorf("feeds: urgency facts: %w", err)
	}
	for rows.Next() {
		var src, at string
		if err := rows.Scan(&src, &at); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("feeds: urgency facts: %w", err)
		}
		firstLoad[src] = at
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("feeds: urgency facts: %w", err)
	}
	out := map[string]UrgencyFacts{}
	for chunk := range slices.Chunk(cves, 500) {
		part, err := json.Marshal(chunk) // one parameter: the CVEs as a JSON array (json_each)
		if err != nil {
			return nil, fmt.Errorf("feeds: urgency facts: %w", err)
		}
		if err := readUrgencySignals(ctx, q, string(part), firstLoad, out); err != nil {
			return nil, err
		}
		if err := readUrgencyCVEs(ctx, q, string(part), out); err != nil {
			return nil, err
		}
		if err := readUrgencyLists(ctx, q, string(part), out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readUrgencySignals(ctx context.Context, q *sql.DB, cves string, firstLoad map[string]string, out map[string]UrgencyFacts) error {
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
		g.FirstLoad = sa == firstLoad[g.Source] && fs <= sa
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
