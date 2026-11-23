package feeds

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
)

// AnnouncedKEV is one feeds.vuln.new_kev as the box recorded it: the entry and when feeds announced it.
type AnnouncedKEV struct {
	NewKEVEvent
	At time.Time
}

// MaxNewKEVPage bounds one NewKEVSince read.
const MaxNewKEVPage = 500

// NewKEVSince lists the entries of the CISA list and VulnCheck KEV that feeds announced as new (feeds.vuln.new_kev, POST-1) after
// the point (at, cve), oldest first, at most limit (1..MaxNewKEVPage). The bus is best-effort: a subscriber that may have missed
// events (its module off, or the box stopped between the pull's commit and the events) keeps the (At, CVE) of the last entry it
// handled and asks again. Entries of a first fill and the CVEs of custom feeds were never announced and are never listed. A CVE
// VulnCheck announced and the CISA list later named is listed twice, as the bus announced it twice. HasTemplate is today's value.
func (s *Store) NewKEVSince(ctx context.Context, at time.Time, cve string, limit int) ([]AnnouncedKEV, error) {
	if limit < 1 || limit > MaxNewKEVPage {
		return nil, fmt.Errorf("feeds: NewKEVSince: limit %d is outside 1..%d", limit, MaxNewKEVPage)
	}
	ts := store.FormatTS(at)
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT k.cve, k.vendor, k.product,
EXISTS (SELECT 1 FROM feeds_signal s WHERE s.cve = k.cve AND s.kind = 'public_exploit' AND s.source = 'nuclei-templates'), k.date_added, k.announced_at
FROM feeds_kev k WHERE k.list IN ('cisa', 'vulncheck') AND k.announced_at IS NOT NULL AND (k.announced_at > ? OR (k.announced_at = ? AND k.cve > ?))
ORDER BY k.announced_at, k.cve LIMIT ?`, ts, ts, cve, limit)
	if err != nil {
		return nil, fmt.Errorf("feeds: read announced KEV entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AnnouncedKEV
	for rows.Next() {
		var k AnnouncedKEV
		var when string
		if err := rows.Scan(&k.CVE, &k.Vendor, &k.Product, &k.HasTemplate, &k.DateAdded, &when); err != nil {
			return nil, fmt.Errorf("feeds: read announced KEV entries: %w", err)
		}
		if k.At, err = time.Parse(time.RFC3339Nano, when); err != nil {
			return nil, fmt.Errorf("feeds: read announced KEV entries: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// markAnnounced records, in the transaction of the pull of list (the CISA list or VulnCheck KEV), that these CVEs are announced as
// new KEV entries: exactly the ones the pull then publishes feeds.vuln.new_kev for. The record commits with the entries, so a stop
// before the events go out loses nothing that NewKEVSince cannot give back. The first announcement of an entry is kept.
func markAnnounced(ctx context.Context, tx *sql.Tx, list string, fresh []VulnRow, at time.Time) error {
	if len(fresh) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `UPDATE feeds_kev SET announced_at = ? WHERE cve = ? AND list = ? AND announced_at IS NULL`)
	if err != nil {
		return fmt.Errorf("feeds: record new KEV entries: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	ts := store.FormatTS(at)
	for _, v := range fresh {
		if _, err := stmt.ExecContext(ctx, ts, v.CVE, list); err != nil {
			return fmt.Errorf("feeds: record a new KEV entry: %w", err)
		}
	}
	return nil
}
