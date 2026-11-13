package feeds

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// The reads of the weekly sentences and of the lookup box answer from SQL (ORDER BY, LIMIT, an index on
// product_key); none of them loads or parses the whole table.

// weeklyVulns returns the newest CISA-list CVE of each of the limit newest products, newest first. Only
// the CISA list: the sentence says "added to the CISA list" and a custom feed's row is not that.
func (s *Store) weeklyVulns(ctx context.Context, limit int) ([]VulnRow, error) {
	return queryVulns(ctx, s.db.Reader(), `WHERE source_id = 'cisa-kev' AND cve = (
SELECT w.cve FROM feeds_vuln w WHERE w.source_id = 'cisa-kev' AND w.product_key = feeds_vuln.product_key
ORDER BY w.date_added DESC, w.cve DESC LIMIT 1)
ORDER BY date_added DESC, cve DESC LIMIT ?`, limit)
}

// searchLimit bounds the answer of a text search (the GUI mock has no bound; 200 rows is more than a screen).
const searchLimit = 200

// likePattern escapes the LIKE wildcards of a user's text (ESCAPE '\').
func likePattern(t string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(t) + "%"
}

// searchVulns finds vulnerabilities whose vendor, product or name contains t (lower case), or whose product has a
// recognised name (DisplayOf) that contains it, newest first. Case folding is ASCII only (SQLite lower()).
func (s *Store) searchVulns(ctx context.Context, t string) ([]VulnRow, error) {
	where := `WHERE lower(vendor || ' ' || product || ' ' || name) LIKE ? ESCAPE '\'`
	args := []any{likePattern(t)}
	var keys []string
	for k, d := range displaySlugs {
		if strings.Contains(strings.ToLower(d), t) {
			keys = append(keys, k)
		}
	}
	if len(keys) > 0 {
		where += ` OR product_key IN (?` + strings.Repeat(`, ?`, len(keys)-1) + `)`
		for _, k := range keys {
			args = append(args, k)
		}
	}
	args = append(args, searchLimit)
	return queryVulns(ctx, s.db.Reader(), where+` ORDER BY date_added DESC, cve DESC LIMIT ?`, args...)
}

// weeklyAnswer is the stored answer to one product's question.
type weeklyAnswer struct {
	Answer      string
	DeviceAdded bool // the "I have it" device was created through the inventory
}

// weeklyAnswers returns the answers given for these product keys.
func (s *Store) weeklyAnswers(ctx context.Context, keys []string) (map[string]weeklyAnswer, error) {
	out := map[string]weeklyAnswer{}
	if len(keys) == 0 {
		return out, nil
	}
	args := make([]any, len(keys))
	for i, k := range keys {
		args[i] = k
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT key, answer, device_added FROM feeds_weekly_answer WHERE key IN (?`+strings.Repeat(`, ?`, len(keys)-1)+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("feeds: read answers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k string
		var a weeklyAnswer
		var added int
		if err := rows.Scan(&k, &a.Answer, &added); err != nil {
			return nil, fmt.Errorf("feeds: read answers: %w", err)
		}
		a.DeviceAdded = added != 0
		out[k] = a
	}
	return out, rows.Err()
}

// pendingDevices lists the products answered "have" whose device was not created yet (the inventory was off).
func (s *Store) pendingDevices(ctx context.Context) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT key FROM feeds_weekly_answer WHERE answer = 'have' AND device_added = 0 ORDER BY answered_at`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read pending devices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, fmt.Errorf("feeds: read pending devices: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Have is the "I have this" scope of one declared device (D-484): its version-less software of KEV key Key is matched
// from the CISA date Since on.
type Have struct {
	Key   string
	Since time.Time
}

// HaveSince maps each device an "I have this" answer declared (S-FEED-2) to its scope: the answered product and the date
// a week before the answered entry (HaveWindow), set by the first "have". Only answers that are still "have" and whose
// device the inventory named count; findings scopes that one device, never the product on other devices.
func (s *Store) HaveSince(ctx context.Context) (map[string]Have, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT device_id, key, have_since FROM feeds_weekly_answer
		WHERE answer = 'have' AND device_id IS NOT NULL AND have_since IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read answered products: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]Have{}
	for rows.Next() {
		var id, key, since string
		if err := rows.Scan(&id, &key, &since); err != nil {
			return nil, fmt.Errorf("feeds: read answered products: %w", err)
		}
		if t, err := time.Parse(time.DateOnly, since); err == nil {
			out[id] = Have{Key: key, Since: t}
		}
	}
	return out, rows.Err()
}
