package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/store"
)

const tsLayout = "2006-01-02T15:04:05.000Z"

func parseTS(s string) (time.Time, error) { return time.Parse(tsLayout, s) }

func optTS(s *string) (*time.Time, error) {
	if s == nil {
		return nil, nil
	}
	t, err := parseTS(*s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ErrNotFound is returned when a feed or a record does not exist.
var ErrNotFound = errors.New("feeds: not found")

// Retention (DATA_MODEL 4.1).
const (
	fetchLogKeep = 90 * 24 * time.Hour
	iocGrace     = 30 * 24 * time.Hour
)

// defaultConfidence is what an IOC row carries when its feed gives no confidence.
const defaultConfidence = 0.5

// Store is the module's database access. Reads use the read-only pool; every write goes through
// DB.Write. A pull is one transaction, except an indicator list: that goes in chunks (applyIOCs).
type Store struct{ db *store.DB }

// NewStore wraps a migrated database.
func NewStore(db *store.DB) *Store { return &Store{db: db} }

// sourceRow is one feeds_source row.
type sourceRow struct {
	ID            string
	Builtin       bool
	Name          string
	Kind          Kind
	Format        Format
	URL           string
	DefaultURL    *string
	Enabled       bool
	IntervalHours int
	Auth          AuthType
	HeaderName    *string
	Username      *string
	SecretID      *string
	SecretLast4   *string
	Parser        *Parser
	License       *string
	CreatedAt     time.Time
	Rev           int // edits so far (see migration 0002): a pull writes only if it is unchanged

	LastFetch      *time.Time
	LastSuccess    *time.Time
	Failures       int
	Records        *int
	Status         string // never, ok, error
	Error          *string
	ETag           *string
	LastModified   *string
	CatalogVersion *string
	AnsweredBy     *string // D-91: "CISA" or "CISA GitHub mirror", only for the CISA list
}

func (r sourceRow) state() State {
	var s State
	if r.LastSuccess != nil {
		s.LastSuccess = *r.LastSuccess
	}
	if r.LastFetch != nil {
		s.LastAttempt = *r.LastFetch
	}
	s.Failures = r.Failures
	return s
}

const sourceCols = `id, builtin, name, kind, format, url, default_url, enabled, interval_hours, auth_type, auth_header_name,
auth_username, secret_id, secret_last4, parser, license, created_at, last_fetch, last_success, failures, records, status,
error, etag, last_modified, catalog_version, rev, answered_by`

type scanner interface{ Scan(dest ...any) error }

func scanSource(r scanner) (sourceRow, error) {
	var (
		s                              sourceRow
		builtin, enabled               int
		kind, format, auth, created    string
		parser, lastFetch, lastSuccess *string
	)
	err := r.Scan(&s.ID, &builtin, &s.Name, &kind, &format, &s.URL, &s.DefaultURL, &enabled, &s.IntervalHours, &auth,
		&s.HeaderName, &s.Username, &s.SecretID, &s.SecretLast4, &parser, &s.License, &created, &lastFetch, &lastSuccess,
		&s.Failures, &s.Records, &s.Status, &s.Error, &s.ETag, &s.LastModified, &s.CatalogVersion, &s.Rev, &s.AnsweredBy)
	if err != nil {
		return sourceRow{}, err
	}
	s.Builtin, s.Enabled = builtin != 0, enabled != 0
	s.Kind, s.Format, s.Auth = Kind(kind), Format(format), AuthType(auth)
	if parser != nil {
		var p Parser
		if err := json.Unmarshal([]byte(*parser), &p); err != nil {
			return sourceRow{}, fmt.Errorf("feeds: stored parser of %s: %w", s.ID, err)
		}
		s.Parser = &p
	}
	if s.CreatedAt, err = parseTS(created); err != nil {
		return sourceRow{}, fmt.Errorf("feeds: stored time of %s: %w", s.ID, err)
	}
	if s.LastFetch, err = optTS(lastFetch); err != nil {
		return sourceRow{}, fmt.Errorf("feeds: stored time of %s: %w", s.ID, err)
	}
	if s.LastSuccess, err = optTS(lastSuccess); err != nil {
		return sourceRow{}, fmt.Errorf("feeds: stored time of %s: %w", s.ID, err)
	}
	return s, nil
}

// sources returns every feed row: built-ins in the order of BuiltinSources, then custom feeds oldest first.
func (s *Store) sources(ctx context.Context) ([]sourceRow, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT `+sourceCols+` FROM feeds_source ORDER BY builtin DESC, created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("feeds: list sources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var all []sourceRow
	for rows.Next() {
		r, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("feeds: list sources: %w", err)
	}
	order := map[string]int{}
	for i, b := range BuiltinSources() {
		order[b.ID] = i
	}
	slices.SortStableFunc(all, func(a, b sourceRow) int {
		if a.Builtin != b.Builtin {
			if a.Builtin {
				return -1
			}
			return 1
		}
		if a.Builtin {
			return order[a.ID] - order[b.ID]
		}
		return 0
	})
	return all, nil
}

func (s *Store) source(ctx context.Context, id string) (sourceRow, error) {
	r, err := scanSource(s.db.Reader().QueryRowContext(ctx, `SELECT `+sourceCols+` FROM feeds_source WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return sourceRow{}, ErrNotFound
	}
	return r, err
}

func sourceTx(ctx context.Context, tx *sql.Tx, id string) (sourceRow, error) {
	r, err := scanSource(tx.QueryRowContext(ctx, `SELECT `+sourceCols+` FROM feeds_source WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return sourceRow{}, ErrNotFound
	}
	return r, err
}

// SeedBuiltins merges BuiltinSources() into feeds_source: new feeds are inserted (on); existing rows keep what
// the admin chose (enabled, schedule, a mirror address) while name, format, license and the default address
// follow the code. A feed whose address is still its old default moves to the new default.
func (s *Store) SeedBuiltins(ctx context.Context, now time.Time) error {
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		for _, b := range BuiltinSources() {
			_, err := tx.ExecContext(ctx, `INSERT INTO feeds_source (id, builtin, name, kind, format, url, default_url, enabled, interval_hours, license, created_at)
VALUES (?, 1, ?, ?, ?, ?, ?, 1, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET name = excluded.name, kind = excluded.kind, format = excluded.format, license = excluded.license,
  url = CASE WHEN url = default_url THEN excluded.url ELSE url END, default_url = excluded.default_url`,
				b.ID, b.Name, string(b.Kind), string(b.Format), b.URL, b.URL, b.IntervalHours, b.License, store.FormatTS(now))
			if err != nil {
				return fmt.Errorf("feeds: seed %s: %w", b.ID, err)
			}
		}
		return retireBuiltins(ctx, tx)
	})
}

// retireBuiltins deletes the built-in rows the code no longer lists (D-92, INV-16), with their listings, vulnerabilities
// and pull history. Custom feeds are never touched.
func retireBuiltins(ctx context.Context, tx *sql.Tx) error {
	keep := map[string]bool{}
	for _, b := range BuiltinSources() {
		keep[b.ID] = true
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM feeds_source WHERE builtin = 1`)
	if err != nil {
		return fmt.Errorf("feeds: list built-in rows: %w", err)
	}
	var gone []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return fmt.Errorf("feeds: scan built-in row: %w", err)
		}
		if !keep[id] {
			gone = append(gone, id)
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("feeds: list built-in rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("feeds: list built-in rows: %w", err)
	}
	for _, id := range gone {
		if err := purgeLoaded(ctx, tx, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_source WHERE id = ? AND builtin = 1`, id); err != nil {
			return fmt.Errorf("feeds: retire built-in %s: %w", id, err)
		}
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func parserJSON(p *Parser) (*string, error) {
	if p == nil {
		return nil, nil
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("feeds: encode parser: %w", err)
	}
	s := string(b)
	return &s, nil
}

// insertCustom stores a new custom feed.
func insertCustom(ctx context.Context, tx *sql.Tx, r sourceRow) error {
	parser, err := parserJSON(r.Parser)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO feeds_source (id, builtin, name, kind, format, url, enabled, interval_hours, auth_type,
auth_header_name, auth_username, secret_id, secret_last4, parser, created_at)
VALUES (?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Name, string(r.Kind), string(r.Format), r.URL, boolInt(r.Enabled), r.IntervalHours, string(r.Auth),
		r.HeaderName, r.Username, r.SecretID, r.SecretLast4, parser, store.FormatTS(r.CreatedAt))
	if err != nil {
		return fmt.Errorf("feeds: insert feed: %w", err)
	}
	return nil
}

// updateCustom saves the editable columns of a custom feed. The pull validators are dropped: the address or
// the rules may have changed, so the next pull must download the file again. Pull state stays.
func updateCustom(ctx context.Context, tx *sql.Tx, r sourceRow) error {
	parser, err := parserJSON(r.Parser)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE feeds_source SET name = ?, kind = ?, format = ?, url = ?, enabled = ?, interval_hours = ?,
auth_type = ?, auth_header_name = ?, auth_username = ?, secret_id = ?, secret_last4 = ?, parser = ?, etag = NULL, last_modified = NULL,
rev = rev + 1, failures = CASE WHEN ? = 1 AND enabled = 0 THEN 0 ELSE failures END
WHERE id = ? AND builtin = 0`,
		r.Name, string(r.Kind), string(r.Format), r.URL, boolInt(r.Enabled), r.IntervalHours, string(r.Auth),
		r.HeaderName, r.Username, r.SecretID, r.SecretLast4, parser, boolInt(r.Enabled), r.ID)
	if err != nil {
		return fmt.Errorf("feeds: update feed: %w", err)
	}
	return nil
}

// updateSettings is PUT /feeds/sources/{id}: the three things both kinds of feed allow to change.
func updateSettings(ctx context.Context, tx *sql.Tx, id string, enabled bool, hours int, url string, urlChanged bool) error {
	// turning a feed back on forgets its back-off: the admin fixed what failed
	q := `UPDATE feeds_source SET rev = rev + 1, failures = CASE WHEN ? = 1 AND enabled = 0 THEN 0 ELSE failures END, enabled = ?, interval_hours = ? WHERE id = ?`
	args := []any{boolInt(enabled), boolInt(enabled), hours, id}
	if urlChanged {
		q = `UPDATE feeds_source SET rev = rev + 1, failures = CASE WHEN ? = 1 AND enabled = 0 THEN 0 ELSE failures END, enabled = ?, interval_hours = ?, url = ?, etag = NULL, last_modified = NULL, answered_by = NULL WHERE id = ?`
		args = []any{boolInt(enabled), boolInt(enabled), hours, url, id}
	}
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("feeds: update feed settings: %w", err)
	}
	return nil
}

// purgeLoaded deletes what a feed loaded: its vulnerabilities and its listings (indicators nobody else lists go too).
func purgeLoaded(ctx context.Context, tx *sql.Tx, id string) error {
	for _, st := range []struct {
		query string
		args  []any
	}{
		{`DELETE FROM feeds_vuln WHERE source_id = ?`, []any{id}},
		{`DELETE FROM feeds_ioc WHERE id IN (SELECT ioc_id FROM feeds_ioc_source WHERE source_id = ?)
		   AND NOT EXISTS (SELECT 1 FROM feeds_ioc_source o WHERE o.ioc_id = feeds_ioc.id AND o.source_id <> ?)`, []any{id, id}},
		{`DELETE FROM feeds_ioc_source WHERE source_id = ?`, []any{id}},
	} {
		if _, err := tx.ExecContext(ctx, st.query, st.args...); err != nil {
			return fmt.Errorf("feeds: purge %s: %w", id, err)
		}
	}
	return nil
}

// deleteCustom removes a custom feed and everything it loaded (INV-4); fetch log rows follow by cascade.
func deleteCustom(ctx context.Context, tx *sql.Tx, id string) error {
	if err := purgeLoaded(ctx, tx, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_source WHERE id = ? AND builtin = 0`, id); err != nil {
		return fmt.Errorf("feeds: delete feed: %w", err)
	}
	return nil
}

// customNames lists the names of the custom feeds other than skipID (for CheckName).
func customNames(ctx context.Context, tx *sql.Tx, skipID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM feeds_source WHERE builtin = 0 AND id <> ?`, skipID)
	if err != nil {
		return nil, fmt.Errorf("feeds: list names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("feeds: list names: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ---------- vulnerabilities

// VulnRow is a stored vulnerability.
type VulnRow struct {
	Vuln
	EPSS        *float64
	EPSS7dAgo   *float64
	HasTemplate bool
	SourceID    string
}

const vulnCols = `cve, vendor, product, name, description, required_action, links, date_added, due_date, ransomware, epss,
epss_7d_ago, has_template, source_id`

func scanVuln(r scanner) (VulnRow, error) {
	var (
		v             VulnRow
		links         string
		due           *string
		ransom, hasTp int
	)
	err := r.Scan(&v.CVE, &v.Vendor, &v.Product, &v.Name, &v.Description, &v.RequiredAction, &links, &v.DateAdded, &due,
		&ransom, &v.EPSS, &v.EPSS7dAgo, &hasTp, &v.SourceID)
	if err != nil {
		return VulnRow{}, err
	}
	if err := json.Unmarshal([]byte(links), &v.Links); err != nil || v.Links == nil {
		v.Links = []string{}
	}
	if due != nil {
		v.DueDate = *due
	}
	v.Ransomware, v.HasTemplate = ransom != 0, hasTp != 0
	return v, nil
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func queryVulns(ctx context.Context, q queryer, where string, args ...any) ([]VulnRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+vulnCols+` FROM feeds_vuln `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("feeds: read vulnerabilities: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []VulnRow{}
	for rows.Next() {
		v, err := scanVuln(rows)
		if err != nil {
			return nil, fmt.Errorf("feeds: read vulnerabilities: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// VulnByCVE returns one vulnerability (cve in upper case).
func (s *Store) VulnByCVE(ctx context.Context, cve string) (VulnRow, bool, error) {
	rows, err := queryVulns(ctx, s.db.Reader(), `WHERE cve = ?`, cve)
	if err != nil || len(rows) == 0 {
		return VulnRow{}, false, err
	}
	return rows[0], true, nil
}

// VulnsByProductKey returns the vulnerabilities of one product key (ProductKey), newest first.
func (s *Store) VulnsByProductKey(ctx context.Context, key string) ([]VulnRow, error) {
	return queryVulns(ctx, s.db.Reader(), `WHERE product_key = ? ORDER BY date_added DESC, cve DESC`, key)
}

// HasTemplate reports whether nuclei has a template for the CVE.
func (s *Store) HasTemplate(ctx context.Context, cve string) (bool, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM feeds_template WHERE cve = ?`, cve).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("feeds: read template: %w", err)
	}
	return n > 0, nil
}

// Product is a vendor and product pair as KEV writes them.
type Product struct{ Vendor, Product string }

// Key is ProductKey of the pair.
func (p Product) Key() string { return ProductKey(p.Vendor, p.Product) }

// KevPairs lists every vendor and product pair of the CISA list (cisa-kev rows only), for the inventory
// catalog. A custom feed's products are not KEV entries.
func (s *Store) KevPairs(ctx context.Context) ([]Product, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT DISTINCT vendor, product FROM feeds_vuln WHERE source_id = 'cisa-kev' ORDER BY product_key`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read products: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.Vendor, &p.Product); err != nil {
			return nil, fmt.Errorf("feeds: read products: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// vulnsNewestFirst returns vulnerabilities added on or after day (YYYY-MM-DD; "" for all), newest first.
func (s *Store) vulnsNewestFirst(ctx context.Context, day string) ([]VulnRow, error) {
	return queryVulns(ctx, s.db.Reader(), `WHERE date_added >= ? ORDER BY date_added DESC, cve DESC`, day)
}

func sameVuln(a, b Vuln, aSource, bSource string) bool {
	return a.Vendor == b.Vendor && a.Product == b.Product && a.Name == b.Name && a.Description == b.Description &&
		a.RequiredAction == b.RequiredAction && slices.Equal(a.Links, b.Links) && a.DateAdded == b.DateAdded &&
		a.DueDate == b.DueDate && a.Ransomware == b.Ransomware && aSource == bSource
}

// Bounds of one pull transaction (ponytail: one transaction per fetch result keeps "all or nothing", so the
// write lock is held for the whole apply; at the limits of INV-2 that is 50,000 rows for a vulnerability feed
// and 100,000 for hagezi, about a second or two on the target hardware). The context is checked every
// ctxEvery rows, and what is read is read once, before the loop.
const ctxEvery = 256

// Bounds of a stored vulnerability's vendor and product (characters): the matching key vendor|product must
// stay inside the CHECK of feeds_weekly_answer.key whatever a custom feed sends.
const (
	maxVendorProduct = 200
	maxProductKey    = 500
)

// clampDate turns a date a feed gives in the future into today, like the IOC path does for first_seen.
func clampDate(day, today string) string {
	if day > today { // YYYY-MM-DD compares as text
		return today
	}
	return day
}

// applyVulns writes the vulnerabilities of one pull inside tx. It returns the CVEs that are new to the box, or
// that cisa-kev lists for the first time because a custom feed had them first, and the CVEs that changed. A
// vulnerability with an empty DateAdded takes today's date when new and keeps its date when it exists; dates in
// the future become today. A CVE has one owner: cisa-kev takes over a custom feed's row, a custom feed never
// touches another feed's row. With replace (custom feeds) rows of the feed that are no longer listed are deleted.
func applyVulns(ctx context.Context, tx *sql.Tx, now time.Time, source string, vulns []Vuln, replace bool) (fresh []VulnRow, updated []string, err error) {
	tmpl, err := stringSet(ctx, tx, `SELECT cve FROM feeds_template`)
	if err != nil {
		return nil, nil, err
	}
	existing := map[string]VulnRow{}
	all, err := queryVulns(ctx, tx, ``)
	if err != nil {
		return nil, nil, err
	}
	for _, v := range all {
		existing[v.CVE] = v
	}

	stamp, today := store.FormatTS(now), now.UTC().Format("2006-01-02")
	listed := map[string]bool{}
	for i, v := range vulns {
		if i%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
		}
		listed[v.CVE] = true
		if v.DateAdded != "" {
			v.DateAdded = clampDate(v.DateAdded, today)
		}
		links, err := json.Marshal(append([]string{}, v.Links...))
		if err != nil {
			return nil, nil, fmt.Errorf("feeds: encode links: %w", err)
		}
		var due *string
		if v.DueDate != "" {
			due = &v.DueDate
		}
		old, found := existing[v.CVE]
		if !found {
			added := v.DateAdded
			if added == "" {
				added = today
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO feeds_vuln (cve, vendor, product, product_key, name, description, required_action, links,
date_added, due_date, ransomware, has_template, source_id, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				v.CVE, v.Vendor, v.Product, v.Key(), v.Name, v.Description, v.RequiredAction, string(links), added, due,
				boolInt(v.Ransomware), boolInt(tmpl[v.CVE]), source, stamp)
			if err != nil {
				return nil, nil, fmt.Errorf("feeds: insert vulnerability: %w", err)
			}
			nv := v
			nv.DateAdded = added
			row := VulnRow{Vuln: nv, HasTemplate: tmpl[v.CVE], SourceID: source}
			existing[v.CVE] = row
			fresh = append(fresh, row)
			continue
		}
		if old.SourceID != source && source != "cisa-kev" {
			continue // another feed owns this CVE
		}
		next := v
		if next.DateAdded == "" {
			next.DateAdded = old.DateAdded
		}
		if sameVuln(old.Vuln, next, old.SourceID, source) {
			continue
		}
		_, err = tx.ExecContext(ctx, `UPDATE feeds_vuln SET vendor = ?, product = ?, product_key = ?, name = ?, description = ?, required_action = ?,
links = ?, date_added = ?, due_date = ?, ransomware = ?, source_id = ?, updated_at = ? WHERE cve = ?`,
			v.Vendor, v.Product, v.Key(), v.Name, v.Description, v.RequiredAction, string(links), next.DateAdded, due,
			boolInt(v.Ransomware), source, stamp, v.CVE)
		if err != nil {
			return nil, nil, fmt.Errorf("feeds: update vulnerability: %w", err)
		}
		row := VulnRow{Vuln: next, EPSS: old.EPSS, EPSS7dAgo: old.EPSS7dAgo, HasTemplate: old.HasTemplate, SourceID: source}
		existing[v.CVE] = row
		if old.SourceID != source { // cisa-kev lists a CVE a custom feed had first: its first sighting as KEV
			fresh = append(fresh, row)
		} else {
			updated = append(updated, v.CVE)
		}
	}
	if replace {
		for c, row := range existing {
			if row.SourceID == source && !listed[c] {
				if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_vuln WHERE cve = ?`, c); err != nil {
					return nil, nil, fmt.Errorf("feeds: delete vulnerability: %w", err)
				}
			}
		}
	}
	return fresh, updated, nil
}

func stringSet(ctx context.Context, q queryer, query string) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("feeds: read set: %w", err)
	}
	out := map[string]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("feeds: read set: %w", err)
		}
		out[s] = true
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("feeds: read set: %w", err)
	}
	return out, nil
}

// applyTemplates replaces the set of CVEs that have a nuclei template and refreshes has_template; it returns
// the CISA-list CVEs whose flag changed (a custom feed's CVE changing is no event).
func applyTemplates(ctx context.Context, tx *sql.Tx, cves []string) ([]string, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_template`); err != nil {
		return nil, fmt.Errorf("feeds: clear templates: %w", err)
	}
	for i, c := range cves {
		if i%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_template (cve) VALUES (?) ON CONFLICT(cve) DO NOTHING`, c); err != nil {
			return nil, fmt.Errorf("feeds: insert template: %w", err)
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT cve FROM feeds_vuln WHERE source_id = 'cisa-kev' AND has_template <> (cve IN (SELECT cve FROM feeds_template)) ORDER BY cve`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read changed templates: %w", err)
	}
	var changed []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("feeds: read changed templates: %w", err)
		}
		changed = append(changed, c)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("feeds: read changed templates: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE feeds_vuln SET has_template = (cve IN (SELECT cve FROM feeds_template))
WHERE has_template <> (cve IN (SELECT cve FROM feeds_template))`); err != nil {
		return nil, fmt.Errorf("feeds: refresh has_template: %w", err)
	}
	return changed, nil
}

// kevCVEs lists the CVEs whose EPSS the box asks for: the CISA list only. A CVE that only a custom feed lists
// is the company's own data and never goes to api.first.org.
func (s *Store) kevCVEs(ctx context.Context) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT cve FROM feeds_vuln WHERE source_id = 'cisa-kev' ORDER BY cve`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read cves: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("feeds: read cves: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// applyEPSS stores today's score and the score of 7 days ago for the CVEs the API answered for; a CVE with no
// old score gets NULL there (a new CVE is not "rising"). It returns how many CVEs got a score.
func applyEPSS(ctx context.Context, tx *sql.Tx, latest, ago map[string]float64) (int, error) {
	n := 0
	for cve, score := range latest {
		var old any
		if v, ok := ago[cve]; ok {
			old = v
		}
		res, err := tx.ExecContext(ctx, `UPDATE feeds_vuln SET epss = ?, epss_7d_ago = ? WHERE cve = ?`, score, old, cve)
		if err != nil {
			return 0, fmt.Errorf("feeds: store epss: %w", err)
		}
		if c, _ := res.RowsAffected(); c > 0 {
			n++
		}
	}
	return n, nil
}

// ---------- indicators

type iocInput struct {
	Kind, Value string
	Confidence  *float64
	FirstSeen   string // YYYY-MM-DD or ""
}

// iocChunkRows is how many listings one write transaction stores. The writer is one connection shared by the
// whole box, so a 250 000-row list in one transaction stalled every other write for ~20 s; between chunks a
// waiting write gets the connection. A var only so that the package's tests run with smaller chunks (TestMain).
var iocChunkRows = 2000

// applyIOCs stores the full listing of one feed: every indicator it lists now, with the other feeds' listings
// of the same value merged in, and drops the feed's listings that vanished. It returns how many listings were
// added and removed.
//
// The list goes in as one transaction per iocChunkRows records, each re-reading the feed row: a feed edited,
// switched off or deleted meanwhile stops the pull (stale) and no later chunk writes. Every upsert stamps
// last_seen with this pull's stamp, so the last transactions drop the listings that carry any other stamp (<>, not <:
// a clock set back leaves older pulls stamped in the future; chunk 0 moves the stamp up by 1 ms until no listing of
// the feed already has it), 2 000 at a time, and the last one runs finish (the outcome row, the audit entry) with the counts. Until then a reader sees the old and the new
// list together, never fewer listings; a pull cut off halfway leaves extra rows that the next pull removes.
// hook, when not nil, runs after each chunk has committed (tests).
func applyIOCs(ctx context.Context, db *store.DB, now time.Time, src sourceRow, recs []iocInput, hook func(chunk int), finish func(tx *sql.Tx, added, removed int) error) (added, removed int, stale bool, err error) {
	stamp := store.FormatTS(now)
	live := func(tx *sql.Tx) (bool, error) { // false: edited or switched off meanwhile
		cur, err := sourceTx(ctx, tx, src.ID)
		if err != nil {
			return false, err // ErrNotFound: deleted meanwhile
		}
		return cur.Rev == src.Rev && cur.Enabled, nil
	}
	count := func(tx *sql.Tx) (int, error) {
		var n int
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM feeds_ioc_source WHERE source_id = ?`, src.ID).Scan(&n)
		return n, err
	}
	var before int
	for i, chunk := 0, 0; i == 0 || i < len(recs); chunk++ {
		end := min(i+iocChunkRows, len(recs))
		part := recs[i:end]
		err = db.Write(ctx, func(tx *sql.Tx) error {
			ok, err := live(tx)
			if err != nil || !ok {
				stale = !ok
				return err
			}
			if chunk == 0 {
				if before, err = count(tx); err != nil {
					return fmt.Errorf("feeds: count listings: %w", err)
				}
				for { // a stamp no earlier pull of this feed used, so "any other stamp" means "not in this list"
					var one int
					err := tx.QueryRowContext(ctx, `SELECT 1 FROM feeds_ioc_source WHERE source_id = ? AND last_seen = ? LIMIT 1`, src.ID, stamp).Scan(&one)
					if errors.Is(err, sql.ErrNoRows) {
						break
					}
					if err != nil {
						return fmt.Errorf("feeds: check stamp: %w", err)
					}
					now = now.Add(time.Millisecond)
					stamp = store.FormatTS(now)
				}
			}
			return upsertIOCs(ctx, tx, stamp, src.ID, part)
		})
		if err != nil || stale {
			return 0, 0, stale, err
		}
		if hook != nil {
			hook(chunk)
		}
		i = end
	}
	for last := false; !last; {
		err = db.Write(ctx, func(tx *sql.Tx) error {
			ok, err := live(tx)
			if err != nil || !ok {
				stale = !ok
				return err
			}
			res, err := tx.ExecContext(ctx, `DELETE FROM feeds_ioc_source WHERE source_id = ?1 AND ioc_id IN (
SELECT ioc_id FROM feeds_ioc_source WHERE source_id = ?1 AND last_seen <> ?2 LIMIT ?3)`, src.ID, stamp, iocChunkRows)
			if err != nil {
				return fmt.Errorf("feeds: drop listings: %w", err)
			}
			n, _ := res.RowsAffected()
			removed += int(n)
			if last = n < int64(iocChunkRows); !last {
				return nil
			}
			after, err := count(tx)
			if err != nil {
				return fmt.Errorf("feeds: count listings: %w", err)
			}
			added = after - (before - removed)
			return finish(tx, added, removed)
		})
		if err != nil || stale {
			return 0, 0, stale, err
		}
	}
	return added, removed, false, nil
}

// upsertIOCs stores one chunk of a feed's listing, stamping every row with the pull's stamp.
func upsertIOCs(ctx context.Context, tx *sql.Tx, stamp, source string, recs []iocInput) error {
	upsertIOC, err := tx.PrepareContext(ctx, `INSERT INTO feeds_ioc (id, type, value, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(type, value) DO UPDATE SET last_seen = excluded.last_seen, first_seen = min(first_seen, excluded.first_seen)
RETURNING id`)
	if err != nil {
		return fmt.Errorf("feeds: prepare indicator: %w", err)
	}
	defer func() { _ = upsertIOC.Close() }()
	upsertSrc, err := tx.PrepareContext(ctx, `INSERT INTO feeds_ioc_source (ioc_id, source_id, last_seen, confidence) VALUES (?, ?, ?, ?)
ON CONFLICT(ioc_id, source_id) DO UPDATE SET last_seen = excluded.last_seen, confidence = excluded.confidence`)
	if err != nil {
		return fmt.Errorf("feeds: prepare listing: %w", err)
	}
	defer func() { _ = upsertSrc.Close() }()
	for i, r := range recs {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		first := stamp
		if r.FirstSeen != "" {
			first = r.FirstSeen + "T00:00:00.000Z"
		}
		if first > stamp { // a feed that dates an indicator in the future
			first = stamp
		}
		var id string
		if err := upsertIOC.QueryRowContext(ctx, store.NewID("ioc"), r.Kind, r.Value, first, stamp).Scan(&id); err != nil {
			return fmt.Errorf("feeds: store indicator: %w", err)
		}
		conf := defaultConfidence
		if r.Confidence != nil {
			conf = *r.Confidence
		}
		if _, err := upsertSrc.ExecContext(ctx, id, source, stamp, conf); err != nil {
			return fmt.Errorf("feeds: store listing: %w", err)
		}
	}
	return nil
}

// IOCSighting is one feed's listing of an indicator.
type IOCSighting struct {
	SourceID   string
	SourceName string
	Confidence float64
	// Enabled is whether the feed is switched on now: a switched-off feed is never pulled and its listings are not pruned, so they go stale (logs ignores them).
	Enabled bool
}

// IOCRecord is an indicator with the feeds that list it now.
type IOCRecord struct {
	Type, Value string
	FirstSeen   time.Time
	LastSeen    time.Time
	Sightings   []IOCSighting
}

// IOCLookup returns an indicator by type ("ip", "domain", "url", "hash") and canonical value (see IOCKey).
// An indicator no feed lists any more is reported with no sightings.
func (s *Store) IOCLookup(ctx context.Context, kind, value string) (IOCRecord, bool, error) {
	var (
		id, first, last string
		rec             IOCRecord
	)
	err := s.db.Reader().QueryRowContext(ctx, `SELECT id, type, value, first_seen, last_seen FROM feeds_ioc WHERE type = ? AND value = ?`, kind, value).
		Scan(&id, &rec.Type, &rec.Value, &first, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return IOCRecord{}, false, nil
	}
	if err != nil {
		return IOCRecord{}, false, fmt.Errorf("feeds: read indicator: %w", err)
	}
	if rec.FirstSeen, err = parseTS(first); err != nil {
		return IOCRecord{}, false, fmt.Errorf("feeds: stored time of an indicator: %w", err)
	}
	if rec.LastSeen, err = parseTS(last); err != nil {
		return IOCRecord{}, false, fmt.Errorf("feeds: stored time of an indicator: %w", err)
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT s.source_id, f.name, s.confidence, f.enabled FROM feeds_ioc_source s
JOIN feeds_source f ON f.id = s.source_id WHERE s.ioc_id = ?`, id)
	if err != nil {
		return IOCRecord{}, false, fmt.Errorf("feeds: read listings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var g IOCSighting
		if err := rows.Scan(&g.SourceID, &g.SourceName, &g.Confidence, &g.Enabled); err != nil {
			return IOCRecord{}, false, fmt.Errorf("feeds: read listings: %w", err)
		}
		rec.Sightings = append(rec.Sightings, g)
	}
	return rec, true, rows.Err()
}

// ---------- pull records

// outcome is what one pull produced for feeds_source and feeds_fetch_log.
type outcome struct {
	Started, Finished time.Time
	OK                bool
	NotModified       bool
	Accepted          int // records_accepted
	Rejected          int
	Reasons           []Reason
	Records           int    // feeds_source.records after an ok pull (ignored when NotModified)
	Note              string // an ok pull that dropped some rows
	Err               string // user-safe text of a failed pull
	Bytes             int
	ETag, LastModif   string
	CatalogVersion    string
	AnsweredBy        string // D-91: which address answered ("" leaves the stored answer as it is)
}

// recordOutcome writes the fetch log row and updates the pull state of the feed.
func recordOutcome(ctx context.Context, tx *sql.Tx, id string, o outcome) error {
	reasons, err := json.Marshal(append([]Reason{}, o.Reasons...))
	if err != nil {
		return fmt.Errorf("feeds: encode reasons: %w", err)
	}
	status := "error"
	var msg *string
	switch {
	case !o.OK:
		m := o.Err
		msg = &m
	case o.Note != "":
		m := o.Note
		msg = &m
	}
	if o.OK {
		status = "ok"
	}
	var etag, lm *string
	if o.ETag != "" {
		etag = &o.ETag
	}
	if o.LastModif != "" {
		lm = &o.LastModif
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO feeds_fetch_log (id, source_id, started_at, finished_at, status, records_accepted, records_rejected,
reject_reasons, error, bytes, etag, last_modified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		store.NewID("fl"), id, store.FormatTS(o.Started), store.FormatTS(o.Finished), status, o.Accepted, o.Rejected, string(reasons), msg, o.Bytes, etag, lm)
	if err != nil {
		return fmt.Errorf("feeds: write fetch log: %w", err)
	}
	fin := store.FormatTS(o.Finished)
	if !o.OK {
		_, err = tx.ExecContext(ctx, `UPDATE feeds_source SET last_fetch = ?, failures = failures + 1, status = 'error', error = ? WHERE id = ?`, fin, msg, id)
	} else {
		var records any
		if !o.NotModified {
			records = o.Records
		}
		var ver, answered any
		if o.AnsweredBy != "" {
			answered = o.AnsweredBy
		}
		if o.CatalogVersion != "" {
			ver = o.CatalogVersion
		}
		_, err = tx.ExecContext(ctx, `UPDATE feeds_source SET last_fetch = ?, last_success = ?, failures = 0, status = 'ok', error = ?,
records = COALESCE(?, records), etag = ?, last_modified = ?, catalog_version = COALESCE(?, catalog_version), answered_by = COALESCE(?, answered_by) WHERE id = ?`,
			fin, fin, msg, records, etag, lm, ver, answered, id)
	}
	if err != nil {
		return fmt.Errorf("feeds: update pull state: %w", err)
	}
	return nil
}

// maintain applies the retention rules: fetch log rows older than 90 days go (the newest ok row of each feed
// stays), indicators no feed lists for 30 days go.
func (s *Store) maintain(ctx context.Context, now time.Time) error {
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_fetch_log WHERE started_at < ? AND id NOT IN (
SELECT l.id FROM feeds_fetch_log l WHERE l.status = 'ok' AND l.started_at = (
  SELECT max(m.started_at) FROM feeds_fetch_log m WHERE m.source_id = l.source_id AND m.status = 'ok'))`, store.FormatTS(now.Add(-fetchLogKeep))); err != nil {
			return fmt.Errorf("feeds: prune fetch log: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_ioc WHERE last_seen < ? AND NOT EXISTS (
SELECT 1 FROM feeds_ioc_source s WHERE s.ioc_id = feeds_ioc.id)`, store.FormatTS(now.Add(-iocGrace))); err != nil {
			return fmt.Errorf("feeds: prune indicators: %w", err)
		}
		return nil
	})
}

// latest returns the newest vulnerability added, nil when there is none.
func (s *Store) latest(ctx context.Context) (*VulnRow, error) {
	rows, err := queryVulns(ctx, s.db.Reader(), `ORDER BY date_added DESC, cve DESC LIMIT 1`)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}
