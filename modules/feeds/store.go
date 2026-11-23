package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	coreschedule "github.com/knt048/vedette/core/schedule"
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
type Store struct {
	db     *store.DB
	kevIdx kevIndexCache // KevIndex under its stamp
}

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
	IntervalHours int // how often the source's schedule pulls it, in hours: read from core_schedule (feeds.source:<id>), never stored here
	Auth          AuthType
	HeaderName    *string
	Username      *string
	SecretID      *string
	SecretLast4   *string
	Parser        *Parser
	License       *string
	CreatedAt     time.Time
	Rev           int // edits so far: a pull writes only if it is unchanged

	LastFetch      *time.Time
	LastSuccess    *time.Time
	Failures       int
	Records        *int
	Status         string // never, ok, error
	Error          *string
	ETag           *string
	LastModified   *string
	CatalogVersion *string
	AnsweredBy     *string // "CISA" or "CISA GitHub mirror", only for the CISA list
	// MirrorETag and MirrorLastModified are the validators of the CISA GitHub mirror: ETag and LastModified stay the
	// validators of the feed's own address, so neither address is ever sent the other's.
	MirrorETag         *string
	MirrorLastModified *string
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

const sourceCols = `id, builtin, name, kind, format, url, default_url, enabled, COALESCE((SELECT MAX(1, (every_minutes + 59) / 60) FROM core_schedule WHERE owner_key = 'feeds.source:' || feeds_source.id AND freq = 'interval'), 24),
auth_type, auth_header_name,
auth_username, secret_id, secret_last4, parser, license, created_at, last_fetch, last_success, failures, records, status,
error, etag, last_modified, catalog_version, rev, answered_by, mirror_etag, mirror_last_modified`

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
		&s.Failures, &s.Records, &s.Status, &s.Error, &s.ETag, &s.LastModified, &s.CatalogVersion, &s.Rev, &s.AnsweredBy,
		&s.MirrorETag, &s.MirrorLastModified)
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
			_, err := tx.ExecContext(ctx, `INSERT INTO feeds_source (id, builtin, name, kind, format, url, default_url, enabled, license, created_at)
VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET name = excluded.name, kind = excluded.kind, format = excluded.format, license = excluded.license,
  url = CASE WHEN url = default_url THEN excluded.url ELSE url END, default_url = excluded.default_url`,
				b.ID, b.Name, string(b.Kind), string(b.Format), b.URL, b.URL, boolInt(!b.BYOK), b.License, store.FormatTS(now))
			if err != nil {
				return fmt.Errorf("feeds: seed %s: %w", b.ID, err)
			}
		}
		return retireBuiltins(ctx, tx)
	})
}

// retireBuiltins deletes the built-in rows the code no longer lists (INV-16), with their listings, vulnerabilities
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
		if err := coreschedule.DeleteTx(ctx, tx, scheduleKey(id)); err != nil {
			return err
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
	_, err = tx.ExecContext(ctx, `INSERT INTO feeds_source (id, builtin, name, kind, format, url, enabled, auth_type,
auth_header_name, auth_username, secret_id, secret_last4, parser, created_at)
VALUES (?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Name, string(r.Kind), string(r.Format), r.URL, boolInt(r.Enabled), string(r.Auth),
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
	_, err = tx.ExecContext(ctx, `UPDATE feeds_source SET name = ?, kind = ?, format = ?, url = ?, enabled = ?,
auth_type = ?, auth_header_name = ?, auth_username = ?, secret_id = ?, secret_last4 = ?, parser = ?, etag = NULL, last_modified = NULL,
rev = rev + 1, failures = CASE WHEN ? = 1 AND enabled = 0 THEN 0 ELSE failures END
WHERE id = ? AND builtin = 0`,
		r.Name, string(r.Kind), string(r.Format), r.URL, boolInt(r.Enabled), string(r.Auth),
		r.HeaderName, r.Username, r.SecretID, r.SecretLast4, parser, boolInt(r.Enabled), r.ID)
	if err != nil {
		return fmt.Errorf("feeds: update feed: %w", err)
	}
	return nil
}

// updateSettings is PUT /feeds/sources/{id}: the two things both kinds of feed allow to change here (how often it pulls is its schedule).
func updateSettings(ctx context.Context, tx *sql.Tx, id string, enabled bool, url string, urlChanged bool) error {
	var was bool
	if err := tx.QueryRowContext(ctx, `SELECT enabled FROM feeds_source WHERE id = ?`, id).Scan(&was); err != nil {
		return fmt.Errorf("feeds: read feed settings: %w", err)
	}
	// turning a feed back on forgets its back-off: the admin fixed what failed
	q := `UPDATE feeds_source SET rev = rev + 1, failures = CASE WHEN ? = 1 AND enabled = 0 THEN 0 ELSE failures END, enabled = ? WHERE id = ?`
	args := []any{boolInt(enabled), boolInt(enabled), id}
	if urlChanged { // a new address starts a new count of failures (#946 r1 Low) and forgets what the old one said: its count, version
		// and validators (#946 r2: a count from another address must never judge this one)
		q = `UPDATE feeds_source SET rev = rev + 1, failures = 0, enabled = ?, url = ?, etag = NULL, last_modified = NULL,
answered_by = NULL, mirror_etag = NULL, mirror_last_modified = NULL, kev_copies = NULL, catalog_version = NULL, catalog_released = NULL,
records = NULL, stale_failed_since = NULL, stale_failed_checks = 0 WHERE id = ?`
		args = []any{boolInt(enabled), url, id}
	}
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("feeds: update feed settings: %w", err)
	}
	if was == enabled {
		return nil
	}
	// Turned on or off: the watch of the CISA list restarts (the checks count from when it is on again, and an alert open when it
	// was turned off is not followed by "up to date again"), and the CISA list forgets its held version, count and every validator (#946 r1:
	// the way out of a catalog the box should not have kept; the next check reads both copies in full).
	if _, err := tx.ExecContext(ctx, `UPDATE feeds_source SET stale_watch_from = NULL, stale_alerted_at = NULL, stale_failed_since = NULL,
stale_failed_checks = 0 WHERE id = ?`, id); err != nil {
		return fmt.Errorf("feeds: restart the watch: %w", err)
	}
	if id == nucleiFeedID || publicExploitFeed(id) || vendorClaimFeed(id) { // the next index is taken as it is: the way to accept one the shrink guard refused
		// (a vendor feed then reads every advisory of its feed again; the claims it stored stay, as for the other built-in feeds)
		if _, err := tx.ExecContext(ctx, `UPDATE feeds_source SET records = NULL, etag = NULL, last_modified = NULL WHERE id = ?`, id); err != nil {
			return fmt.Errorf("feeds: forget the last nuclei index: %w", err)
		}
	}
	if id == kevFeedID {
		if _, err := tx.ExecContext(ctx, `UPDATE feeds_source SET catalog_version = NULL, catalog_released = NULL, records = NULL, kev_copies = NULL,
etag = NULL, last_modified = NULL, mirror_etag = NULL, mirror_last_modified = NULL WHERE id = ?`, id); err != nil {
			return fmt.Errorf("feeds: forget the held CISA list version: %w", err)
		}
	}
	return nil
}

// purgeLoaded deletes what a feed loaded: its exploited-list entries and signals, and its listings (indicators nobody else lists go
// too). A catalogue CVE no list or signal keeps any more goes with the retention rule (pruneCatalogue).
func purgeLoaded(ctx context.Context, tx *sql.Tx, id string) error {
	for _, st := range []struct {
		query string
		args  []any
	}{
		{`DELETE FROM feeds_kev WHERE source_id = ?`, []any{id}},
		{`DELETE FROM feeds_signal WHERE source = ?`, []any{id}},
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
	return coreschedule.DeleteTx(ctx, tx, scheduleKey(id))
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
	// Subdomains is whether the feed lists a name for itself and all of its subdomains (a built-in source with Source.Subdomains);
	// false for a custom feed, which lists names exactly.
	Subdomains bool
}

// IOCRecord is an indicator with the feeds that list it now.
type IOCRecord struct {
	Type, Value string
	FirstSeen   time.Time
	LastSeen    time.Time
	Sightings   []IOCSighting
}

// IOCListed says whether a switched-on feed lists at least one indicator now: false while every IOC feed is off or none has loaded yet, so
// logs' digest can say that no connection can be matched instead of "none of your devices connected to a listed address".
func (s *Store) IOCListed(ctx context.Context) (bool, error) {
	var ok bool
	err := s.db.Reader().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM feeds_ioc_source s JOIN feeds_source f ON f.id = s.source_id WHERE f.enabled = 1)`).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("feeds: read listings: %w", err)
	}
	return ok, nil
}

// IOCSubdomainsOn says whether a switched-on built-in feed lists names with all of their subdomains (Source.Subdomains): logs
// looks up the parents of an unlisted name only then. A custom feed is always exact.
func (s *Store) IOCSubdomainsOn(ctx context.Context) (bool, error) {
	ids := []any{}
	for _, b := range BuiltinSources() {
		if b.Subdomains {
			ids = append(ids, b.ID)
		}
	}
	if len(ids) == 0 {
		return false, nil
	}
	var ok bool
	err := s.db.Reader().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM feeds_source WHERE enabled = 1 AND builtin = 1 AND id IN (?`+strings.Repeat(", ?", len(ids)-1)+`))`, ids...).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("feeds: read sources: %w", err)
	}
	return ok, nil
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
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT s.source_id, f.name, s.confidence, f.enabled, f.builtin FROM feeds_ioc_source s
JOIN feeds_source f ON f.id = s.source_id WHERE s.ioc_id = ?`, id)
	if err != nil {
		return IOCRecord{}, false, fmt.Errorf("feeds: read listings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var g IOCSighting
		var builtin bool
		if err := rows.Scan(&g.SourceID, &g.SourceName, &g.Confidence, &g.Enabled, &builtin); err != nil {
			return IOCRecord{}, false, fmt.Errorf("feeds: read listings: %w", err)
		}
		if b, ok := BuiltinByID(g.SourceID); ok && builtin {
			g.Subdomains = b.Subdomains
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
	CatalogReleased   time.Time // dateReleased of the catalog stored (zero leaves it as it is)
	AnsweredBy        string    // The copy of the CISA list the stored catalog came from ("" leaves it as it is)
	// Copies is what each copy of the CISA list said at this check, with each copy's validators; nil for
	// every other pull. Written for a failed pull too.
	Copies *kevCopies
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
records = COALESCE(?, records), etag = ?, last_modified = ?, catalog_version = COALESCE(?, catalog_version), answered_by = COALESCE(?, answered_by)
WHERE id = ?`,
			fin, fin, msg, records, etag, lm, ver, answered, id)
		if err == nil && !o.CatalogReleased.IsZero() {
			_, err = tx.ExecContext(ctx, `UPDATE feeds_source SET catalog_released = ? WHERE id = ?`, store.FormatTS(o.CatalogReleased), id)
		}
	}
	if err == nil && o.Copies != nil {
		err = o.Copies.write(ctx, tx, id)
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
