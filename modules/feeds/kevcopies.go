package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// D-91 as amended 2026-11-17 (kien G13): there is no single primary address for the CISA list any more. Every check asks both copies,
// cisa.gov and CISA's GitHub copy (cisagov/kev-data, which follows cisa.gov within about an hour), each with its own conditional
// validators, and keeps the newer catalog (a plausible catalogVersion, then dateReleased); it never rolls back and never freezes. One copy failing is a quiet note
// on the feed; both failing is a failed pull (and the alert of D-629).

// kevCopyState is what one copy of the CISA list said at its last check.
type kevCopyState struct {
	Version   string    `json:"version,omitempty"`   // its catalogVersion, "" when not known yet
	Released  time.Time `json:"released,omitzero"`   // its dateReleased
	CheckedAt time.Time `json:"checked_at,omitzero"` // when the box last asked it
	Error     string    `json:"error,omitempty"`     // why the last ask failed, one clause naming the copy; "" when it answered
	Read      bool      `json:"read,omitempty"`      // a body of this copy was read and its validators kept: it is asked conditionally
	Refused   string    `json:"refused,omitempty"`   // why the body last read was not used ("" when it was usable)
	ETag      string    `json:"-"`                   // validators: kept in their own columns
	LastMod   string    `json:"-"`
}

// kevCopies is feeds_source.kev_copies of the CISA list: the two copies.
type kevCopies struct {
	CISA   kevCopyState `json:"cisa"`
	Mirror kevCopyState `json:"mirror"`
}

// copyLabel is how Home, Settings and the alerts name a copy.
func copyLabel(answeredBy string) string {
	if answeredBy == AnsweredMirror {
		return "CISA's GitHub copy"
	}
	return "cisa.gov"
}

// kevCopies reads what each copy said last and the dateReleased of the catalog the box holds. Read on its own, not with sourceCols,
// so the code that reads the feed rows still works on the schema before migration 0016 (the migration tests run it there).
func (s *Store) kevCopies(ctx context.Context) (kevCopies, time.Time, error) {
	var raw, rel *string
	err := s.db.Reader().QueryRowContext(ctx, `SELECT kev_copies, catalog_released FROM feeds_source WHERE id = ?`, kevFeedID).Scan(&raw, &rel)
	if errors.Is(err, sql.ErrNoRows) {
		return kevCopies{}, time.Time{}, nil
	}
	if err != nil {
		return kevCopies{}, time.Time{}, fmt.Errorf("feeds: read the copies of the CISA list: %w", err)
	}
	var c kevCopies
	if raw != nil {
		_ = json.Unmarshal([]byte(*raw), &c) // unreadable: as if nothing were known, so each copy is asked in full once
	}
	var held time.Time
	if rel != nil {
		if t, err := parseTS(*rel); err == nil {
			held = t
		}
	}
	return c, held, nil
}

// write stores the copies and the validators of each (cisa.gov's in etag/last_modified, the GitHub copy's in mirror_*).
func (c *kevCopies) write(ctx context.Context, tx *sql.Tx, id string) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("feeds: encode the copies of the CISA list: %w", err)
	}
	null := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	_, err = tx.ExecContext(ctx, `UPDATE feeds_source SET kev_copies = ?, etag = ?, last_modified = ?, mirror_etag = ?, mirror_last_modified = ? WHERE id = ?`,
		string(raw), null(c.CISA.ETag), null(c.CISA.LastMod), null(c.Mirror.ETag), null(c.Mirror.LastMod), id)
	return err
}

// kevAheadMax is how far ahead of the box's clock a catalogVersion or dateReleased may be and still count (#946 r1 High): a version
// years ahead (a typo such as "2062.11.17") would otherwise win every comparison and freeze the list for good.
const kevAheadMax = 48 * time.Hour

// kevKeepShare is the share of the held entries a newer catalog must have (KEV only grows, #946 r1): a cut copy is refused with a note.
const kevKeepShare = 95

// kevKey is what orders two catalogs: the day of a plausible catalogVersion ("2026.11.17": a real date, not more than kevAheadMax after
// the box's clock, within a day of its own dateReleased when that is known) and a plausible dateReleased. Zero parts do not count.
type kevKey struct{ day, released time.Time }

func keyOf(version string, released, now time.Time) kevKey {
	var k kevKey
	if !released.IsZero() && !released.After(now.Add(kevAheadMax)) {
		k.released = released
	}
	if d, err := time.Parse("2006.01.02", version); err == nil && !d.After(now.Add(kevAheadMax)) {
		rd := k.released.Truncate(24 * time.Hour)
		if k.released.IsZero() || (!d.Before(rd.Add(-24*time.Hour)) && !d.After(rd.Add(24*time.Hour))) {
			k.day = d
		}
	}
	return k
}

func (k kevKey) usable() bool { return !k.day.IsZero() || !k.released.IsZero() }

// newer reports whether catalog k is newer than o: by version day when both have one and they differ, else by dateReleased when both
// have one, else by the day each has (version day, or the day of its release). A tie is not newer.
func (k kevKey) newer(o kevKey) bool {
	switch {
	case !k.day.IsZero() && !o.day.IsZero() && !k.day.Equal(o.day):
		return k.day.After(o.day)
	case !k.released.IsZero() && !o.released.IsZero():
		return k.released.After(o.released)
	}
	day := func(x kevKey) time.Time {
		if !x.day.IsZero() {
			return x.day
		}
		return x.released.Truncate(24 * time.Hour)
	}
	return day(k).After(day(o))
}

// buildKEVBoth is one check of the CISA list at its built-in address: both copies asked, the newer catalog kept (D-91 as amended).
// Never a freeze or a roll back (#946 r1): a copy without a plausible version or release date, or with fewer than kevKeepShare % of the
// entries the box holds, is refused with a note (it counts as a failed copy); a held version that is not plausible counts as none.
func (s *Service) buildKEVBoth(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	st, heldReleased, err := s.st.kevCopies(ctx)
	if err != nil {
		return p, err
	}
	now := s.now()
	type answer struct {
		by    string
		cat   KEVCatalog
		bytes int
		key   kevKey
		c     *kevCopyState
	}
	var got []answer
	var errs []error
	loaded := src.LastSuccess != nil
	held := kevKey{}
	if loaded {
		held = keyOf(orEmpty(src.CatalogVersion), heldReleased, now)
	}
	heldCount := 0
	if loaded && src.Records != nil {
		heldCount = *src.Records
	}
	for _, c := range []struct {
		by, url  string
		st       *kevCopyState
		etag, lm *string
	}{
		{AnsweredCISA, s.kevPrimary(), &st.CISA, src.ETag, src.LastModified},
		{AnsweredMirror, s.kevFallback(), &st.Mirror, src.MirrorETag, src.MirrorLastModified},
	} {
		c.st.ETag, c.st.LastMod, c.st.CheckedAt = orEmpty(c.etag), orEmpty(c.lm), now // kept unless the copy hands out new ones
		req := Request{URL: c.url}                                                    // no credentials
		if loaded && c.st.Read {                                                      // conditional once a body of this copy was read: a 304 then means that body (refused or not)
			req.ETag, req.LastModified = c.st.ETag, c.st.LastMod
		}
		resp, err := s.get(ctx, req)
		if err == nil && resp.NotModified {
			c.st.Error = c.st.Refused // the same body as last time: a refusal stands
			if c.st.Refused != "" {
				errs = append(errs, errors.New(c.st.Refused))
			}
			continue
		}
		if err == nil {
			var cat KEVCatalog
			if cat, err = ParseKEV(resp.Body); err == nil {
				err = accepted(cat.Stats)
			}
			if err == nil {
				c.st.Version, c.st.Released, c.st.ETag, c.st.LastMod, c.st.Read = cat.Version, cat.ReleasedAt, resp.ETag, resp.LastModified, true
				label, key := copyLabel(c.by), keyOf(cat.Version, cat.ReleasedAt, now)
				switch {
				case !key.usable(): // a schema change or a typo: refused, never a freeze
					c.st.Refused = label + " sent a list with no readable version or release date, so it was not used"
				case heldCount > 0 && cat.Accepted*100 < kevKeepShare*heldCount: // KEV only grows
					c.st.Refused = fmt.Sprintf("%s sent a list of %s entries, fewer than %d%% of the %s on this box, so it was not used",
						label, grouped(cat.Accepted), kevKeepShare, grouped(heldCount))
				default:
					c.st.Refused = ""
				}
				c.st.Error = c.st.Refused
				if c.st.Refused != "" {
					errs = append(errs, errors.New(c.st.Refused))
					continue
				}
				got = append(got, answer{c.by, cat, len(resp.Body), key, c.st})
				continue
			}
		}
		c.st.Error = copyWhy(copyLabel(c.by), err, c.url)
		errs = append(errs, err)
	}
	p.out.Copies = &st
	if len(errs) == 2 { // both failed: a failed pull, one sentence with both reasons and no address
		return p, &Error{Err: errs[1], Detail: st.CISA.Error + ", and " + st.Mirror.Error + "."}
	}
	quiet := "" // one copy failing is a note, not a failure
	for _, c := range []kevCopyState{st.CISA, st.Mirror} {
		if c.Error != "" {
			quiet = c.Error + "; the other copy answered."
		}
	}
	var best *answer
	for i := range got { // cisa.gov first: of two equal catalogs, cisa.gov's (deterministic)
		if best == nil || got[i].key.newer(best.key) {
			best = &got[i]
		}
	}
	take := false
	if best != nil {
		heldBy := orEmpty(src.AnsweredBy)
		switch {
		case !loaded || !held.usable() || best.key.newer(held): // nothing held, a held version that is not plausible, or news
			take = true
		case held.newer(best.key): // behind the box: never a roll back
		case best.by == AnsweredCISA && heldBy != AnsweredCISA: // the same catalog: cisa.gov's is the one kept
			take = true
		case best.cat.Accepted > heldCount: // the same catalog with more entries than a partial copy held (#946 r1)
			take = true
		}
	}
	if !take {
		p.out = outcome{OK: true, NotModified: true, Note: quiet, Copies: &st}
		return p, nil
	}
	cat := best.cat
	p.vulns, p.hasVulns = cat.Vulns, true
	p.out = outcome{OK: true, Bytes: best.bytes, ETag: best.c.ETag, LastModif: best.c.LastMod, AnsweredBy: best.by, CatalogVersion: cat.Version,
		CatalogReleased: cat.ReleasedAt, Copies: &st}
	p.out.fill(cat.Stats, cat.Accepted)
	if quiet != "" {
		p.out.Note = strings.TrimSpace(quiet + " " + p.out.Note)
	}
	return p, nil
}

// copyWhy is why a copy of the CISA list did not give the box its list, one clause that names the copy ("cisa.gov refused this box
// (HTTP 403)", "CISA's GitHub copy did not answer in time"), never an address: Home, Settings and the alert show it.
func copyWhy(label string, err error, rawURL string) string {
	var se *StatusError
	switch {
	case errors.As(err, &se) && se.Code == http.StatusForbidden:
		return label + " refused this box (HTTP 403)"
	case errors.As(err, &se):
		return fmt.Sprintf("%s answered HTTP %d", label, se.Code)
	case isTimeout(err):
		return label + " did not answer in time"
	}
	if u := unreached(err); u != "" {
		return label + " " + u
	}
	var fe *Error
	if errors.As(err, &fe) { // a list that could not be read: the parser's own words
		return label + ": " + strings.TrimRight(fe.Detail, ".")
	}
	return label + ": " + strings.TrimRight(userError(err, rawURL), ".")
}
