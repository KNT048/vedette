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
// validators, and keeps the newer catalog (catalogVersion, then dateReleased); it never rolls back. One copy failing is a quiet note
// on the feed; both failing is a failed pull (and the alert of D-629).

// kevCopyState is what one copy of the CISA list said at its last check.
type kevCopyState struct {
	Version   string    `json:"version,omitempty"`   // its catalogVersion, "" when not known yet
	Released  time.Time `json:"released,omitzero"`   // its dateReleased
	CheckedAt time.Time `json:"checked_at,omitzero"` // when the box last asked it
	Error     string    `json:"error,omitempty"`     // why the last ask failed, one clause naming the copy; "" when it answered
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

// kevNewer reports whether catalog a (version, dateReleased) is newer than b. A known version beats an unknown one; equal versions
// (or versions that do not compare) are decided by dateReleased, and a tie is not newer.
func kevNewer(av string, ar time.Time, bv string, br time.Time) bool {
	switch {
	case av != "" && bv == "":
		return true
	case av == "" && bv != "":
		return false
	case kevOlder(bv, av):
		return true
	case kevOlder(av, bv):
		return false
	}
	return ar.After(br)
}

// buildKEVBoth is one check of the CISA list at its built-in address: both copies asked, the newer catalog kept (D-91 as amended).
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
		c     *kevCopyState
	}
	var got []answer
	var errs []error
	loaded := src.LastSuccess != nil
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
		if loaded && c.st.Version != "" {                                             // conditional only when the version the copy last gave is known: a 304 then means that version
			req.ETag, req.LastModified = c.st.ETag, c.st.LastMod
		}
		resp, err := s.get(ctx, req)
		if err == nil && !resp.NotModified {
			var cat KEVCatalog
			if cat, err = ParseKEV(resp.Body); err == nil {
				err = accepted(cat.Stats)
			}
			if err == nil {
				c.st.Version, c.st.Released, c.st.ETag, c.st.LastMod, c.st.Error = cat.Version, cat.ReleasedAt, resp.ETag, resp.LastModified, ""
				got = append(got, answer{c.by, cat, len(resp.Body), c.st})
				continue
			}
		}
		if err != nil {
			c.st.Error = copyWhy(copyLabel(c.by), err, c.url)
			errs = append(errs, err)
			continue
		}
		c.st.Error = "" // 304: the copy still has the version it last gave
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
	for i := range got { // cisa.gov first: of two equal catalogs, the box keeps cisa.gov's
		if best == nil || kevNewer(got[i].c.Version, got[i].c.Released, best.c.Version, best.c.Released) {
			best = &got[i]
		}
	}
	if best == nil || (loaded && !kevNewer(best.c.Version, best.c.Released, orEmpty(src.CatalogVersion), heldReleased)) {
		// nothing newer than the catalog on the box (a 304, or a copy that is behind): never a roll back
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
