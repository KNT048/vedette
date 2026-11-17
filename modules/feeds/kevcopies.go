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

// There is no single primary address for the CISA list any more. Every check asks both copies,
// cisa.gov and CISA's GitHub copy (cisagov/kev-data, which follows cisa.gov within about an hour), each with its own conditional
// validators, and keeps the newer catalog (a plausible catalogVersion, then dateReleased); it never rolls back and never freezes. One copy failing is a quiet note
// on the feed; both failing is a failed pull (and an alert).

// kevCopyState is what one copy of the CISA list said at its last check, and what the box knows of the body it last read from it
// (version, release, entries): a 304 is judged again from these under the rules of the day (#946 r2), never from a stored verdict.
type kevCopyState struct {
	Version   string    `json:"version,omitempty"`   // its catalogVersion, "" when not known yet
	Released  time.Time `json:"released,omitzero"`   // its dateReleased
	Count     int       `json:"count,omitempty"`     // the entries of its body that were accepted
	CheckedAt time.Time `json:"checked_at,omitzero"` // when the box last asked it
	Error     string    `json:"error,omitempty"`     // why the last ask failed or was not used, one clause naming the copy; "" when it answered
	Read      bool      `json:"read,omitempty"`      // a body of this copy was read and its validators kept: it is asked conditionally
	ETag      string    `json:"-"`                   // validators: kept in their own columns
	LastMod   string    `json:"-"`
}

// kevCopies is feeds_source.kev_copies of the CISA list: the two copies, and how far the box's clock was from the servers' at the
// last check (seconds, the box minus the server; 0 when no server said its time).
type kevCopies struct {
	CISA     kevCopyState `json:"cisa"`
	Mirror   kevCopyState `json:"mirror"`
	SkewSecs int64        `json:"clock_skew_s,omitempty"`
}

// kevSkewMax is how far the box's clock may be from the servers' before the feed note and the alert say so (#946 r2).
const kevSkewMax = time.Hour

// skewText says how far off the box's clock is, "" when it is within kevSkewMax.
func skewText(secs int64) string {
	d := time.Duration(secs) * time.Second
	if d.Abs() <= kevSkewMax {
		return ""
	}
	amount := fmt.Sprintf("%d hours", int(d.Abs().Hours()))
	if d.Abs() >= 48*time.Hour {
		amount = fmt.Sprintf("%d days", int(d.Abs().Hours()/24))
	}
	way := "behind"
	if d > 0 {
		way = "ahead of"
	}
	return fmt.Sprintf("This box's clock is %s %s the time the servers give; set its time (NTP).", amount, way)
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

// kevAheadMax is how far ahead of the answering server's clock (its Date header; the box's clock when it gives none, #946 r2) a
// catalogVersion or dateReleased may be and still count (#946 r1 High): a version years ahead (a typo such as "2062.11.17") would
// otherwise win every comparison and freeze the list for good.
const kevAheadMax = 48 * time.Hour

// kevKey is what orders two catalogs: the day of a plausible catalogVersion ("2026.11.17": a real date, not more than kevAheadMax after
// now, within a day of its own dateReleased when that is known) and a plausible dateReleased. Zero parts do not count. now is the
// answering server's clock when it gave one.
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

// buildKEVBoth is one check of the CISA list at its built-in address: both copies asked, the newer catalog kept.
// Never a freeze or a roll back (#946 r1, r2): a copy without a plausible version or release date is not used (a note; it counts as a
// failed copy); a held version that is not plausible counts as none. Plausible is judged against the answering server's clock, so a
// box whose clock is days off still loads the list (and says its clock is off). Of two copies with the same catalog the fuller one is
// used, then cisa.gov's; there is no other count rule (cisa-kev applies additively). A 304 is judged again from what the box knows of
// that copy's body; when that body would now be taken, it is read in full in the same check.
func (s *Service) buildKEVBoth(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	st, heldReleased, err := s.st.kevCopies(ctx)
	if err != nil {
		return p, err
	}
	now := s.now()
	type cand struct {
		by    string
		key   kevKey
		count int
		cat   *KEVCatalog // nil: a 304, nothing to apply
		bytes int
		c     *kevCopyState
	}
	var cands []cand
	var errs []error
	loaded := src.LastSuccess != nil
	reload := src.reload() // new code reads both copies in full and takes the list held again unless a copy is newer (INV-32)
	heldCount, heldBy := 0, orEmpty(src.AnsweredBy)
	if loaded && src.Records != nil {
		heldCount = *src.Records
	}
	// takes says whether a catalog with key k and count entries from copy by replaces the one held (ref: the clock to judge by)
	takes := func(k kevKey, count int, by string, ref time.Time) bool {
		held := keyOf(orEmpty(src.CatalogVersion), heldReleased, ref)
		switch {
		case !loaded || !held.usable() || k.newer(held):
			return true
		case held.newer(k):
			return false // behind the box: never a roll back
		case reload:
			return count >= heldCount // the same catalog parsed by this code, never a shorter copy of it
		}
		return count > heldCount || (count == heldCount && by == AnsweredCISA && heldBy != AnsweredCISA)
	}
	var skew time.Duration
	ref := now // the latest clock a server gave, else the box's
	for _, c := range []struct {
		by, url  string
		st       *kevCopyState
		etag, lm *string
	}{
		{AnsweredCISA, s.kevPrimary(), &st.CISA, src.ETag, src.LastModified},
		{AnsweredMirror, s.kevFallback(), &st.Mirror, src.MirrorETag, src.MirrorLastModified},
	} {
		label := copyLabel(c.by)
		c.st.ETag, c.st.LastMod, c.st.CheckedAt = orEmpty(c.etag), orEmpty(c.lm), now // kept unless the copy hands out new ones
		req := Request{URL: c.url}                                                    // no credentials
		if loaded && c.st.Read && !reload {                                           // conditional once a body of this copy was read: a 304 then means that body
			req.ETag, req.LastModified = c.st.ETag, c.st.LastMod
		}
		resp, err := s.get(ctx, req)
		cref := now
		if err == nil && !resp.Date.IsZero() {
			cref = resp.Date
			if d := now.Sub(resp.Date); d.Abs() > skew.Abs() {
				skew = d
			}
			if resp.Date.After(ref) {
				ref = resp.Date
			}
		}
		if err == nil && resp.NotModified {
			k := keyOf(c.st.Version, c.st.Released, cref)
			switch {
			case !k.usable(): // judged again, still no usable version or date: not used, and not read again
				c.st.Error = label + " sent a list with no readable version or release date, so it was not used"
				errs = append(errs, errors.New(c.st.Error))
				continue
			case !takes(k, c.st.Count, c.by, cref):
				c.st.Error = ""
				cands = append(cands, cand{c.by, k, c.st.Count, nil, 0, c.st})
				continue
			}
			// judged again, the body it has would now be taken (a clock or a held list that changed, #946 r2): read it in full
			resp, err = s.get(ctx, Request{URL: c.url})
		}
		if err == nil {
			var cat KEVCatalog
			if cat, err = ParseKEV(resp.Body); err == nil {
				err = accepted(cat.Stats)
			}
			if err == nil {
				c.st.Version, c.st.Released, c.st.Count, c.st.ETag, c.st.LastMod, c.st.Read = cat.Version, cat.ReleasedAt, cat.Accepted, resp.ETag, resp.LastModified, true
				k := keyOf(cat.Version, cat.ReleasedAt, cref)
				if !k.usable() { // a schema change or a typo: not used, never a freeze
					c.st.Error = label + " sent a list with no readable version or release date, so it was not used"
					errs = append(errs, errors.New(c.st.Error))
					continue
				}
				c.st.Error = ""
				cands = append(cands, cand{c.by, k, cat.Accepted, &cat, len(resp.Body), c.st})
				continue
			}
		}
		c.st.Error = copyWhy(label, err, c.url)
		errs = append(errs, err)
	}
	st.SkewSecs = int64(skew / time.Second)
	clock := skewText(st.SkewSecs)
	p.out.Copies = &st
	if len(errs) == 2 { // both failed: a failed pull, one sentence with both reasons and no address
		return p, &Error{Err: errs[1], Detail: strings.TrimSpace(st.CISA.Error + ", and " + st.Mirror.Error + ". " + clock)}
	}
	var notes []string // one copy failing is a note, not a failure
	for _, c := range []kevCopyState{st.CISA, st.Mirror} {
		if c.Error != "" {
			notes = append(notes, c.Error+"; the other copy answered.")
		}
	}
	var best *cand
	for i := range cands { // the newer; of the same catalog the fuller, then cisa.gov's (first)
		c := &cands[i]
		if best == nil || c.key.newer(best.key) || (!best.key.newer(c.key) && c.count > best.count) {
			best = c
		}
	}
	if len(cands) == 2 && !cands[0].key.newer(cands[1].key) && !cands[1].key.newer(cands[0].key) && cands[0].count != cands[1].count {
		notes = append(notes, fmt.Sprintf("cisa.gov and CISA's GitHub copy have the same list with %s and %s entries; the fuller one counts.",
			grouped(cands[0].count), grouped(cands[1].count)))
	}
	if clock != "" {
		notes = append(notes, clock)
	}
	note := strings.Join(notes, " ")
	if best == nil || best.cat == nil || !takes(best.key, best.count, best.by, ref) {
		p.out = outcome{OK: true, NotModified: true, Note: note, Copies: &st}
		return p, nil
	}
	cat := best.cat
	p.vulns, p.hasVulns = cat.Vulns, true
	p.out = outcome{OK: true, Bytes: best.bytes, ETag: best.c.ETag, LastModif: best.c.LastMod, AnsweredBy: best.by, CatalogVersion: cat.Version,
		CatalogReleased: cat.ReleasedAt, Copies: &st}
	p.out.fill(cat.Stats, cat.Accepted)
	if note != "" {
		p.out.Note = strings.TrimSpace(note + " " + p.out.Note)
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
