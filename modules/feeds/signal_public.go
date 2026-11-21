package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Public-exploit indexes: three public lists that say a working exploit or a proof of concept exists for a CVE. Each is downloaded
// whole once a day and read for facts only (CVE id, date, link and, for GitHub proofs of concept, star and author counts); no exploit
// code is ever fetched, stored or run. Each CVE a list names becomes one feeds_signal row (kind public_exploit, source = the feed),
// with qualifies set by the quality rule of that list: a Metasploit module or an Exploit-DB entry always qualifies; a GitHub proof
// of concept qualifies with 50 stars when seen, a known author (content/catalog/exploit-authors.json), or 5 different authors.

// The built-in public-exploit feeds.
const (
	metasploitFeedID = "metasploit"
	exploitDBFeedID  = "exploit-db"
	pocGitHubFeedID  = "poc-in-github"
)

// The decoders of the public-exploit feeds.
const (
	DecoderMetasploit Decoder = "metasploit"    // parseMetasploitModules: Metasploit's db/modules_metadata_base.json
	DecoderExploitDB  Decoder = "exploit-db"    // parseExploitDBIndex: Exploit-DB's files_exploits.csv
	DecoderPoCGitHub  Decoder = "poc-in-github" // parsePoCInGitHub: the PoC-in-GitHub repository as one tar.gz archive
)

// The licence lines of the public-exploit indexes (THIRD_PARTY_NOTICES.md has the terms read). The box keeps facts only: CVE id,
// date, link, and star and author counts.
const (
	metasploitNotice = "BSD-3-Clause, Rapid7 metasploit-framework module metadata. Facts only; no module code is fetched."
	exploitDBNotice  = "GPL-2.0, OffSec exploitdb repository index. Facts only; no exploit file is fetched."
	pocGitHubNotice  = "CC0, nomi-sec PoC-in-GitHub index. Facts only; no repository is fetched."
)

// readFail is the error of a decoder that could not read its input: the download's own size cap (ErrTooLarge, which Fetch words as
// "larger than …") or a broken connection (transportErr, when the reader marks it) as it is, anything else as a bad index.
func readFail(err error, format string, a ...any) error {
	var te transportErr
	if errors.Is(err, ErrTooLarge) || errors.As(err, &te) { // the download's own failure, not the data's
		return err
	}
	return fail(ErrBadSample, format, a...)
}

// publicExploitFeed reports a feed of the public-exploit indexes.
func publicExploitFeed(id string) bool {
	return id == metasploitFeedID || id == exploitDBFeedID || id == pocGitHubFeedID
}

// The limits of one download (bytes after the transport's own decoding) and the shrink guard of each index: below shrinkFloor CVEs in
// the last good index any index is taken (a first load, a test); an index of at least floor CVEs is always taken. Sizes and counts of
// November 2026: Metasploit 11 MB and about 3,300 CVEs, Exploit-DB 10 MB and about 25,000, PoC-in-GitHub 6 MB packed (71 MB
// unpacked) and about 11,900.
var publicExploitLimits = map[string]struct {
	maxBytes int64
	floor    int
}{
	metasploitFeedID: {64 << 20, 1_500},
	exploitDBFeedID:  {64 << 20, 10_000},
	pocGitHubFeedID:  {64 << 20, 5_000},
}

const (
	publicExploitShrinkFloor = 100
	publicExploitTimeout     = 5 * time.Minute
)

// maxCVEsPerEntry bounds the CVEs one Metasploit module or Exploit-DB entry names (10 and 60 at most in November 2026): an entry naming
// more is rejected. maxSignalsPerIndex bounds the CVEs of one index (about 25,000 for Exploit-DB): an index naming more fails.
const (
	maxCVEsPerEntry    = 100
	maxSignalsPerIndex = 200_000
)

// pocStars, pocAuthors: the quality rule of a GitHub proof of concept (with a known author).
const (
	pocStars   = 50
	pocAuthors = 5
)

// publicSignal is one CVE of a public-exploit index, as its decoder read it.
type publicSignal struct {
	CVE  string
	Date time.Time // when the index says the exploit existed: see each decoder; for PoC-in-GitHub the oldest repository
	URL  string    // where a person reads the entry ("" when the index gives no usable address)
	// Detail is a small JSON object for display: {"modules":2} | {"entries":3} | {"repos":31,"authors":29,"stars":264,"by":"sfewer-r7"}.
	Detail string

	// PoC-in-GitHub only. Qualifies is the quality rule now; Rule is when it became true by facts that do not move later (a known
	// author's repository, the fifth author's first repository); Stars is the creation of the oldest repository with pocStars stars
	// or more, a date the star count did not have yet (applyPublicSignals reads it with what the box saw before).
	Qualifies   bool
	Rule, Stars time.Time
}

// publicIndex is what a decoder read from one index.
type publicIndex struct {
	Signals []publicSignal // one per CVE, sorted by CVE
	Stats
}

// buildPublicExploit downloads one public-exploit index as a stream (conditional on the last good pull's validators, so an unchanged
// file is not downloaded again) and parses it whole before anything is written.
func (s *Service) buildPublicExploit(ctx context.Context, src sourceRow, p pullPlan, dec Decoder) (pullPlan, error) {
	parse := map[Decoder]func(io.Reader) (publicIndex, error){
		DecoderMetasploit: parseMetasploitModules,
		DecoderExploitDB:  parseExploitDBIndex,
		DecoderPoCGitHub:  parsePoCInGitHub,
	}[dec]
	lim := publicExploitLimits[src.ID]
	if parse == nil || lim.maxBytes == 0 {
		return p, fail(ErrBadConfig, "This built-in feed is no longer part of Vedette.")
	}
	var (
		res  publicIndex
		read int
	)
	req := Request{URL: src.URL, MaxBytes: lim.maxBytes, Stream: func(r io.Reader) error {
		c := &countReader{r: r}
		var err error
		res, err = parse(c)
		read = c.n
		return err
	}}
	if src.Status == "ok" {
		req.ETag, req.LastModified = orEmpty(src.ETag), orEmpty(src.LastModified)
	}
	ctx, cancel := context.WithTimeout(ctx, publicExploitTimeout)
	defer cancel()
	resp, err := s.Fetcher.Fetch(ctx, req)
	if err != nil {
		return p, err
	}
	if resp.NotModified {
		p.out = outcome{OK: true, NotModified: true, ETag: req.ETag, LastModif: req.LastModified}
		return p, nil
	}
	if err := accepted(res.Stats); err != nil {
		return p, err
	}
	// A cut or substituted index must not take the signal from the CVEs it no longer names (the catalogue would then drop the old
	// CVEs they keep), as for the nuclei index. The yardstick is the last good pull from this address (feeds_source.records: cleared
	// by a new address or by turning the feed off and on).
	if n, held := len(res.Signals), src.Records; held != nil && *held >= publicExploitShrinkFloor && 2*n < *held && n < lim.floor {
		return p, fail(ErrBadSample, "The index lists %s CVEs, fewer than half of the %s of the last good index; Vedette kept the signals it had. To take this index anyway, turn the feed off and on again.", grouped(n), grouped(*held))
	}
	p.out = outcome{OK: true, Bytes: read, ETag: resp.ETag, LastModif: resp.LastModified}
	p.out.fill(res.Stats, len(res.Signals))
	p.signals, p.hasSignals = res.Signals, true
	return p, nil
}

// heldSignal is a feeds_signal row of a public-exploit feed as the box holds it before a pull.
type heldSignal struct {
	firstSeen, lastSeen time.Time
	qualifies           bool
}

// applyPublicSignals replaces the public-exploit signals of one feed with the CVEs of one index. A CVE seen before keeps its earlier
// first_seen while it qualifies; one that starts to qualify now is dated by when its rule became true. Rows of CVEs the index no
// longer names are deleted.
func applyPublicSignals(ctx context.Context, tx *sql.Tx, now time.Time, source string, sigs []publicSignal) error {
	held := map[string]heldSignal{}
	rows, err := tx.QueryContext(ctx, `SELECT cve, first_seen, last_seen, qualifies FROM feeds_signal WHERE source = ? AND kind = ?`, source, SignalPublicExploit)
	if err != nil {
		return fmt.Errorf("feeds: read signals: %w", err)
	}
	for rows.Next() {
		var (
			cve, fs, ls string
			h           heldSignal
		)
		if err := rows.Scan(&cve, &fs, &ls, &h.qualifies); err != nil {
			_ = rows.Close()
			return fmt.Errorf("feeds: read signals: %w", err)
		}
		var e1, e2 error
		h.firstSeen, e1 = parseTS(fs)
		h.lastSeen, e2 = parseTS(ls)
		if err := errors.Join(e1, e2); err != nil {
			_ = rows.Close()
			return fmt.Errorf("feeds: read signals: %w", err)
		}
		held[cve] = h
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("feeds: read signals: %w", err)
	}
	// a stamp no row of the source has, so "any other last_seen" means "not in this index" (as applyTemplates)
	for {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM feeds_signal WHERE source = ? AND kind = ? AND last_seen = ? LIMIT 1`, source, SignalPublicExploit, store.FormatTS(now)).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return fmt.Errorf("feeds: check stamp: %w", err)
		}
		now = now.Add(time.Millisecond)
	}
	stamp := store.FormatTS(now)
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies, url, detail)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(cve, kind, source) DO UPDATE SET first_seen = excluded.first_seen, last_seen = excluded.last_seen, qualifies = excluded.qualifies,
url = excluded.url, detail = excluded.detail`)
	if err != nil {
		return fmt.Errorf("feeds: store signal: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	for i, g := range sigs {
		if i%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		h, had := held[g.CVE]
		qualifies, first := signalDate(source, g, h, had)
		if first.After(now) {
			first = now // an index that dates an entry in the future
		}
		var detail any
		if g.Detail != "" {
			detail = g.Detail
		}
		if _, err := stmt.ExecContext(ctx, g.CVE, SignalPublicExploit, source, store.FormatTS(first), stamp, stamp, boolInt(qualifies), g.URL, detail); err != nil {
			return fmt.Errorf("feeds: store signal: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_signal WHERE source = ? AND kind = ? AND last_seen <> ?`, source, SignalPublicExploit, stamp); err != nil {
		return fmt.Errorf("feeds: drop signals: %w", err)
	}
	return nil
}

// signalDate is whether a CVE of an index qualifies now and its first_seen, given the row the box held for it (had).
//
// Metasploit and Exploit-DB always qualify: first_seen is the earliest date the index or the box ever gave. A GitHub proof of concept
// that qualified before keeps its earlier date; one that qualifies now for the first time is dated by its rule: a known author's or
// the fifth author's repository by its creation (a fact that does not move), the star count by its oldest repository with enough
// stars, but never before the box last saw the CVE without enough stars (the stars came after that). One that does not qualify keeps
// the oldest repository's date, so the row says since when a proof of concept was claimed.
func signalDate(source string, g publicSignal, h heldSignal, had bool) (bool, time.Time) {
	if source != pocGitHubFeedID {
		if had && h.firstSeen.Before(g.Date) {
			return true, h.firstSeen
		}
		return true, g.Date
	}
	if !g.Qualifies {
		if had && h.firstSeen.Before(g.Date) {
			return false, h.firstSeen
		}
		return false, g.Date
	}
	stars := g.Stars
	if had && !h.qualifies && !stars.IsZero() && stars.Before(h.lastSeen) {
		stars = h.lastSeen
	}
	first := earliest(g.Rule, stars)
	if had && h.qualifies && h.firstSeen.Before(first) {
		first = h.firstSeen
	}
	return true, first
}

// earliest is the earlier of two times, a zero time standing for "none".
func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero() || a.Before(b):
		return a
	}
	return b
}
