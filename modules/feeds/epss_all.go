package feeds

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/store"
)

// The EPSS score of every CVE: FIRST publishes the scores of all CVEs once a day as one gzip CSV
// ("#model_version:…,score_date:…", "cve,epss,percentile", then one row per CVE). Measured 2026-11-15: 2,849,094 bytes
// for 406,543 CVEs, about 12 MB once unpacked; 15.5 MB in SQLite. The scores feed tier 2 (EPSS at or above
// EPSSLikely, published in the last 12 months) and are kept for every CVE (CVE pages, scan-found older CVEs).
const (
	epssAllFeedID = "epss-all"
	// EPSSLikely is the score from which a CVE is "likely to be exploited" (tier 2): FIRST's own example
	// threshold, 17,562 CVEs on 2026-11-14.
	EPSSLikely = 0.1
	// epssAllMaxBytes caps the download (the gzip file); epssAllMaxUnpacked caps what it unpacks to, so a hostile
	// file cannot make the box inflate gigabytes; epssAllMaxRows caps the rows.
	epssAllMaxBytes = 20_000_000
	epssAllTimeout  = 5 * time.Minute
)

// Vars for the tests (the real values are far above what a test file holds).
var (
	epssAllMaxUnpacked int64 = 64_000_000
	epssAllMaxRows           = 1_000_000
	// epssChunkRows rows per transaction, so the writer is never held for long (as applyIOCs does).
	epssChunkRows = 20_000
	// epssFloor: a file with at least this many scores is never refused as short (the real file has about 406,000).
	epssFloor = 200_000
)

// epssNum is a score as FIRST writes it.
var epssNum = regexp.MustCompile(`^[0-9]*\.?[0-9]+([eE][+-]?[0-9]+)?$`)

// epssBaseline is the count of the last good pull of epss-all from url; 0 when there is none (first pull, another
// address, or the feed was turned back on).
func (s *Store) epssBaseline(ctx context.Context, url string) (int, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count FROM feeds_epss_baseline WHERE id = 1 AND url = ?`, url).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("feeds: epss baseline: %w", err)
	}
	return n, nil
}

// EPSSAllScore is one row of the daily file.
type EPSSAllScore struct {
	CVE        string
	Score, Pct float64
}

// EPSSAllData is the parsed daily file.
type EPSSAllData struct {
	Model, ScoreDate string // from the first line, "" when absent
	Scores           []EPSSAllScore
	Stats
}

// ParseEPSSCSV reads FIRST's daily file of every EPSS score, gzip or plain CSV, as it downloads. The header must be
// cve,epss,percentile; a row with a bad CVE id or a value outside 0..1 is rejected and counted. A damaged gzip stream, a
// file that unpacks past epssAllMaxUnpacked or has more than epssAllMaxRows rows fails the parse (fail closed: the scores
// stored before stay).
func ParseEPSSCSV(r io.Reader) (EPSSAllData, error) {
	br := bufio.NewReader(r)
	var in io.Reader = br
	if magic, _ := br.Peek(2); bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return EPSSAllData{}, fail(ErrBadSample, "The EPSS file is not a readable gzip file.")
		}
		defer func() { _ = gz.Close() }()
		in = gz
	}
	capped := &io.LimitedReader{R: in, N: epssAllMaxUnpacked + 1}
	sc := bufio.NewScanner(capped)
	sc.Buffer(make([]byte, 0, 4096), 4096)
	out := EPSSAllData{Scores: []EPSSAllScore{}}
	tl := newTally()
	header, row := false, 0
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if !header {
			switch {
			case strings.HasPrefix(line, "#"):
				for _, kv := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
					k, v, _ := strings.Cut(kv, ":")
					switch strings.TrimSpace(k) {
					case "model_version":
						out.Model = cleanMeta(v)
					case "score_date":
						out.ScoreDate = cleanMeta(v)
					}
				}
			case strings.EqualFold(strings.ReplaceAll(line, " ", ""), "cve,epss,percentile"):
				header = true
				out.Scores = make([]EPSSAllScore, 0, 450_000) // the real file: about 406,000 rows
			case strings.TrimSpace(line) == "":
			default:
				return EPSSAllData{}, fail(ErrBadSample, `The EPSS file has no "cve,epss,percentile" header.`)
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		row++
		if row > epssAllMaxRows {
			return EPSSAllData{}, fail(ErrBadSample, "The EPSS file has more than %s rows; Vedette kept the scores it had.", grouped(epssAllMaxRows))
		}
		f := strings.Split(line, ",")
		if len(f) != 3 {
			tl.reject(row, "row has %s fields, not 3", strconv.Itoa(len(f)))
			continue
		}
		cve := strings.ToUpper(strings.TrimSpace(f[0]))
		score, ok1 := unitString(f[1])
		pct, ok2 := unitString(f[2])
		switch {
		case !cveRE.MatchString(cve) || len(cve) > 32:
			tl.reject(row, "cve: %s is not a CVE ID", quoteVal(f[0]))
		case !ok1:
			tl.reject(row, "epss: %s is not a number from 0 to 1", quoteVal(f[1]))
		case !ok2:
			tl.reject(row, "percentile: %s is not a number from 0 to 1", quoteVal(f[2]))
		default:
			tl.Accepted++
			out.Scores = append(out.Scores, EPSSAllScore{CVE: cve, Score: score, Pct: pct})
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return EPSSAllData{}, fail(ErrBadSample, "The EPSS file has a line longer than 4 KB.")
		}
		var fe *Error
		if errors.As(err, &fe) || errors.Is(err, ErrTooLarge) {
			return EPSSAllData{}, err
		}
		return EPSSAllData{}, fail(ErrBadSample, "The EPSS file is damaged or was cut off.")
	}
	if capped.N <= 0 {
		return EPSSAllData{}, fail(ErrTooLarge, "The EPSS file unpacks to more than %d MB; Vedette would skip it.", epssAllMaxUnpacked/1_000_000)
	}
	if !header {
		return EPSSAllData{}, fail(ErrBadSample, `The EPSS file has no "cve,epss,percentile" header.`)
	}
	out.Stats = tl.stats()
	return out, nil
}

func unitString(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if !epssNum.MatchString(s) {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil && f >= 0 && f <= 1
}

// cleanMeta keeps a value of the first line only when it is short printable ASCII (it ends up in the feed's status line).
func cleanMeta(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 40 || !printableASCII(v) {
		return ""
	}
	return v
}

// countReader counts the bytes read through it (the size of a streamed download).
type countReader struct {
	r io.Reader
	n int
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// buildEPSSAll downloads the daily file as a stream (conditional on the last good pull's validators, so an unchanged file
// is not downloaded again) and parses it whole before anything is written.
func (s *Service) buildEPSSAll(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	var (
		res  EPSSAllData
		read int
	)
	req := Request{URL: src.URL, MaxBytes: epssAllMaxBytes, Stream: func(r io.Reader) error {
		c := &countReader{r: r}
		var err error
		res, err = ParseEPSSCSV(c)
		read = c.n
		return err
	}}
	if src.Status == "ok" {
		req.ETag, req.LastModified = orEmpty(src.ETag), orEmpty(src.LastModified)
	}
	ctx, cancel := context.WithTimeout(ctx, epssAllTimeout)
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
	// A short file that parses (a proxy's page of a few rows, a cut mirror) must not replace every score (review r1 #7). The
	// yardstick is what the last good pull from this same address stored (review r2 #4), and a file is refused only below
	// half of it and below epssFloor, so one oversized file stored once never blocks the real one for good.
	base, err := s.st.epssBaseline(ctx, src.URL)
	if err != nil {
		return p, err
	}
	if n := len(res.Scores); base > 0 && 2*n < base && n < epssFloor {
		return p, fail(ErrBadSample, "The EPSS file has %s scores, fewer than half of the %s of the last good file; Vedette kept the scores it had. To take this file anyway, turn the feed off and on again.", grouped(n), grouped(base))
	}
	p.out = outcome{OK: true, Bytes: read, ETag: resp.ETag, LastModif: resp.LastModified}
	p.out.fill(res.Stats, len(res.Scores))
	// The file's score_date is FIRST's day for these scores (a calendar day, written as such): the note and the plan's "EPSS scores
	// of <day>" (TierStatus) name it, not the day the box downloaded the file.
	if len(res.ScoreDate) >= 10 {
		if d, err := time.Parse(time.DateOnly, res.ScoreDate[:10]); err == nil {
			p.epssDay = d.Format(time.DateOnly)
			line := fmt.Sprintf("FIRST's scores of %s for %s CVEs.", orgtime.CalendarDay(d), grouped(len(res.Scores)))
			p.out.Note = strings.TrimSpace(line + " " + p.out.Note)
		}
	}
	p.epssAll, p.hasEPSSAll = res.Scores, true
	return p, nil
}

// applyEPSSAll stores the scores of one complete file in chunks of epssChunkRows rows, each its own transaction (406,543
// rows held the writer about 0.4 s on a Mac in one transaction; the box is slower), under a new gen; the last transaction
// drops the rows of CVEs the file no longer lists and records the pull (finish). A feed edited or turned off meanwhile
// stops the writes (stale): the rows written so far are scores of the same day, and the next full pull settles the rest.
func applyEPSSAll(ctx context.Context, db *store.DB, now time.Time, src sourceRow, scores []EPSSAllScore, day string, finish func(tx *sql.Tx) error) (stale bool, err error) {
	live := func(tx *sql.Tx) (bool, error) {
		cur, err := sourceTx(ctx, tx, src.ID)
		if err != nil {
			return false, err
		}
		return cur.Rev == src.Rev && cur.Enabled, nil
	}
	var gen int64
	for i, chunk := 0, 0; chunk == 0 || i < len(scores); chunk++ { // chunk 0 always runs: it takes the gen
		end := min(i+epssChunkRows, len(scores))
		part := scores[i:end]
		err = db.Write(ctx, func(tx *sql.Tx) error {
			ok, err := live(tx)
			if err != nil || !ok {
				stale = !ok
				return err
			}
			if chunk == 0 {
				if err := tx.QueryRowContext(ctx, `SELECT coalesce(max(gen), 0) + 1 FROM feeds_epss`).Scan(&gen); err != nil {
					return fmt.Errorf("feeds: epss gen: %w", err)
				}
			}
			st, err := tx.PrepareContext(ctx, `INSERT INTO feeds_epss (cve, epss, percentile, gen) VALUES (?, ?, ?, ?)
ON CONFLICT(cve) DO UPDATE SET epss = excluded.epss, percentile = excluded.percentile, gen = excluded.gen`)
			if err != nil {
				return fmt.Errorf("feeds: store epss: %w", err)
			}
			defer func() { _ = st.Close() }()
			for _, sc := range part {
				if _, err := st.ExecContext(ctx, sc.CVE, sc.Score, sc.Pct, gen); err != nil {
					return fmt.Errorf("feeds: store epss: %w", err)
				}
			}
			return nil
		})
		if err != nil || stale {
			return stale, err
		}
		i = end
	}
	err = db.Write(ctx, func(tx *sql.Tx) error {
		ok, err := live(tx)
		if err != nil || !ok {
			stale = !ok
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_epss WHERE gen <> ?`, gen); err != nil {
			return fmt.Errorf("feeds: drop old epss: %w", err)
		}
		// the day's scores of the CVEs a list or a signal names, kept a few days for the "rising" display (epssHistKeep)
		hist := day
		if hist == "" {
			hist = now.UTC().Format(time.DateOnly)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_epss_hist (cve, day, epss) SELECT e.cve, ?, e.epss FROM feeds_epss e
WHERE e.cve IN (SELECT cve FROM feeds_kev UNION SELECT cve FROM feeds_signal)
ON CONFLICT(cve, day) DO UPDATE SET epss = excluded.epss`, hist); err != nil {
			return fmt.Errorf("feeds: epss history: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_epss_baseline (id, url, count, score_date) VALUES (1, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET url = excluded.url, count = excluded.count, score_date = excluded.score_date`, src.URL, len(scores), sql.NullString{String: day, Valid: day != ""}); err != nil {
			return fmt.Errorf("feeds: epss baseline: %w", err)
		}
		return finish(tx)
	})
	return stale, err
}
