package feeds

import (
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
)

func gz(t *testing.T, text string) string {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

const epssFile = "#model_version:v2026.06.15,score_date:2026-11-14T12:00:22Z\ncve,epss,percentile\n" +
	"CVE-1999-0001,0.04753,0.92024\nCVE-2026-1234,0.69289,0.99369\ncve-2025-0002,0.1,0.95\n" +
	"CVE-2025-x,0.1,0.5\nCVE-2025-0003,1.5,0.5\nCVE-2025-0004,0.2\n"

// D-614: the daily file of every score, gzip or plain: rows checked one by one (bad id, value outside 0..1, wrong field
// count rejected and counted), the model and the score date read from the first line.
func TestParseEPSSCSV(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{"gzip": gz(t, epssFile), "plain": epssFile} {
		d, err := ParseEPSSCSV(strings.NewReader(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d.Model != "v2026.06.15" || d.ScoreDate != "2026-11-14T12:00:22Z" || d.Accepted != 3 || d.Rejected != 3 || len(d.Scores) != 3 {
			t.Fatalf("%s: %+v", name, d)
		}
		if d.Scores[2] != (EPSSAllScore{CVE: "CVE-2025-0002", Score: 0.1, Pct: 0.95}) {
			t.Fatalf("%s: %+v", name, d.Scores[2])
		}
	}
	for name, in := range map[string]string{
		"no header":    "CVE-1999-0001,0.1,0.2\n",
		"broken gzip":  gz(t, epssFile)[:40],
		"empty":        "",
		"long line":    "cve,epss,percentile\n" + strings.Repeat("x", 5000) + "\n",
		"not the file": "<html>busy</html>\n",
	} {
		if _, err := ParseEPSSCSV(strings.NewReader(in)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// D-614: a pull stores every score; the next file replaces them and drops a CVE it no longer lists; an unchanged file
// (304) keeps them; the feed's line gives the score date and the count.
func TestEPSSAllPull_StoresEveryScoreAndDropsTheGoneOnes(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(epssAllFeedID)
	e.mirror(epssAllFeedID, o.url("/epss.csv.gz"))
	o.body("/epss.csv.gz", `"d1"`, gz(t, epssFile))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	f := e.feed(epssAllFeedID)
	if f.Status != "ok" || f.Records == nil || *f.Records != 3 || f.Error == nil || !strings.HasPrefix(*f.Error, "Scores of 2026-11-14 for 3 CVEs.") {
		t.Fatalf("feed = %+v %v", f, *f.Error)
	}
	if n := rowsOf(t, e.db, "feeds_epss"); n != 3 {
		t.Fatalf("%d scores", n)
	}
	o.body("/epss.csv.gz", `"d2"`, gz(t, "cve,epss,percentile\nCVE-1999-0001,0.5,0.97\nCVE-2026-1234,0.7,0.99\n"))
	e.setNow(e.clock().Add(25 * 3600e9))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	var score float64
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT epss FROM feeds_epss WHERE cve = 'CVE-1999-0001'`).Scan(&score); err != nil || score != 0.5 {
		t.Fatalf("score %v %v", score, err)
	}
	if n := rowsOf(t, e.db, "feeds_epss"); n != 2 {
		t.Fatalf("%d scores after a file without CVE-2025-0002", n)
	}
	e.setNow(e.clock().Add(25 * 3600e9))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	if n := rowsOf(t, e.db, "feeds_epss"); n != 2 || e.feed(epssAllFeedID).Status != "ok" {
		t.Fatalf("304: %d scores, %+v", n, e.feed(epssAllFeedID))
	}
}

// D-614, INV-3: a file Vedette cannot read fails the pull and keeps the scores stored before.
func TestEPSSAllPull_BadFileKeepsTheScores(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(epssAllFeedID)
	e.mirror(epssAllFeedID, o.url("/epss.csv.gz"))
	o.body("/epss.csv.gz", `"d1"`, gz(t, epssFile))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	o.body("/epss.csv.gz", `"d2"`, gz(t, epssFile)[:60])
	e.setNow(e.clock().Add(25 * 3600e9))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e.feed(epssAllFeedID); f.Status != "error" || rowsOf(t, e.db, "feeds_epss") != 3 {
		t.Fatalf("feed %+v, %d scores", f, rowsOf(t, e.db, "feeds_epss"))
	}
}

// Review r1 #7: a file that parses but holds fewer than half the scores on the box is refused; the scores stay.
func TestEPSSAllPull_ShortFileKeepsTheScores(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(epssAllFeedID)
	e.mirror(epssAllFeedID, o.url("/epss.csv.gz"))
	o.body("/epss.csv.gz", `"d1"`, gz(t, epssFile))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	o.body("/epss.csv.gz", `"d2"`, gz(t, "cve,epss,percentile\nCVE-1999-0001,0.5,0.97\n"))
	e.setNow(e.clock().Add(25 * 3600e9))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	f := e.feed(epssAllFeedID)
	if f.Status != "error" || f.Error == nil || !strings.Contains(*f.Error, "fewer than half of the 3") || rowsOf(t, e.db, "feeds_epss") != 3 {
		t.Fatalf("feed %+v, %d scores", f, rowsOf(t, e.db, "feeds_epss"))
	}
}

// Not parallel: it lowers package limits (parallel tests run after it). A file is stored over several chunks under one
// gen (the stale rows of an earlier gen go once, at the end), and the unpack and row caps fail the parse.
func TestEPSSAll_ChunksAndCaps(t *testing.T) {
	chunk, unpacked, rows := epssChunkRows, epssAllMaxUnpacked, epssAllMaxRows
	t.Cleanup(func() { epssChunkRows, epssAllMaxUnpacked, epssAllMaxRows = chunk, unpacked, rows })
	epssChunkRows = 1
	e, o := pullEnv(t)
	e.only(epssAllFeedID)
	e.mirror(epssAllFeedID, o.url("/epss.csv.gz"))
	o.body("/epss.csv.gz", `"d1"`, gz(t, epssFile))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	o.body("/epss.csv.gz", `"d2"`, gz(t, "cve,epss,percentile\nCVE-1999-0001,0.5,0.97\nCVE-2026-1234,0.7,0.99\n"))
	e.setNow(e.clock().Add(25 * 3600e9))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	var n, gens int
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT count(*), count(DISTINCT gen) FROM feeds_epss`).Scan(&n, &gens); err != nil || n != 2 || gens != 1 {
		t.Fatalf("%d rows in %d gens (%v)", n, gens, err)
	}
	floor := epssFloor
	t.Cleanup(func() { epssFloor = floor })
	epssFloor = 1 // a file of at least epssFloor scores is never short, whatever the yardstick
	o.body("/epss.csv.gz", `"d3"`, gz(t, "cve,epss,percentile\nCVE-1999-0001,0.5,0.97\n"))
	e.setNow(e.clock().Add(25 * 3600e9))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil || e.feed(epssAllFeedID).Status != "ok" {
		t.Fatalf("floor: %v %+v", err, e.feed(epssAllFeedID))
	}
	epssAllMaxRows = 2
	if _, err := ParseEPSSCSV(strings.NewReader(epssFile)); err == nil || !strings.Contains(err.Error(), "more than 2 rows") {
		t.Fatalf("row cap: %v", err)
	}
	epssAllMaxRows, epssAllMaxUnpacked = rows, 100
	if _, err := ParseEPSSCSV(strings.NewReader(gz(t, epssFile+strings.Repeat("CVE-2025-0005,0.1,0.5\n", 20)))); err == nil || !errors.Is(err, ErrTooLarge) {
		t.Fatalf("unpack cap: %v", err)
	}
}

// Review r2 #4: turning the feed off and on again, or a new address, drops the yardstick: the next file is taken as it is.
func TestEPSSAllPull_BaselineResets(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(epssAllFeedID)
	e.mirror(epssAllFeedID, o.url("/epss.csv.gz"))
	o.body("/epss.csv.gz", `"d1"`, gz(t, epssFile))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	short := gz(t, "cve,epss,percentile\nCVE-1999-0001,0.5,0.97\n")
	o.body("/epss.csv.gz", `"d2"`, short)
	e.setNow(e.clock().Add(25 * 3600e9))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	if e.feed(epssAllFeedID).Status != "error" {
		t.Fatal("short file taken")
	}
	e.put(epssAllFeedID, `{"enabled":false}`)
	e.put(epssAllFeedID, `{"enabled":true}`)
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e.feed(epssAllFeedID); f.Status != "ok" || rowsOf(t, e.db, "feeds_epss") != 1 {
		t.Fatalf("after off and on: %+v, %d scores", f, rowsOf(t, e.db, "feeds_epss"))
	}
	o.body("/other.csv.gz", `"o1"`, gz(t, epssFile))
	e.mirror(epssAllFeedID, o.url("/other.csv.gz"))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	o.body("/epss.csv.gz", `"d3"`, short)
	e.mirror(epssAllFeedID, o.url("/epss.csv.gz"))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e.feed(epssAllFeedID); f.Status != "ok" {
		t.Fatalf("after an address change the next file is taken: %+v", f)
	}
}
