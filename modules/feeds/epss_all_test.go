package feeds

import (
	"bytes"
	"compress/gzip"
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
