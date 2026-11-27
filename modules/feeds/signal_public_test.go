package feeds

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

// The frozen indexes of testdata/publicexploit were read from the three public sources on 21 November 2026 and cut to the fields the
// decoders read (Metasploit: modules with a CVE reference, their full name, mod_time and references; Exploit-DB: rows with a CVE,
// their id, date_published and codes; PoC-in-GitHub: each CVE file's repositories that are not forks, with name, owner, address,
// creation time and stars). Facts only: no description, no exploit code. The Exploit-DB file keeps only the rows published from
// 20 November 2025 on (210 of 27,433); the whole index's numbers were measured outside the repository with the same count
// (publicIndexCounts on the downloaded file) and are in the comment of the count test.

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	return fixtureBytesIn(t, filepath.Join("testdata", "publicexploit"), name)
}

func fixtureBytesIn(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(dir), name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func gunzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// frozenIndexes parses the three frozen indexes.
func frozenIndexes(t *testing.T) map[string]publicIndex {
	t.Helper()
	return indexesIn(t, filepath.Join("testdata", "publicexploit"))
}

// indexesIn parses the three indexes of a folder laid out as testdata/publicexploit.
func indexesIn(t *testing.T, dir string) map[string]publicIndex {
	t.Helper()
	out := map[string]publicIndex{}
	for _, c := range []struct {
		id    string
		file  string
		parse func(io.Reader) (publicIndex, error)
		unzip bool
	}{
		{metasploitFeedID, "metasploit.json.gz", parseMetasploitModules, true},
		{exploitDBFeedID, "exploitdb.csv.gz", parseExploitDBIndex, true},
		{pocGitHubFeedID, "poc-in-github.tar.gz", parsePoCInGitHub, false}, // the archive is a tar.gz as the source serves it
	} {
		b := fixtureBytesIn(t, dir, c.file)
		if c.unzip {
			b = gunzipBytes(t, b)
		}
		idx, err := c.parse(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("%s: %v", c.id, err)
		}
		out[c.id] = idx
	}
	return out
}

// sourceCount is what the count test reads from one index.
type sourceCount struct{ pairs, qualifying, rejected int }

// publicIndexCounts is, per source, the (CVE, date) pairs, how many qualify and the rows rejected, and the CVEs first flagged in the
// window the earlier measurement used (20 Nov 2025 to 19 Nov 2026), by any claim and by the quality rule.
func publicIndexCounts(idxs map[string]publicIndex) (per map[string]sourceCount, all, kept int) {
	w0, w1 := time.Date(2025, 11, 20, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	anyFirst, qualFirst := map[string]time.Time{}, map[string]time.Time{}
	per = map[string]sourceCount{}
	for id, idx := range idxs {
		q := 0
		for _, g := range idx.Signals {
			ok, first := signalDate(id, g, heldSignal{}, false)
			if ok {
				q++
				qualFirst[g.CVE] = earliest(qualFirst[g.CVE], first)
			}
			anyFirst[g.CVE] = earliest(anyFirst[g.CVE], g.Date)
		}
		per[id] = sourceCount{len(idx.Signals), q, idx.Rejected}
	}
	in := func(m map[string]time.Time) int {
		n := 0
		for _, d := range m {
			if !d.Before(w0) && d.Before(w1) {
				n++
			}
		}
		return n
	}
	return per, in(anyFirst), in(qualFirst)
}

// Count test: per source, the (CVE, date) pairs read from the frozen index and how many qualify. The whole indexes of 21 Nov 2026 (the
// same count, publicIndexCounts, run outside the repository on the downloaded files) give Metasploit 3,215 (all qualify), Exploit-DB
// 25,094 (all qualify) and PoC-in-GitHub 11,875 (1,406 qualify); in the window of the earlier measurement, 4,775 CVEs first flagged by
// any claim and 1,174 by the quality rule (24.6%), where it found 5,370 and 1,513 (28.2%) with nuclei templates included, which this
// count cannot date. The window is a union over the whole indexes (an older entry anywhere moves a CVE's first day), so it is not
// asserted on the committed Exploit-DB sample, which holds only that index's rows from 20 Nov 2025 on.
func TestPublicExploit_CountsOfTheFrozenIndexes(t *testing.T) {
	t.Parallel()
	want := map[string]sourceCount{
		metasploitFeedID: {3_215, 3_215, 0},
		exploitDBFeedID:  {217, 217, 0},
		pocGitHubFeedID:  {11_875, 1_406, 0},
	}
	per, _, _ := publicIndexCounts(frozenIndexes(t))
	for id, c := range per {
		t.Logf("%s: %d (CVE, date) pairs, %d qualify, %d rows rejected", id, c.pairs, c.qualifying, c.rejected)
		if c != want[id] {
			t.Errorf("%s: %+v, want %+v", id, c, want[id])
		}
	}
}

// The sample CVEs of the measurement, from the frozen indexes through a real pull of each feed: the NGINX HTTP/2 flaw and Java4Shell
// qualify with the days the measurement found (a known author's repository on 18 Nov, the fifth author on 17 Nov); the Synology
// flaw, whose only proofs of concept have a handful of stars, does not.
func TestPublicExploit_SampleCVEsQualifyWithTheirDays(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(metasploitFeedID, exploitDBFeedID, pocGitHubFeedID)
	for _, f := range []struct{ id, path, file string }{
		{metasploitFeedID, "/msf.json", "metasploit.json.gz"},
		{exploitDBFeedID, "/edb.csv", "exploitdb.csv.gz"},
		{pocGitHubFeedID, "/poc.tar.gz", "poc-in-github.tar.gz"},
	} {
		b := fixtureBytes(t, f.file)
		if f.id != pocGitHubFeedID {
			b = gunzipBytes(t, b)
		}
		o.body(f.path, `"`+f.id+`"`, string(b))
		e.mirror(f.id, o.url(f.path))
		if err := e.svc.Fetch(t.Context(), f.id); err != nil {
			t.Fatal(err)
		}
		if st := e.feed(f.id); st.Status != "ok" {
			t.Fatalf("%s: %+v %q", f.id, st, deref(st.Error))
		}
	}
	rows, err := e.svc.st.Signals(t.Context(), []string{"CVE-2026-123007", "CVE-2026-114938", "CVE-2024-10441"})
	if err != nil {
		t.Fatal(err)
	}
	qualifying := func(cve string) (string, string) {
		for _, g := range rows[cve] {
			if g.Kind == SignalPublicExploit && g.Qualifies {
				return g.Source, g.FirstSeen.Format(time.DateOnly)
			}
		}
		return "", ""
	}
	if src, day := qualifying("CVE-2026-123007"); src != pocGitHubFeedID || day != "2026-11-18" {
		t.Errorf("CVE-2026-123007: %s %s; rows %+v", src, day, rows["CVE-2026-123007"])
	}
	if src, day := qualifying("CVE-2026-114938"); src != pocGitHubFeedID || day != "2026-11-17" {
		t.Errorf("CVE-2026-114938: %s %s; rows %+v", src, day, rows["CVE-2026-114938"])
	}
	if src, _ := qualifying("CVE-2024-10441"); src != "" {
		t.Errorf("CVE-2024-10441 qualifies by %s; rows %+v", src, rows["CVE-2024-10441"])
	}
	for _, g := range rows["CVE-2026-123007"] {
		if g.Source == pocGitHubFeedID && (g.URL != "https://github.com/sfewer-r7/CVE-2026-123007" || !strings.Contains(string(g.Detail), `"by":"sfewer-r7"`)) {
			t.Errorf("CVE-2026-123007 link %q detail %s", g.URL, g.Detail)
		}
	}
	// the qualifying CVEs the window keeps may have their NVD records asked by ID (public lists the box downloads whole)
	var asked int
	w := Window{Cutoff: e.clock().AddDate(0, 0, -windowDays)}
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM (`+w.publicListedSQL()+`) WHERE cve = 'CVE-2026-123007'`).Scan(&asked); err != nil || asked != 1 {
		t.Errorf("CVE-2026-123007 not among the publicly listed CVEs: %d %v", asked, err)
	}
}

// pocArchive is a PoC-in-GitHub archive of the given CVE files (path under the year folder → JSON).
func pocArchive(t testing.TB, files map[string]string) []byte {
	t.Helper()
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: "PoC-in-GitHub-master/" + n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(files[n])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(tb.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return gz.Bytes()
}

// repoJSON is one repository of a CVE file.
func repoJSON(owner, name, created string, stars int, fork bool) string {
	return fmt.Sprintf(`{"full_name":%q,"owner":{"login":%q},"html_url":"https://github.com/%s/%s","fork":%v,"created_at":%q,"stargazers_count":%d}`,
		owner+"/"+name, owner, owner, name, fork, created, stars)
}

func pocFile(repos ...string) string { return "[" + strings.Join(repos, ",") + "]" }

// The PoC quality rule and its dates across pulls: a claim that does not qualify keeps its first day; when stars come later the
// signal is dated from when the box last saw it without them, not from the repository's creation; a known author or the fifth author
// dates it by that repository's creation; a CVE the index drops loses its row.
func TestPoCInGitHub_QualityRuleAndDatesAcrossPulls(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(pocGitHubFeedID)
	e.mirror(pocGitHubFeedID, o.url("/poc.tar.gz"))
	day1 := time.Date(2026, 11, 10, 6, 0, 0, 0, time.UTC)
	e.setNow(day1)
	first := map[string]string{
		"2026/CVE-2026-0001.json": pocFile(repoJSON("alice", "poc", "2026-11-01T10:00:00Z", 3, false), repoJSON("bob", "poc", "2026-11-02T10:00:00Z", 0, false),
			repoJSON("eve", "poc-fork", "2026-10-01T10:00:00Z", 900, true)), // a fork counts for nothing
		"2026/CVE-2026-0002.json": pocFile(repoJSON("a1", "x", "2026-11-03T00:00:00Z", 0, false), repoJSON("a2", "x", "2026-11-04T00:00:00Z", 0, false),
			repoJSON("a3", "x", "2026-11-05T00:00:00Z", 0, false), repoJSON("a4", "x", "2026-11-06T00:00:00Z", 0, false), repoJSON("a5", "x", "2026-11-07T00:00:00Z", 0, false)),
		"2026/CVE-2026-0003.json": pocFile(repoJSON("someone", "x", "2026-11-01T00:00:00Z", 1, false), repoJSON("watchTowrLabs", "x", "2026-11-08T00:00:00Z", 2, false)),
		"2026/CVE-2026-0004.json": pocFile(repoJSON("carol", "x", "2026-11-01T00:00:00Z", 1, false)),
		"2026/CVE-2026-0005.json": pocFile(repoJSON("dave", "x", "2026-10-30T00:00:00Z", 120, false)),
		"2026/CVE-2026-0006.json": pocFile(repoJSON("mallory", "x", "2026-11-01T00:00:00Z", 1000, false)[:20]), // not JSON: rejected
		"README.md":               "# not a CVE file",
	}
	o.body("/poc.tar.gz", `"1"`, string(pocArchive(t, first)))
	if err := e.svc.Fetch(t.Context(), pocGitHubFeedID); err != nil {
		t.Fatal(err)
	}
	type row struct {
		first string
		q     bool
	}
	read := func() map[string]row {
		t.Helper()
		out := map[string]row{}
		rows, err := e.db.Reader().QueryContext(t.Context(), `SELECT cve, first_seen, qualifies FROM feeds_signal WHERE source = 'poc-in-github'`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var c, f string
			var q bool
			if err := rows.Scan(&c, &f, &q); err != nil {
				t.Fatal(err)
			}
			out[c] = row{f[:10], q}
		}
		return out
	}
	got := read()
	want := map[string]row{
		"CVE-2026-0001": {"2026-11-01", false}, // two authors, 3 stars: the claim's first day, not qualifying
		"CVE-2026-0002": {"2026-11-07", true},  // the fifth author
		"CVE-2026-0003": {"2026-11-08", true},  // a known author (logins compare in lower case)
		"CVE-2026-0004": {"2026-11-01", false},
		"CVE-2026-0005": {"2026-10-30", true}, // first seen with 120 stars: its creation, as on any first load
	}
	if !maps.Equal(got, want) {
		t.Fatalf("first pull: %+v", got)
	}
	if st := e.feed(pocGitHubFeedID); st.Records == nil || *st.Records != 5 {
		t.Errorf("feed after the first pull: %+v", st)
	}

	// a day later: CVE-2026-0001 has 60 stars now, CVE-2026-0004 is gone from the index
	e.setNow(day1.Add(24 * time.Hour))
	second := map[string]string{
		"2026/CVE-2026-0001.json": pocFile(repoJSON("alice", "poc", "2026-11-01T10:00:00Z", 60, false), repoJSON("bob", "poc", "2026-11-02T10:00:00Z", 0, false)),
		"2026/CVE-2026-0002.json": first["2026/CVE-2026-0002.json"],
		"2026/CVE-2026-0003.json": first["2026/CVE-2026-0003.json"],
		"2026/CVE-2026-0005.json": first["2026/CVE-2026-0005.json"],
	}
	o.body("/poc.tar.gz", `"2"`, string(pocArchive(t, second)))
	if err := e.svc.Fetch(t.Context(), pocGitHubFeedID); err != nil {
		t.Fatal(err)
	}
	got = read()
	want = map[string]row{
		"CVE-2026-0001": {"2026-11-10", true}, // stars came after the box last saw it without them (10 Nov), not on 1 Nov
		"CVE-2026-0002": {"2026-11-07", true},
		"CVE-2026-0003": {"2026-11-08", true},
		"CVE-2026-0005": {"2026-10-30", true},
	}
	if !maps.Equal(got, want) {
		t.Fatalf("second pull: %+v", got)
	}
}

// Metasploit and Exploit-DB always qualify; a CVE keeps its earliest date across pulls; an index cut to a fraction is refused and
// the signals stay; turning the feed off and on takes the next index as it is.
func TestExploitDB_EarliestDateAndShrinkGuard(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(exploitDBFeedID)
	e.mirror(exploitDBFeedID, o.url("/edb.csv"))
	var full strings.Builder
	full.WriteString("id,file,description,date_published,codes\n")
	for i := range 200 {
		fmt.Fprintf(&full, "%d,exploits/x/%d.txt,\"Product %d - Remote, \"\"quoted\"\" text\",2019-01-%02d,CVE-2019-%04d;OSVDB-%d\n", 1000+i, i, i, 1+i%28, i, i)
	}
	full.WriteString("5000,exploits/x/5000.txt,later entry of the same CVE,2020-05-05,CVE-2019-0000\n")
	full.WriteString("5001,exploits/x/5001.txt,no CVE,2020-05-05,OSVDB-1\n")
	full.WriteString("x5002,exploits/x/5002.txt,bad id,2020-05-05,CVE-2020-1234\n")
	full.WriteString("5003,exploits/x/5003.txt,bad day,05/05/2020,CVE-2020-1235\n")
	full.WriteString("2026,exploits/x/2026.txt,a future day,2027-01-01,CVE-2026-9999\n")
	o.body("/edb.csv", `"e1"`, full.String())
	if err := e.svc.Fetch(t.Context(), exploitDBFeedID); err != nil {
		t.Fatal(err)
	}
	st := e.feed(exploitDBFeedID)
	if st.Status != "ok" || st.Records == nil || *st.Records != 201 {
		t.Fatalf("feed %+v %q", st, deref(st.Error))
	}
	var first, url string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT first_seen, url FROM feeds_signal WHERE cve = 'CVE-2019-0000' AND source = 'exploit-db' AND qualifies = 1`).Scan(&first, &url); err != nil {
		t.Fatal(err)
	}
	if first[:10] != "2019-01-01" || url != "https://www.exploit-db.com/exploits/1000" {
		t.Errorf("CVE-2019-0000: %s %s", first, url)
	}
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT first_seen FROM feeds_signal WHERE cve = 'CVE-2026-9999'`).Scan(&first); err != nil || first != "2026-11-21T06:00:00.000Z" {
		t.Errorf("a future day is the pull's time: %s %v", first, err)
	}

	o.body("/edb.csv", `"e2"`, "id,date_published,codes\n1,2019-01-01,CVE-2019-0001\n")
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), exploitDBFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e.feed(exploitDBFeedID); f.Status != "error" || !strings.Contains(deref(f.Error), "fewer than half of the 201") {
		t.Fatalf("feed %+v %q", f, deref(f.Error))
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_signal WHERE source = 'exploit-db'`); n != 201 {
		t.Fatalf("%d signals kept", n)
	}
	for _, body := range []string{`{"enabled":false}`, `{"enabled":true}`} {
		if c, b := e.put(exploitDBFeedID, body); c != 200 {
			t.Fatalf("%s: %d %v", body, c, b)
		}
	}
	if err := e.svc.Fetch(t.Context(), exploitDBFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e.feed(exploitDBFeedID); f.Status != "ok" || count(t, e.db, `SELECT count(*) FROM feeds_signal WHERE source = 'exploit-db'`) != 1 {
		t.Fatalf("after off and on: %+v", f)
	}
}

func TestMetasploitModules_ShapesAndRejects(t *testing.T) {
	t.Parallel()
	good := `{"exploit_a":{"fullname":"exploit/linux/http/a","mod_time":"2026-11-18 10:00:00 +0000","references":["CVE-2026-1111","URL-https://example.com","cve-2026-2222","CVE-2026-1111"],"targets":null},
"aux_b":{"fullname":"auxiliary/scanner/b","mod_time":"2024-01-02 03:04:05 +0200","references":["CVE-2026-1111"]},
"no_cve":{"fullname":"post/x","mod_time":"bad","references":["OSVDB-1"]},
"bad_time":{"fullname":"exploit/x","mod_time":"yesterday","references":["CVE-2026-3333"]},
"bad_name":{"fullname":"exploit/../x","mod_time":"2024-01-02 03:04:05 +0000","references":["CVE-2026-4444"]},
"bad_type":{"fullname":"exploit/y","mod_time":"2024-01-02 03:04:05 +0000","references":"CVE-2026-5555"}}`
	idx, err := parseMetasploitModules(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	if idx.Accepted != 2 || idx.Rejected != 3 || len(idx.Signals) != 2 {
		t.Fatalf("%+v", idx)
	}
	a, b := idx.Signals[0], idx.Signals[1]
	if a.CVE != "CVE-2026-1111" || a.Date.Format(time.RFC3339) != "2024-01-02T01:04:05Z" || a.URL != "https://www.rapid7.com/db/modules/auxiliary/scanner/b/" || a.Detail != `{"modules":2}` {
		t.Errorf("%+v", a)
	}
	if b.CVE != "CVE-2026-2222" || b.URL != "https://www.rapid7.com/db/modules/exploit/linux/http/a/" {
		t.Errorf("%+v", b)
	}
	for _, bad := range []string{``, `[]`, `{"a":{}`, `{"a":{}} {}`, `{"a":{"fullname":`, `{"a":1}x`} {
		if _, err := parseMetasploitModules(strings.NewReader(bad)); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

func TestExploitDBIndex_HeaderIsRequired(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"", "id,date,codes\n1,2020-01-01,CVE-2020-1234\n", "\"unclosed\n"} {
		if _, err := parseExploitDBIndex(strings.NewReader(bad)); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
	idx, err := parseExploitDBIndex(strings.NewReader("\ufeffcodes,id,date_published\nCVE-2020-1234,7,2020-01-01\nshort\n"))
	if err != nil || len(idx.Signals) != 1 || idx.Signals[0].URL != "https://www.exploit-db.com/exploits/7" || idx.Rejected != 1 {
		t.Fatalf("%+v %v", idx, err)
	}
}

func TestPoCInGitHub_ArchiveShapes(t *testing.T) {
	t.Parallel()
	if _, err := parsePoCInGitHub(strings.NewReader("not gzip")); err == nil {
		t.Error("not gzip: accepted")
	}
	// a repository whose address is not its own name, or whose owner differs, or whose date is bad, is left out
	files := map[string]string{
		"2025/CVE-2025-0001.json": pocFile(
			`{"full_name":"a/x","owner":{"login":"a"},"html_url":"https://evil.example.com/a/x","fork":false,"created_at":"2025-01-01T00:00:00Z","stargazers_count":999}`,
			`{"full_name":"a/x","owner":{"login":"b"},"html_url":"https://github.com/a/x","fork":false,"created_at":"2025-01-01T00:00:00Z","stargazers_count":999}`,
			`{"full_name":"a/x","owner":{"login":"a"},"html_url":"https://github.com/a/x","fork":false,"created_at":"yesterday","stargazers_count":999}`),
		"2025/CVE-2025-0002.json": pocFile(repoJSON("a", "y", "2025-02-01T00:00:00Z", 1, false)),
		"2025/CVE-2025-0003.json": `{"not":"a list"}`,
		"2025/not-a-cve.json":     `[]`,
	}
	idx, err := parsePoCInGitHub(bytes.NewReader(pocArchive(t, files)))
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Signals) != 1 || idx.Signals[0].CVE != "CVE-2025-0002" || idx.Rejected != 1 || idx.Accepted != 1 {
		t.Fatalf("%+v", idx)
	}
	if g := idx.Signals[0]; g.Qualifies || g.Detail != `{"authors":1,"repos":1,"stars":1}` || g.URL != "https://github.com/a/y" {
		t.Errorf("%+v", g)
	}
}

// The known authors' file: lower case GitHub logins, sorted, no duplicate.
func TestExploitAuthors(t *testing.T) {
	t.Parallel()
	var f struct {
		Logins []string `json:"logins"`
	}
	if err := json.Unmarshal(catalogdata.ExploitAuthors, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Logins) < 10 || !slices.IsSorted(f.Logins) || len(slices.Compact(slices.Clone(f.Logins))) != len(f.Logins) {
		t.Fatalf("logins: %v", f.Logins)
	}
	for _, l := range f.Logins {
		if l != strings.ToLower(l) || !githubLoginRE.MatchString(l) {
			t.Errorf("login %q", l)
		}
	}
	if !exploitAuthors()["sfewer-r7"] {
		t.Error("sfewer-r7 is not a known author")
	}
}

// A signal source that names hundreds of older CVEs without a record: while that many are unread, the exploited lists' CVEs are asked
// for first, then the signalled ones as the backlog of the pull (recordsBacklog), each once; a few unread signalled CVEs are asked for
// by ID as before.
func TestCVERecordsByID_ManySignalledCVEsAfterTheExploitedLists(t *testing.T) {
	t.Parallel()
	signals := func(n int) []publicSignal {
		out := make([]publicSignal, n)
		for i := range out {
			out[i] = publicSignal{CVE: fmt.Sprintf("CVE-2015-%04d", 1000+i), Date: epoch0}
		}
		return out
	}
	e, o, _ := recordEnv(t, false)
	write(t, e.db, func(tx *sql.Tx) error {
		return applyPublicSignals(t.Context(), tx, epoch0, exploitDBFeedID, signals(recordRescanUnread))
	})
	for _, g := range signals(recordRescanUnread) {
		o.serve("/repo/cves/2015/1xxx/"+g.CVE+".json", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	}
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	hits := o.all()
	if len(hits) != recordRescanUnread+4 || o.count("/repo/cves/2024/3xxx/CVE-2024-3400.json") != 1 {
		t.Fatalf("%d asks; the exploited list's CVE asked %d times", len(hits), o.count("/repo/cves/2024/3xxx/CVE-2024-3400.json"))
	}
	for _, h := range hits[:4] {
		if strings.Contains(h.path, "CVE-2015-") {
			t.Fatalf("a signalled CVE before the exploited lists': %s", h.path)
		}
	}

	e2, o2, _ := recordEnv(t, false)
	write(t, e2.db, func(tx *sql.Tx) error {
		return applyPublicSignals(t.Context(), tx, epoch0, exploitDBFeedID, signals(5))
	})
	for _, g := range signals(5) {
		o2.serve("/repo/cves/2015/1xxx/"+g.CVE+".json", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	}
	if err := e2.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if n := o2.count("/repo/cves/2015/1xxx/CVE-2015-1004.json"); n != 1 {
		t.Fatalf("a few signalled CVEs are asked for by ID: %d", n)
	}
}

// Every entry of the PoC-in-GitHub archive counts toward its unpacked limit, the files it skips too.
func TestPoCInGitHub_SkippedEntriesCountTowardTheLimit(t *testing.T) { //nolint:paralleltest // changes pocMaxUnpacked
	was := pocMaxUnpacked
	t.Cleanup(func() { pocMaxUnpacked = was })
	pocMaxUnpacked = 1 << 10
	arch := pocArchive(t, map[string]string{"README.md": strings.Repeat("x", 2<<10), "2026/CVE-2026-0001.json": pocFile(repoJSON("a", "b", "2026-11-01T00:00:00Z", 1, false))})
	if _, err := parsePoCInGitHub(bytes.NewReader(arch)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a skipped entry over the limit: %v", err)
	}
}

// A download cut at the fetcher's size cap fails each decoder as too large (Fetch words it so), not as a bad index.
func TestPublicExploit_SizeCapIsTooLarge(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		parse func(io.Reader) (publicIndex, error)
		body  []byte
	}{
		"metasploit": {parseMetasploitModules, gunzipBytes(t, fixtureBytes(t, "metasploit.json.gz"))},
		"exploit-db": {parseExploitDBIndex, gunzipBytes(t, fixtureBytes(t, "exploitdb.csv.gz"))},
		"poc":        {parsePoCInGitHub, fixtureBytes(t, "poc-in-github.tar.gz")},
	} {
		if _, err := c.parse(newCapReader(bytes.NewReader(c.body), int64(len(c.body)/2))); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// An entry naming a flood of CVEs is rejected quickly (no quadratic de-duplication), and an index naming more CVEs than any real one
// fails.
func TestPublicExploit_EntryAndIndexCaps(t *testing.T) {
	t.Parallel()
	var codes strings.Builder
	for i := range 100_000 {
		if i > 0 {
			codes.WriteByte(';')
		}
		fmt.Fprintf(&codes, "CVE-2020-%06d", i)
	}
	start := time.Now()
	idx, err := parseExploitDBIndex(strings.NewReader("id,date_published,codes\n1,2020-01-01," + codes.String() + "\n2,2020-01-02,CVE-2020-1234;CVE-2020-1234\n"))
	if err != nil || len(idx.Signals) != 1 || idx.Rejected != 1 || idx.Accepted != 1 {
		t.Fatalf("%+v %v", idx.Stats, err)
	}
	if d := time.Since(start); d > 5*time.Second { // linear: milliseconds; the quadratic way took about 12 s
		t.Errorf("a 100,000-CVE row took %v", d)
	}
	refs := make([]string, maxCVEsPerEntry+1)
	for i := range refs {
		refs[i] = fmt.Sprintf("CVE-2020-%04d", 1000+i)
	}
	mod, _ := json.Marshal(map[string]any{"m": map[string]any{"fullname": "exploit/x/y", "mod_time": "2024-01-02 03:04:05 +0000", "references": refs}})
	if idx, err := parseMetasploitModules(bytes.NewReader(mod)); err != nil || idx.Rejected != 1 || len(idx.Signals) != 0 {
		t.Fatalf("a module over the cap: %+v %v", idx.Stats, err)
	}
	var many strings.Builder
	many.WriteString("id,date_published,codes\n")
	for i := range maxSignalsPerIndex + 1 {
		fmt.Fprintf(&many, "%d,2020-01-01,CVE-2020-%07d\n", i+1, i)
	}
	if _, err := parseExploitDBIndex(strings.NewReader(many.String())); err == nil || !strings.Contains(err.Error(), "more than 200,000 CVEs") {
		t.Fatalf("an index over the cap: %v", err)
	}
}

// The CVE records of signalled CVEs: an old signalled CVE without NVD ranges is not asked again every 12 hours (an exploited-list or a
// recent one is); the throttle counts only CVEs a public source names; a complete read of the whole list stamps the listed CVEs it did
// not hold, so they stop counting as unread.
func TestCVERecords_SignalledCVEsRecheckAndStamp(t *testing.T) {
	t.Parallel()
	e, o, _ := recordEnv(t, true)
	e.setNow(time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC))
	sigs := make([]publicSignal, recordRescanUnread)
	for i := range sigs {
		sigs[i] = publicSignal{CVE: fmt.Sprintf("CVE-2015-%04d", 1000+i), Date: epoch0}
	}
	write(t, e.db, func(tx *sql.Tx) error {
		if err := applyPublicSignals(t.Context(), tx, epoch0, exploitDBFeedID, sigs); err != nil {
			return err
		}
		// a custom list's unread CVEs never count toward the throttle
		if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_source (id, builtin, name, kind, format, url, parser, created_at)
VALUES ('cf-own', 0, 'Own list', 'vulnerabilities', 'json', 'https://feeds.example.com/x.json', '{}', '2026-11-05T00:00:00.000Z')`); err != nil {
			return err
		}
		for i := range 5 {
			c := fmt.Sprintf("CVE-2014-%04d", 1000+i)
			if err := ensureCVE(t.Context(), tx, c, "2026-11-05T00:00:00.000Z"); err != nil {
				return err
			}
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_kev (cve, list, source_id, vendor, product, name, date_added, updated_at)
VALUES (?, 'custom:cf-own', 'cf-own', 'Acme', 'Gateway', 'x', '2026-11-05', '2026-11-05T00:00:00.000Z')`, c); err != nil {
				return err
			}
		}
		return nil
	})
	if n, err := e.svc.st.recordUnread(t.Context(), Window{Cutoff: e.clock().AddDate(0, 0, -windowDays)}); err != nil || n != recordRescanUnread+4 { // the 4 CVEs of the CISA list and the signals
		t.Fatalf("unread = %d %v", n, err)
	}
	o.serve("/repo/releases/download/cve_2026-11-20_2300Z/2026-11-20_all_CVEs_at_midnight.zip.zip", func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "a.zip", time.Time{}, bytes.NewReader(dailyArchive(t, map[string][]byte{"cves/2024/3xxx/CVE-2024-3400.json": fixture(t, "cveorg/CVE-2024-3400.json")})))
	})
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil { // by ID only the CISA list's CVEs (a CVE-2015 ask hits an undeclared path)
		t.Fatal(err)
	}
	if cur, err := e.svc.st.nvdCursor(t.Context(), selectorRecord); err != nil || cur == nil || cur.Mode != modeDone {
		t.Fatalf("the whole list was not read: %+v %v", cur, err)
	}
	if n, err := e.svc.st.recordUnread(t.Context(), Window{Cutoff: e.clock().AddDate(0, 0, -windowDays)}); err != nil || n != 0 {
		t.Fatalf("after the whole list: %d unread %v", n, err)
	}
	// a day later: the CISA list's CVEs without NVD ranges are due again, the old signalled ones are not; a recent signalled one is
	write(t, e.db, func(tx *sql.Tx) error {
		if err := applyPublicSignals(t.Context(), tx, epoch0, pocGitHubFeedID, []publicSignal{{CVE: "CVE-2026-0950", Date: epoch0, Qualifies: true, Rule: epoch0}}); err != nil {
			return err
		}
		if err := ensureCVE(t.Context(), tx, "CVE-2026-0950", "2026-11-05T00:00:00.000Z"); err != nil {
			return err
		}
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_cve SET published = '2026-11-01T00:00:00.000Z', record_at = '2026-11-21T10:00:00.000Z' WHERE cve = 'CVE-2026-0950'`)
		return err
	})
	due, err := e.svc.st.recordDue(t.Context(), e.clock().Add(24*time.Hour), 1000)
	if err != nil || slices.ContainsFunc(due, func(c string) bool { return strings.HasPrefix(c, "CVE-2015-") }) || !slices.Contains(due, "CVE-2026-0950") ||
		!slices.Contains(due, "CVE-2024-3400") {
		t.Fatalf("due a day later: %v %v", due, err)
	}
}
