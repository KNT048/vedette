package feeds

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
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
// creation time and stars). Facts only: no description, no exploit code.

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(filepath.Join("testdata", "publicexploit")), name)
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
		b := fixtureBytes(t, c.file)
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

// Count test: per source, the (CVE, date) pairs read from the frozen index, how many qualify, and the qualifying share of the CVEs
// first flagged in the window the measurement used (20 Nov 2025 to 19 Nov 2026): there, all public-exploit sources together flagged
// 5,370 CVEs and the quality rule kept 1,513 (28.2%), nuclei templates included, which this count cannot date (nuclei's index has no
// dates): without them, 4,775 and 1,174 (24.6%).
func TestPublicExploit_CountsOfTheFrozenIndexes(t *testing.T) {
	t.Parallel()
	want := map[string]struct{ pairs, qualifying, rejected int }{
		metasploitFeedID: {3_215, 3_215, 0},
		exploitDBFeedID:  {25_094, 25_094, 0},
		pocGitHubFeedID:  {11_875, 1_406, 0},
	}
	w0, w1 := time.Date(2025, 11, 20, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	anyFirst, qualFirst := map[string]time.Time{}, map[string]time.Time{}
	for id, idx := range frozenIndexes(t) {
		q := 0
		for _, g := range idx.Signals {
			ok, first := signalDate(id, g, heldSignal{}, false)
			if ok {
				q++
				qualFirst[g.CVE] = earliest(qualFirst[g.CVE], first)
			}
			anyFirst[g.CVE] = earliest(anyFirst[g.CVE], g.Date)
		}
		t.Logf("%s: %d (CVE, date) pairs, %d qualify, %d rows rejected", id, len(idx.Signals), q, idx.Rejected)
		if w := want[id]; len(idx.Signals) != w.pairs || q != w.qualifying || idx.Rejected != w.rejected {
			t.Errorf("%s: %d pairs, %d qualify, %d rejected; want %+v", id, len(idx.Signals), q, idx.Rejected, w)
		}
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
	all, kept := in(anyFirst), in(qualFirst)
	t.Logf("first flagged in the window: %d CVEs by any claim, %d by the quality rule (%.1f%%; the measurement: 5,370 and 1,513, 28.2%%)",
		all, kept, 100*float64(kept)/float64(all))
	if all != 4_775 || kept != 1_174 {
		t.Errorf("window: %d any, %d qualifying", all, kept)
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
	// the qualifying CVEs are kept at any age and their NVD records may be asked by ID (public lists the box downloads whole)
	var asked int
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM (`+publicListedSQL+`) WHERE cve = 'CVE-2026-123007'`).Scan(&asked); err != nil || asked != 1 {
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
