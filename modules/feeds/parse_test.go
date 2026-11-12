package feeds

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

func regexpMatch(pattern, s string) bool { return regexp.MustCompile(pattern).MatchString(s) }

var update = flag.Bool("update", false, "rewrite testdata/golden/*.json")

func sample(t testing.TB, kind Kind, format Format) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "samples", fmt.Sprintf("%s.%s", map[Kind]string{KindVulnerabilities: "vulnerabilities", KindIOC: "ioc"}[kind], format)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func run(t testing.TB, kind Kind, format Format) Result {
	t.Helper()
	r, err := ParseFeed(context.Background(), sample(t, kind, format), kind, DefaultParser(kind, format))
	if err != nil {
		t.Fatalf("ParseFeed(context.Background(), %s,%s): %v", kind, format, err)
	}
	return r
}

func reasonsOf(r Result) []string {
	var out []string
	for _, x := range r.Reasons {
		out = append(out, x.Reason)
	}
	return out
}

// ---------- the cases of parsers.test.ts, on the same samples (IMPACT.md: test chéo)

func TestCross_JSONPathSubset(t *testing.T) {
	t.Parallel()
	doc, err := decodeJSON(`{"a":[{"b":1},{"b":2}],"x-y":3}`)
	if err != nil {
		t.Fatal(err)
	}
	eval := func(path string) []string {
		toks, err := compilePath(path)
		if err != nil {
			t.Fatalf("compilePath(%q): %v", path, err)
		}
		var out []string
		for _, n := range evalPath(doc, toks) {
			out = append(out, jsString(n))
		}
		return out
	}
	if got := eval("$.a[*].b"); !reflect.DeepEqual(got, []string{"1", "2"}) {
		t.Errorf("$.a[*].b = %v", got)
	}
	if got := eval("$['x-y']"); !reflect.DeepEqual(got, []string{"3"}) {
		t.Errorf("$['x-y'] = %v", got)
	}
	if got := eval(`$["x-y"]`); !reflect.DeepEqual(got, []string{"3"}) {
		t.Errorf(`$["x-y"] = %v`, got)
	}
	if got := eval("$.a[1]"); !reflect.DeepEqual(got, []string{"[object Object]"}) {
		t.Errorf("$.a[1] = %v", got)
	}
	if got := eval("$.a[5]"); len(got) != 0 {
		t.Errorf("$.a[5] = %v", got)
	}
	if got := eval("$.a[99999999999999999999]"); len(got) != 0 {
		t.Errorf("huge index = %v", got)
	}
	if got := eval("$"); len(got) != 1 {
		t.Errorf("$ = %v", got)
	}
	for _, bad := range []string{"$..b", "a.b", "$.a[?(@.b>1)]", "$.a[-1]", "$.", "$[", "$.a b", "$.1x", "$.a[1:2]", "$." + strings.Repeat("a", MaxPathLen)} {
		if _, err := compilePath(bad); !errors.Is(err, ErrBadConfig) {
			t.Errorf("compilePath(%q) = %v, want ErrBadConfig", bad, err)
		}
	}
	if _, err := compilePath("a.b"); err == nil || !strings.Contains(err.Error(), "start with $") {
		t.Errorf("message: %v", err)
	}
}

func TestCross_JSONVulnerabilities(t *testing.T) {
	t.Parallel()
	r := run(t, KindVulnerabilities, FormatJSON)
	if r.Accepted != 3 || r.Rejected != 3 {
		t.Fatalf("accepted/rejected = %d/%d", r.Accepted, r.Rejected)
	}
	if r.Records[2]["cve"] != "CVE-2026-18002" {
		t.Errorf("cve not upper-cased: %v", r.Records[2]["cve"])
	}
	joined := strings.Join(reasonsOf(r), "|")
	if !regexpMatch(`not a CVE ID.*unrecognised date.*not an http\(s\) address`, joined) {
		t.Errorf("reasons: %s", joined)
	}
	want := []Reject{
		{4, `cve: "TBD" is not a CVE ID`},
		{5, `date: unrecognised date "31/13/2026"`},
		{6, "link: not an http(s) address"},
	}
	if !reflect.DeepEqual(r.Rejects, want) {
		t.Errorf("rejects = %+v", r.Rejects)
	}
	if r.Records[0]["date"] != "2026-11-03" || r.Records[0]["vendor"] != "Synology" || r.Truncated {
		t.Errorf("record 0 = %v", r.Records[0])
	}
}

func TestCross_CSV(t *testing.T) {
	t.Parallel()
	got := csvCells("# c\na,\"b,c\"\n1,\"x \"\"y\"\"\"\n", ',')
	if want := [][]string{{"a", "b,c"}, {"1", `x "y"`}}; !reflect.DeepEqual(got, want) {
		t.Errorf("parseCSV = %q", got)
	}
	r := run(t, KindVulnerabilities, FormatCSV)
	if r.Accepted != 3 || r.Rejected != 2 || r.Records[0]["date"] != "2026-11-03" {
		t.Errorf("csv: %d accepted, %d rejected, date %v", r.Accepted, r.Rejected, r.Records[0]["date"])
	}
	if r.Records[0]["description"] != "Authentication bypass, remote" {
		t.Errorf("quoted comma lost: %v", r.Records[0]["description"])
	}
}

func TestCross_RSS(t *testing.T) {
	t.Parallel()
	r := run(t, KindVulnerabilities, FormatRSS)
	if r.Accepted != 3 {
		t.Fatalf("accepted = %d", r.Accepted)
	}
	var cves []string
	for _, rec := range r.Records {
		cves = append(cves, rec["cve"].(string))
	}
	if want := []string{"CVE-2026-20311", "CVE-2026-19844", "CVE-2026-18002"}; !reflect.DeepEqual(cves, want) {
		t.Errorf("cves = %v", cves)
	}
	if r.Records[0]["date"] != "2026-11-03" || r.Reasons[0].Reason != "cve: regex did not match" {
		t.Errorf("date %v, reasons %v", r.Records[0]["date"], r.Reasons)
	}
	if r.Records[0]["link"] != "https://advisories.example.com/sa-26-11" || r.Records[0]["product"] != "DiskStation Manager" {
		t.Errorf("record 0 = %v", r.Records[0])
	}
}

func TestCross_AtomIOC(t *testing.T) {
	t.Parallel()
	r := run(t, KindIOC, FormatRSS)
	// "Weekly summary" is not a valid indicator; the two hosts are.
	if r.Accepted != 2 || r.Rejected != 1 || r.Records[0]["indicator"] != "update-dsm-synology.com" || r.Records[0]["kind"] != "domain" || r.Records[0]["first_seen"] != "2026-10-29" {
		t.Errorf("atom: %+v %v", r.Stats, r.Records)
	}
}

func TestCross_STIX(t *testing.T) {
	t.Parallel()
	r := run(t, KindIOC, FormatSTIX)
	var got []string
	for _, rec := range r.Records {
		got = append(got, fmt.Sprintf("%v:%s", rec["kind"], jsSlice(rec["indicator"].(string), 14)))
	}
	want := []string{"ip:185.220.101.47", "domain:update-dsm-syn", "ip:45.148.10.95", "ip:103.75.190.12", "hash:a3f5c1d9e8b7a6"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("records = %v", got)
	}
	if r.Records[0]["confidence"] != 0.85 || r.Records[2]["confidence"] != 0.6 || r.Records[4]["confidence"] != nil {
		t.Errorf("confidence: %v %v %v", r.Records[0]["confidence"], r.Records[2]["confidence"], r.Records[4]["confidence"])
	}
	if r.Rejected != 2 {
		t.Errorf("rejected = %d", r.Rejected)
	}
	found := false
	for _, x := range reasonsOf(r) {
		found = found || strings.HasPrefix(x, "unsupported pattern object")
	}
	if !found {
		t.Errorf("reasons = %v", reasonsOf(r))
	}
}

func TestCross_Lines(t *testing.T) {
	t.Parallel()
	r := run(t, KindIOC, FormatLines)
	// The TS sample lists 198.51.100.23 (a documentation address): the Go side refuses it (INV-12), so 3 of 4.
	if r.Accepted != 3 || r.Rejected != 2 {
		t.Fatalf("lines: %+v", r.Stats)
	}
	for _, rec := range r.Records {
		if rec["kind"] != "ip" {
			t.Errorf("kind = %v", rec["kind"])
		}
	}
	// Plain list: the reject names the line of the sample (two comments and a blank line before it).
	if r.Rejects[0].Row != 7 || r.Records[1]["indicator"] != "45.148.10.95" {
		t.Errorf("rejects %v, records %v", r.Rejects, r.Records)
	}
}

// Walk 2 (S-FEED-5): a pasted plain list names the rejected lines, with the value, and a
// reserved test name is not called a local host; the grouped reasons stay masked.
func TestWalk2_LinesRejectsNameTheLineAndValue(t *testing.T) {
	t.Parallel()
	text := "# partner list\n203.0.113.9\nbad.example.com extra words\nhttp://evil.example/x\nnot an ip!!\n10.0.0.1\n44d88612fea8a8f36de82e1278abb02f\n"
	r, err := ParseFeed(context.Background(), []byte(text), KindIOC, DefaultParser(KindIOC, FormatLines))
	if err != nil {
		t.Fatal(err)
	}
	want := []Reject{
		{2, `indicator: "203.0.113.9" is a private, reserved or special-purpose address`},
		{4, `indicator: "http://evil.example/x" points at a reserved example or test name`},
		{5, `indicator: "not" is not a valid indicator`},
		{6, `indicator: "10.0.0.1" is a private, reserved or special-purpose address`},
	}
	if !reflect.DeepEqual(r.Rejects, want) || r.Accepted != 2 {
		t.Errorf("accepted %d, rejects %+v", r.Accepted, r.Rejects)
	}
	for _, x := range r.Reasons {
		if strings.Contains(x.Reason, "evil") || strings.Contains(x.Reason, "10.0.0.1") {
			t.Errorf("grouped reason shows a value: %q", x.Reason)
		}
	}
}

func TestWalk2_URLHostReasons(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"http://evil.example/x":      "%s points at a reserved example or test name",
		"https://a.test/":            "%s points at a reserved example or test name",
		"http://x.invalid/":          "%s points at a reserved example or test name",
		"http://nas.local/":          "%s points at a local or private host",
		"http://intranet/":           "%s points at a local or private host",
		"http://10.1.2.3/":           "%s points at a private, reserved or special-purpose address",
		"http://[::1]/":              "%s points at a private, reserved or special-purpose address",
		"https://evil.example.com/x": "",
	} {
		if _, why := normaliseIOC("url", in); why.tmpl != want {
			t.Errorf("%s: %q, want %q", in, why.tmpl, want)
		}
	}
}

func TestCross_JSONIOC(t *testing.T) {
	t.Parallel()
	r := run(t, KindIOC, FormatJSON)
	var kinds []any
	for _, rec := range r.Records {
		kinds = append(kinds, rec["kind"])
	}
	if want := []any{"ip", "domain", "url", "hash"}; !reflect.DeepEqual(kinds, want) {
		t.Errorf("kinds = %v", kinds)
	}
	if r.Records[0]["confidence"] != 0.92 || r.Rejected != 3 {
		t.Errorf("confidence %v, rejected %d", r.Records[0]["confidence"], r.Rejected)
	}
	if r.Records[0]["first_seen"] != "2026-09-12" {
		t.Errorf("first_seen = %v", r.Records[0]["first_seen"])
	}
}

func TestCross_SampleCSVIOC(t *testing.T) {
	t.Parallel()
	r := run(t, KindIOC, FormatCSV)
	// 203.0.113.77 and 198.51.100.23 are documentation addresses: refused here, accepted by the TS sample run.
	if r.Accepted != 2 || r.Rejected != 3 || r.Records[0]["indicator"] != "45.148.10.95" || r.Records[0]["first_seen"] != "2026-10-02" {
		t.Errorf("csv ioc: %+v %v", r.Stats, r.Records[0])
	}
}

func TestContract_INV3_FailsClosedOnBadInput(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindIOC, FormatLines)
	if _, err := ParseFeed(context.Background(), []byte(strings.Repeat("x", MaxBodyBytes+1)), KindIOC, p); !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "larger than 5 MB") {
		t.Errorf("too large: %v", err)
	}
	if _, err := ParseFeed(context.Background(), make([]byte, MaxBodyBytes), KindIOC, p); errors.Is(err, ErrTooLarge) {
		t.Errorf("exactly the limit must be accepted: %v", err)
	}
	if _, err := ParseFeed(context.Background(), []byte("{nope"), KindIOC, DefaultParser(KindIOC, FormatJSON)); !errors.Is(err, ErrBadSample) || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("bad json: %v", err)
	}
	p.Fields["indicator"] = FieldMap{Regex: "([", Trim: true, DateFormat: DateAuto}
	if _, err := ParseFeed(context.Background(), []byte("1.2.3.4"), KindIOC, p); !errors.Is(err, ErrBadConfig) || !strings.Contains(err.Error(), "Invalid regular expression") {
		t.Errorf("bad regex: %v", err)
	}
}

func TestContract_INV2_RowLimitTruncates(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := 0; i < MaxRows+10; i++ {
		fmt.Fprintf(&b, "45.%d.%d.%d\n", (i>>16)&255, (i>>8)&255, i&255)
	}
	for _, f := range []Format{FormatLines, FormatCSV} {
		p := DefaultParser(KindIOC, f)
		p.HasHeader = false
		p.Fields["indicator"] = fm("1")
		text := b.String()
		if f == FormatLines {
			p.Fields["indicator"] = fm("")
		}
		r, err := ParseFeed(context.Background(), []byte(text), KindIOC, p)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Truncated || r.Accepted != MaxRows || len(r.Records) != MaxRows {
			t.Errorf("%s: truncated=%v accepted=%d records=%d", f, r.Truncated, r.Accepted, len(r.Records))
		}
	}
	// Exactly MaxRows is not truncated.
	exact := strings.Join(strings.Fields(strings.Repeat("1.2.3.4 ", MaxRows)), "\n")
	r, err := ParseFeed(context.Background(), []byte(exact), KindIOC, DefaultParser(KindIOC, FormatLines))
	if err != nil || r.Truncated || r.Accepted != MaxRows {
		t.Errorf("exact: %v truncated=%v accepted=%d", err, r.Truncated, r.Accepted)
	}
}

func TestContract_INV3_NoHalfAcceptedRow(t *testing.T) {
	t.Parallel()
	// The second row has a good CVE and a bad date: the whole row must go, not just the date.
	csv := "cve,vendor,product,published,summary,url\nCVE-2026-1111,A,B,01/02/2026,ok,\nCVE-2026-2222,A,B,garbage,half,https://x.example\n"
	r, err := ParseFeed(context.Background(), []byte(csv), KindVulnerabilities, DefaultParser(KindVulnerabilities, FormatCSV))
	if err != nil {
		t.Fatal(err)
	}
	if r.Accepted != 1 || r.Rejected != 1 || len(r.Records) != 1 || r.Records[0]["cve"] != "CVE-2026-1111" {
		t.Fatalf("%+v %v", r.Stats, r.Records)
	}
	if r.Accepted != len(r.Records) {
		t.Fatal("accepted must equal the number of records")
	}
}

func TestContract_INV3_RejectListIsBounded(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("not-an-ioc\n", 30) + "1.2.3.4\n"
	r, _ := ParseFeed(context.Background(), []byte(text), KindIOC, DefaultParser(KindIOC, FormatLines))
	if r.Rejected != 30 || len(r.Rejects) != MaxRejects || r.Rejects[19].Row != 20 || r.Accepted != 1 {
		t.Errorf("%+v", r.Stats)
	}
	if len(r.Reasons) != 1 || r.Reasons[0].Count != 30 || r.Reasons[0].Reason != `indicator: "…" is not a valid indicator` {
		t.Errorf("reasons = %+v", r.Reasons)
	}
	if got := r.Preview(); len(got.Records) != 1 {
		t.Errorf("preview = %d", len(got.Records))
	}
}

func TestPreviewKeepsFirstTwentyRecords(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("1.2.3.4\n", 25)
	r, _ := ParseFeed(context.Background(), []byte(text), KindIOC, DefaultParser(KindIOC, FormatLines))
	if r.Accepted != 25 || len(r.Records) != 25 || len(r.Preview().Records) != PreviewRows {
		t.Errorf("%d %d %d", r.Accepted, len(r.Records), len(r.Preview().Records))
	}
}

func TestNormDate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		f    DateFormat
		want string
	}{
		{"03/11/2026", DateDMY, "2026-11-03"},
		{"11/03/2026", DateMDY, "2026-11-03"},
		{"3.11.2026", DateDMY, "2026-11-03"},
		{"1793700000", DateEpoch, "2026-11-03"},
		{"1793700000000", DateEpoch, "2026-11-03"},
		{"Mon, 03 Nov 2026 09:00:00 GMT", DateAuto, "2026-11-03"},
		{"Mon, 03 Nov 2026 23:30:00 -0500", DateAuto, "2026-11-04"},
		{"03 Nov 2026", DateAuto, "2026-11-03"},
		{"Nov 3, 2026", DateAuto, "2026-11-03"},
		{"2026-11-03", DateAuto, "2026-11-03"},
		{"2026-11-03T10:00:00Z", DateAuto, "2026-11-03"},
		{"2026-11-03 10:22:01", "", "2026-11-03"},
		{"31/13/2026", DateDMY, ""},
		{"30/02/2026", DateDMY, ""},
		{"2026-02-30", DateAuto, ""},
		{"0050-01-01", DateAuto, ""},
		{"2026/11/03", DateAuto, ""},
		{"12345", DateEpoch, ""},
		{"1793700000", DateAuto, ""},
		{"yesterday", DateAuto, ""},
		{"", DateAuto, ""},
	}
	for _, c := range cases {
		got, ok := normDate(c.in, c.f)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("normDate(%q,%q) = %q,%v want %q", c.in, c.f, got, ok, c.want)
		}
	}
}

// ---------- behaviour specific to the Go side

func TestOutputShapeMatchesApiResult(t *testing.T) {
	t.Parallel()
	r := run(t, KindIOC, FormatLines).Preview()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"records", "accepted", "rejected", "reasons", "rejects", "truncated"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in %s", k, b)
		}
	}
	empty, _ := ParseFeed(context.Background(), []byte(""), KindIOC, DefaultParser(KindIOC, FormatLines))
	eb, _ := json.Marshal(empty)
	if !strings.Contains(string(eb), `"records":[]`) || !strings.Contains(string(eb), `"reasons":[]`) || !strings.Contains(string(eb), `"rejects":[]`) {
		t.Errorf("empty slices must encode as []: %s", eb)
	}
}

func TestGoldenOutputs(t *testing.T) {
	t.Parallel()
	for _, k := range []Kind{KindVulnerabilities, KindIOC} {
		for _, f := range FormatsFor(k) {
			name := fmt.Sprintf("%s.%s.json", k, f)
			b, err := json.MarshalIndent(run(t, k, f).Preview(), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			b = append(b, '\n')
			path := filepath.Join("testdata", "golden", name)
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path) //nolint:gosec // path built from fixed kinds and formats
			if err != nil {
				t.Fatalf("%v (run go test -run Golden -update)", err)
			}
			if string(want) != string(b) {
				t.Errorf("%s differs from golden", name)
			}
		}
	}
}

func TestParseRejectsMismatchedFormatAndConfig(t *testing.T) {
	t.Parallel()
	bad := map[string]func(p *Parser){
		"stix for vulns":        func(p *Parser) { p.Format = FormatSTIX },
		"unknown format":        func(p *Parser) { p.Format = "xml" },
		"bad records path":      func(p *Parser) { p.RecordsPath = "$..x" },
		"bad field path":        func(p *Parser) { p.Fields["cve"] = fm("$.a[") },
		"long regex":            func(p *Parser) { f := fm("$.cveID"); f.Regex = strings.Repeat("a", MaxRegexLen+1); p.Fields["cve"] = f },
		"re2 unsupported":       func(p *Parser) { f := fm("$.cveID"); f.Regex = `(?=x)a`; p.Fields["cve"] = f },
		"backreference":         func(p *Parser) { f := fm("$.cveID"); f.Regex = `(a)\1`; p.Fields["cve"] = f },
		"unknown field":         func(p *Parser) { p.Fields["evil"] = fm("$.x") },
		"required unmapped":     func(p *Parser) { p.Fields["cve"] = fm("  ") },
		"required missing":      func(p *Parser) { delete(p.Fields, "cve") },
		"bad date format":       func(p *Parser) { f := fm("$.dateAdded"); f.DateFormat = "ymd"; p.Fields["date"] = f },
		"source too long":       func(p *Parser) { p.Fields["vendor"] = fm("$." + strings.Repeat("a", MaxPathLen)) },
		"records path too long": func(p *Parser) { p.RecordsPath = "$." + strings.Repeat("a", MaxPathLen) },
	}
	for name, mut := range bad {
		t.Run(name, func(t *testing.T) {
			p := DefaultParser(KindVulnerabilities, FormatJSON)
			mut(&p)
			if err := CheckParser(KindVulnerabilities, p); !errors.Is(err, ErrBadConfig) {
				t.Fatalf("CheckParser = %v", err)
			}
			if _, err := ParseFeed(context.Background(), []byte(`{}`), KindVulnerabilities, p); !errors.Is(err, ErrBadConfig) {
				t.Fatalf("ParseFeed = %v", err)
			}
		})
	}
	for _, d := range []string{`"`, "\n", "ab", "\xff"} {
		p := DefaultParser(KindIOC, FormatCSV)
		p.Delimiter = d
		if err := CheckParser(KindIOC, p); !errors.Is(err, ErrBadConfig) {
			t.Errorf("delimiter %q accepted", d)
		}
	}
	p := DefaultParser(KindIOC, FormatCSV)
	p.Delimiter = ";"
	if err := CheckParser(KindIOC, p); err != nil {
		t.Errorf("semicolon: %v", err)
	}
	p.Delimiter = "§"
	if err := CheckParser(KindIOC, p); err != nil {
		t.Errorf("non-ASCII single character: %v", err)
	}
	for _, s := range BuiltinSources() {
		if s.Parser != nil {
			if err := CheckParser(s.Kind, *s.Parser); err != nil {
				t.Errorf("built-in %s: %v", s.ID, err)
			}
		}
	}
}

func TestParseEmptyRecordsPathDefaultsToRootArray(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindIOC, FormatJSON)
	p.RecordsPath = ""
	p.Fields["indicator"] = fm("$.ioc")
	r, err := ParseFeed(context.Background(), []byte(`[{"ioc":"1.2.3.4"},{"ioc":"example.com"},{"nope":1}]`), KindIOC, p)
	if err != nil || r.Accepted != 2 || r.Rejected != 1 || r.Reasons[0].Reason != "indicator: missing" {
		t.Fatalf("%v %+v", err, r.Stats)
	}
}

func TestJSONValueConversion(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindIOC, FormatJSON)
	p.RecordsPath = "$.d[*]"
	p.Fields["indicator"] = fm("$.i")
	p.Fields["confidence"] = fm("$.c")
	text := `{"d":[
	 {"i":"1.1.1.1","c":0.5},
	 {"i":"1.1.1.2","c":1},
	 {"i":"1.1.1.3","c":100},
	 {"i":"1.1.1.4","c":101},
	 {"i":"1.1.1.5","c":-1},
	 {"i":"1.1.1.6","c":"0x1A"},
	 {"i":"1.1.1.7","c":"1e1"},
	 {"i":"1.1.1.8","c":"abc"},
	 {"i":"1.1.1.9","c":null},
	 {"i":"1.1.1.10","c":true},
	 {"i":["1.1.1.11"],"c":[5]},
	 {"i":{"x":1}},
	 {"i":[["a"]]},
	 {"i":12},
	 {"i":"1.1.1.12","c":0.005},
	 {"i":"1.1.1.13","c":1e999}
	]}`
	r, err := ParseFeed(context.Background(), []byte(text), KindIOC, p)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, rec := range r.Records {
		got = append(got, fmt.Sprintf("%v=%v", rec["indicator"], rec["confidence"]))
	}
	want := []string{"1.1.1.1=0.5", "1.1.1.2=1", "1.1.1.3=1", "1.1.1.6=0.26", "1.1.1.7=0.1", "1.1.1.9=<nil>", "1.1.1.11=0.05", "1.1.1.12=0.01"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("records:\n got %v\nwant %v", got, want)
	}
	reasons := strings.Join(reasonsOf(r), "|")
	for _, s := range []string{"is not a number from 0 to 100", "value is an object, not text"} {
		if !strings.Contains(reasons, s) {
			t.Errorf("reasons %q lack %q", reasons, s)
		}
	}
}

func TestJSONStarOnObjectKeepsJSOrder(t *testing.T) {
	t.Parallel()
	doc, _ := decodeJSON(`{"b":"B","2":"two","a":"A","1":"one"}`)
	toks, _ := compilePath("$.*")
	var got []string
	for _, n := range evalPath(doc, toks) {
		got = append(got, n.s)
	}
	if want := []string{"one", "two", "B", "A"}; !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v", got)
	}
	dup, _ := decodeJSON(`{"k":"first","k":"second"}`)
	if v, _ := dup.get("k"); v.s != "second" {
		t.Errorf("last duplicate must win, got %q", v.s)
	}
}

func TestJSONNumberStrings(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"92": "92", "0.92": "0.92", "1e21": "1e+21", "1e20": "100000000000000000000", "1.5e-7": "1.5e-7", "0.000001": "0.000001",
		"-0": "0", "123456789012345680000": "123456789012345680000", "0.1": "0.1", "-2.5": "-2.5", "1e999": "Infinity",
	} {
		doc, err := decodeJSON(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := jsString(doc); got != want {
			t.Errorf("String(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestJSONRejectsMalformedAndDeep(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindIOC, FormatJSON)
	for _, s := range []string{"", "{", `{"data":[1,]}`, `{"a" 1}`, `[1] x`, `{"a":1}{"b":2}`, "nul", `{'a':1}`} {
		if _, err := ParseFeed(context.Background(), []byte(s), KindIOC, p); !errors.Is(err, ErrBadSample) {
			t.Errorf("%q: %v", s, err)
		}
	}
	deep := strings.Repeat("[", 5000) + strings.Repeat("]", 5000)
	if _, err := ParseFeed(context.Background(), []byte(deep), KindIOC, p); !errors.Is(err, ErrBadSample) || !strings.Contains(err.Error(), "too deeply") {
		t.Errorf("deep nesting: %v", err)
	}
	if _, err := ParseFeed(context.Background(), []byte(strings.Repeat(`{"a":`, maxJSONDepth+2)+"1"+strings.Repeat("}", maxJSONDepth+2)), KindIOC, p); !errors.Is(err, ErrBadSample) {
		t.Errorf("just over the depth limit accepted: %v", err)
	}
}

func TestEncodingAndControlCharacters(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindIOC, FormatLines)
	r, err := ParseFeed(context.Background(), []byte("\xef\xbb\xbf1.2.3.4\n\xff\xfe9.9.9.9\nbad\x00.example.com\nexample\xc3.com\nok.example.com\n"), KindIOC, p)
	if err != nil {
		t.Fatal(err)
	}
	var got []any
	for _, rec := range r.Records {
		got = append(got, rec["indicator"])
	}
	if !reflect.DeepEqual(got, []any{"1.2.3.4", "ok.example.com"}) || r.Rejected != 3 {
		t.Errorf("records %v, stats %+v", got, r.Stats)
	}
	for _, rec := range r.Records {
		for _, v := range rec {
			if s, ok := v.(string); ok && !utf8.ValidString(s) {
				t.Errorf("invalid UTF-8 survived: %q", s)
			}
		}
	}
	// A control character inside a free-text field rejects the row.
	vp := DefaultParser(KindVulnerabilities, FormatCSV)
	vr, _ := ParseFeed(context.Background(), []byte("cve,vendor,product,published,summary,url\nCVE-2026-1,A,B,01/02/2026,ok,\nCVE-2026-1234,A\x07,B,01/02/2026,ok,\n"), KindVulnerabilities, vp)
	if vr.Accepted != 0 || vr.Rejected != 2 {
		t.Errorf("vuln: %+v", vr.Stats)
	}
}

func TestIndicatorNormalisation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, kindField string
		want          string // "kind:value" or "" for rejected
	}{
		{"1.2.3.4", "", "ip:1.2.3.4"},
		{"1.2.3.4:8080", "ip", "ip:1.2.3.4"},
		{"1.2.3.4:8080", "", ""},
		{"2606:4700:0:0:0:0:0:1111", "", "ip:2606:4700::1111"},
		{"::ffff:1.2.3.4", "", "ip:1.2.3.4"},
		{"fe80::1%eth0", "ip", ""},
		{"01.2.3.4", "", ""},
		{"256.1.1.1", "", ""},
		{"dead:beef", "", ""},
		{"::::", "", ""},
		{"Example.COM", "", "domain:example.com"},
		{"-bad.example.com", "", ""},
		{"example.com.", "", ""},
		{"examKple.com", "", ""}, // Kelvin sign must not fold into ASCII k
		{"a.b", "", ""},
		{strings.Repeat("a", 64) + ".com", "", ""},
		{"HTTPS://Evil.example.com/Path?x=1", "", "url:HTTPS://Evil.example.com/Path?x=1"},
		{"http://", "url", ""},
		{"http:///x", "url", ""},
		{"http://a b.example/", "url", ""},
		{"ftp://example.com/x", "url", ""},
		{"44D88612FEA8A8F36DE82E1278ABB02F", "", "hash:44d88612fea8a8f36de82e1278abb02f"},
		{"44d88612fea8a8f36de82e1278abb02", "hash", ""},
		{"example.com", "ip", ""},
		{"1.2.3.4", "domain", ""},
	}
	p := DefaultParser(KindIOC, FormatJSON)
	p.RecordsPath = "$[*]"
	p.Fields["indicator"] = fm("$.i")
	p.Fields["kind"] = fm("$.k")
	for _, c := range cases {
		in, _ := json.Marshal(map[string]string{"i": c.in, "k": c.kindField})
		r, err := ParseFeed(context.Background(), []byte("["+string(in)+"]"), KindIOC, p)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if len(r.Records) == 1 {
			got = fmt.Sprintf("%v:%v", r.Records[0]["kind"], r.Records[0]["indicator"])
		}
		if got != c.want {
			t.Errorf("%q (kind %q) = %q, want %q (%v)", c.in, c.kindField, got, c.want, r.Reasons)
		}
	}
}

func TestVulnerabilityFieldRules(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindVulnerabilities, FormatCSV)
	long := strings.Repeat("é", 600)
	text := "cve,vendor,product,published,summary,url\n" +
		"cve-2026-0001,  Spaced ,B,01/02/2026," + long + ",HTTP://ok.example/x\n" +
		"CVE-2026-001,A,B,01/02/2026,x,\n" +
		"CVE-2026-0002,A,B,01/02/2026,x,http://has space.example\n" +
		"CVE-2026-0003,A,B,01/02/2026,x,http://\n" +
		"CVE-2026-0004,A,B,,x,\n"
	r, err := ParseFeed(context.Background(), []byte(text), KindVulnerabilities, p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Accepted != 2 || r.Rejected != 3 {
		t.Fatalf("%+v", r.Stats)
	}
	if r.Records[0]["vendor"] != "Spaced" || len([]rune(r.Records[0]["description"].(string))) != 500 || r.Records[0]["link"] != "HTTP://ok.example/x" {
		t.Errorf("record 0 = %v", r.Records[0])
	}
	if r.Records[1]["date"] != nil || r.Records[1]["description"] != "x" {
		t.Errorf("record 1 = %v", r.Records[1])
	}
}

func TestFieldRulesTrimLowercaseRegex(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindIOC, FormatLines)
	f := fm("")
	f.Regex = `host=([A-Za-z.]+)`
	f.Lowercase = true
	p.Fields["indicator"] = f
	r, _ := ParseFeed(context.Background(), []byte("host=Example.com extra\nhost=\nnothing\n"), KindIOC, p)
	if r.Accepted != 1 || r.Rejected != 2 || r.Records[0]["indicator"] != "example.com" {
		t.Errorf("regex+lowercase: %+v %v", r.Stats, r.Records)
	}
	p2 := DefaultParser(KindIOC, FormatLines)
	g := fm("")
	g.Regex = `^(\d+\.\d+\.\d+\.\d+)`
	p2.Fields["indicator"] = g
	r2, _ := ParseFeed(context.Background(), []byte("1.2.3.4|x\nnope\n"), KindIOC, p2)
	if r2.Accepted != 1 || r2.Records[0]["indicator"] != "1.2.3.4" || r2.Reasons[0].Reason != "indicator: regex did not match" {
		t.Errorf("%+v %v", r2.Stats, r2.Records)
	}
	// A group that did not take part keeps the whole match, like JS m[1] ?? m[0].
	p3 := DefaultParser(KindIOC, FormatLines)
	h := fm("")
	h.Regex = `(x)?1\.2\.3\.4`
	p3.Fields["indicator"] = h
	r3, _ := ParseFeed(context.Background(), []byte("1.2.3.4\n"), KindIOC, p3)
	if r3.Accepted != 1 {
		t.Errorf("optional group: %+v", r3.Stats)
	}
	// trim=false keeps whitespace, which then fails validation.
	p4 := DefaultParser(KindIOC, FormatCSV)
	p4.Fields["indicator"] = FieldMap{Source: "ip", Trim: false, DateFormat: DateAuto}
	r4, _ := ParseFeed(context.Background(), []byte("ip\n 1.2.3.4\n"), KindIOC, p4)
	if r4.Accepted != 0 || r4.Rejected != 1 {
		t.Errorf("trim=false: %+v", r4.Stats)
	}
}
