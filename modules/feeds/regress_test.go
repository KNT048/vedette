package feeds

// Regression tests for the independent security review of feat/feeds-lib.
// Each test asserts the safe behaviour that the review found missing.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
)

// peakHeap runs fn and returns the peak HeapInuse above the starting baseline,
// sampled every millisecond (tolerant: a coarse upper bound, not exact).
func peakHeap(fn func()) uint64 {
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak.Load() {
					peak.Store(m.HeapInuse)
				}
			}
		}
	}()
	fn()
	var end runtime.MemStats
	runtime.ReadMemStats(&end)
	if end.HeapInuse > peak.Load() {
		peak.Store(end.HeapInuse)
	}
	close(stop)
	<-done
	if p := peak.Load(); p > base.HeapInuse {
		return p - base.HeapInuse
	}
	return 0
}

func fit(s string) []byte {
	if len(s) > MaxBodyBytes {
		s = s[:MaxBodyBytes]
	}
	return []byte(s)
}

func parseLines(t testing.TB, in string) Result {
	t.Helper()
	r, err := ParseFeed(context.Background(), []byte(in), KindIOC, DefaultParser(KindIOC, FormatLines))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func indicators(r Result) []string {
	var out []string
	for _, rec := range r.Records {
		out = append(out, fmt.Sprint(rec["indicator"]))
	}
	return out
}

// printable: no control, format or separator characters, only what a log or UI can show verbatim.
func printable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func assertSafeReasons(t *testing.T, name string, st Stats) {
	t.Helper()
	for _, x := range st.Reasons {
		if !printable(x.Reason) {
			t.Errorf("%s: reason with unsafe characters: %q", name, x.Reason)
		}
	}
	for _, x := range st.Rejects {
		if !printable(x.Reason) {
			t.Errorf("%s: reject with unsafe characters: %q", name, x.Reason)
		}
	}
}

// ---------- 1. special-purpose addresses and local names

func TestContract_INV12_SpecialAddressesNeverBecomeIOC(t *testing.T) {
	t.Parallel()
	bad := []string{
		"0.0.0.0", "255.255.255.255", "127.0.0.1", "127.8.8.8", "10.0.0.1", "172.16.5.5", "192.168.1.1", "169.254.169.254",
		"224.0.0.251", "100.64.0.1", "192.0.0.8", "198.18.0.1", "198.19.255.1", "240.0.0.1", "0.1.2.3",
		"192.0.2.1", "198.51.100.23", "203.0.113.77",
		"::", "::1", "fe80::1", "ff02::1", "fc00::1", "fd12:3456::1", "2001:db8::1",
		"::ffff:192.168.1.1", "::ffff:127.0.0.1", "::ffff:10.1.1.1", "::ffff:0.0.0.0", "::ffff:169.254.1.1",
		"64:ff9b::808:808", "2002:c0a8:101::1", "::1.2.3.4",
		"printer.local", "nas.lan", "corp.internal", "x.localhost", "1.168.192.in-addr.arpa", "a.test", "a.invalid", "a.example",
		"localhost", "intranet", "com", "com.vn", "co.uk", "github.io", "blogspot.com",
	}
	r := parseLines(t, strings.Join(bad, "\n"))
	if r.Accepted != 0 {
		t.Errorf("accepted special addresses or local names: %v", indicators(r))
	}
	good := []string{"8.8.8.8", "45.148.10.95", "185.220.101.47", "2606:4700:4700::1111", "::ffff:8.8.4.4", "evil.example.com", "evil.co.uk", "a.b.example.org"}
	g := parseLines(t, strings.Join(good, "\n"))
	if g.Accepted != len(good) {
		t.Errorf("public values wrongly rejected: accepted %v rejects %+v", indicators(g), g.Rejects)
	}
	// An explicit kind does not bypass the check.
	p := DefaultParser(KindIOC, FormatJSON)
	p.RecordsPath = "$[*]"
	p.Fields["indicator"] = fm("$.i")
	p.Fields["kind"] = fm("$.k")
	in := `[{"i":"10.0.0.1","k":"ip"},{"i":"http://192.168.1.1/x","k":"url"},{"i":"http://printer.local/x","k":"url"},{"i":"https://evil.example.com/x","k":"url"},{"i":"corp.internal","k":"domain"},{"i":"::ffff:10.0.0.1","k":"ipv4"}]`
	jr, err := ParseFeed(context.Background(), []byte(in), KindIOC, p)
	if err != nil || jr.Accepted != 1 || jr.Records[0]["indicator"] != "https://evil.example.com/x" {
		t.Errorf("explicit kinds: %v %+v %v", err, jr.Stats, jr.Records)
	}
}

func TestContract_INV12_JudgeRepeatsTheAddressCheck(t *testing.T) {
	t.Parallel()
	cc0 := []Sighting{{Source: "abusech-feodo", BlockClass: true}}
	for _, v := range []string{"0.0.0.0", "192.168.1.1", "127.0.0.1", "::", "fe80::1", "::ffff:10.0.0.1", "192.0.2.4", "100.64.1.1"} {
		if got := Judge("ip", v, cc0, Whitelist{}); got != VerdictNone {
			t.Errorf("Judge(ip,%s) = %q, want no verdict", v, got)
		}
		if k, ok := IOCKey("ip", v); ok {
			t.Errorf("IOCKey(ip,%s) = %q accepted", v, k)
		}
	}
	for _, v := range []string{"printer.local", "corp.internal", "com", "co.uk", "github.io", "a.example", "localhost", "x.arpa"} {
		if got := Judge("domain", v, cc0, Whitelist{}); got != VerdictNone {
			t.Errorf("Judge(domain,%s) = %q, want no verdict", v, got)
		}
	}
	if Judge("ip", "45.148.10.95", cc0, Whitelist{}) != VerdictBlock || Judge("domain", "evil.co.uk", cc0, Whitelist{}) != VerdictBlock {
		t.Error("public values must still be judged")
	}
}

func TestRegress_HostsFileLinesYieldTheDomain(t *testing.T) {
	t.Parallel()
	in := "# hosts\n0.0.0.0 evil.example.com\n127.0.0.1\tbad.example.net # trailing\n::1 localhost\n0.0.0.0 a.example.com b.example.com\n45.148.10.95\t8\n127.0.0.1\n"
	r := parseLines(t, in)
	want := []string{"evil.example.com", "bad.example.net", "a.example.com", "b.example.com", "45.148.10.95"}
	if got := indicators(r); !reflect.DeepEqual(got, want) {
		t.Errorf("indicators = %v, want %v", got, want)
	}
	if r.Rejected != 2 { // "localhost" and the bare sink address
		t.Errorf("rejected = %d (%+v)", r.Rejected, r.Reasons)
	}
	for _, rec := range r.Records {
		if rec["indicator"] == "0.0.0.0" || rec["indicator"] == "127.0.0.1" {
			t.Errorf("sink address became an IOC: %v", rec)
		}
	}
}

// ---------- 2. customer regex time

func TestRegress_RegexCellLengthLimit(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindIOC, FormatLines)
	f := fm("")
	f.Regex = `([0-9.]+)`
	p.Fields["indicator"] = f
	long := strings.Repeat("1", maxRegexCell+1)
	ok := strings.Repeat("1", 40)
	start := time.Now()
	r, err := ParseFeed(context.Background(), []byte(long+"\n"+ok+".2.3.4\n"+"8.8.8.8\n"), KindIOC, p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rejected != 2 || r.Accepted != 1 || !strings.Contains(r.Rejects[0].Reason, "longer than 4096 bytes") || r.Rejects[0].Row != 1 {
		t.Errorf("%+v", r.Stats)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
	// A single 1 MB token with realistic regexes finishes at once, rejected before any regex runs.
	tok := strings.Repeat("a", 1_000_000)
	for _, re := range []string{`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`, `([a-z0-9.-]{1,253}\.[a-z]{2,63})`, `([A-Fa-f0-9]{64})`} {
		q := DefaultParser(KindIOC, FormatLines)
		g := fm("")
		g.Regex = re
		q.Fields["indicator"] = g
		s := time.Now()
		res, err := ParseFeed(context.Background(), []byte(tok), KindIOC, q)
		if err != nil || res.Rejected != 1 || time.Since(s) > 2*time.Second {
			t.Errorf("%q: %v %+v %v", re, err, res.Stats, time.Since(s))
		}
	}
}

func TestRegress_RegexProgramSizeIsLimited(t *testing.T) {
	t.Parallel()
	for _, re := range []string{
		`([a-z]{0,1000}){0,1}b`, `(?:[^b]{1,1000}[^c]{1,1000}){1,1}(x)`, `(\w{1,1000})(\w{1,1000})(\w{1,1000})z`, `(a{1,1000}){1,1000}`, `((a{100}){100}){100}`,
	} {
		p := DefaultParser(KindIOC, FormatLines)
		f := fm("")
		f.Regex = re
		p.Fields["indicator"] = f
		if err := CheckParser(KindIOC, p); !errors.Is(err, ErrBadConfig) {
			t.Errorf("%q accepted: %v", re, err)
		}
	}
	for _, re := range []string{`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`, `([a-z0-9.-]{1,253}\.[a-z]{2,63})`, `([A-Fa-f0-9]{64})`, `host=([A-Za-z.]+)`, `(CVE-\d{4}-\d{4,})`} {
		p := DefaultParser(KindIOC, FormatLines)
		f := fm("")
		f.Regex = re
		p.Fields["indicator"] = f
		if err := CheckParser(KindIOC, p); err != nil {
			t.Errorf("realistic %q refused: %v", re, err)
		}
	}
}

// cancelAfter reports context.Canceled once Err has been asked n times.
type cancelAfter struct {
	context.Context
	n atomic.Int32
}

func (c *cancelAfter) Err() error {
	if c.n.Add(-1) < 0 {
		return context.Canceled
	}
	return nil
}

func TestRegress_ParseFeedHonoursTheContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ParseFeed(ctx, []byte("8.8.8.8\n"), KindIOC, DefaultParser(KindIOC, FormatLines)); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: %v", err)
	}
	in := strings.Repeat("8.8.8.8\n", 5000)
	c := &cancelAfter{Context: context.Background()}
	c.n.Store(20)
	r, err := ParseFeed(c, []byte(in), KindIOC, DefaultParser(KindIOC, FormatLines))
	if !errors.Is(err, context.Canceled) || r.Accepted != 0 || len(r.Records) != 0 {
		t.Errorf("mid-run cancel must fail closed: %v %+v", err, r.Stats)
	}
	dl, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := ParseFeed(dl, []byte(in), KindIOC, DefaultParser(KindIOC, FormatLines)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("deadline: %v", err)
	}
}

// ---------- 3. memory amplification

func TestRegress_MemoryAmplificationIsBounded(t *testing.T) {
	// A tight GC target makes HeapInuse follow live memory instead of garbage waiting to be collected.
	old := debug.SetGCPercent(20)
	defer debug.SetGCPercent(old)
	big := MaxBodyBytes
	build := func(prefix, unit, suffix string, n int) string {
		return prefix + strings.Repeat(unit, n) + suffix
	}
	attrs := func(unit string) string {
		var b strings.Builder
		b.WriteString("<rss><item ")
		for i := 0; b.Len() < big-40; i++ {
			fmt.Fprintf(&b, unit, i)
		}
		b.WriteString("/></rss>")
		return b.String()
	}
	cases := []struct {
		name   string
		format Format
		in     string
	}{
		{"json objects", FormatJSON, build("[", "{},", "{}]", big/3-2)},
		{"json zeros", FormatJSON, build("[", "0,", "0]", big/2-2)},
		{"json empty arrays", FormatJSON, build("[", "[],", "[]]", big/3-2)},
		{"json empty keys", FormatJSON, build("{", `"":0,`, `"":0}`, big/5-2)},
		{"csv commas header", FormatCSV, strings.Repeat(",", big)},
		{"csv commas data", FormatCSV, "dst_ip\n" + strings.Repeat(",", big-10)},
		{"csv comma rows", FormatCSV, "dst_ip\n" + strings.Repeat(",\n", big/2-8)},
		{"xml attrs", FormatRSS, attrs("a%x='' ")},
		{"xml xmlns", FormatRSS, attrs("xmlns:n%x='u' ")},
		{"xml text split by comments", FormatRSS, build("<rss>", "a<!---->", "</rss>", big/8-2)},
		{"xml text split by PIs", FormatRSS, build("<rss>", "a<?p?>", "</rss>", big/6-2)},
		{"xml items", FormatRSS, build("<r>", "<item/>", "</r>", big/7-2)},
		{"stix indicators", FormatSTIX, `{"objects":[` + strings.Repeat(`{"type":"indicator","pattern":"[ipv4-addr:value = '8.8.8.8']"},`, big/70) + `{}]}`},
		{"lines tiny", FormatLines, strings.Repeat("a\n", big/2)},
	}
	const limit = 80 << 20 // ~64 MB target; race-instrumented heaps run a little larger
	for _, c := range cases {
		in := fit(c.in)
		var err error
		peak := peakHeap(func() { _, err = ParseFeed(context.Background(), in, KindIOC, DefaultParser(KindIOC, c.format)) })
		if err != nil && !errors.Is(err, ErrBadSample) && !errors.Is(err, ErrBadConfig) {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if peak > limit {
			t.Errorf("%s: peak heap %d MB over the %d MB budget", c.name, peak>>20, limit>>20)
		}
	}
}

func TestRegress_JSONNodeBudget(t *testing.T) {
	t.Parallel()
	over := "[" + strings.Repeat("0,", maxJSONNodes) + "0]"
	if _, err := decodeJSON(over); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("node budget not enforced: %v", err)
	}
	if _, err := decodeJSON("[" + strings.Repeat("0,", 1000) + "0]"); err != nil {
		t.Errorf("small document refused: %v", err)
	}
	p := DefaultParser(KindIOC, FormatJSON)
	if _, err := ParseFeed(context.Background(), []byte(over), KindIOC, p); !errors.Is(err, ErrBadSample) {
		t.Errorf("ParseFeed: %v", err)
	}
}

func TestRegress_CSVFieldsPerRowAreCapped(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindIOC, FormatCSV)
	wide := strings.Repeat("x,", maxCSVFields+5) + "x"
	in := "dst_ip,first_seen_utc\n8.8.8.8,2026-01-01\n" + wide + "\n8.8.4.4,2026-01-02\n"
	r, err := ParseFeed(context.Background(), []byte(in), KindIOC, p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Accepted != 2 || r.Rejected != 1 || r.Rejects[0].Row != 2 || !strings.Contains(r.Rejects[0].Reason, "more than 1000 fields") {
		t.Errorf("%+v", r.Stats)
	}
	if _, err := ParseFeed(context.Background(), []byte(wide+"\n1.1.1.1\n"), KindIOC, p); !errors.Is(err, ErrBadSample) {
		t.Errorf("wide header: %v", err)
	}
	// Exactly the cap is fine.
	exact := strings.Repeat("x,", maxCSVFields-1) + "x"
	if rows := parseCSV(exact+"\n", ',', true); len(rows) != 1 || rows[0].bad != "" || len(rows[0].cells) != maxCSVFields {
		t.Errorf("exact cap: %+v", rows)
	}
}

func TestRegress_XMLBudgetCountsTextAndAttributes(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("<rss><item ")
	for i := 0; i < maxXMLAttrs+10; i++ {
		fmt.Fprintf(&b, "a%d='' ", i)
	}
	b.WriteString("/></rss>")
	if _, err := parseXML(b.String()); err == nil {
		t.Error("attribute budget not enforced")
	}
	if _, err := parseXML("<rss>" + strings.Repeat("a<!---->", 20) + "</rss>"); err != nil {
		t.Errorf("small document: %v", err)
	}
	// Adjacent text pieces are merged into one node.
	items, err := parseXML("<r><item>a<!---->b<?p?>c</item></r>")
	if err != nil || len(items) != 1 {
		t.Fatalf("%v %+v", err, items)
	}
	if got := items[0].textContent(); got != "abc" || len(items[0].children) != 1 {
		t.Errorf("text = %q children = %d", got, len(items[0].children))
	}
}

// ---------- 4. reasons

func TestRegress_ReasonsAreBounded(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := 0; i < MaxRows; i++ {
		fmt.Fprintf(&b, "x\"%d\n", i)
	}
	r := parseLines(t, b.String())
	if r.Rejected != MaxRows || len(r.Reasons) != 1 || r.Reasons[0].Count != MaxRows {
		t.Errorf("a quote inside a value must not split the reason: %d reasons, first %+v", len(r.Reasons), r.Reasons[0])
	}
	js, _ := json.Marshal(r.Preview())
	if len(js) > 8192 {
		t.Errorf("preview JSON is %d bytes", len(js))
	}
	tl := newTally()
	for i := 0; i < 200; i++ {
		tl.reject(i+1, fmt.Sprintf("template %d %%s", i), "value")
	}
	st := tl.stats()
	if len(st.Reasons) != maxReasons+1 || st.Reasons[len(st.Reasons)-1].Reason != "other" || st.Reasons[len(st.Reasons)-1].Count != 200-maxReasons || st.Rejected != 200 {
		t.Errorf("%d reasons, last %+v", len(st.Reasons), st.Reasons[len(st.Reasons)-1])
	}
	sum := 0
	for _, x := range st.Reasons {
		sum += x.Count
	}
	if sum != 200 {
		t.Errorf("counts add up to %d", sum)
	}
	if len(st.Rejects) != MaxRejects {
		t.Errorf("rejects = %d", len(st.Rejects))
	}
}

func TestRegress_ReasonsEchoOnlySafeQuotedText(t *testing.T) {
	t.Parallel()
	r := parseLines(t, "\x1b[31mevil\u202e.com\nCVE\u200b\ntab\there\n"+strings.Repeat("z", 500)+"\n")
	assertSafeReasons(t, "lines", r.Stats)
	for _, x := range r.Rejects {
		if len(x.Reason) > 200 {
			t.Errorf("echoed value not truncated: %d bytes", len(x.Reason))
		}
	}
	k, _ := ParseKEV([]byte(`{"vulnerabilities":[{"cveID":"\u001b[2J\u202eX","vendorProject":"v","product":"p","dateAdded":"2024-01-01"}]}`))
	assertSafeReasons(t, "kev", k.Stats)
	n, _ := ParseNucleiCVEs([]byte(`{"ID":"\u001b[2J\u202e"}` + "\n"))
	assertSafeReasons(t, "nuclei", n.Stats)
	if len(k.Rejects) != 1 || !strings.Contains(k.Rejects[0].Reason, `\x1b[2J\u202e`) || len(n.Rejects) != 1 || !strings.Contains(n.Rejects[0].Reason, `\x1b`) {
		t.Errorf("escapes expected: %+v %+v", k.Rejects, n.Rejects)
	}
	if k.Rejected != 1 || n.Rejected != 1 {
		t.Errorf("kev %+v nuclei %+v", k.Stats, n.Stats)
	}
}

// ---------- 5. silent row loss

func TestRegress_LineEndingsAreAllSplit(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"CR only":   "8.8.8.8\r8.8.4.4\r1.1.1.1\r9.9.9.9\r",
		"CRLF":      "8.8.8.8\r\n8.8.4.4\r\n1.1.1.1\r\n9.9.9.9\r\n",
		"LF":        "8.8.8.8\n8.8.4.4\n1.1.1.1\n9.9.9.9",
		"mixed":     "8.8.8.8\r8.8.4.4\r\n1.1.1.1\n9.9.9.9\r",
		"CR blanks": "8.8.8.8\r\r\r8.8.4.4\r#c\r1.1.1.1\r\n\r\n9.9.9.9",
	} {
		if r := parseLines(t, in); r.Accepted != 4 || r.Rejected != 0 {
			t.Errorf("%s: %+v", name, r.Stats)
		}
	}
}

func TestRegress_CSVUnterminatedQuoteIsCounted(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindIOC, FormatCSV)
	in := "dst_ip,note\n8.8.8.8,\"oops\n8.8.4.4,x\n1.1.1.1,y\n9.9.9.9,z\n"
	r, err := ParseFeed(context.Background(), []byte(in), KindIOC, p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Accepted+r.Rejected != 4 || r.Rejected != 1 || r.Rejects[0].Row != 1 || !strings.Contains(r.Rejects[0].Reason, "quote") {
		t.Errorf("%+v", r.Stats)
	}
	if got := indicators(r); !reflect.DeepEqual(got, []string{"8.8.4.4", "1.1.1.1", "9.9.9.9"}) {
		t.Errorf("rows after the bad quote must survive: %v", got)
	}
	// Quote opens on the last row.
	r2, _ := ParseFeed(context.Background(), []byte("dst_ip\n8.8.8.8\n\"9.9.9.9"), KindIOC, p)
	if r2.Accepted != 1 || r2.Rejected != 1 {
		t.Errorf("last row: %+v", r2.Stats)
	}
}

// ---------- 6. display safety

func TestRegress_BidiAndInvisibleTextInKeysIsRejected(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindVulnerabilities, FormatJSON)
	p.RecordsPath = "$[*]"
	row := func(v, prod, desc string) string {
		b, _ := json.Marshal(map[string]string{"cveID": "CVE-2024-0001", "vendorProject": v, "product": prod, "shortDescription": desc, "dateAdded": "2024-01-01"})
		return string(b)
	}
	in := "[" + strings.Join([]string{
		row("Micro\u202esoft", "Windows", "d"),
		row("Microsoft", "Win\u200bdows", "d"),
		row("Microsoft", "Win\u2066dows", "d"),
		row("Microsoft", "Win\u0085dows", "d"),
		row("Microsoft", "Win\ufeffdows", "d"),
		row("Microsoft", "Win\tdows", "d"),
		row("Microsoft", "Windows", "a\u200bb\u202ec\u0085d\u2066e"),
	}, ",") + "]"
	r, err := ParseFeed(context.Background(), []byte(in), KindVulnerabilities, p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Accepted != 1 || r.Rejected != 6 {
		t.Fatalf("%+v", r.Stats)
	}
	if r.Records[0]["description"] != "abcde" {
		t.Errorf("free text not sanitised: %q", r.Records[0]["description"])
	}
	assertSafeReasons(t, "bidi", r.Stats)
	// IOC values and CVE ids.
	ir := parseLines(t, "evil\u202e.com\nevil\u200b.com\n8.8.8.8\u200f\n")
	if ir.Accepted != 0 {
		t.Errorf("IOC with invisible characters accepted: %v", indicators(ir))
	}
	kev := `{"vulnerabilities":[
	 {"cveID":"CVE-2024-0002","vendorProject":"\u202eevil","product":"p","dateAdded":"2024-01-01"},
	 {"cveID":"CVE-2024-0003","vendorProject":"v","product":"x\u2066y","dateAdded":"2024-01-01"},
	 {"cveID":"CVE-2024-0004\u200b","vendorProject":"v","product":"p","dateAdded":"2024-01-01"},
	 {"cveID":"CVE-2024-0005","vendorProject":"v","product":"p","vulnerabilityName":"n\u202eame","shortDescription":"d\u0085\u200bx","requiredAction":"a\u2067b","dateAdded":"2024-01-01","notes":"https://ok.example.com/a\u200b"}]}`
	c, _ := ParseKEV([]byte(kev))
	if c.Accepted != 1 || c.Vulns[0].CVE != "CVE-2024-0005" || c.Vulns[0].Description != "dx" || c.Vulns[0].Name != "name" || c.Vulns[0].RequiredAction != "ab" {
		t.Errorf("KEV: %+v %+v", c.Stats, c.Vulns)
	}
	assertSafeReasons(t, "kev", c.Stats)
}

// ---------- 11. Go vs SPA divergence

func TestRegress_KEVKeysAreExactAndLastWins(t *testing.T) {
	t.Parallel()
	kev := `{"vulnerabilities":[
	 {"cveID":"CVE-2024-0001","CVEID":"CVE-2099-9999","vendorProject":"v","product":"p","dateAdded":"2024-01-01"},
	 {"cveID":"CVE-2024-0002","cveID":"CVE-2024-0003","vendorProject":"v","product":"p","dateAdded":"2024-01-01"},
	 {"CVEID":"CVE-2024-0004","vendorProject":"v","product":"p","dateAdded":"2024-01-01"}]}`
	c, err := ParseKEV([]byte(kev))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, v := range c.Vulns {
		got = append(got, v.CVE)
	}
	if !reflect.DeepEqual(got, []string{"CVE-2024-0001", "CVE-2024-0003"}) || c.Rejected != 1 {
		t.Errorf("cves %v, %+v", got, c.Stats)
	}
}

func TestRegress_JSONWildcardDeduplicatesKeys(t *testing.T) {
	t.Parallel()
	p := DefaultParser(KindIOC, FormatJSON)
	p.RecordsPath = "$.data.*"
	r, err := ParseFeed(context.Background(), []byte(`{"data":{"a":{"ioc":"8.8.8.8"},"b":{"ioc":"9.9.9.9"},"a":{"ioc":"1.1.1.1"}}}`), KindIOC, p)
	if err != nil {
		t.Fatal(err)
	}
	// JS: Object.values(JSON.parse(...)) keeps the first position of "a" with the last value.
	if got := indicators(r); !reflect.DeepEqual(got, []string{"1.1.1.1", "9.9.9.9"}) {
		t.Errorf("records = %v", got)
	}
}

// ---------- 12. URL userinfo and empty-file hashes

func TestRegress_UnsafeURLAndWellKnownHashIOCs(t *testing.T) {
	t.Parallel()
	bad := []string{
		"https://user:pw@evil.example.com/x", "http://admin@evil.example.com/", "https://evil.example.com@8.8.8.8/",
		"d41d8cd98f00b204e9800998ecf8427e", "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	if r := parseLines(t, strings.Join(bad, "\n")); r.Accepted != 0 {
		t.Errorf("accepted %v", indicators(r))
	}
	good := []string{"https://evil.example.com/a?b=c#frag", "44d88612fea8a8f36de82e1278abb02f"}
	if r := parseLines(t, strings.Join(good, "\n")); r.Accepted != 2 {
		t.Errorf("rejected good values: %+v", r.Rejects)
	}
}

// ---------- 8. schedule clock skew

func TestContract_INV9_FutureTimestampsMeanDueAndStale(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	future := now.AddDate(10, 0, 0)
	ok := State{LastSuccess: future, LastAttempt: future}
	if !ok.Due(now, 6) || !IsStale(now, future, 6) {
		t.Errorf("future success: due=%v stale=%v", ok.Due(now, 6), IsStale(now, future, 6))
	}
	failed := State{LastSuccess: now.Add(-time.Hour), LastAttempt: future, Failures: 3}
	if !failed.Due(now, 6) {
		t.Error("future failed attempt blocks retries")
	}
	if (State{LastSuccess: now, LastAttempt: now}).Due(now, 6) || IsStale(now, now, 6) {
		t.Error("a pull made right now is neither due nor stale")
	}
	if !IsStale(now, now.Add(time.Second), 6) {
		t.Error("one second in the future is already a clock fault")
	}
}

// ---------- 9. redirect headers

func TestRegress_RedirectDropsReferer(t *testing.T) {
	t.Parallel()
	var refs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refs = append(refs, r.Header.Get("Referer"))
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusFound)
		case "/b":
			http.Redirect(w, r, "/c", http.StatusFound)
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	if _, err := (Fetcher{Client: srv.Client()}).Fetch(context.Background(), Request{URL: srv.URL + "/a?token=abc"}); err != nil {
		t.Fatal(err)
	}
	if len(refs) != 3 {
		t.Fatalf("hops = %d", len(refs))
	}
	for i, r := range refs {
		if r != "" {
			t.Errorf("hop %d sent Referer %q", i, r)
		}
	}
}
