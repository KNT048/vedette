package ai

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func entry(n string) ActivityEntry {
	return ActivityEntry{ID: "act-" + n, TS: "2026-11-09T05:00:00.000Z", Job: "ask-my-data", Profile: "p", Model: "m", Trigger: "system:schedule",
		InputHash: HashContent("in " + n), OutputHash: HashContent("out " + n), Summary: "s " + n, TokensIn: 10, TokensOut: 5, Result: ResultOK}
}

func chainOf(t *testing.T, n int) []ActivityEntry {
	t.Helper()
	var l ActivityLog
	for i := range n {
		e := entry(strconv.Itoa(i))
		e.Tools = []ActivityTool{{Name: "t", Access: AccessRead, Args: "x=1"}}
		if _, err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	return l.Entries()
}

// vectors is the shared test vector for core_audit and resp_log (D-57 item 14): another implementation, in
// any language, must reproduce `canonical` and `hash` for every row.
type vectors struct {
	Genesis string `json:"genesis"`
	Rows    []struct {
		Entry     ActivityEntry `json:"entry"`
		Canonical string        `json:"canonical"`
	} `json:"rows"`
}

func TestGoldenChainVectors(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/chain_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Genesis != Genesis || len(v.Rows) != 3 {
		t.Fatalf("vector file: %+v", v)
	}
	// Hand-computed with sha256sum over prev_hash + "\n" + canonical, independent of this code.
	if v.Rows[0].Entry.Hash != "6a526c1db822d1471294ca6e0dd22d3bef23032f4aa69d1cbacc599ea1fd8a95" {
		t.Fatalf("row 1 hash changed: %s", v.Rows[0].Entry.Hash)
	}
	var entries []ActivityEntry
	prev := Genesis
	for i, r := range v.Rows {
		got, err := canonical(r.Entry, "hash")
		if err != nil || string(got) != r.Canonical {
			t.Fatalf("row %d canonical:\n got %s\nwant %s (%v)", i+1, got, r.Canonical, err)
		}
		if h := HashContent(prev + "\n" + r.Canonical); h != r.Entry.Hash {
			t.Fatalf("row %d: sha256(prev + LF + canonical) = %s, vector says %s", i+1, h, r.Entry.Hash)
		}
		if h, err := ChainHash(prev, r.Entry); err != nil || h != r.Entry.Hash {
			t.Fatalf("row %d ChainHash: %s %v", i+1, h, err)
		}
		prev = r.Entry.Hash
		entries = append(entries, r.Entry)
	}
	if res := VerifyChain(entries, Genesis); !res.OK || res.Count != 3 {
		t.Fatalf("%+v", res)
	}
	// The strange characters of row 2 are escaped like JSON.stringify: raw <, >, &, U+2028; \n \t \u001f escaped.
	c := v.Rows[1].Canonical
	for _, want := range []string{"<có dữ liệu> & ", `\"cá nhân\"\n\ttab`, string(rune(0x2028)), "\\" + "u001f"} {
		if !strings.Contains(c, want) {
			t.Errorf("canonical row 2 lacks %q", want)
		}
	}
}

func TestCanonicalForm(t *testing.T) {
	t.Parallel()
	type inner struct {
		Z int  `json:"z"`
		A bool `json:"a"`
	}
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"keys sorted at every level", map[string]any{"b": 1, "a": map[string]any{"d": 1, "c": 2}}, `{"a":{"c":2,"d":1},"b":1}`},
		{"struct", inner{1, true}, `{"a":true,"z":1}`},
		{"null kept, empty list kept", map[string]any{"n": nil, "l": []string{}, "m": []int(nil)}, `{"l":[],"m":null,"n":null}`},
		{"order of arrays kept", []any{3, 1, "b", "a"}, `[3,1,"b","a"]`},
		{"escapes like JSON.stringify", "q\" b\\ \b\f\n\r\t \x01\x1f \x7f <>& é \u2028 \U0001F600", "\"q\\\" b\\\\ \\b\\f\\n\\r\\t \\" + "u0001\\" + "u001f \x7f <>& é \u2028 \U0001F600\""},
		{"numbers", []any{0, -7, 9007199254740991, -9007199254740991, 12.0}, `[0,-7,9007199254740991,-9007199254740991,12]`},
		{"key order is by byte", map[string]any{"b": 1, "B": 2, "a": 3, "_": 4}, `{"B":2,"_":4,"a":3,"b":1}`},
	}
	for _, c := range cases {
		got, err := Canonical(c.in)
		if err != nil || string(got) != c.want {
			t.Errorf("%s:\n got %s (%v)\nwant %s", c.name, got, err, c.want)
		}
	}
	for _, bad := range []any{1.5, math.Pow(2, 53), -math.Pow(2, 53), 1e21, []any{map[string]any{"x": 0.1}}, make(chan int)} {
		if _, err := Canonical(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if _, err := Canonical(1.5); !errors.Is(err, ErrCanonical) {
		t.Error("non-integer must be ErrCanonical")
	}
}

func TestChainHashRules(t *testing.T) {
	t.Parallel()
	e := entry("a")
	e.Hooks, e.Tools = []string{}, []ActivityTool{}
	e.PrevHash = Genesis
	h1, err := ChainHash(Genesis, e)
	if err != nil {
		t.Fatal(err)
	}
	// The hash field is ignored; a map with the same keys gives the same hash; the formula includes the LF.
	e.Hash = "ignored"
	h2, _ := ChainHash(Genesis, e)
	var m map[string]any
	b, _ := json.Marshal(e)
	_ = json.Unmarshal(b, &m)
	h3, _ := ChainHash(Genesis, m)
	if h1 != h2 || h1 != h3 {
		t.Fatalf("%s %s %s", h1, h2, h3)
	}
	canon, _ := canonical(e, "hash")
	if h1 == HashContent(Genesis+string(canon)) || h1 != HashContent(Genesis+"\n"+string(canon)) {
		t.Fatal("formula must be prev + LF + canonical (D-57)")
	}
	for name, prev := range map[string]string{"short": "abc", "upper": strings.Repeat("A", 64), "other link": strings.Repeat("1", 64), "empty": ""} {
		if _, err := ChainHash(prev, e); !errors.Is(err, ErrChainLink) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ChainHash(Genesis, map[string]any{"id": "x"}); !errors.Is(err, ErrChainLink) {
		t.Errorf("entry without prev_hash: %v", err)
	}
	if _, err := ChainHash(Genesis, []int{1}); !errors.Is(err, ErrCanonical) {
		t.Errorf("non-object entry: %v", err)
	}
}

func TestContract_INV17_EntryShapeAndNoContent(t *testing.T) {
	t.Parallel()
	e := entry("a")
	e.Links = []ActivityLink{{Kind: "proposal", ID: "prop-1"}}
	e.Hooks = []string{"Block personal data"}
	e.Tools = []ActivityTool{NewActivityTool("search_assets", AccessRead, `{"ip":"10.0.0.1","password":"hunter2"}`)}
	s, err := Seal(Genesis, e)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"id", "ts", "job", "profile", "model", "trigger", "hooks", "tools", "input_hash", "output_hash", "summary", "tokens_in", "tokens_out", "result", "links", "prev_hash", "hash"} {
		if _, ok := m[k]; !ok {
			t.Errorf("field %s missing", k)
		}
	}
	if strings.Contains(string(raw), "hunter2") {
		t.Fatal("a secret reached the entry")
	}
	// Only hashes of the content exist: the type has no field that could hold it, and the hash is of the text.
	if s.InputHash != HashContent("in a") || len(s.InputHash) != 64 {
		t.Fatal("input hash")
	}
	// Empty hooks and tools are stored as [], an empty links list is left out, so nil and empty hash the same.
	bare := entry("b")
	s1, _ := Seal(Genesis, bare)
	bare.Hooks, bare.Tools, bare.Links = []string{}, []ActivityTool{}, []ActivityLink{}
	s2, _ := Seal(Genesis, bare)
	if s1.Hash != s2.Hash || !bytes.Contains(mustJSON(s1), []byte(`"hooks":[]`)) || bytes.Contains(mustJSON(s1), []byte(`"links"`)) {
		t.Fatalf("normalisation: %s", mustJSON(s1))
	}
	mut := func(f func(*ActivityEntry)) ActivityEntry { x := entry("c"); f(&x); return x }
	for name, bad := range map[string]ActivityEntry{
		"bad id":          mut(func(x *ActivityEntry) { x.ID = "has space" }),
		"empty id":        mut(func(x *ActivityEntry) { x.ID = "" }),
		"ts without ms":   mut(func(x *ActivityEntry) { x.TS = "2026-11-09T05:00:00Z" }),
		"ts local":        mut(func(x *ActivityEntry) { x.TS = "2026-11-09T12:00:00.000+07:00" }),
		"no job":          mut(func(x *ActivityEntry) { x.Job = "" }),
		"no trigger":      mut(func(x *ActivityEntry) { x.Trigger = "" }),
		"content as hash": mut(func(x *ActivityEntry) { x.InputHash = "the question was: ..." }),
		"upper hash":      mut(func(x *ActivityEntry) { x.OutputHash = strings.ToUpper(x.OutputHash) }),
		"negative tokens": mut(func(x *ActivityEntry) { x.TokensIn = -1 }),
		"bad result":      mut(func(x *ActivityEntry) { x.Result = "great" }),
		"tool no access":  mut(func(x *ActivityEntry) { x.Tools = []ActivityTool{{Name: "t"}} }),
		"tool no name":    mut(func(x *ActivityEntry) { x.Tools = []ActivityTool{{Access: AccessRead}} }),
		"bad link":        mut(func(x *ActivityEntry) { x.Links = []ActivityLink{{Kind: "other", ID: "x"}} }),
	} {
		if _, err := Seal(Genesis, bad); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if _, err := Seal("nothex", entry("d")); !errors.Is(err, ErrChainLink) {
		t.Errorf("bad prev: %v", err)
	}
	for _, r := range []ActivityResult{ResultOK, ResultBlockedByHook, ResultFallbackUsed, ResultError} {
		x := entry("e")
		x.Result = r
		if _, err := Seal(Genesis, x); err != nil {
			t.Errorf("result %s: %v", r, err)
		}
	}
	if FormatTS(time.Date(2026, 11, 9, 12, 0, 1, 5_000_000, time.FixedZone("x", 7*3600))) != "2026-11-09T05:00:01.005Z" {
		t.Error("FormatTS")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestSummarizeArgsAndTools(t *testing.T) {
	t.Parallel()
	cases := map[string]string{ //nolint:gosec // test inputs are fake secrets used to prove redaction
		`{"ip":"10.0.0.1"}`: `{"ip":"10.0.0.1"}`,
		`{"b":2,"a":1}`:     `{"a":1,"b":2}`,
		`{"user":"a","password":"x","nested":{"api_key":"k","ok":1},"list":[{"Authorization":"Bearer t"}]}`: `{"list":[{"Authorization":"[redacted]"}],"nested":{"api_key":"[redacted]","ok":1},"password":"[redacted]","user":"a"}`,
		`{"ratio":0.5}`:                   `{"ratio":0.5}`,
		"filter=service:rdp":              "filter=service:rdp",
		"since=24h token=abc123 host=x":   "since=24h token=[redacted] host=x",
		`password: "my secret pass" next`: `password=[redacted] next`,
		"":                                "",
	}
	for in, want := range cases {
		if got := SummarizeArgs(in); got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
	long := SummarizeArgs(`{"q":"` + strings.Repeat("é", 500) + `"}`)
	if n := len([]rune(long)); n != 120 || !strings.HasSuffix(long, "...") {
		t.Errorf("long args: %d %q", n, long[len(long)-10:])
	}
	if got := NewActivityTool("x", "", "a=1"); got.Access != AccessWrite {
		t.Errorf("unknown access must be recorded as write: %+v", got)
	}
	if got := NewActivityTool("x", AccessRead, "a=1"); got.Access != AccessRead {
		t.Errorf("%+v", got)
	}
}

func TestContract_INV18_ChainHashAndVerify(t *testing.T) {
	t.Parallel()
	good := chainOf(t, 4)
	if good[0].PrevHash != Genesis || good[1].PrevHash != good[0].Hash || good[3].PrevHash != good[2].Hash {
		t.Fatal("chain is not linked")
	}
	if res := VerifyChain(good, Genesis); !res.OK || res.Count != 4 || res.BrokenAt != 0 || res.EntryID != "" {
		t.Fatalf("%+v", res)
	}
	if res := VerifyChain(nil, Genesis); !res.OK || res.Count != 0 {
		t.Fatalf("empty chain: %+v", res)
	}
	clone := func() []ActivityEntry { return append([]ActivityEntry(nil), good...) }
	edits := map[string]func(*ActivityEntry){
		"summary": func(e *ActivityEntry) { e.Summary = "changed" }, "tokens": func(e *ActivityEntry) { e.TokensOut++ },
		"result": func(e *ActivityEntry) { e.Result = ResultError }, "profile": func(e *ActivityEntry) { e.Profile = "other" },
		"hooks": func(e *ActivityEntry) { e.Hooks = []string{"x"} }, "tool args": func(e *ActivityEntry) { e.Tools = []ActivityTool{{Name: "t", Access: AccessRead, Args: "x=2"}} },
		"tool access": func(e *ActivityEntry) { e.Tools = []ActivityTool{{Name: "t", Access: AccessWrite, Args: "x=1"}} },
		"input hash":  func(e *ActivityEntry) { e.InputHash = HashContent("other") }, "ts": func(e *ActivityEntry) { e.TS = "2026-11-09T05:00:00.001Z" },
		"links": func(e *ActivityEntry) { e.Links = []ActivityLink{{Kind: "action", ID: "a"}} }, "id": func(e *ActivityEntry) { e.ID = "act-zzz" },
		"hash": func(e *ActivityEntry) { e.Hash = strings.Repeat("0", 64) }, "prev hash": func(e *ActivityEntry) { e.PrevHash = strings.Repeat("1", 64) },
	}
	for name, edit := range edits {
		for pos := range good {
			c := clone()
			edit(&c[pos])
			res := VerifyChain(c, Genesis)
			if res.OK || res.BrokenAt != pos+1 || res.EntryID != c[pos].ID {
				t.Errorf("edit %q at %d: %+v", name, pos+1, res)
			}
		}
	}
	// Removing, swapping or inserting entries breaks the chain at the first affected position.
	if res := VerifyChain(append(clone()[:1], clone()[2:]...), Genesis); res.OK || res.BrokenAt != 2 {
		t.Errorf("removed: %+v", res)
	}
	sw := clone()
	sw[1], sw[2] = sw[2], sw[1]
	if res := VerifyChain(sw, Genesis); res.OK || res.BrokenAt != 2 {
		t.Errorf("swapped: %+v", res)
	}
	if res := VerifyChain(clone()[1:], Genesis); res.OK || res.BrokenAt != 1 {
		t.Errorf("head removed without an anchor: %+v", res)
	}
	// After retention pruning the first kept entry is checked against the anchor (the last pruned hash).
	if res := VerifyChain(clone()[1:], good[0].Hash); !res.OK {
		t.Errorf("pruned chain with its anchor: %+v", res)
	}
	if res := VerifyChain(clone()[1:], strings.Repeat("2", 64)); res.OK || res.BrokenAt != 1 {
		t.Errorf("wrong anchor: %+v", res)
	}
	if res := VerifyChain(clone()[1:], ""); !res.OK {
		t.Errorf("no anchor trusts the first link: %+v", res)
	}
	// Known limit (docs/DATA_MODEL.md 5.3): cutting off the tail is invisible without an outside head hash.
	if res := VerifyChain(clone()[:2], Genesis); !res.OK {
		t.Errorf("tail cut is not detectable here by design: %+v", res)
	}
	// A log that came back from a database with null instead of [] still verifies.
	c := clone()
	c[0].Hooks = nil
	if res := VerifyChain(c, Genesis); !res.OK {
		t.Errorf("nil hooks: %+v", res)
	}
}

func TestActivityLogAppendOnly(t *testing.T) {
	t.Parallel()
	var l ActivityLog
	if r := l.Verify(); !r.OK || r.Count != 0 {
		t.Fatalf("%+v", r)
	}
	a, err := l.Append(entry("a"))
	if err != nil || a.PrevHash != Genesis || a.Hash == "" {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err := l.Append(ActivityEntry{}); err == nil {
		t.Fatal("invalid entry stored")
	}
	b, _ := l.Append(entry("b"))
	if b.PrevHash != a.Hash {
		t.Fatal("not chained to the previous entry")
	}
	got := l.Entries()
	got[0].Summary = "tampered" // the caller holds a copy; the log is unchanged
	if r := l.Verify(); !r.OK || r.Count != 2 {
		t.Fatalf("%+v", r)
	}
	// Concurrent appends still form one valid chain.
	done := make(chan struct{})
	for i := range 20 {
		go func() { _, _ = l.Append(entry("c" + strconv.Itoa(i))); done <- struct{}{} }()
	}
	for range 20 {
		<-done
	}
	if r := l.Verify(); !r.OK || r.Count != 22 {
		t.Fatalf("%+v", r)
	}
}

func FuzzCanonical(f *testing.F) {
	for _, s := range []string{`{"b":1,"a":[1,2,{"c":null}]}`, `"x\u2028<>&\u0000"`, `[1.5]`, `{"":{"":[]}}`, `-0`, `1e3`, `{"a":"\ud800"}`, ``} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		var x any
		if dec.Decode(&x) != nil {
			return
		}
		c1, err := Canonical(x)
		if err != nil {
			if !errors.Is(err, ErrCanonical) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		if !json.Valid(c1) || bytes.ContainsAny(c1, "\n\r\t") || bytes.Contains(c1, []byte(`": `)) || bytes.Contains(c1, []byte(`, "`)) {
			t.Fatalf("not compact valid JSON: %q", c1)
		}
		// Canonical form is a fixed point: reading it back and writing it again gives the same bytes.
		var y any
		d2 := json.NewDecoder(bytes.NewReader(c1))
		d2.UseNumber()
		if err := d2.Decode(&y); err != nil {
			t.Fatal(err)
		}
		c2, err := Canonical(y)
		if err != nil || !bytes.Equal(c1, c2) {
			t.Fatalf("not idempotent:\n%s\n%s (%v)", c1, c2, err)
		}
	})
}
