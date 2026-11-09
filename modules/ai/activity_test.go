package ai

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/chain"
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

func headOf(es []ActivityEntry) *ChainHead {
	h := ChainHead{Hash: Genesis, Count: len(es)}
	if len(es) > 0 {
		h.Hash = es[len(es)-1].Hash
	}
	return &h
}

// The shared vectors of core/chain (D-57 item 14): the ai_activity rows must hash to the same values here as in
// core and in the TypeScript mock, through the ActivityEntry -> map conversion this package owns.
func TestChainVectorsSharedWithCore(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../core/testdata/chain_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Vectors []struct {
			Chain string          `json:"chain"`
			Prev  string          `json:"prev"`
			Entry json.RawMessage `json:"entry"`
			Hash  string          `json:"hash"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var rows []ActivityEntry
	for _, row := range v.Vectors {
		if row.Chain != "ai_activity" {
			continue
		}
		var e ActivityEntry
		dec := json.NewDecoder(bytes.NewReader(row.Entry))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			// A row with extra columns (the vectors also exercise core's canon of unknown fields) is not an
			// ActivityEntry; the rows after it would not link, so stop here.
			break
		}
		e = e.normalized()
		if e.PrevHash != row.Prev {
			t.Fatalf("%s: vector prev", e.ID)
		}
		if got, err := entryHash(e); err != nil || got != row.Hash {
			t.Errorf("%s: entryHash %s (%v), vector %s", e.ID, got, err, row.Hash)
		}
		// Sealing the same content after the same previous hash gives the same hash.
		bare := e
		bare.PrevHash, bare.Hash = "", ""
		if s, err := Seal(row.Prev, bare); err != nil || s.Hash != row.Hash {
			t.Errorf("%s: Seal %s (%v)", e.ID, s.Hash, err)
		}
		e.Hash = row.Hash
		rows = append(rows, e)
	}
	if len(rows) < 2 {
		t.Fatalf("expected ai_activity rows in the vector file, got %d", len(rows))
	}
	if res := VerifyChain(rows, "", headOf(rows)); !res.OK || res.Count != len(rows) {
		t.Fatalf("%+v", res)
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

// F12 / item 9: secrets do not survive the summary, wherever they sit in the arguments.
func TestContract_INV17_SummarizeArgsRemovesSecrets(t *testing.T) {
	t.Parallel()
	leaks := []string{
		`{"command":"mysql -u root --password=hunter2 db"}`,
		`{"cmd":["curl","-H","Authorization: Bearer abc123secret","https://x"]}`,
		`curl -H "Authorization: Bearer abc123secret" https://x`,
		`curl -H "Authorization: Basic dXNlcjpodW50ZXIy" https://x`,
		`{"url":"https://admin:hunter2@10.0.0.1/api"}`,
		`GET https://admin:hunter2@10.0.0.1/api`,
		`{"nested":{"deep":[{"note":"export API_TOKEN=hunter2 && run"}]}}`,
		`{"Authorization":"Bearer abc123secret"}`,
		`{"query":"password: \"hunter2 hunter3\""}`,
		`since=24h token=hunter2 host=x`,
		`{"headers":"X-Api-Key: hunter2"}`,
		`ssh://root:hunter2@host`,
	}
	for _, in := range leaks {
		out := SummarizeArgs(in)
		for _, secret := range []string{"hunter2", "hunter3", "abc123secret", "dXNlcjpodW50ZXIy"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s -> %s", in, out)
			}
		}
	}
	// A secret beyond the 120-character cut is scrubbed before the cut, not after.
	far := SummarizeArgs(`{"note":"` + strings.Repeat("x", 118) + ` --password=hunter2"}`)
	if strings.Contains(far, "hunter2") || len([]rune(far)) > 120 {
		t.Errorf("%q", far)
	}
	// Ordinary arguments stay readable.
	cases := map[string]string{ //nolint:gosec // test inputs are fake secrets used to prove redaction
		`{"ip":"10.0.0.1"}`:  `{"ip":"10.0.0.1"}`,
		`{"b":2,"a":1}`:      `{"a":1,"b":2}`,
		`{"ratio":0.5}`:      `{"ratio":0.5}`,
		`{"q":"a<b & c>d"}`:  `{"q":"a<b & c>d"}`,
		"filter=service:rdp": "filter=service:rdp",
		"":                   "",
		`{"user":"a","password":"x","nested":{"api_key":"k","ok":1},"list":[{"Authorization":"Bearer t"}]}`: `{"list":[{"Authorization":"[redacted]"}],"nested":{"api_key":"[redacted]","ok":1},"password":"[redacted]","user":"a"}`,
	}
	for in, want := range cases {
		if got := SummarizeArgs(in); got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
	long := SummarizeArgs(`{"q":"` + strings.Repeat("é", 500) + `"}`)
	if n := len([]rune(long)); n != 120 || !strings.HasSuffix(long, "...") {
		t.Errorf("long args: %d", n)
	}
	if got := NewActivityTool("x", "", "a=1"); got.Access != AccessWrite {
		t.Errorf("unknown access must be recorded as write: %+v", got)
	}
	if got := NewActivityTool("x", AccessRead, "a=1"); got.Access != AccessRead {
		t.Errorf("%+v", got)
	}
}

// F10 / item 10: deleting the newest entries is caught when the head record says otherwise.
func TestContract_INV18_TailTruncationIsDetectedWithTheHead(t *testing.T) {
	t.Parallel()
	good := chainOf(t, 4)
	head := headOf(good)
	if res := VerifyChain(good, "", head); !res.OK {
		t.Fatalf("%+v", res)
	}
	for keep := range 4 {
		res := VerifyChain(good[:keep], "", head)
		if res.OK || res.BrokenAt != keep+1 || res.EntryID != "" || res.Count != keep {
			t.Errorf("keeping %d of 4: %+v", keep, res)
		}
	}
	// A head hash that is not the last entry.
	if res := VerifyChain(good, "", &ChainHead{Hash: good[2].Hash, Count: 4}); res.OK || res.BrokenAt != 5 {
		t.Errorf("wrong head hash: %+v", res)
	}
	// An empty chain whose head says empty is fine, with or without pruning.
	if res := VerifyChain(nil, "", &ChainHead{Hash: Genesis, Count: 0}); !res.OK {
		t.Errorf("%+v", res)
	}
	if res := VerifyChain(nil, good[1].Hash, &ChainHead{Hash: good[1].Hash, Count: 0}); !res.OK {
		t.Errorf("pruned to empty: %+v", res)
	}
	// Without a head the cut stays invisible (documented): the caller must pass the head.
	if res := VerifyChain(good[:2], "", nil); !res.OK {
		t.Errorf("%+v", res)
	}
	// A break inside the chain is still reported at its position, not at the tail.
	c := append([]ActivityEntry(nil), good...)
	c[1].Summary = "changed"
	if res := VerifyChain(c, "", head); res.OK || res.BrokenAt != 2 || res.EntryID != c[1].ID {
		t.Errorf("%+v", res)
	}
}

// F11 / item 15: invalid UTF-8 is refused instead of collapsing to U+FFFD, so two different rows never hash alike.
func TestContract_INV18_InvalidUTF8IsRefused(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"x\xff", "x\xfe", "\xc3(", "a\xed\xa0\x80b"} {
		e := entry("a")
		e.Summary = bad
		if _, err := Seal(Genesis, e); !errors.Is(err, chain.ErrCanon) {
			t.Errorf("summary %q: %v", bad, err)
		}
	}
	for field, mut := range map[string]func(*ActivityEntry){
		"profile": func(e *ActivityEntry) { e.Profile = "p\xff" },
		"hooks":   func(e *ActivityEntry) { e.Hooks = []string{"h\xff"} },
		"tool":    func(e *ActivityEntry) { e.Tools = []ActivityTool{{Name: "t", Access: AccessRead, Args: "a\xfe"}} },
	} {
		e := entry("b")
		mut(&e)
		if _, err := Seal(Genesis, e); !errors.Is(err, chain.ErrCanon) {
			t.Errorf("%s: %v", field, err)
		}
	}
	// A real U+FFFD is valid.
	e := entry("c")
	e.Summary = "x\ufffd"
	if _, err := Seal(Genesis, e); err != nil {
		t.Errorf("valid U+FFFD refused: %v", err)
	}
	// A stored row with invalid UTF-8 fails verification instead of passing.
	good := chainOf(t, 2)
	good[1].Summary = "x\xff"
	if res := VerifyChain(good, "", headOf(good)); res.OK || res.BrokenAt != 2 {
		t.Errorf("%+v", res)
	}
}

func TestContract_INV18_ChainHashAndVerify(t *testing.T) {
	t.Parallel()
	good := chainOf(t, 4)
	if good[0].PrevHash != Genesis || good[1].PrevHash != good[0].Hash || good[3].PrevHash != good[2].Hash {
		t.Fatal("chain is not linked")
	}
	if res := VerifyChain(good, "", headOf(good)); !res.OK || res.Count != 4 || res.BrokenAt != 0 || res.EntryID != "" {
		t.Fatalf("%+v", res)
	}
	if res := VerifyChain(nil, "", nil); !res.OK || res.Count != 0 {
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
			res := VerifyChain(c, "", headOf(good))
			if res.OK || res.BrokenAt != pos+1 || res.EntryID != c[pos].ID {
				t.Errorf("edit %q at %d: %+v", name, pos+1, res)
			}
		}
	}
	// Removing, swapping or inserting entries breaks the chain at the first affected position.
	if res := VerifyChain(append(clone()[:1], clone()[2:]...), "", nil); res.OK || res.BrokenAt != 2 {
		t.Errorf("removed: %+v", res)
	}
	sw := clone()
	sw[1], sw[2] = sw[2], sw[1]
	if res := VerifyChain(sw, "", nil); res.OK || res.BrokenAt != 2 {
		t.Errorf("swapped: %+v", res)
	}
	if res := VerifyChain(clone()[1:], "", nil); res.OK || res.BrokenAt != 1 {
		t.Errorf("head removed without an anchor: %+v", res)
	}
	// After retention pruning the first kept entry is checked against the anchor (the last pruned hash), and the
	// head's count follows the prune.
	pruned := clone()[1:]
	if res := VerifyChain(pruned, good[0].Hash, headOf(pruned)); !res.OK {
		t.Errorf("pruned chain with its anchor and head: %+v", res)
	}
	if res := VerifyChain(pruned, good[0].Hash, headOf(good)); res.OK {
		t.Errorf("a head that still counts the pruned entry must not verify: %+v", res)
	}
	if res := VerifyChain(pruned, strings.Repeat("2", 64), nil); res.OK || res.BrokenAt != 1 {
		t.Errorf("wrong anchor: %+v", res)
	}
	// A log that came back from a database with null instead of [] still verifies.
	c := clone()
	c[0].Hooks = nil
	if res := VerifyChain(c, "", headOf(good)); !res.OK {
		t.Errorf("nil hooks: %+v", res)
	}
}

func TestActivityLogAppendOnly(t *testing.T) {
	t.Parallel()
	var l ActivityLog
	if r := l.Verify(); !r.OK || r.Count != 0 {
		t.Fatalf("%+v", r)
	}
	if h := l.Head(); h.Count != 0 || h.Hash != Genesis {
		t.Fatalf("%+v", h)
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
	if h := l.Head(); h.Count != 2 || h.Hash != b.Hash {
		t.Fatalf("%+v", h)
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

func FuzzActivityEntryHash(f *testing.F) {
	for _, s := range []string{"", "plain", "x\xff", "\u2028<>&\"\\\n", "tiếng Việt 😀", "\x00\x1f"} {
		f.Add(s, s, 1180)
	}
	f.Fuzz(func(t *testing.T, summary, arg string, tokens int) {
		e := entry("f")
		e.Summary, e.TokensIn = summary, tokens
		e.Tools = []ActivityTool{{Name: "t", Access: AccessRead, Args: arg}}
		s, err := Seal(Genesis, e)
		if err != nil {
			// Refused: invalid UTF-8 or a shape the entry rules forbid. Never a panic, never a hash.
			if s.Hash != "" {
				t.Fatal("a refused entry carries a hash")
			}
			return
		}
		if !hashRE.MatchString(s.Hash) {
			t.Fatalf("hash %q", s.Hash)
		}
		if res := VerifyChain([]ActivityEntry{s}, "", &ChainHead{Hash: s.Hash, Count: 1}); !res.OK {
			t.Fatalf("%+v", res)
		}
		again, _ := Seal(Genesis, e)
		if again.Hash != s.Hash {
			t.Fatal("hash is not deterministic")
		}
		other := e
		other.Summary = summary + "x"
		if o, err := Seal(Genesis, other); err == nil && o.Hash == s.Hash {
			t.Fatal("different entries hashed alike")
		}
	})
}
