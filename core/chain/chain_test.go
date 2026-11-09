package chain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/chain"
)

func TestCanon(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"null kept", map[string]any{"a": nil}, `{"a":null}`},
		{"keys sorted", map[string]any{"b": 1, "a": 2, "c": 3}, `{"a":2,"b":1,"c":3}`},
		{"no whitespace nested", map[string]any{"z": []any{1, "x", true, nil, map[string]any{"y": 0, "x": -5}}}, `{"z":[1,"x",true,null,{"x":-5,"y":0}]}`},
		{"quote and backslash", "a\"b\\c", `"a\"b\\c"`},
		{"named controls", "\b\f\n\r\t", `"\b\f\n\r\t"`},
		{"other controls lowercase hex", "\x00\x01\x1f", `"\u0000\u0001\u001f"`},
		{"DEL untouched", "\x7f", "\"\x7f\""},
		{"html chars not escaped", "<a href='x'>&</a>", `"<a href='x'>&</a>"`},
		{"U+2028 U+2029 raw", "a b c", "\"a b c\""},
		{"vietnamese raw", "Máy chủ không phản hồi", `"Máy chủ không phản hồi"`},
		{"astral raw", "x😀y", `"x😀y"`},
		{"escaped key", map[string]any{"a\"b": 1}, `{"a\"b":1}`},
		{"empty containers", map[string]any{"a": map[string]any{}, "b": []any{}}, `{"a":{},"b":[]}`},
		{"int64", int64(9007199254740991), `9007199254740991`},
		{"negative zero int", 0, `0`},
		{"false", false, `false`},
		// U+FF5E (UTF-8 EF BD 9E) sorts before U+1F600 (UTF-8 F0 9F 98 80) by code point and byte order;
		// UTF-16 order would put them the other way round.
		{"code point order, not UTF-16", map[string]any{"\U0001F600": 2, "\uFF5E": 1}, "{\"\uFF5E\":1,\"\U0001F600\":2}"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := chain.Canon(tc.in)
			if err != nil {
				t.Fatalf("Canon: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("Canon = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCanonRejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   any
	}{
		{"float", 1.5},
		{"float whole", float64(2)},
		{"NaN", math.NaN()},
		{"Inf", math.Inf(1)},
		{"nested float", map[string]any{"a": []any{1.5}}},
		{"invalid utf8 value", "a\xffb"},
		{"invalid utf8 key", map[string]any{"a\xff": 1}},
		{"unsupported type", struct{}{}},
		{"unsafe integer", int64(1) << 53},
		{"unsafe negative integer", -(int64(1) << 53)},
		{"uint", uint(1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, err := chain.Canon(tc.in); err == nil {
				t.Fatalf("Canon accepted %v as %q", tc.in, got)
			}
		})
	}
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestHashCanonical(t *testing.T) {
	t.Parallel()
	entry := map[string]any{"id": "au-1", "ts": "2026-11-09T01:02:03.000Z", "detail": "a<b>& ", "n": 3, "x": nil}
	want := sum(chain.Genesis + "\n" + `{"detail":"a<b>&` + " " + `","id":"au-1","n":3,"prev_hash":"` + chain.Genesis + `","ts":"2026-11-09T01:02:03.000Z","x":null}`)
	got, err := chain.HashCanonical(chain.Genesis, entry)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("HashCanonical = %s, want %s", got, want)
	}
	if _, ok := entry["prev_hash"]; ok {
		t.Fatal("HashCanonical modified its argument")
	}
	// prev_hash may already be in the entry when it agrees with prev.
	entry["prev_hash"] = chain.Genesis
	if again, err := chain.HashCanonical(chain.Genesis, entry); err != nil || again != want {
		t.Fatalf("with prev_hash in entry: %s, %v", again, err)
	}
	entry["prev_hash"] = "other"
	if _, err := chain.HashCanonical(chain.Genesis, entry); err == nil {
		t.Fatal("conflicting prev_hash accepted")
	}
	if _, err := chain.HashCanonical(chain.Genesis, map[string]any{"a": 1.5}); err == nil {
		t.Fatal("float accepted")
	}
}

func TestGenesis(t *testing.T) {
	t.Parallel()
	if chain.Genesis != strings.Repeat("0", 64) {
		t.Fatalf("Genesis = %q", chain.Genesis)
	}
}

func TestVerifier(t *testing.T) {
	t.Parallel()
	const anchor = "abcd"
	type row struct{ id, prev, stored, recomputed string }
	tests := []struct {
		name   string
		anchor string
		rows   []row
		want   chain.Result
	}{
		{"empty is ok", "", nil, chain.Result{OK: true}},
		{"good chain from genesis", "", []row{{"1", chain.Genesis, "h1", "h1"}, {"2", "h1", "h2", "h2"}}, chain.Result{OK: true, Count: 2}},
		{"good chain from anchor", anchor, []row{{"1", anchor, "h1", "h1"}, {"2", "h1", "h2", "h2"}}, chain.Result{OK: true, Count: 2}},
		{"first prev must be genesis", "", []row{{"1", "zz", "h1", "h1"}}, chain.Result{Count: 1, BrokenAt: 1, EntryID: "1"}},
		{"first prev must be anchor", anchor, []row{{"1", chain.Genesis, "h1", "h1"}}, chain.Result{Count: 1, BrokenAt: 1, EntryID: "1"}},
		{"bad link", "", []row{{"1", chain.Genesis, "h1", "h1"}, {"2", "wrong", "h2", "h2"}, {"3", "h2", "h3", "h3"}}, chain.Result{Count: 3, BrokenAt: 2, EntryID: "2"}},
		{"bad hash keeps first break", "", []row{{"1", chain.Genesis, "h1", "h1"}, {"2", "h1", "h2", "other"}, {"3", "bad", "h3", "h3"}}, chain.Result{Count: 3, BrokenAt: 2, EntryID: "2"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := chain.NewVerifier(tc.anchor)
			for _, r := range tc.rows {
				v.Add(r.id, r.prev, r.stored, r.recomputed)
			}
			if got := v.Result(); got != tc.want {
				t.Fatalf("Result = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestChainVectors checks every section of the vectors shared with the TypeScript side
// (modules/core/testdata/chain_vectors.json, not edited here): sha256, canon, vectors, tampered.
func TestChainVectors(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "modules", "core", "testdata", "chain_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Genesis string `json:"genesis"`
		SHA256  []struct {
			Input string `json:"input"`
			Hex   string `json:"hex"`
		} `json:"sha256"`
		Canon []struct {
			Value json.RawMessage `json:"value"`
			Canon string          `json:"canon"`
		} `json:"canon"`
		Vectors []struct {
			Chain string          `json:"chain"`
			Prev  string          `json:"prev"`
			Entry json.RawMessage `json:"entry"`
			Hash  string          `json:"hash"`
		} `json:"vectors"`
		Tampered []struct {
			Chain       string            `json:"chain"`
			Description string            `json:"description"`
			Entries     []json.RawMessage `json:"entries"`
			BrokenAt    int               `json:"broken_at"`
		} `json:"tampered"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.SHA256) == 0 || len(f.Canon) == 0 || len(f.Vectors) == 0 || len(f.Tampered) == 0 {
		t.Fatal("a section of chain_vectors.json is empty")
	}
	if f.Genesis != chain.Genesis {
		t.Fatalf("genesis = %s, want %s", f.Genesis, chain.Genesis)
	}

	t.Run("sha256", func(t *testing.T) {
		for i, v := range f.SHA256 {
			if got := sum(v.Input); got != v.Hex {
				t.Errorf("sha256[%d] = %s, want %s", i, got, v.Hex)
			}
		}
	})
	t.Run("canon", func(t *testing.T) {
		for i, v := range f.Canon {
			val, err := decode(v.Value)
			if err != nil {
				t.Fatalf("canon[%d]: %v", i, err)
			}
			got, err := chain.Canon(val)
			if err != nil || string(got) != v.Canon {
				t.Errorf("canon[%d] = %q (%v), want %q", i, got, err, v.Canon)
			}
		}
	})
	t.Run("vectors", func(t *testing.T) {
		for i, v := range f.Vectors {
			val, err := decode(v.Entry)
			if err != nil {
				t.Fatalf("vectors[%d]: %v", i, err)
			}
			entry, _ := val.(map[string]any)
			if entry["prev_hash"] != v.Prev {
				t.Errorf("vectors[%d] (%s): entry.prev_hash %v != prev", i, v.Chain, entry["prev_hash"])
			}
			got, err := chain.HashCanonical(v.Prev, entry)
			if err != nil || got != v.Hash {
				t.Errorf("vectors[%d] (%s) = %s (%v), want %s", i, v.Chain, got, err, v.Hash)
			}
		}
	})
	t.Run("tampered", func(t *testing.T) {
		for _, c := range f.Tampered {
			var ver *chain.Verifier
			for i, raw := range c.Entries {
				val, err := decode(raw)
				if err != nil {
					t.Fatalf("%s: %v", c.Description, err)
				}
				row, _ := val.(map[string]any)
				prev, _ := row["prev_hash"].(string)
				if i == 0 {
					ver = chain.NewVerifier(prev)
				}
				entry := make(map[string]any, len(row))
				for k, v := range row {
					if k != "hash" {
						entry[k] = v
					}
				}
				recomputed, err := chain.HashCanonical(prev, entry)
				if err != nil {
					t.Fatalf("%s: %v", c.Description, err)
				}
				id, _ := row["id"].(string)
				stored, _ := row["hash"].(string)
				ver.Add(id, prev, stored, recomputed)
			}
			res := ver.Result()
			if res.OK || res.BrokenAt != c.BrokenAt || res.Count != len(c.Entries) {
				t.Errorf("%s (%s): result %+v, want broken_at %d", c.Chain, c.Description, res, c.BrokenAt)
			}
		}
	})
}

// decode parses JSON with integers as int64 (what Canon accepts).
func decode(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return intify(v)
}

// intify turns json.Number values into int64.
func intify(v any) (any, error) {
	switch x := v.(type) {
	case json.Number:
		return x.Int64()
	case map[string]any:
		for k, e := range x {
			n, err := intify(e)
			if err != nil {
				return nil, err
			}
			x[k] = n
		}
		return x, nil
	case []any:
		for i, e := range x {
			n, err := intify(e)
			if err != nil {
				return nil, err
			}
			x[i] = n
		}
		return x, nil
	default:
		return v, nil
	}
}

func TestVerifierWithHead(t *testing.T) {
	t.Parallel()
	good := func(v *chain.Verifier) {
		v.Add("1", chain.Genesis, "h1", "h1")
		v.Add("2", "h1", "h2", "h2")
		v.Add("3", "h2", "h3", "h3")
	}
	tests := []struct {
		name string
		head *chain.Head
		feed func(*chain.Verifier)
		want chain.Result
	}{
		{"matches", &chain.Head{Hash: "h3", Count: 3}, good, chain.Result{OK: true, Count: 3}},
		{"empty chain, no head", nil, func(*chain.Verifier) {}, chain.Result{OK: true}},
		{"empty chain, head of zero rows", &chain.Head{Hash: "h3", Count: 0}, func(*chain.Verifier) {}, chain.Result{OK: true}},
		{"newest rows deleted", &chain.Head{Hash: "h3", Count: 3}, func(v *chain.Verifier) {
			v.Add("1", chain.Genesis, "h1", "h1")
		}, chain.Result{Count: 1, BrokenAt: 2}},
		{"every row deleted", &chain.Head{Hash: "h3", Count: 3}, func(*chain.Verifier) {}, chain.Result{BrokenAt: 1}},
		{"row appended without the head", &chain.Head{Hash: "h2", Count: 2}, good, chain.Result{Count: 3, BrokenAt: 3, EntryID: "3"}},
		{"newest row replaced", &chain.Head{Hash: "other", Count: 3}, good, chain.Result{Count: 3, BrokenAt: 3, EntryID: "3"}},
		{"rows but no head", nil, good, chain.Result{Count: 3, BrokenAt: 3, EntryID: "3"}},
		{"earlier break wins", &chain.Head{Hash: "h3", Count: 3}, func(v *chain.Verifier) {
			v.Add("1", chain.Genesis, "h1", "bad")
		}, chain.Result{Count: 1, BrokenAt: 1, EntryID: "1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := chain.NewVerifierWithHead("", tc.head)
			tc.feed(v)
			if got := v.Result(); got != tc.want {
				t.Fatalf("Result = %+v, want %+v", got, tc.want)
			}
		})
	}
	// A verifier built without a head never looks at one.
	v := chain.NewVerifier("")
	v.Add("1", chain.Genesis, "h1", "h1")
	if got := v.Result(); !got.OK {
		t.Fatalf("NewVerifier ignores the head: %+v", got)
	}
}
