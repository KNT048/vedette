package jsonstrict

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// L1: a number that overflows float64 must not stop the repeated-key check, and a field that keeps raw
// bytes (host/api CommandRequest.Args is a json.RawMessage) must not hide a repeated key behind it.
func TestRepeatedKeyAfterOverflowingNumberIsFound(t *testing.T) {
	if Ambiguous([]byte(`{"a":1e400,"b":1,"b":2}`)) != WhyRepeated {
		t.Error(`Ambiguous missed the repeated key "b" after an overflowing number`)
	}
	var req struct {
		Args json.RawMessage `json:"args"`
	}
	if err := Decode([]byte(`{"args":{"pad":1e400},"args":{"service":"core"}}`), &req); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("Decode accepted a repeated key; args = %s: %v", req.Args, err)
	}
}

// L1: any tokenizer error other than the end of a complete value is reported, never read as clean;
// and a document nested too deep says so instead of claiming repeated keys.
func TestAmbiguousFailsClosedAndNamesDepth(t *testing.T) {
	for _, bad := range []string{`{"a":`, `{"a":1,`, `{"a" 1}`, `{"a":tru}`, `[1,,2]`, `{"a":1}}`[:0] + `{`} {
		if got := Ambiguous([]byte(bad)); got != WhyMalformed {
			t.Errorf("%q: %q", bad, got)
		}
	}
	if got := Ambiguous([]byte(`{"a":1}`)); got != "" {
		t.Errorf("clean document: %q", got)
	}
	if got := Ambiguous(nil); got != "" {
		t.Errorf("empty input: %q", got)
	}
	deep := `{"x":` + strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1) + `}`
	if got := Ambiguous([]byte(deep)); got != WhyDeep {
		t.Errorf("deep: %q", got)
	}
	var v map[string]any
	if err := Decode([]byte(deep), &v); !errors.Is(err, ErrTooDeep) || errors.Is(err, ErrAmbiguous) {
		t.Errorf("Decode deep: %v", err)
	}
	if err := Decode([]byte(`{"a":1,"a":2}`), &v); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("Decode repeated: %v", err)
	}
}

// Found by fuzzing: only JSON whitespace may surround the value. bytes.TrimSpace would also drop \v, \f
// and U+0085, which encoding/json refuses.
func TestDecodeRefusesNonJSONWhitespace(t *testing.T) {
	var v map[string]any
	for _, s := range []string{"{}\v", "\f{}", "{}\u0085", " {}"} {
		if err := Decode([]byte(s), &v); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if err := Decode([]byte(" \t\r\n{}\n "), &v); err != nil {
		t.Error(err)
	}
}
