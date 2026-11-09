package jsonstrict

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	type doc struct {
		A int `json:"a"`
		B struct {
			C string `json:"c"`
		} `json:"b"`
	}
	ok := []string{`{}`, `{"a":1}`, ` {"a":1,"b":{"c":"x"}} `, "{\"a\":1}\n"}
	for _, s := range ok {
		var d doc
		if err := Decode([]byte(s), &d); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	bad := map[string]error{
		`{"a":1,"a":2}`:           ErrAmbiguous,
		`{"a":1,"A":2}`:           ErrAmbiguous,
		`{"b":{"c":"x","C":"y"}}`: ErrAmbiguous,
		"{\"k\":1,\"K\":2}":       ErrAmbiguous, // Kelvin sign folds to k
		`{"s":1,"ſ":2}`:           ErrAmbiguous, // long s folds to s
		`{"x":[{"a":1,"a":1}]}`:   ErrAmbiguous,
		`{"a":1} {"a":2}`:         ErrTrailing,
		`{"a":1}x`:                ErrTrailing,
		`[]`:                      ErrNotObject,
		`null`:                    ErrNotObject,
		``:                        ErrNotObject,
		`{"zzz":1}`:               nil, // unknown field: a decoder error, checked below
		`{"a":"s"}`:               nil, // wrong type
		`{"a":`:                   nil, // truncated
		`{"x":` + strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1) + `}`: ErrTooDeep,
	}
	for s, want := range bad {
		var d doc
		err := Decode([]byte(s), &d)
		if err == nil || (want != nil && !errors.Is(err, want)) {
			t.Errorf("%q: got %v, want %v", s, err, want)
		}
	}
	// the same key in different objects is fine
	var v map[string]any
	if err := Decode([]byte(`{"a":{"x":1},"b":{"x":2}}`), &v); err != nil {
		t.Error(err)
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{`{}`, `{"a":1,"A":2}`, `{"a":{"b":[1,{"c":null}]}}`, `{"k":1,"K":2}`, `[`, `{"a":1}x`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var v map[string]any
		if err := Decode(b, &v); err != nil {
			return
		}
		// accepted: encoding/json must agree, and no two top-level keys may fold together
		var w map[string]any
		if json.Unmarshal(b, &w) != nil {
			t.Fatalf("accepted what encoding/json refuses: %q", b)
		}
		seen := map[string]bool{}
		for k := range v {
			if seen[Fold(k)] {
				t.Fatalf("folded duplicate accepted: %q", b)
			}
			seen[Fold(k)] = true
		}
	})
}
