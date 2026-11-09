package jsonstrict

// Independent review of slice 3-2 (feat/release-verify). Each test here fails on a real defect.

import (
	"encoding/json"
	"testing"
)

// Ambiguous walks the document with json.Decoder.Token, which converts every number to float64. A
// number that overflows float64 (1e400) makes Token return an error, and Ambiguous returns "" on any
// error (jsonstrict.go:60-61): it stops looking, and every repeated key after that point passes. A field
// that keeps raw bytes (json.RawMessage, like api.CommandRequest.Args in host/api/api.go:118) absorbs
// the number without converting it, so Decode then succeeds and the last "args" silently wins. The
// fix is one line: dec.UseNumber() in Ambiguous (and fail closed on a Token error other than io.EOF).
func TestReviewAmbiguousNotBlindedByOverflowingNumber(t *testing.T) {
	if Ambiguous([]byte(`{"a":1e400,"b":1,"b":2}`)) == "" {
		t.Error(`Ambiguous missed the repeated key "b" after an overflowing number`)
	}
	var req struct {
		Args json.RawMessage `json:"args"`
	}
	if err := Decode([]byte(`{"args":{"pad":1e400},"args":{"service":"core"}}`), &req); err == nil {
		t.Errorf("Decode accepted a repeated key; args = %s", req.Args)
	}
}
