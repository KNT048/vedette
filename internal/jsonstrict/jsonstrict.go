// Package jsonstrict holds the one strict-JSON rule shared by vedette-host and internal/release:
// an object may not repeat a key, may not have two keys that differ only by case (encoding/json
// matches field names case-insensitively, so a reader and the decoder would disagree on what such
// an object means), unknown fields are errors, and nothing may follow the value.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// MaxDepth is how deep objects and arrays may nest. Real documents are a handful of levels deep;
// the cap keeps the checker's stack small for a hostile input.
const MaxDepth = 32

var (
	// ErrAmbiguous means a key repeats (exactly or after case folding), or the nesting is too deep.
	ErrAmbiguous = errors.New("json: repeated key or nesting too deep")
	// ErrTrailing means data follows the JSON value.
	ErrTrailing = errors.New("json: data after the value")
	// ErrNotObject means the top-level value is not an object.
	ErrNotObject = errors.New("json: top-level value is not an object")
)

// Decode decodes one JSON object from raw into v under the strict rule above.
func Decode(raw []byte, v any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return ErrNotObject
	}
	if Ambiguous(raw) != "" {
		return ErrAmbiguous
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrTrailing
	}
	return nil
}

// Ambiguous returns a non-empty description when some JSON object in raw repeats a key (exactly
// or equal after case folding) or the nesting is deeper than MaxDepth. Malformed JSON gives "".
func Ambiguous(raw []byte) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	type frame struct {
		object bool
		seen   map[string]bool
		key    bool // next string token in an object is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		top := (*frame)(nil)
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				if len(stack) >= MaxDepth {
					return "nesting too deep"
				}
				stack = append(stack, &frame{object: true, seen: map[string]bool{}, key: true})
			case '[':
				if len(stack) >= MaxDepth {
					return "nesting too deep"
				}
				stack = append(stack, &frame{})
			default:
				stack = stack[:len(stack)-1]
				if n := len(stack); n > 0 && stack[n-1].object {
					stack[n-1].key = true // the value just ended; the next token is a key
				}
			}
			continue
		case string:
			if top != nil && top.object && top.key {
				low := Fold(t)
				if top.seen[low] {
					return "repeated key"
				}
				top.seen[low] = true
				top.key = false
				continue
			}
		}
		if top != nil && top.object && !top.key {
			top.key = true // a scalar value ended
		}
		if len(stack) == 0 {
			return ""
		}
	}
}

// Fold maps keys that encoding/json treats as the same field to the same string. json matches
// with strings.EqualFold (Unicode simple folding), under which "s" and U+017F (long s), or "k" and
// U+212A (Kelvin sign), are equal; lower-casing alone does not see that, upper-then-lower does.
func Fold(k string) string { return strings.ToLower(strings.ToUpper(k)) }
