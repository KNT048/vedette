package ai

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// This file is the one hash-chain formula for core_audit, ai_activity and resp_log (D-57, item 14):
//
//	hash = hex(SHA-256(prev_hash + "\n" + canonical JSON of the entry without its "hash" field))
//
// The entry still carries its own "prev_hash", so the previous link is part of what is signed. The first
// entry of a chain has prev_hash = Genesis. Canonical JSON: object keys sorted ascending (by byte), no
// white space, strings escaped exactly like JavaScript's JSON.stringify (so the TypeScript mock and any
// offline verifier agree), null kept, numbers integers only. Keep columns that must not be hashed (a
// sequence number) out of the struct with `json:"-"`.
//
// ponytail: it lives in the ai package because core does not exist yet; it should move to core
// (core/chain) when core exists, and core_audit and resp_log should import it from there.

// Genesis is the prev_hash of the first entry of a chain: 64 zeros.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// ErrCanonical means a value cannot be written in canonical form (a non-integer number, or a number a
// JavaScript verifier could not read exactly).
var ErrCanonical = errors.New("ai: value has no canonical JSON form")

// ErrChainLink means an entry's prev_hash is missing or is not the hash it was chained to.
var ErrChainLink = errors.New("ai: entry does not carry the prev_hash it is chained to")

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// HashContent returns the lowercase hex SHA-256 of s, used for input_hash and output_hash: the content
// itself is never stored, only this hash (INV-17).
func HashContent(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Canonical returns the canonical JSON of v (a struct, map or slice that encoding/json can marshal).
func Canonical(v any) ([]byte, error) { return canonical(v, "") }

// ChainHash returns the hash of entry given the hash of the previous entry. entry is marshalled to JSON;
// it must be an object that carries "prev_hash" equal to prev. Its "hash" field, if any, is ignored.
func ChainHash(prev string, entry any) (string, error) {
	if !hashRE.MatchString(prev) {
		return "", fmt.Errorf("%w: prev_hash must be 64 lowercase hex characters", ErrChainLink)
	}
	canon, err := canonical(entry, "hash")
	if err != nil {
		return "", err
	}
	var probe struct {
		Prev *string `json:"prev_hash"`
	}
	if err := json.Unmarshal(canon, &probe); err != nil || probe.Prev == nil || *probe.Prev != prev {
		return "", ErrChainLink
	}
	return HashContent(prev + "\n" + string(canon)), nil
}

func canonical(v any, drop string) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("ai: canonical JSON: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return nil, fmt.Errorf("ai: canonical JSON: %w", err)
	}
	if drop != "" {
		m, ok := x.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: an entry must be a JSON object", ErrCanonical)
		}
		delete(m, drop)
	}
	var b bytes.Buffer
	if err := writeCanonical(&b, x); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

const maxSafeInt = 1<<53 - 1 // largest integer JavaScript represents exactly

func writeCanonical(b *bytes.Buffer, x any) error {
	switch v := x.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case json.Number:
		n, err := strconv.ParseInt(v.String(), 10, 64)
		if err != nil || n > maxSafeInt || n < -maxSafeInt {
			return fmt.Errorf("%w: number %s", ErrCanonical, v)
		}
		b.WriteString(strconv.FormatInt(n, 10))
	case string:
		writeJSString(b, v)
	case []any:
		b.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, v[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("%w: unexpected %T", ErrCanonical, x)
	}
	return nil
}

// writeJSString writes s like JSON.stringify: quote, backslash and the C0 controls are escaped (\b \f \n \r \t
// or a lowercase six-character escape); everything else, including <, >, & and U+2028, is written as is.
func writeJSString(b *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			b.WriteString("\\" + "u00")
			b.WriteByte(hexDigits[r>>4])
			b.WriteByte(hexDigits[r&0xf])
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// sensitiveKey matches names of fields whose values must not appear in a summary.
var sensitiveKey = regexp.MustCompile(`(?i)pass|secret|token|key|auth|cookie|credential|private|bearer|session`)

// sensitivePair matches key=value or key: value text where the key looks sensitive.
var sensitivePair = regexp.MustCompile(`(?i)\b([\w-]*(?:pass|secret|token|key|auth|cookie|credential|private|bearer|session)[\w-]*)\s*[:=]\s*("[^"]*"|\S+)`)

const maxArgsSummary = 120

// SummarizeArgs shortens a tool call's arguments for the activity log and removes secrets (INV-17): JSON
// values under sensitive-looking keys, and key=value pairs in plain text, become [redacted]. The result is at
// most 120 characters.
func SummarizeArgs(raw string) string {
	s := strings.TrimSpace(raw)
	var x any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if dec.Decode(&x) == nil && !dec.More() {
		if out, err := writeRedacted(x); err == nil {
			s = out
		}
	} else {
		s = sensitivePair.ReplaceAllString(s, "$1=[redacted]")
	}
	if r := []rune(s); len(r) > maxArgsSummary {
		s = string(r[:maxArgsSummary-3]) + "..."
	}
	return s
}

func writeRedacted(x any) (string, error) {
	var redact func(any) any
	redact = func(v any) any {
		switch t := v.(type) {
		case map[string]any:
			out := make(map[string]any, len(t))
			for k, e := range t {
				if sensitiveKey.MatchString(k) {
					out[k] = "[redacted]"
				} else {
					out[k] = redact(e)
				}
			}
			return out
		case []any:
			out := make([]any, len(t))
			for i, e := range t {
				out[i] = redact(e)
			}
			return out
		}
		return v
	}
	var b bytes.Buffer
	err := writeLoose(&b, redact(x))
	return b.String(), err
}

// writeLoose is writeCanonical without the integer restriction: a summary is for people, not for hashing.
func writeLoose(b *bytes.Buffer, x any) error {
	if n, ok := x.(json.Number); ok {
		b.WriteString(n.String())
		return nil
	}
	switch v := x.(type) {
	case []any:
		b.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeLoose(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSString(b, k)
			b.WriteByte(':')
			if err := writeLoose(b, v[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
		return nil
	}
	return writeCanonical(b, x)
}
