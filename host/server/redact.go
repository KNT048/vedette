package server

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/chain"
)

// Bounds of args_redacted in an audit line (spec section 9): the audit file must not grow
// because a caller sends a huge args object.
const (
	redactMaxDepth   = 6
	redactMaxItems   = 32
	redactMaxString  = 256
	redactMaxCanon   = 4096
	redactedMarker   = "[redacted]"
	truncatedMarker  = "[truncated]"
	minTokenLen      = 20
	tokenEntropyBits = 3.5
)

var (
	sensitiveKeyRE = regexp.MustCompile(`(?i)(pass|secret|token|key|auth|cred|private|cookie|session|signature|bearer)`)
	jwtRE          = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
	tokenCharsRE   = regexp.MustCompile(`^[A-Za-z0-9+/=_.~-]+$`)
)

var secretPrefixes = []string{
	"bearer ", "basic ", "vdt_", "xapp-", "xoxb-", "xoxp-", "xoxa-", "xoxs-", "sk-", "ghp_", "gho_", "ghs_", "ghu_",
	"github_pat_", "glpat-", "akia", "asia", "-----begin", "ssh-rsa ", "ssh-ed25519 ", "age-secret-key-",
}

// looksSecret reports whether a string value looks like a key or token. It errs on the side of
// redacting: the commands take no secrets, so a hit means something is wrong or hostile.
func looksSecret(s string) bool {
	low := strings.ToLower(s)
	for _, p := range secretPrefixes {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	switch {
	case strings.Contains(low, "-----begin") || strings.Contains(low, "password=") || strings.Contains(low, "authorization:") || strings.Contains(low, "bearer "):
		return true
	case jwtRE.MatchString(s):
		return true
	case len(s) < minTokenLen || !tokenCharsRE.MatchString(s):
		return false
	}
	// A long run of base64/url-safe characters that mixes digits, lower and upper case.
	var digit, lower, upper bool
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		}
	}
	return digit && lower && upper && entropy(s) >= tokenEntropyBits
}

func entropy(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// redactArgs returns args_redacted for the audit line: the args with every value that looks like a
// key or token replaced, strings, arrays, objects and depth bounded, and the result always
// canonicalisable by core/chain. Input that is not JSON gives nil.
func redactArgs(raw []byte) any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	out := redactValue(v, 0)
	if c, err := chain.Canon(out); err != nil || len(c) > redactMaxCanon {
		return map[string]any{"truncated": true}
	}
	return out
}

func redactValue(v any, depth int) any {
	if depth > redactMaxDepth {
		return truncatedMarker
	}
	switch x := v.(type) {
	case nil, bool:
		return x
	case json.Number:
		if n, err := x.Int64(); err == nil && n <= 1<<53-1 && n >= -(1<<53-1) {
			return n
		}
		return "[number]"
	case string:
		switch {
		case looksSecret(x):
			return redactedMarker
		case !utf8.ValidString(x):
			return "[invalid text]"
		case len(x) > redactMaxString:
			return truncatedMarker
		}
		return x
	case []any:
		out := make([]any, 0, min(len(x), redactMaxItems+1))
		for i, e := range x {
			if i == redactMaxItems {
				out = append(out, truncatedMarker)
				break
			}
			out = append(out, redactValue(e, depth+1))
		}
		return out
	case map[string]any:
		keys := sortedKeys(x)
		out := make(map[string]any, min(len(keys), redactMaxItems+1))
		for i, k := range keys {
			if i == redactMaxItems {
				out["_truncated"] = true
				break
			}
			ck := k
			if !utf8.ValidString(ck) || len(ck) > 64 {
				ck = "[key]"
			}
			if looksSecret(k) { // a key can carry the secret too
				ck = fmt.Sprintf("[redacted-key-%d]", i)
			}
			if sensitiveKeyRE.MatchString(k) && !isPlain(x[k]) {
				out[ck] = redactedMarker
				continue
			}
			out[ck] = redactValue(x[k], depth+1)
		}
		return out
	}
	return "[unsupported]"
}

// isPlain reports a value that cannot hold a secret: nothing, an empty string, a boolean or a
// number. A flag such as include_secrets must stay readable in the audit line.
func isPlain(v any) bool {
	switch x := v.(type) {
	case nil, bool, json.Number:
		return true
	case string:
		return x == ""
	}
	return false
}
