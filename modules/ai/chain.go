package ai

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/knt048/vedette/core/chain"
)

// The hash chain itself (canonical JSON and the formula of D-57 item 14) lives in core/chain and is shared with
// core_audit and resp_log. This file keeps only what is specific to the AI log: hashing the content that is not
// stored, and summarising tool arguments without secrets.

// Genesis is the prev_hash of the first entry of a chain.
const Genesis = chain.Genesis

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// HashContent returns the lowercase hex SHA-256 of s, used for input_hash and output_hash: the content
// itself is never stored, only this hash (INV-17).
func HashContent(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sensitiveKey matches names of fields whose values must not appear in a summary.
var sensitiveKey = regexp.MustCompile(`(?i)pass|secret|token|key|auth|cookie|credential|private|bearer|session`)

var (
	// scheme://user:password@host: the user info is removed.
	urlUserinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/\s@"']+@`)
	// Authorization values: "Bearer <token>" and "Basic <token>" are one value, not a word and a secret.
	authScheme = regexp.MustCompile(`(?i)\b(bearer|basic|digest|negotiate)\s+[A-Za-z0-9._~+/=:-]+`)
	// key=value or key: value where the key looks sensitive (--password=x, api_key: "x", token=x).
	sensitivePair = regexp.MustCompile(`(?i)([\w-]*(?:pass|secret|token|key|auth|cookie|credential|private|bearer|session)[\w-]*)\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;&"']+)`)
)

// scrubText removes secrets from free text: URL user info, Authorization values and sensitive key=value pairs.
func scrubText(s string) string {
	s = urlUserinfo.ReplaceAllString(s, "${1}[redacted]@")
	s = authScheme.ReplaceAllString(s, "$1 [redacted]")
	return sensitivePair.ReplaceAllString(s, "$1=[redacted]")
}

const maxArgsSummary = 120

// SummarizeArgs shortens a tool call's arguments for the activity log and removes secrets (INV-17, FORBID-4).
// JSON: values under sensitive-looking keys are replaced, and every string value, whatever its key, is scrubbed
// like free text. Plain text is scrubbed the same way. Scrubbing runs before the text is shortened. The result
// is at most 120 characters.
func SummarizeArgs(raw string) string {
	s := strings.TrimSpace(raw)
	var x any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if dec.Decode(&x) == nil && !dec.More() {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if enc.Encode(redactTree(x)) == nil {
			s = strings.TrimSuffix(b.String(), "\n")
		}
	} else {
		s = scrubText(s)
	}
	if r := []rune(s); len(r) > maxArgsSummary {
		s = string(r[:maxArgsSummary-3]) + "..."
	}
	return s
}

func redactTree(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			if sensitiveKey.MatchString(k) {
				out[k] = "[redacted]"
			} else {
				out[k] = redactTree(e)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = redactTree(e)
		}
		return out
	case string:
		return scrubText(t)
	}
	return v
}
