// Package chain implements the tamper-evident hash chains shared by core_audit,
// ai_activity and resp_log. One formula (D-57 (14)):
//
//	hash = lowercase hex SHA-256( prev_hash + "\n" + canon(entry) )
//
// where entry is every column of the row except hash and the DB-only seq (so prev_hash
// is inside the entry and a NULL column is null). The shared test vectors are in
// modules/core/testdata/chain_vectors.json; the TS side must produce identical bytes.
package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Genesis is the prev_hash of the first row of a chain.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// maxSafeInt is the largest integer a JavaScript number holds exactly; the TS
// side cannot reproduce larger values, so they are rejected here too.
const maxSafeInt = 1<<53 - 1

// ErrCanon is wrapped by every Canon failure.
var ErrCanon = errors.New("chain: value is not canonicalisable")

// Canon returns the canonical JSON of v: object keys sorted by Unicode code point (UTF-8 byte order),
// no whitespace, strings escaped like JavaScript JSON.stringify, null kept,
// integers only. It accepts map[string]any, []any, string, bool, nil, int and int64.
func Canon(v any) ([]byte, error) {
	var b strings.Builder
	if err := writeCanon(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func writeCanon(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		return writeString(b, x)
	case int:
		return writeInt(b, int64(x))
	case int64:
		return writeInt(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanon(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			if !utf8.ValidString(k) {
				return fmt.Errorf("%w: key is not valid UTF-8", ErrCanon)
			}
			keys = append(keys, k)
		}
		slices.Sort(keys) // byte order == code point order for valid UTF-8
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := writeCanon(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported type %T (floats are not allowed)", ErrCanon, v)
	}
	return nil
}

func writeInt(b *strings.Builder, n int64) error {
	if n > maxSafeInt || n < -maxSafeInt {
		return fmt.Errorf("%w: integer %d exceeds 2^53-1", ErrCanon, n)
	}
	b.WriteString(strconv.FormatInt(n, 10))
	return nil
}

const hexDigits = "0123456789abcdef"

// writeString escapes exactly like JavaScript JSON.stringify: only `"`, `\`
// and control characters below 0x20; <, >, &, U+2028, U+2029 and non-ASCII stay raw.
func writeString(b *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: string is not valid UTF-8", ErrCanon)
	}
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xf])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return nil
}

func hexSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// HashCanonical returns the chain hash of one row: hex SHA-256 of prev + "\n" + Canon(entry).
// entry holds every column except hash and seq. prev_hash belongs inside it: it is added here,
// and an entry that already carries a different prev_hash is an error.
func HashCanonical(prev string, entry map[string]any) (string, error) {
	if have, ok := entry["prev_hash"]; ok && have != prev {
		return "", fmt.Errorf("%w: entry prev_hash %v differs from prev %q", ErrCanon, have, prev)
	}
	full := make(map[string]any, len(entry)+1)
	maps.Copy(full, entry)
	full["prev_hash"] = prev
	c, err := Canon(full)
	if err != nil {
		return "", err
	}
	return hexSHA256(prev + "\n" + string(c)), nil
}

// Result is the outcome of a verification (API type ActivityVerify).
type Result struct {
	OK       bool
	Count    int    // rows examined
	BrokenAt int    // 1-based index of the first bad row, 0 when OK
	EntryID  string // id of that row
}

// Verifier checks rows fed in seq order. Rows after the first break are still counted.
// Built with NewVerifierWithHead it also checks the chain head (see Head).
type Verifier struct {
	expectPrev string
	res        Result
	checkHead  bool
	head       *Head
	lastID     string // id of the newest row seen
	afterHead  string // id of the row after the head's count, "" when there is none
}

// NewVerifier starts a verification that does not look at the chain head. anchor is the last pruned
// hash from core_chain_anchor, or "" for a chain that starts at Genesis.
func NewVerifier(anchor string) *Verifier {
	if anchor == "" {
		anchor = Genesis
	}
	return &Verifier{expectPrev: anchor, res: Result{OK: true}}
}

// NewVerifierWithHead is NewVerifier plus the head read from core_chain_head (nil when the table has no
// row for the chain). Result then also fails when the newest row is not the head, the row count differs from
// the head's, or rows exist but the head is missing: deleting the newest rows no longer goes unnoticed.
func NewVerifierWithHead(anchor string, head *Head) *Verifier {
	v := NewVerifier(anchor)
	v.checkHead, v.head = true, head
	return v
}

// Add feeds the next row: its stored id, prev_hash and hash, and the hash recomputed from its columns.
func (v *Verifier) Add(id, prevHash, storedHash, recomputedHash string) {
	v.res.Count++
	if v.res.OK && (prevHash != v.expectPrev || storedHash != recomputedHash) {
		v.res.OK = false
		v.res.BrokenAt = v.res.Count
		v.res.EntryID = id
	}
	v.expectPrev = storedHash
	v.lastID = id
	if v.head != nil && int64(v.res.Count) == v.head.Count+1 {
		v.afterHead = id
	}
}

// Result returns the verdict so far. A head mismatch is reported (when no row is broken before it) as:
//   - fewer rows than the head says: BrokenAt = Count+1 (the first missing row), EntryID empty;
//   - more rows than the head says: BrokenAt = head.Count+1, EntryID of that row (appended without the head);
//   - same count but another newest hash, or rows with no head at all: BrokenAt = Count, EntryID of the newest row.
func (v *Verifier) Result() Result {
	r := v.res
	if !r.OK || !v.checkHead {
		return r
	}
	n := int64(r.Count)
	switch {
	case v.head == nil && n == 0:
		return r
	case v.head == nil:
		return Result{Count: r.Count, BrokenAt: r.Count, EntryID: v.lastID}
	case n < v.head.Count:
		return Result{Count: r.Count, BrokenAt: r.Count + 1}
	case n > v.head.Count:
		return Result{Count: r.Count, BrokenAt: int(v.head.Count) + 1, EntryID: v.afterHead}
	case n == 0:
		return r
	case v.expectPrev != v.head.Hash:
		return Result{Count: r.Count, BrokenAt: r.Count, EntryID: v.lastID}
	}
	return r
}
