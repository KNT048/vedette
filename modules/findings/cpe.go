// Package findings holds the pure logic of the findings module: CPE and version
// handling, matching KEV entries against an asset's software, and the finding
// lifecycle. It does no I/O and touches no database; the module service wraps it.
//
// Everything here treats its input as untrusted (software strings from agents,
// CPEs and version ranges from feeds): parsers are fail-closed and size-limited.
package findings

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidCPE is returned (wrapped) for a CPE 2.3 formatted string that is
// malformed, too long or uses characters the format does not allow.
var ErrInvalidCPE = errors.New("invalid CPE 2.3 formatted string")

const (
	cpePrefix = "cpe:2.3:"
	maxCPELen = 1024
)

// Kind says how an attribute of a CPE is bound (NISTIR 7695 section 5.3.3).
type Kind uint8

const (
	// Any is the logical value ANY, written "*".
	Any Kind = iota
	// NA is the logical value NA ("not applicable"), written "-".
	NA
	// Value is a literal string, possibly with leading/trailing wildcards.
	Value
)

// Attr is one CPE attribute. For Kind Value, Value is canonical: lower case,
// every character outside [a-z0-9_.-] backslash-quoted, wildcards ('*', '?')
// unquoted. Use Literal to get the plain text back.
type Attr struct {
	Kind  Kind
	Value string
}

// CPE is a parsed CPE 2.3 name.
type CPE struct {
	Part, Vendor, Product, Version, Update, Edition Attr
	Language, SWEdition, TargetSW, TargetHW, Other  Attr
}

func (c *CPE) fields() [11]*Attr {
	return [11]*Attr{&c.Part, &c.Vendor, &c.Product, &c.Version, &c.Update, &c.Edition,
		&c.Language, &c.SWEdition, &c.TargetSW, &c.TargetHW, &c.Other}
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// ParseCPE parses a CPE 2.3 formatted string such as
// "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*".
// Only printable ASCII is accepted. Wildcards inside a value are allowed only as
// leading or trailing runs, as NVD uses them.
func ParseCPE(s string) (CPE, error) {
	var c CPE
	if len(s) > maxCPELen {
		return c, fmt.Errorf("findings: parsing CPE: %w: longer than %d bytes", ErrInvalidCPE, maxCPELen)
	}
	parts, err := splitCPE(s)
	if err != nil {
		return c, fmt.Errorf("findings: parsing CPE: %w: %w", ErrInvalidCPE, err)
	}
	if len(parts) != 13 || parts[0] != "cpe" || parts[1] != "2.3" {
		return c, fmt.Errorf("findings: parsing CPE: %w: want cpe:2.3 and 11 attributes", ErrInvalidCPE)
	}
	for i, f := range c.fields() {
		a, err := parseAttr(parts[i+2])
		if err != nil {
			return CPE{}, fmt.Errorf("findings: parsing CPE: %w: attribute %d: %w", ErrInvalidCPE, i+1, err)
		}
		*f = a
	}
	if c.Part.Kind == Value && c.Part.Value != "a" && c.Part.Value != "o" && c.Part.Value != "h" {
		return CPE{}, fmt.Errorf("findings: parsing CPE: %w: part must be a, o or h", ErrInvalidCPE)
	}
	return c, nil
}

// splitCPE splits on unescaped ':' and rejects anything but printable ASCII.
func splitCPE(s string) ([]string, error) {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b < 0x21 || b > 0x7e:
			return nil, errors.New("character outside printable ASCII")
		case b == '\\':
			if i+1 >= len(s) {
				return nil, errors.New("trailing backslash")
			}
			i++
			if s[i] < 0x21 || s[i] > 0x7e {
				return nil, errors.New("character outside printable ASCII")
			}
		case b == ':':
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:]), nil
}

type item struct {
	b    byte
	wild bool
}

func parseAttr(raw string) (Attr, error) {
	switch raw {
	case "":
		return Attr{}, errors.New("empty attribute")
	case "*":
		return Attr{Kind: Any}, nil
	case "-":
		return Attr{Kind: NA}, nil
	}
	items := make([]item, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		switch {
		case b == '\\':
			i++ // splitCPE guarantees a printable byte follows
			n := raw[i]
			if isAlnum(n) || n == '_' {
				return Attr{}, errors.New("backslash before an unreserved character")
			}
			items = append(items, item{b: n})
		case b == '*' || b == '?':
			items = append(items, item{b: b, wild: true})
		case isAlnum(b) || b == '_' || b == '.' || b == '-':
			items = append(items, item{b: b})
		default:
			return Attr{}, fmt.Errorf("unquoted special character %q", b)
		}
	}
	if !wildcardsAtEnds(items) {
		return Attr{}, errors.New("wildcard inside a value")
	}
	var sb strings.Builder
	for _, it := range items {
		if it.wild {
			sb.WriteByte(it.b)
			continue
		}
		b := it.b
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if isAlnum(b) || b == '_' || b == '.' || b == '-' {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('\\')
			sb.WriteByte(b)
		}
	}
	v := sb.String()
	if v == "-" { // a literal hyphen alone must stay distinct from NA
		v = `\-`
	}
	return Attr{Kind: Value, Value: v}, nil
}

// wildcardsAtEnds reports whether all wildcards sit in a leading or trailing run.
func wildcardsAtEnds(items []item) bool {
	i := 0
	for i < len(items) && items[i].wild {
		i++
	}
	j := len(items)
	for j > i && items[j-1].wild {
		j--
	}
	for _, it := range items[i:j] {
		if it.wild {
			return false
		}
	}
	return true
}

// String returns the canonical formatted string. ParseCPE(c.String()) == c.
func (c CPE) String() string {
	var sb strings.Builder
	sb.WriteString(cpePrefix)
	for i, f := range c.fields() {
		if i > 0 {
			sb.WriteByte(':')
		}
		switch f.Kind {
		case Any:
			sb.WriteByte('*')
		case NA:
			sb.WriteByte('-')
		default:
			sb.WriteString(f.Value)
		}
	}
	return sb.String()
}

// Literal returns the unquoted text of a Value attribute. ok is false for ANY,
// NA and values that contain wildcards.
func (a Attr) Literal() (string, bool) {
	if a.Kind != Value {
		return "", false
	}
	var sb strings.Builder
	for i := 0; i < len(a.Value); i++ {
		switch b := a.Value[i]; b {
		case '\\':
			if i++; i >= len(a.Value) {
				return "", false // malformed hand-built value: dangling backslash
			}
			sb.WriteByte(a.Value[i])
		case '*', '?':
			return "", false
		default:
			sb.WriteByte(b)
		}
	}
	return sb.String(), true
}

// attrMatch reports whether the configuration attribute c covers the target
// attribute t (NISTIR 7696 "superset or equal"): ANY covers everything, NA covers
// only NA, a value covers equal values (case-insensitive, with wildcards in c).
// A target that is broader than the configuration (ANY, NA, or a pattern that is
// not identical) never matches.
func attrMatch(c, t Attr) bool {
	switch c.Kind {
	case Any:
		return true
	case NA:
		return t.Kind == NA
	}
	if t.Kind != Value {
		return false
	}
	if c.Value == t.Value {
		return true
	}
	if hasWildcard(t.Value) {
		return false
	}
	return wildMatch(c.Value, t.Value)
}

// Matches reports whether configuration cpe c covers every attribute of the
// target cpe t. The target is normally a CPE of installed software.
func (c CPE) Matches(t CPE) bool {
	cf, tf := c.fields(), t.fields()
	for i := range cf {
		if !attrMatch(*cf[i], *tf[i]) {
			return false
		}
	}
	return true
}

// SameProduct reports whether c covers t on part, vendor and product only,
// ignoring version and the remaining attributes.
func (c CPE) SameProduct(t CPE) bool {
	return attrMatch(c.Part, t.Part) && attrMatch(c.Vendor, t.Vendor) && attrMatch(c.Product, t.Product)
}

// wildMatch matches a canonical pattern (wildcards unquoted) against a canonical
// literal. '*' matches any run, '?' any single character.
func wildMatch(pattern, text string) bool {
	type tok struct {
		b    byte
		kind byte // 0 literal, '*', '?'
	}
	var p []tok
	for i := 0; i < len(pattern); i++ {
		switch b := pattern[i]; b {
		case '\\':
			if i+1 < len(pattern) { // a dangling backslash (hand-built value) stays literal
				i++
			}
			p = append(p, tok{b: pattern[i]})
		case '*', '?':
			p = append(p, tok{kind: b})
		default:
			p = append(p, tok{b: b})
		}
	}
	var t []byte
	for i := 0; i < len(text); i++ {
		if text[i] == '\\' && i+1 < len(text) {
			i++
		}
		t = append(t, text[i])
	}
	// dp[j]: p[:i] matches t[:j]
	dp := make([]bool, len(t)+1)
	dp[0] = true
	for _, pt := range p {
		next := make([]bool, len(t)+1)
		if pt.kind == '*' {
			next[0] = dp[0]
		}
		for j := 1; j <= len(t); j++ {
			switch pt.kind {
			case '*':
				next[j] = next[j-1] || dp[j]
			case '?':
				next[j] = dp[j-1]
			default:
				next[j] = dp[j-1] && t[j-1] == pt.b
			}
		}
		dp = next
	}
	return dp[len(t)]
}

// hasWildcard reports whether a canonical value contains an unquoted wildcard.
func hasWildcard(v string) bool {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			i++
		case '*', '?':
			return true
		}
	}
	return false
}
