// Package debver compares Debian package versions ("1:9.6p1-3ubuntu13.5") the way dpkg does (D-516): Debian Policy
// §5.6.12, https://www.debian.org/doc/debian-policy/ch-controlfields.html#version . It is a pure function on text a
// device or a feed sent, so a version that is not well formed is refused, never guessed.
package debver

import (
	"errors"
	"strings"
)

// MaxLen bounds a version: the inventory stores at most 100 characters of a package version.
const MaxLen = 100

// ErrInvalid is a version that is not a Debian version.
var ErrInvalid = errors.New("debver: not a Debian version")

type version struct {
	epoch    uint64
	upstream string
	revision string
}

// parse splits [epoch:]upstream[-revision] and checks each part's characters. The upstream part must start with a
// digit (Policy: "should"; every Ubuntu and Debian archive version does), may hold a colon only with an epoch and a
// hyphen only with a revision.
func parse(s string) (version, error) {
	var v version
	if s == "" || len(s) > MaxLen {
		return v, ErrInvalid
	}
	rest := s
	if i := strings.IndexByte(s, ':'); i >= 0 {
		e := s[:i]
		if e == "" || len(e) > 9 {
			return v, ErrInvalid
		}
		for _, c := range []byte(e) {
			if c < '0' || c > '9' {
				return v, ErrInvalid
			}
			v.epoch = v.epoch*10 + uint64(c-'0')
		}
		rest = s[i+1:]
	}
	v.upstream = rest
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		v.upstream, v.revision = rest[:i], rest[i+1:]
		if v.revision == "" {
			return v, ErrInvalid
		}
	}
	if v.upstream == "" || v.upstream[0] < '0' || v.upstream[0] > '9' {
		return v, ErrInvalid
	}
	for _, c := range []byte(v.upstream) {
		if !alnum(c) && !strings.ContainsRune(".+~-:", rune(c)) {
			return v, ErrInvalid
		}
	}
	for _, c := range []byte(v.revision) {
		if !alnum(c) && !strings.ContainsRune(".+~", rune(c)) {
			return v, ErrInvalid
		}
	}
	return v, nil
}

// Valid reports whether s is a Debian version Compare accepts.
func Valid(s string) bool {
	_, err := parse(s)
	return err == nil
}

// Compare returns -1, 0 or +1 as a is lower than, equal to or higher than b in dpkg's order ("dpkg
// --compare-versions"). Either version not well formed is ErrInvalid.
func Compare(a, b string) (int, error) {
	va, err := parse(a)
	if err != nil {
		return 0, err
	}
	vb, err := parse(b)
	if err != nil {
		return 0, err
	}
	switch {
	case va.epoch < vb.epoch:
		return -1, nil
	case va.epoch > vb.epoch:
		return 1, nil
	}
	if c := part(va.upstream, vb.upstream); c != 0 {
		return c, nil
	}
	return part(va.revision, vb.revision), nil
}

func alnum(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func digit(c byte) bool { return c >= '0' && c <= '9' }

// order is the weight of one non-digit character: '~' before the end of the part, the end before letters, letters
// before every other character (Policy §5.6.12).
func order(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case digit(c):
		return 0
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

// part compares an upstream or revision part: alternately the longest non-digit prefix, character by character with
// order, and the longest digit prefix, as a number (an empty one is 0).
func part(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !digit(a[i]) || j < len(b) && !digit(b[j]) {
			ac, bc := order(a, i), order(b, j)
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		first := 0
		for i < len(a) && digit(a[i]) && j < len(b) && digit(b[j]) {
			if first == 0 {
				first = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && digit(a[i]) {
			return 1
		}
		if j < len(b) && digit(b[j]) {
			return -1
		}
		if first != 0 {
			return sign(first)
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
