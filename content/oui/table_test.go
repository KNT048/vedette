package oui

// Checks on the committed table itself (the lookup is tested in oui_test.go): what `make oui` writes must be clean.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

type rawRow struct{ prefix, bits, vendor string }

func rawRows(t *testing.T) []rawRow {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var out []rawRow
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		p := strings.SplitN(sc.Text(), "\t", 3)
		if len(p) != 3 {
			t.Fatalf("line %q is not three columns", sc.Text())
		}
		out = append(out, rawRow{p[0], p[1], p[2]})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// invisibleOrBidi is what the sensor's printable() refuses: controls, line separators and every invisible format
// character (Unicode Cf: bidirectional marks, zero-width, BOM, word joiner, soft hyphen, tags).
func invisibleOrBidi(r rune) bool {
	switch {
	case r >= 0x7f && r <= 0x9f, r == 0x2028, r == 0x2029, r >= 0xe0000 && r <= 0xe007f, unicode.Is(unicode.Cf, r):
		return true
	}
	return r < 0x20
}

// The vendor goes from this table to the inventory as text a person reads (INV-3): `make oui` cleans it, and this
// test keeps a rebuilt table honest.
func TestEveryVendorIsCleanText(t *testing.T) {
	t.Parallel()
	bad := 0
	for _, r := range rawRows(t) {
		v := r.vendor
		var why string
		switch {
		case v == "" || utf8.RuneCountInString(v) > 200 || len(v) > 200:
			why = "length"
		case !utf8.ValidString(v):
			why = "utf-8"
		case strings.ContainsFunc(v, invisibleOrBidi):
			why = "control/bidi/invisible"
		case v != strings.TrimSpace(v):
			why = "leading/trailing space"
		case strings.ContainsFunc(v, unicode.IsSpace) && strings.ContainsFunc(v, func(r rune) bool { return unicode.IsSpace(r) && r != ' ' }):
			why = "non-ASCII space"
		}
		if why != "" {
			bad++
			if bad <= 20 {
				t.Errorf("%s/%s: %s: %q", r.prefix, r.bits, why, v)
			}
		}
	}
	if bad > 0 {
		t.Errorf("%d vendor strings are not clean", bad)
	}
}

// One row per prefix: load() keeps the last of two, so a duplicate would make the vendor depend on file order.
func TestNoPrefixTwice(t *testing.T) {
	t.Parallel()
	seen := map[string]string{}
	for _, r := range rawRows(t) {
		k := r.prefix + "/" + r.bits
		if old, ok := seen[k]; ok {
			t.Errorf("prefix %s twice: %q and %q (load keeps whichever comes last)", k, old, r.vendor)
		}
		seen[k] = r.vendor
	}
}
