package api

import (
	"strings"
	"testing"
)

func TestValidHostname(t *testing.T) {
	t.Parallel()
	label63 := strings.Repeat("a", 63)
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"vedette", true},
		{"box-01", true},
		{"Box01.corp.example", true},
		{"1box", true},
		{"a", true},
		{label63, true},
		{label63[:31] + "." + label63[:32], true}, // 64 bytes
		{"", false},
		{label63 + "a", false}, // a 64-byte label
		{label63[:32] + "." + label63[:32], false}, // 65 bytes
		{"-box", false},
		{"box-", false},
		{"box.", false},
		{".box", false},
		{"bo..x", false},
		{"bo_x", false},
		{"bo x", false},
		{"box\n", false},
		{"box\x00", false},
		{"bo" + string(rune(0x200b)) + "x", false}, // a zero-width space
		{"hộp", false},
		{"box;id", false},
		{"<box>", false},
	} {
		if got := ValidHostname(tc.in); got != tc.want {
			t.Errorf("ValidHostname(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func FuzzValidHostname(f *testing.F) {
	f.Add("vedette")
	f.Add("a.b-c.d")
	f.Add("bad name\n")
	f.Fuzz(func(t *testing.T, s string) {
		if !ValidHostname(s) {
			return
		}
		if len(s) > MaxHostname {
			t.Fatalf("too long: %q", s)
		}
		for _, r := range s {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '.' {
				t.Fatalf("unsafe character in %q", s)
			}
		}
	})
}
