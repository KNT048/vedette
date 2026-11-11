package ops

import (
	"strings"
	"testing"
)

func TestRunIdentity(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("a", 64)
	for _, tc := range []struct{ id, at, want string }{
		{id, "2026-11-11T10:00:00.123456789+07:00", id + "@2026-11-11T10:00:00.123456789+07:00"},
		{id, "2026-11-11T10:00:00Z", id + "@2026-11-11T10:00:00Z"},
		{id, "", id + "@"},
		{"", "2026-11-11T10:00:00Z", "@2026-11-11T10:00:00Z"},
		{"", "", ""},
		{"nothex", "yesterday", ""},
		{id + "x", "2026-11-11 10:00:00", ""},
	} {
		if got := runIdentity(tc.id, tc.at); got != tc.want {
			t.Errorf("runIdentity(%q, %q) = %q, want %q", tc.id, tc.at, got, tc.want)
		}
	}
}

func TestConntrackDeletedLine(t *testing.T) {
	t.Parallel()
	m := ctDeletedRE.FindSubmatch([]byte("conntrack v1.4.8 (conntrack-tools): 3 flow entries have been deleted.\n"))
	if m == nil || string(m[1]) != "3" {
		t.Fatalf("%q", m)
	}
	if ctDeletedRE.Match([]byte("conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.x")) == false {
		t.Error("a zero count does not match")
	}
	if ctDeletedRE.Match([]byte("conntrack: Operation failed")) {
		t.Error("a failure line matched")
	}
}
