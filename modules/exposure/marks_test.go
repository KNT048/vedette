package exposure

import "testing"

// The plain columns of migration 0003 take only the values their SQL CHECK would have allowed: a timestamp of store.FormatTS for
// opened_at, 0 or 1 for exploited. Anything else is refused before it is written.
func TestMarksRefuseABadValue(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"2026-11-28T09:30:00.000Z", "1999-01-01T00:00:00.123Z"} {
		if got, err := openedAt(ok); err != nil || got != ok {
			t.Errorf("openedAt(%q) = %q, %v", ok, got, err)
		}
	}
	for _, bad := range []string{"", "2026-11-28", "2026-11-28T09:30:00Z", "2026-11-28 09:30:00.000Z", "2026-11-28T09:30:00.000+07:00", "yesterday"} {
		if _, err := openedAt(bad); err == nil {
			t.Errorf("openedAt(%q) was accepted", bad)
		}
	}
	for _, ok := range []int{0, 1} {
		if got, err := exploitedMark(ok); err != nil || got != ok {
			t.Errorf("exploitedMark(%d) = %d, %v", ok, got, err)
		}
	}
	for _, bad := range []int{-1, 2, 7} {
		if _, err := exploitedMark(bad); err == nil {
			t.Errorf("exploitedMark(%d) was accepted", bad)
		}
	}
}
