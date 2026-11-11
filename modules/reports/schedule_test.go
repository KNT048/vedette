package reports

import (
	"testing"
	"time"
)

func TestSlotAndNextRun(t *testing.T) {
	t.Parallel()
	hcm, err := time.LoadLocation("Asia/Ho_Chi_Minh")
	if err != nil {
		t.Skip("no tzdata")
	}
	// Wednesday 2026-11-11 10:00 UTC = 17:00 in Ho Chi Minh.
	for _, c := range []struct {
		name       string
		loc        *time.Location
		day, hour  int
		slot, next string
	}{
		{"monday 08:00 utc", time.UTC, 1, 8, "2026-11-09T08:00:00.000Z", "2026-11-16T08:00:00.000Z"},
		{"today, hour already passed", time.UTC, 3, 9, "2026-11-11T09:00:00.000Z", "2026-11-18T09:00:00.000Z"},
		{"today, hour not yet", time.UTC, 3, 11, "2026-11-04T11:00:00.000Z", "2026-11-11T11:00:00.000Z"},
		{"sunday is 7", time.UTC, 7, 23, "2026-11-08T23:00:00.000Z", "2026-11-15T23:00:00.000Z"},
		{"box time zone", hcm, 3, 8, "2026-11-11T01:00:00.000Z", "2026-11-18T01:00:00.000Z"},
	} {
		if got := ts(slotAt(t0, c.loc, c.day, c.hour)); got != c.slot {
			t.Errorf("%s: slot = %s, want %s", c.name, got, c.slot)
		}
		if got := ts(nextRun(t0, c.loc, c.day, c.hour)); got != c.next {
			t.Errorf("%s: next = %s, want %s", c.name, got, c.next)
		}
	}
}

func TestNextRunIsAlwaysInTheFutureAndWithinAWeek(t *testing.T) {
	t.Parallel()
	for d := 1; d <= 7; d++ {
		for h := 0; h < 24; h++ {
			n := nextRun(t0, time.UTC, d, h)
			if !n.After(t0) || n.Sub(t0) > 7*24*time.Hour {
				t.Fatalf("day %d hour %d: next = %s", d, h, n)
			}
		}
	}
}
