package core

import (
	"slices"
	"testing"
	"time"
)

func TestMaintWindowContains(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("test", 7*3600)
	at := func(day, h, m int) time.Time { return time.Date(2026, 11, day, h, m, 0, 0, loc) } // 2026-11-09 is a Monday
	same := maintWindow{Mode: windowOnly, Days: []int{1}, From: "02:00", To: "05:00"}
	cross := maintWindow{Mode: windowOnly, Days: []int{7}, From: "23:00", To: "02:00"} // Sunday night into Monday
	for _, c := range []struct {
		w    maintWindow
		t    time.Time
		want bool
	}{
		{same, at(9, 2, 0), true}, {same, at(9, 4, 59), true}, {same, at(9, 5, 0), false}, {same, at(9, 1, 59), false}, {same, at(10, 3, 0), false},
		{cross, at(8, 23, 0), true}, {cross, at(9, 1, 59), true}, {cross, at(9, 2, 0), false}, {cross, at(8, 22, 59), false}, {cross, at(9, 23, 30), false}, {cross, at(16, 0, 30), true}, {cross, at(15, 0, 30), false},
		{maintWindow{Mode: windowAlways}, at(9, 12, 0), true},
	} {
		if got := c.w.contains(c.t, loc); got != c.want {
			t.Errorf("%+v contains %v = %v, want %v", c.w, c.t, got, c.want)
		}
	}
	// The instant is read in the zone given, whatever zone it carries.
	if !same.contains(time.Date(2026, 11, 8, 19, 0, 0, 0, time.UTC), loc) { // Monday 02:00 at +07:00
		t.Error("an instant in another zone was read in that zone")
	}
}

func TestMaintWindowNextStartStaysInsideWhatTheHostAccepts(t *testing.T) {
	t.Parallel()
	loc := time.UTC
	w := maintWindow{Mode: windowOnly, Days: []int{1, 3}, From: "02:00", To: "05:00"}
	// One minute before Monday 02:00 is too soon for the host (60 s minimum, 2 minutes here): Wednesday.
	now := time.Date(2026, 11, 9, 1, 59, 0, 0, loc)
	got, ok := w.nextStart(now, loc)
	if !ok || !got.Equal(time.Date(2026, 11, 11, 2, 0, 0, 0, loc)) {
		t.Errorf("nextStart = %v %v", got, ok)
	}
	// A window whose only start is next Monday is just beyond the 7 days the host accepts: none.
	only := maintWindow{Mode: windowOnly, Days: []int{1}, From: "02:00", To: "05:00"}
	if got, ok := only.nextStart(now, loc); ok {
		t.Errorf("nextStart = %v, want none (more than 7 days ahead)", got)
	}
	// Ten minutes before is fine.
	now = time.Date(2026, 11, 9, 1, 50, 0, 0, loc)
	if got, ok := w.nextStart(now, loc); !ok || !got.Equal(time.Date(2026, 11, 9, 2, 0, 0, 0, loc)) {
		t.Errorf("nextStart = %v %v", got, ok)
	}
	if _, ok := (maintWindow{Mode: windowAlways}).nextStart(now, loc); ok {
		t.Error("an any-time window has no start")
	}
}

func TestMaintWindowNormalize(t *testing.T) {
	t.Parallel()
	stored := maintWindow{Mode: windowAlways, Days: []int{2}, From: "01:00", To: "03:00"}
	got, err := maintWindow{Mode: windowOnly, Days: []int{5, 1, 5}, From: "23:00", To: "02:00"}.normalize(stored)
	if err != nil || got.Mode != windowOnly || !slices.Equal(got.Days, []int{1, 5}) {
		t.Errorf("normalize = %+v %v", got, err)
	}
	if got, err := (maintWindow{Mode: windowAlways}).normalize(stored); err != nil || got.From != "01:00" || got.Mode != windowAlways {
		t.Errorf("always = %+v %v", got, err)
	}
	for name, w := range map[string]maintWindow{
		"mode": {Mode: "x"}, "days": {Mode: windowOnly, From: "01:00", To: "02:00"}, "day 0": {Mode: windowOnly, Days: []int{0}, From: "01:00", To: "02:00"},
		"time": {Mode: windowOnly, Days: []int{1}, From: "1:00", To: "02:00"}, "empty": {Mode: windowOnly, Days: []int{1}, From: "01:00", To: "01:00"},
	} {
		if _, err := w.normalize(stored); err == nil || err.Status != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
}
