package schedule

import (
	"testing"
	"time"
)

func TestWindowSpanAndLength(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("ICT", 7*3600)
	w := Window{Days: []int{1, 2, 3, 4, 5}, From: "22:00", To: "05:00"}
	if got := w.Length(); got != 7*time.Hour {
		t.Fatalf("length %v", got)
	}
	// Friday 23:30 is in the window that opened on Friday and closes on Saturday 05:00
	fri := time.Date(2026, 11, 20, 23, 30, 0, 0, loc)
	s, e, ok := w.Span(fri, loc)
	if !ok || !s.Equal(time.Date(2026, 11, 20, 22, 0, 0, 0, loc)) || !e.Equal(time.Date(2026, 11, 21, 5, 0, 0, 0, loc)) {
		t.Fatalf("span %v %v %v", s, e, ok)
	}
	// Saturday noon: the next window opens on Monday 22:00
	sat := time.Date(2026, 11, 21, 12, 0, 0, 0, loc)
	if s, _, ok := w.Span(sat, loc); !ok || !s.Equal(time.Date(2026, 11, 23, 22, 0, 0, 0, loc)) {
		t.Fatalf("next window opens %v %v", s, ok)
	}
	if _, _, ok := (Window{From: "22:00", To: "05:00"}).Span(sat, loc); ok {
		t.Fatal("a window with no day opens")
	}
	if (Window{Days: []int{1}, From: "bad", To: "05:00"}).Length() != 0 {
		t.Fatal("hours that are not valid have no length")
	}
}
