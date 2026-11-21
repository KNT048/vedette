package sensoractive

import (
	"context"
	"testing"
	"time"
)

// INV-21, review #857 L2: inside an open window every run gets that window's own end; outside it only the runs of a person's sweep
// (ctx marked by withManualUntil) see the end of its hour, never the box's own runs (rounds, queue, SNMP).
func TestWindowNowIsNeverLengthenedByAManualRun(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 9, 4, 50, 0, 0, time.UTC) // Monday 04:50, inside 01:00 to 05:00
	s := &Service{clock: func() time.Time { return now }, loc: func() *time.Location { return time.UTC }}
	st := Settings{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "01:00", To: "05:00"}
	until := now.Add(time.Hour)
	ctx, manual := context.Background(), withManualUntil(context.Background(), until)
	windowEnd := time.Date(2026, 11, 9, 5, 0, 0, 0, time.UTC)
	for _, c := range []context.Context{ctx, manual} {
		if end, ok := s.windowNow(c, st); !ok || !end.Equal(windowEnd) {
			t.Fatalf("inside the window: %v %v, want the window's end %v", end, ok, windowEnd)
		}
	}
	now = now.Add(20 * time.Minute) // 05:10: the window closed
	if _, ok := s.windowNow(ctx, st); ok {
		t.Fatal("the box's own runs got the manual run's hour")
	}
	if end, ok := s.windowNow(manual, st); !ok || !end.Equal(until) {
		t.Fatalf("the manual run: %v %v", end, ok)
	}
	now = until
	if _, ok := s.windowNow(manual, st); ok {
		t.Fatal("the manual run outlived its hour")
	}
}
