package orgtime

import (
	"context"
	"testing"
	"time"
)

func TestInstantsAreWrittenInTheZoneCalendarDaysAsStored(t *testing.T) {
	hcm, err := time.LoadLocation("Asia/Ho_Chi_Minh")
	if err != nil {
		t.Fatal(err)
	}
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	// An agent's list at 21:11 UTC on 14 Nov is 04:11 on 15 Nov in a UTC+7 zone: every page says 15 Nov.
	at := time.Date(2026, 11, 14, 21, 11, 0, 0, time.UTC)
	for _, c := range []struct{ got, want string }{
		{Day(at, hcm), "15 Nov 2026"},
		{Stamp(at, hcm), "15 Nov 2026, 04:11"},
		{Clock(at, hcm), "04:11"},
		{ISODay(at, hcm), "2026-11-15"},
		{Short(at, hcm), "15 Nov"},
		{Day(at, nil), "14 Nov 2026"}, // no zone known: UTC
		{Stamp(at, ny), "14 Nov 2026, 16:11"},
		{StampZone(at, hcm), "15 Nov 2026, 04:11 +07"},
		{StampZone(at, ny), "14 Nov 2026, 16:11 EST"},
		{StampZone(at, nil), "14 Nov 2026, 21:11 UTC"}, // the zone could not be read: said so
		{ClockZone(at, time.UTC), "21:11 UTC"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	// A calendar day (a CVE's published day) is stored at 00:00 UTC and never moves, whatever the zone.
	day := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	if got := CalendarDay(day); got != "3 Nov 2026" {
		t.Errorf("CalendarDay = %q", got)
	}
	if got := CalendarDay(day.In(ny)); got != "3 Nov 2026" {
		t.Errorf("CalendarDay of the same day read in another zone = %q", got)
	}
	if got, want := CalendarMonth(day), "November 2026"; got != want {
		t.Errorf("CalendarMonth = %q", got)
	}
	if got := CalendarShort(day); got != "3 Nov" {
		t.Errorf("CalendarShort = %q", got)
	}
}

func TestAtFallsBackToUTC(t *testing.T) {
	ctx := context.Background()
	if At(ctx, nil) != time.UTC || At(ctx, func(context.Context) *time.Location { return nil }) != time.UTC {
		t.Fatal("no zone known must write UTC")
	}
	hcm, _ := time.LoadLocation("Asia/Ho_Chi_Minh")
	if At(ctx, func(context.Context) *time.Location { return hcm }) != hcm {
		t.Fatal("the source's zone is used")
	}
}
