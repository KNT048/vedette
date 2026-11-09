package notify

import (
	"testing"
	"time"
)

// at builds a local time on 2026-11-09 (a Monday) in a fixed zone.
var zone = time.FixedZone("ICT", 7*3600)

func at(h, m int) time.Time { return time.Date(2026, 11, 9, h, m, 0, 0, zone) }

func TestContract_INV4_MinSeverity(t *testing.T) {
	t.Parallel()
	sevs := []Severity{Critical, High, Medium, Low, Info}
	for i, min := range []Severity{Critical, High, Medium, Low} {
		for j, sev := range sevs {
			want := j <= i // index order is severity order
			if got := MeetsMin(sev, min); got != want {
				t.Errorf("MeetsMin(%s, %s) = %v, want %v", sev, min, got, want)
			}
		}
	}
	for _, bad := range []struct{ sev, min Severity }{{"", Low}, {"urgent", Low}, {High, ""}, {High, "x"}, {Critical, Info}, {Info, Info}} {
		if MeetsMin(bad.sev, bad.min) {
			t.Errorf("MeetsMin(%q, %q) passed", bad.sev, bad.min)
		}
	}
}

func TestQuietValidate(t *testing.T) {
	t.Parallel()
	for q, ok := range map[Quiet]bool{
		{Enabled: true, From: "22:00", To: "06:30"}:   true,
		{Enabled: true, From: "08:00", To: "17:00"}:   true,
		{Enabled: true, From: "22:00", To: "22:00"}:   false, // INV-5: from != to when enabled
		{Enabled: false, From: "22:00", To: "22:00"}:  true,
		{Enabled: true, From: "24:00", To: "06:00"}:   false,
		{Enabled: true, From: "22:60", To: "06:00"}:   false,
		{Enabled: true, From: "2:00", To: "06:00"}:    false,
		{Enabled: false, From: "", To: ""}:            false,
		{Enabled: true, From: "ab:cd", To: "06:00"}:   false,
		{Enabled: true, From: "22:00", To: "06:00\n"}: false,
	} {
		if err := q.Validate(); (err == nil) != ok {
			t.Errorf("%+v: err = %v, want ok=%v", q, err, ok)
		}
	}
}

func TestContract_INV5_QuietHours(t *testing.T) {
	t.Parallel()
	night := Quiet{Enabled: true, From: "22:00", To: "06:30", AllowCritical: true}
	for _, c := range []struct {
		h, m   int
		active bool
	}{{21, 59, false}, {22, 0, true}, {23, 59, true}, {0, 0, true}, {3, 15, true}, {6, 29, true}, {6, 30, false}, {12, 0, false}} {
		if got := night.Active(at(c.h, c.m)); got != c.active {
			t.Errorf("overnight Active(%02d:%02d) = %v", c.h, c.m, got)
		}
	}
	day := Quiet{Enabled: true, From: "08:00", To: "17:00"}
	if !day.Active(at(8, 0)) || day.Active(at(17, 0)) || day.Active(at(7, 59)) || !day.Active(at(16, 59)) {
		t.Error("same-day window edges wrong")
	}
	if (Quiet{Enabled: false, From: "22:00", To: "06:30"}).Active(at(23, 0)) {
		t.Error("disabled rule is active")
	}

	// Release time: evening -> next morning; after midnight -> same morning; DST-free zone.
	if got := night.EndsAt(at(23, 0)); !got.Equal(time.Date(2026, 11, 10, 6, 30, 0, 0, zone)) {
		t.Errorf("EndsAt evening = %v", got)
	}
	if got := night.EndsAt(at(2, 0)); !got.Equal(time.Date(2026, 11, 9, 6, 30, 0, 0, zone)) {
		t.Errorf("EndsAt after midnight = %v", got)
	}
	if !night.EndsAt(at(12, 0)).IsZero() {
		t.Error("EndsAt outside the window must be zero")
	}

	// D-57(8): held, except critical when allow_critical.
	v, until := Decide(at(23, 0), Low, night, High)
	if v != Hold || !until.Equal(time.Date(2026, 11, 10, 6, 30, 0, 0, zone)) {
		t.Errorf("high at night = %v until %v", v, until)
	}
	if v, _ := Decide(at(23, 0), Low, night, Critical); v != Send {
		t.Errorf("critical with allow_critical = %v", v)
	}
	strict := night
	strict.AllowCritical = false
	if v, _ := Decide(at(23, 0), Low, strict, Critical); v != Hold {
		t.Errorf("critical without allow_critical = %v", v)
	}
	if v, _ := Decide(at(12, 0), Low, night, Medium); v != Send {
		t.Errorf("daytime = %v", v)
	}
	// INV-4 comes first: below the minimum is skipped even at night, and never held.
	if v, _ := Decide(at(23, 0), High, night, Medium); v != Skip {
		t.Errorf("below min = %v", v)
	}
}

func TestQuietEndsAtIsWallClockAcrossFallBack(t *testing.T) {
	t.Parallel()
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tz database")
	}
	q := Quiet{Enabled: true, From: "22:00", To: "06:30"}
	// 2026-11-01 is the end of DST in New York: 01:00-02:00 happens twice, so the
	// night from 23:00 to 06:30 is 7h30 on the wall clock but 8h30 for real.
	now := time.Date(2026, 10, 31, 23, 0, 0, 0, ny)
	end := q.EndsAt(now)
	if end.Hour() != 6 || end.Minute() != 30 || end.Day() != 1 || end.Month() != time.November {
		t.Errorf("EndsAt = %v, want 06:30 on 1 November", end)
	}
	if d := end.Sub(now); d != 8*time.Hour+30*time.Minute {
		t.Errorf("window lasts %v, want 8h30m of real time", d)
	}
	if !q.Active(time.Date(2026, 11, 1, 1, 30, 0, 0, ny)) {
		t.Error("01:30 must be inside the window")
	}
}

func FuzzQuiet(f *testing.F) {
	f.Add("22:00", "06:30", int64(1_800_000_000))
	f.Add("00:00", "23:59", int64(0))
	f.Add("\x00", "9:9", int64(-1))
	f.Fuzz(func(t *testing.T, from, to string, ts int64) {
		q := Quiet{Enabled: true, From: from, To: to, AllowCritical: true}
		now := time.Unix(ts%4_000_000_000, 0).In(zone)
		active := q.Active(now)
		end := q.EndsAt(now)
		if q.Validate() != nil && (active || !end.IsZero()) {
			t.Fatalf("invalid rule %q-%q is active", from, to)
		}
		if active && (!end.After(now) || end.Sub(now) > 24*time.Hour+time.Hour) {
			t.Fatalf("EndsAt %v not within a day after %v", end, now)
		}
		if active != !end.IsZero() {
			t.Fatalf("Active=%v but EndsAt=%v", active, end)
		}
	})
}
