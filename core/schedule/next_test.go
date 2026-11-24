package schedule_test

import (
	"errors"
	"testing"
	"time"

	"github.com/knt048/vedette/core/schedule"
)

func zone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return loc
}

func utc(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func ptr[T any](v T) *T { return &v }

func custom(r schedule.Rule, from, to string, days ...int) schedule.Rule {
	r.Window, r.WindowDays, r.WindowFrom, r.WindowTo = schedule.WindowCustom, days, &from, &to
	return r
}

// everyDaysAt is "every n days at hhmm".
func everyDaysAt(n int, hhmm string) schedule.Rule {
	r := schedule.Every(n * schedule.MinuteOfDay)
	r.At = &hhmm
	return r
}

// everyDaysAt230 is "every n days at 02:30".
func everyDaysAt230(n int) schedule.Rule {
	r := schedule.Every(n * schedule.MinuteOfDay)
	r.At = ptr("02:30")
	return r
}

func once(at string) schedule.Rule {
	t := utc(at)
	return schedule.Rule{Freq: schedule.Once, OnceAt: &t, TZ: schedule.OrgZone, Window: schedule.WindowNone}
}

// Next over the cases a calendar gets wrong: summer time starting and ending, month ends, leap years, and windows that cross
// midnight. New York moves its clocks on 8 March and 1 November 2026 at 02:00; Berlin on 29 March and 25 October 2026 at
// 02:00 (03:00 in October); Ho Chi Minh City never does (UTC+7).
func TestNext(t *testing.T) {
	ny, berlin, hcm := zone(t, "America/New_York"), zone(t, "Europe/Berlin"), zone(t, "Asia/Ho_Chi_Minh")
	for _, c := range []struct {
		name  string
		rule  schedule.Rule
		loc   *time.Location
		after string
		want  string // "" = never
	}{
		// Summer time starts: 02:30 does not exist in New York on 8 March.
		{"daily at a skipped time runs when the clocks jump", schedule.DailyAt("02:30"), ny, "2026-03-07T17:00:00Z", "2026-03-08T07:00:00Z"},
		{"daily after the jump keeps its time the next day", schedule.DailyAt("02:30"), ny, "2026-03-08T07:00:00Z", "2026-03-09T06:30:00Z"},
		{"daily before the skipped hour is unchanged", schedule.DailyAt("01:30"), ny, "2026-03-07T17:00:00Z", "2026-03-08T06:30:00Z"},
		{"daily the day before summer time", schedule.DailyAt("02:30"), ny, "2026-03-06T08:00:00Z", "2026-03-07T07:30:00Z"},
		// Summer time ends: 01:30 happens twice in New York on 1 November; it runs once, the first time.
		{"daily at a repeated time runs the first time", schedule.DailyAt("01:30"), ny, "2026-10-31T16:00:00Z", "2026-11-01T05:30:00Z"},
		{"daily at a repeated time does not run again the second time", schedule.DailyAt("01:30"), ny, "2026-11-01T05:30:00Z", "2026-11-02T06:30:00Z"},
		{"hourly is elapsed time across the repeated hour", schedule.Every(60), ny, "2026-11-01T05:30:00Z", "2026-11-01T06:30:00Z"},
		{"hourly is elapsed time across the skipped hour", schedule.Every(60), ny, "2026-03-08T06:30:00Z", "2026-03-08T07:30:00Z"},
		// Every N days at a time counts calendar days, whatever their length.
		{"every 3 days at 02:30 across the start of summer time", everyDaysAt230(3), berlin, "2026-03-27T01:30:00Z", "2026-03-30T00:30:00Z"},
		{"every 3 days at 02:30 across the end of summer time", everyDaysAt230(3), berlin, "2026-10-23T00:30:00Z", "2026-10-26T01:30:00Z"},
		{"every 2 days from a change in the afternoon", everyDaysAt230(2), hcm, "2026-11-20T08:00:00Z", "2026-11-21T19:30:00Z"},
		{"every 90 minutes", schedule.Every(90), hcm, "2026-11-20T08:00:00.250Z", "2026-11-20T09:30:00.250Z"},
		// Weekly.
		{"weekly later the same day", schedule.WeeklyAt("09:00", 1, 3, 5), hcm, "2026-11-20T01:59:00Z", "2026-11-20T02:00:00Z"},
		{"weekly from Friday after the time goes to Monday", schedule.WeeklyAt("09:00", 1, 3, 5), hcm, "2026-11-20T03:00:00Z", "2026-11-23T02:00:00Z"},
		{"weekly at exactly the time goes to the next day", schedule.WeeklyAt("09:00", 1, 3, 5), hcm, "2026-11-20T02:00:00Z", "2026-11-23T02:00:00Z"},
		{"weekly on Sunday across midnight in the zone", schedule.WeeklyAt("00:15", 7), hcm, "2026-11-21T17:00:00Z", "2026-11-21T17:15:00Z"},
		// Month ends.
		{"monthly on the 31st in a 30-day month runs on the 30th", schedule.MonthlyAt("08:00", 31), hcm, "2026-04-01T00:00:00Z", "2026-04-30T01:00:00Z"},
		{"monthly on the 31st after it ran in January runs on 28 February", schedule.MonthlyAt("08:00", 31), hcm, "2026-01-31T01:00:00Z", "2026-02-28T01:00:00Z"},
		{"monthly on the last day in a leap year", schedule.MonthlyAt("08:00", 0), hcm, "2028-02-01T00:00:00Z", "2028-02-29T01:00:00Z"},
		{"monthly on the 30th in February runs on its last day", schedule.MonthlyAt("08:00", 30), hcm, "2027-02-01T00:00:00Z", "2027-02-28T01:00:00Z"},
		{"monthly on the last day at the end of a year", schedule.MonthlyAt("23:30", 0), hcm, "2026-12-31T16:30:00Z", "2027-01-31T16:30:00Z"},
		{"monthly on the 1st at a time summer time skips", schedule.MonthlyAt("02:30", 8), ny, "2026-03-01T00:00:00Z", "2026-03-08T07:00:00Z"},
		// Once.
		{"once in the future", once("2026-12-01T10:00:00Z"), hcm, "2026-11-20T00:00:00Z", "2026-12-01T10:00:00Z"},
		{"once in the past never comes again", once("2026-11-01T10:00:00Z"), hcm, "2026-11-20T00:00:00Z", ""},
		{"once at exactly after never comes again", once("2026-11-20T00:00:00Z"), hcm, "2026-11-20T00:00:00Z", ""},
		// Windows. A window that crosses midnight belongs to the day it opens on.
		{"a time outside the window waits for it to open", custom(schedule.DailyAt("20:00"), "23:00", "05:00", 5), hcm, "2026-11-18T00:00:00Z", "2026-11-20T16:00:00Z"},
		{"inside a window opened the day before", custom(schedule.Every(60), "22:00", "06:00", 1, 2, 3, 4, 5, 6, 7), hcm, "2026-11-20T21:30:00Z", "2026-11-20T22:30:00Z"},
		{"past the end of a window over midnight waits for the evening", custom(schedule.Every(60), "22:00", "06:00", 1, 2, 3, 4, 5, 6, 7), hcm, "2026-11-20T22:30:00Z", "2026-11-21T15:00:00Z"},
		{"the morning after a window day that is not a window day is outside: the regular time in the next opening runs", custom(schedule.DailyAt("04:00"), "23:00", "05:00", 5), hcm, "2026-11-21T00:00:00Z", "2026-11-27T21:00:00Z"},
		// One opening never starts the work twice: a time moved to an opening gives way to a regular time inside it.
		{"daily 03:00 in Friday 23:00-05:00 runs Saturday 03:00 only", custom(schedule.DailyAt("03:00"), "23:00", "05:00", 5), hcm, "2026-11-18T00:00:00Z", "2026-11-20T20:00:00Z"},
		{"daily 03:00 in Friday 23:00-05:00 the week after", custom(schedule.DailyAt("03:00"), "23:00", "05:00", 5), hcm, "2026-11-20T20:00:00Z", "2026-11-27T20:00:00Z"},
		{"daily 02:00 in Monday to Friday 22:00-06:00 runs Tuesday 02:00 after a weekend", custom(schedule.DailyAt("02:00"), "22:00", "06:00", 1, 2, 3, 4, 5), hcm, "2026-11-21T00:00:00Z", "2026-11-23T19:00:00Z"},
		{"every day at 02:00 in Monday to Friday 22:00-06:00 the same", custom(everyDaysAt(1, "02:00"), "22:00", "06:00", 1, 2, 3, 4, 5), hcm, "2026-11-21T00:00:00Z", "2026-11-23T19:00:00Z"},
		{"a regular time outside the opening keeps the opening", custom(schedule.DailyAt("12:00"), "22:00", "06:00", 1, 2, 3, 4, 5, 6, 7), hcm, "2026-11-20T06:00:00Z", "2026-11-21T15:00:00Z"},
		// Every N days at a time: the first run is today when the time is still ahead, like daily.
		{"every 1 day at 22:00 changed in the morning runs that evening", everyDaysAt(1, "22:00"), hcm, "2026-11-20T03:00:00Z", "2026-11-20T15:00:00Z"},
		{"every 3 days at 22:00 changed in the morning runs in two days", everyDaysAt(3, "22:00"), hcm, "2026-11-20T03:00:00Z", "2026-11-22T15:00:00Z"},
		{"every 3 days at 02:30 from after 02:30 counts three days from that day", everyDaysAt230(3), hcm, "2026-11-19T22:00:00Z", "2026-11-22T19:30:00Z"},
		{"the morning after a window day is inside", custom(schedule.DailyAt("04:00"), "23:00", "05:00", 5), hcm, "2026-11-20T00:00:00Z", "2026-11-20T21:00:00Z"},
		{"every 3 days at 02:30 in a Monday to Friday window", custom(everyDaysAt230(3), "00:00", "00:00", 1, 2, 3, 4, 5), hcm, "2026-11-18T19:30:00Z", "2026-11-22T17:00:00Z"},
		{"a window that opens at a skipped time opens when the clocks jump", custom(schedule.DailyAt("01:00"), "02:00", "04:00", 7), ny, "2026-03-07T17:00:00Z", "2026-03-08T07:00:00Z"},
		{"a window in its own zone across the end of summer time", custom(schedule.DailyAt("00:30"), "01:00", "03:00", 7), ny, "2026-10-31T16:00:00Z", "2026-11-01T05:00:00Z"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rule, err := schedule.Validate(c.rule)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			got := schedule.Next(rule, utc(c.after), c.loc)
			if c.want == "" {
				if !got.IsZero() {
					t.Fatalf("Next = %s, want never", got.Format(time.RFC3339Nano))
				}
				return
			}
			if want := utc(c.want); !got.Equal(want) || got.Location() != time.UTC {
				t.Fatalf("Next = %s (%s), want %s (%s)", got.Format(time.RFC3339Nano), got.In(c.loc).Format("Mon 2 Jan 15:04 MST"),
					want.Format(time.RFC3339Nano), want.In(c.loc).Format("Mon 2 Jan 15:04 MST"))
			}
			if !got.After(utc(c.after)) {
				t.Fatalf("Next = %s is not after %s", got, c.after)
			}
		})
	}
}

// Following Next from its own answer steps through a calendar without repeating or skipping a day, through both clock changes of a year.
func TestNextStepsThroughAYearOfDays(t *testing.T) {
	for _, name := range []string{"America/New_York", "Europe/Berlin", "Australia/Lord_Howe", "Asia/Ho_Chi_Minh"} {
		loc := zone(t, name)
		for _, at := range []string{"00:00", "01:30", "02:00", "02:30", "23:59"} {
			rule, err := schedule.Validate(schedule.DailyAt(at))
			if err != nil {
				t.Fatal(err)
			}
			cur := time.Date(2026, 1, 1, 0, 0, 0, 0, loc).Add(-time.Minute)
			prevDay := ""
			for i := 0; i < 365; i++ {
				next := schedule.Next(rule, cur, loc)
				day := next.In(loc).Format("2006-01-02")
				want := time.Date(2026, 1, 1+i, 12, 0, 0, 0, loc).Format("2006-01-02")
				if day != want || day == prevDay {
					t.Fatalf("%s at %s: run %d is on %s, want %s", name, at, i+1, day, want)
				}
				prevDay, cur = day, next
			}
		}
	}
}

func TestWindowContains(t *testing.T) {
	hcm := zone(t, "Asia/Ho_Chi_Minh")
	friNight := schedule.Window{Days: []int{5}, From: "23:00", To: "05:00"}
	allDay := schedule.Window{Days: []int{1, 2, 3, 4, 5}, From: "00:00", To: "00:00"}
	for _, c := range []struct {
		w    schedule.Window
		at   string
		want bool
	}{
		{friNight, "2026-11-20T16:00:00Z", true},  // Fri 23:00
		{friNight, "2026-11-20T21:59:00Z", true},  // Sat 04:59
		{friNight, "2026-11-20T22:00:00Z", false}, // Sat 05:00: closed
		{friNight, "2026-11-20T15:59:00Z", false}, // Fri 22:59
		{friNight, "2026-11-21T16:30:00Z", false}, // Sat 23:30: Saturday is not a window day
		{allDay, "2026-11-20T16:59:00Z", true},    // Fri 23:59
		{allDay, "2026-11-20T17:00:00Z", false},   // Sat 00:00
		{allDay, "2026-11-22T17:00:00Z", true},    // Mon 00:00
		{schedule.Window{Days: []int{1}, From: "25:00", To: "05:00"}, "2026-11-23T00:00:00Z", false},
	} {
		if got := c.w.Contains(utc(c.at), hcm); got != c.want {
			t.Errorf("%+v contains %s (%s) = %v, want %v", c.w, c.at, utc(c.at).In(hcm).Format("Mon 15:04"), got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	bad := map[string]struct {
		rule  schedule.Rule
		field string
	}{
		"unknown freq":                {schedule.Rule{Freq: "hourly"}, "freq"},
		"interval without minutes":    {schedule.Rule{Freq: schedule.Interval}, "every_minutes"},
		"interval over a year":        {schedule.Every(schedule.MaxEveryMinutes + 1), "every_minutes"},
		"time with a part-day period": {func() schedule.Rule { r := schedule.Every(90); r.At = ptr("02:00"); return r }(), "at_time"},
		"daily without a time":        {schedule.Rule{Freq: schedule.Daily}, "at_time"},
		"bad time":                    {schedule.DailyAt("24:00"), "at_time"},
		"weekly without days":         {schedule.WeeklyAt("02:00"), "weekdays"},
		"weekly day 8":                {schedule.WeeklyAt("02:00", 8), "weekdays"},
		"monthly day 32":              {schedule.MonthlyAt("02:00", 32), "month_day"},
		"once without a time":         {schedule.Rule{Freq: schedule.Once}, "once_at"},
		"unknown zone":                {func() schedule.Rule { r := schedule.DailyAt("02:00"); r.TZ = "Mars/Olympus"; return r }(), "tz"},
		"custom window without days":  {custom(schedule.DailyAt("02:00"), "01:00", "02:00"), "window_days"},
		"custom window bad hour":      {custom(schedule.DailyAt("02:00"), "1:00", "02:00", 1), "window_from"},
		"unknown window":              {func() schedule.Rule { r := schedule.DailyAt("02:00"); r.Window = "night"; return r }(), "window"},
	}
	for name, c := range bad {
		_, err := schedule.Validate(c.rule)
		var re *schedule.RuleError
		if !errors.As(err, &re) || re.Field != c.field || re.Message == "" {
			t.Errorf("%s: err %v, want a RuleError on %s", name, err, c.field)
		}
	}
	// Normalized: the fields the frequency does not use go, day lists are sorted, the zone and window have their defaults.
	in := schedule.Rule{Freq: schedule.Weekly, At: ptr("02:00"), Weekdays: []int{5, 1, 5}, MonthDay: ptr(3), EveryMinutes: ptr(10)}
	got, err := schedule.Validate(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.MonthDay != nil || got.EveryMinutes != nil || len(got.Weekdays) != 2 || got.Weekdays[0] != 1 || got.TZ != schedule.OrgZone || got.Window != schedule.WindowNone {
		t.Errorf("normalized %+v", got)
	}
}

func TestLimits(t *testing.T) {
	feeds := schedule.Limits{Freqs: []schedule.Freq{schedule.Interval}, MinEveryMinutes: 60, Reason: "Sources ask clients not to poll more often."}
	for name, c := range map[string]struct {
		rule  schedule.Rule
		field string // "" = allowed
	}{
		"every hour":       {schedule.Every(60), ""},
		"every 10 minutes": {schedule.Every(10), "every_minutes"},
		"daily":            {schedule.DailyAt("02:00"), "freq"},
	} {
		rule, err := schedule.Validate(c.rule)
		if err != nil {
			t.Fatal(err)
		}
		err = feeds.Check(rule)
		var re *schedule.RuleError
		switch {
		case c.field == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case c.field != "" && (!errors.As(err, &re) || re.Field != c.field):
			t.Errorf("%s: err %v, want a refusal on %s", name, err, c.field)
		}
	}
	rule, _ := schedule.Validate(schedule.Every(10))
	var re *schedule.RuleError
	if err := feeds.Check(rule); !errors.As(err, &re) || re.Message != "The interval is at least 1 hour. Sources ask clients not to poll more often." {
		t.Errorf("message: %v", err)
	}
}

// Due keeps the asked days of "every 3 days at 02:30" through a year with both clock changes, whenever each run really started
// (on time, minutes late, most of a day late): every run is on the asked day, at 02:30 or the moment the clocks jump over it.
func TestDueKeepsTheAskedDaysThroughAYear(t *testing.T) {
	for _, name := range []string{"America/New_York", "Europe/Berlin", "Australia/Lord_Howe", "Asia/Ho_Chi_Minh"} {
		loc := zone(t, name)
		rule, err := schedule.Validate(everyDaysAt230(3))
		if err != nil {
			t.Fatal(err)
		}
		updated := time.Date(2026, 1, 1, 10, 0, 0, 0, loc) // the first run: Sunday 4 January
		var last *time.Time
		late := []time.Duration{0, 3 * time.Minute, 5 * time.Hour, 20 * time.Hour, 47 * time.Hour}
		for i := 0; i < 122; i++ {
			due := schedule.Due(rule, last, updated, nil, loc)
			l := due.In(loc)
			if want := time.Date(2026, 1, 4+3*i, 12, 0, 0, 0, loc).Format("2006-01-02"); l.Format("2006-01-02") != want {
				t.Fatalf("%s: run %d is on %s, want %s", name, i+1, l.Format("2006-01-02 15:04"), want)
			}
			if hm := l.Format("15:04"); hm != "02:30" && hm != "03:00" {
				t.Fatalf("%s: run %d at %s", name, i+1, l.Format("2006-01-02 15:04 MST"))
			}
			start := due.Add(late[i%len(late)])
			last = &start
		}
	}
}

// Due keeps the asked times of an elapsed interval whenever each run really started, and never puts two runs less than half an
// interval apart.
func TestDueKeepsTheAskedTimesOfAnElapsedInterval(t *testing.T) {
	rule, err := schedule.Validate(schedule.Every(360))
	if err != nil {
		t.Fatal(err)
	}
	updated := utc("2026-11-20T03:00:00Z") // asked: 09:00, 15:00, 21:00, 03:00 ...
	for _, c := range []struct {
		started, want string
	}{
		{"2026-11-20T09:00:00Z", "2026-11-20T15:00:00Z"}, // on time
		{"2026-11-20T09:02:30Z", "2026-11-20T15:00:00Z"}, // minutes late
		{"2026-11-20T11:59:00Z", "2026-11-20T15:00:00Z"}, // 3 h 1 min before the next: it stays
		{"2026-11-20T12:01:00Z", "2026-11-20T21:00:00Z"}, // under half an interval before the next: the one after
		{"2026-11-23T07:12:00Z", "2026-11-23T15:00:00Z"}, // days late
		{"2026-11-20T02:00:00Z", "2026-11-20T09:00:00Z"}, // a start before the change counts from the change
	} {
		s := utc(c.started)
		if got := schedule.Due(rule, &s, updated, nil, time.UTC); !got.Equal(utc(c.want)) {
			t.Errorf("started %s: next %s, want %s", c.started, got.Format(time.RFC3339), c.want)
		}
	}
}
