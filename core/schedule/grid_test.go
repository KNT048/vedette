package schedule_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/core/schedule"
)

// endRun ends the run a schedule last started, so its next due time starts a new one.
func (b *box) endRun(key string) {
	b.t.Helper()
	if v := b.get(key); v.LastRunID != nil {
		b.exec(`UPDATE core_run SET status = 'done', started_at = queued_at, ended_at = queued_at WHERE id = ?`, *v.LastRunID)
	}
}

// follow lets the clock reach each of the wanted starts of key: a second before it nothing starts, at it the schedule starts once.
// It checks the self-check's rule after every start.
func (b *box) follow(key string, want ...string) {
	b.t.Helper()
	for i, w := range want {
		at := utc(w)
		b.clock.Set(at.Add(-time.Second).Format(time.RFC3339Nano))
		if n, err := b.svc.Tick(b.t.Context()); err != nil || n != 0 {
			v := b.get(key)
			b.t.Fatalf("start %d: something started a second before %s (%d, %v); next due %v", i+1, w, n, err, v.NextDueAt)
		}
		b.clock.Set(w)
		if n, err := b.svc.Tick(b.t.Context()); err != nil || n != 1 {
			v := b.get(key)
			b.t.Fatalf("start %d: nothing started at %s (%d, %v); next due %v, upcoming %v", i+1, w, n, err, v.NextDueAt, at2(v.Upcoming))
		}
		b.holds()
		b.endRun(key)
	}
}

func at2(ts []time.Time) []string { return at(ts...) }

// A run moved by a custom window keeps the times and spacing the person asked for: the runs after it come at the asked times
// again, not counted from the moved one; the first three starts the editor shows are the ones that really start.
func TestAMovedStartKeepsTheAskedTimes(t *testing.T) {
	for _, c := range []struct {
		name  string
		saved string // when the person saves it (Ho Chi Minh City, UTC+7)
		rule  schedule.Rule
		want  []string
	}{
		{
			// Asked: Fri 15:00, 20:00, Sat 01:00, 06:00, 11:00, 16:00, 21:00, Sun 02:00, 07:00, ..., 22:00, Mon 03:00 (local).
			// 15:00 and 20:00 wait for the opening at 22:00 (one start); 06:00 to 21:00 wait for Saturday 22:00.
			name: "every 5 hours in a night window", saved: "2026-11-20T03:00:00Z",
			rule: custom(schedule.Every(300), "22:00", "06:00", 1, 2, 3, 4, 5, 6, 7),
			want: []string{
				"2026-11-20T15:00:00Z", // Fri 22:00, moved off 15:00
				"2026-11-20T18:00:00Z", // Sat 01:00, asked
				"2026-11-21T15:00:00Z", // Sat 22:00, moved off 06:00
				"2026-11-21T19:00:00Z", // Sun 02:00, asked
				"2026-11-22T15:00:00Z", // Sun 22:00, moved off 07:00 (and asked)
				"2026-11-22T20:00:00Z", // Mon 03:00, asked
			},
		},
		{
			// Asked: Fri 27, Mon 30, Thu 3, Sun 6, Wed 9 at 02:30. Monday's 02:30 is outside the window (Sunday has none): it waits
			// for Tuesday 22:00, and the next run is still Thursday 02:30, not three days after Tuesday.
			name: "every 3 days at 02:30 in a Tuesday to Saturday night window", saved: "2026-11-24T03:00:00Z",
			rule: custom(everyDaysAt230(3), "22:00", "06:00", 2, 3, 4, 5, 6),
			want: []string{
				"2026-11-26T19:30:00Z", // Fri 27 02:30
				"2026-12-01T15:00:00Z", // Tue 1 22:00, moved off Mon 30 02:30
				"2026-12-02T19:30:00Z", // Thu 3 02:30
				"2026-12-05T19:30:00Z", // Sun 6 02:30
				"2026-12-08T19:30:00Z", // Wed 9 02:30
			},
		},
		{
			name: "weekly Monday 02:30 in a Tuesday window", saved: "2026-11-20T03:00:00Z",
			rule: custom(schedule.WeeklyAt("02:30", 1), "22:00", "06:00", 2),
			want: []string{"2026-11-24T15:00:00Z", "2026-12-01T15:00:00Z", "2026-12-08T15:00:00Z"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newBox(t, "")
			b.clock.Set(c.saved)
			key := "exposure.target:tgt-1"
			v := b.save(key, schedule.Setting{Enabled: true, Rule: c.rule})
			eq(t, "the editor's next starts", at(v.Upcoming...), c.want[:schedule.Upcoming])
			b.follow(key, c.want...)
		})
	}
}

// A schedule in the scan window waits for it to open, and the runs after it come at the asked times again.
func TestTheScanWindowKeepsTheAskedTimes(t *testing.T) {
	b := newBox(t, "")
	b.window = &schedule.Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "22:00", To: "05:00"}
	// Every 5 hours from Friday 10:00 local: 15:00 and 20:00 wait for 22:00; then 01:00 is asked and in the window; 06:00 to 21:00
	// wait for Saturday 22:00; then 02:00; 07:00 to 22:00 wait for Sunday 22:00; then Monday 03:00.
	want := []string{"2026-11-20T15:00:00Z", "2026-11-20T18:00:00Z", "2026-11-21T15:00:00Z", "2026-11-21T19:00:00Z", "2026-11-22T15:00:00Z", "2026-11-22T20:00:00Z"}
	v := b.save("scan.vuln", schedule.Setting{Enabled: true, Rule: schedule.Every(300).InWindow()})
	eq(t, "the editor's next starts", at(v.Upcoming...), want[:schedule.Upcoming])
	b.follow("scan.vuln", want...)
}

// A start that came late (the box was off, the owner held it) runs once, and the runs after it come at the asked times again.
func TestALateStartKeepsTheAskedTimes(t *testing.T) {
	t.Run("every 6 hours, the box off for a night", func(t *testing.T) {
		b := newBox(t, "")
		key := "exposure.target:tgt-1"
		b.save(key, schedule.Setting{Enabled: true, Rule: schedule.Every(360)}) // asked: 09:00Z, 15:00Z, 21:00Z, 03:00Z, ...
		b.clock.Set("2026-11-21T07:12:00Z")
		b.tick(1)
		v := b.get(key)
		// 09:00Z is less than half an interval after the late start: the next run is 15:00Z, not 13:12Z.
		if !v.LastDueAt.Equal(utc("2026-11-21T07:12:00Z")) || !v.NextDueAt.Equal(utc("2026-11-21T15:00:00Z")) {
			t.Fatalf("after the late start: last %v next %v", v.LastDueAt, v.NextDueAt)
		}
		b.holds()
		b.endRun(key)
		b.follow(key, "2026-11-21T15:00:00Z", "2026-11-21T21:00:00Z")
	})
	t.Run("every 6 hours, held by its owner for five minutes", func(t *testing.T) {
		b := newBox(t, "")
		key := "exposure.target:tgt-1"
		b.save(key, schedule.Setting{Enabled: true, Rule: schedule.Every(360)})
		b.clock.Set("2026-11-20T09:00:00Z")
		b.fail = schedule.Hold("The scanner is not ready.")
		b.tick(1) // held: the due time stays
		if v := b.get(key); v.LastDueAt != nil || !v.NextDueAt.Equal(utc("2026-11-20T09:00:00Z")) {
			t.Fatalf("held: %+v", v)
		}
		b.clock.Set("2026-11-20T09:05:00Z")
		b.tick(1)
		if v := b.get(key); !v.NextDueAt.Equal(utc("2026-11-20T15:00:00Z")) {
			t.Fatalf("after the held start: next %v, want 15:00Z", v.NextDueAt)
		}
		b.holds()
		b.endRun(key)
		b.follow(key, "2026-11-20T15:00:00Z", "2026-11-20T21:00:00Z")
	})
	t.Run("every 3 days at 02:30, the box off on the day", func(t *testing.T) {
		b := newBox(t, "")
		key := "exposure.target:tgt-1"
		b.clock.Set("2026-11-24T03:00:00Z")                                   // Tue 24 10:00 local
		b.save(key, schedule.Setting{Enabled: true, Rule: everyDaysAt230(3)}) // asked: Fri 27, Mon 30, Thu 3 at 02:30
		b.clock.Set("2026-11-28T03:00:00Z")                                   // Sat 28 10:00 local: Friday's 02:30 was missed
		b.tick(1)
		if v := b.get(key); !v.NextDueAt.Equal(utc("2026-11-29T19:30:00Z")) {
			t.Fatalf("after the late start: next %v, want Mon 30 02:30 local", v.NextDueAt)
		}
		b.holds()
		b.endRun(key)
		b.follow(key, "2026-11-29T19:30:00Z", "2026-12-02T19:30:00Z")
	})
}

// A skipped due time (the module off, the last run not ended) and run once now never move the asked times.
func TestSkipsAndRunOnceNowKeepTheAskedTimes(t *testing.T) {
	b := newBox(t, "")
	key := "exposure.target:tgt-1"
	b.save(key, schedule.Setting{Enabled: true, Rule: schedule.Every(360)}) // asked: 09:00Z, 15:00Z, 21:00Z, 03:00Z, ...
	b.clock.Set("2026-11-20T07:00:00Z")
	if _, err := b.svc.RunNow(t.Context(), key, "ann@example.com"); err != nil {
		t.Fatal(err)
	}
	if v := b.get(key); !v.NextDueAt.Equal(utc("2026-11-20T09:00:00Z")) {
		t.Fatalf("after run once now: next %v", v.NextDueAt)
	}
	// The run of run once now has not ended at 09:00: skipped, and 15:00 is next.
	b.clock.Set("2026-11-20T09:00:00Z")
	b.tick(1)
	if v := b.get(key); v.LastSkipReason == nil || !v.NextDueAt.Equal(utc("2026-11-20T15:00:00Z")) {
		t.Fatalf("skipped: %+v", v)
	}
	b.endRun(key)
	b.gate.set("exposure", false)
	b.clock.Set("2026-11-20T15:00:30Z")
	b.tick(1)
	if v := b.get(key); v.LastSkipReason == nil || !v.NextDueAt.Equal(utc("2026-11-20T21:00:00Z")) {
		t.Fatalf("module off: %+v", v)
	}
	b.gate.set("exposure", true)
	b.follow(key, "2026-11-20T21:00:00Z", "2026-11-21T03:00:00Z")
}

// A change of the time: the next run comes at the new time, and the spacing counts from the change.
func TestAChangeOfTheTimeCountsFromTheChange(t *testing.T) {
	b := newBox(t, "")
	key := "exposure.target:tgt-1"
	b.clock.Set("2026-11-24T03:00:00Z") // Tue 24 10:00 local
	b.save(key, schedule.Setting{Enabled: true, Rule: everyDaysAt230(3)})
	b.follow(key, "2026-11-26T19:30:00Z") // Fri 27 02:30
	b.clock.Set("2026-11-27T05:00:00Z")   // Fri 27 12:00 local: changed to 22:00
	v := b.save(key, schedule.Setting{Enabled: true, Rule: everyDaysAt(3, "22:00")})
	// Three days counted from the change: Sun 29 22:00, then Wed 2, Sat 5.
	eq(t, "after the change", at(v.Upcoming...), []string{"2026-11-29T15:00:00Z", "2026-12-02T15:00:00Z", "2026-12-05T15:00:00Z"})
	b.follow(key, "2026-11-29T15:00:00Z", "2026-12-02T15:00:00Z")

	// Every 6 hours changed at 10:00Z: 16:00Z, 22:00Z, ...
	b.clock.Set("2026-12-03T10:00:00Z")
	v = b.save(key, schedule.Setting{Enabled: true, Rule: schedule.Every(360)})
	eq(t, "every 6 hours after the change", at(v.Upcoming...), []string{"2026-12-03T16:00:00Z", "2026-12-03T22:00:00Z", "2026-12-04T04:00:00Z"})
	b.follow(key, "2026-12-03T16:00:00Z", "2026-12-03T22:00:00Z")
}

// An interval paused until a day starts at the end of the pause, and keeps that spacing after the pause has ended.
func TestAPausedIntervalKeepsItsSpacingAfterThePause(t *testing.T) {
	b := newBox(t, "")
	key := "exposure.target:tgt-1"
	b.save(key, schedule.Setting{Enabled: true, PausedUntil: ptr(utc("2026-11-22T17:00:00Z")), Rule: schedule.Every(7 * schedule.MinuteOfDay)})
	b.follow(key, "2026-11-22T17:00:00Z", "2026-11-29T17:00:00Z", "2026-12-06T17:00:00Z")
	b.clock.Set("2026-12-08T00:00:00Z")
	if v := b.get(key); v.PausedUntil != nil {
		t.Fatalf("a pause that has ended still shows: %v", v.PausedUntil)
	}
}

// A schedule whose next due time an older version counted from a late start is brought back to the asked times when the box starts
// (Recompute): the self-check finds it before, and it runs at the asked time after.
func TestRecomputeBringsADriftedScheduleBackToTheAskedTimes(t *testing.T) {
	b := newBox(t, "")
	key := "exposure.target:tgt-1"
	b.save(key, schedule.Setting{Enabled: true, Rule: schedule.Every(360)}) // asked: 09:00Z, 15:00Z, 21:00Z, ...
	b.clock.Set("2026-11-21T08:00:00Z")
	b.exec(`UPDATE core_schedule SET last_due_at = '2026-11-21T07:12:00.000Z', next_due_at = '2026-11-21T13:12:00.000Z'`)
	if n, err := schedule.NextDueMismatches(t.Context(), b.db.Reader()); err != nil || n != 1 {
		t.Fatalf("before: %d mismatches (%v), want 1", n, err)
	}
	must(t, b.db.Write(t.Context(), func(tx *sql.Tx) error { _, err := schedule.Recompute(t.Context(), tx); return err }))
	b.holds()
	b.follow(key, "2026-11-21T15:00:00Z")
}
