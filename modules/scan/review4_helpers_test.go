package scan

import (
	"database/sql"
	"testing"
	"time"
)

// Helpers of the #164 review tests (S4).

// The days of the review's examples (2026-11-16 is a Monday).
var (
	mon16 = time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	tue17 = mon16.AddDate(0, 0, 1)
	wed18 = mon16.AddDate(0, 0, 2)
	thu19 = mon16.AddDate(0, 0, 3)
	fri20 = mon16.AddDate(0, 0, 4)
	sat21 = mon16.AddDate(0, 0, 5)
	sun22 = mon16.AddDate(0, 0, 6)
)

func hm(day time.Time, h, m int) time.Time {
	return day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute)
}

func (r *runEnv) setNow(t time.Time) {
	r.clock.mu.Lock()
	r.clock.now = t
	r.clock.mu.Unlock()
}

// schedEnv is the review's example: a window from 22:00 to 05:00 that starts Monday to Friday, a daily run at 02:00.
func schedEnv(t *testing.T) *runEnv {
	t.Helper()
	r := newRunEnv(t)
	p := Patch{Days: []int{1, 2, 3, 4, 5}, From: ptr("22:00"), To: ptr("05:00"), SchedEnabled: ptr(true), SchedFrequency: ptr("daily"), SchedAt: ptr("02:00")}
	if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", p); err != nil {
		t.Fatal(err)
	}
	return r
}

// schedAt runs the schedule job at the given time and waits for the run it started.
func (r *runEnv) schedAt(at time.Time) {
	r.t.Helper()
	r.setNow(at)
	if err := r.svc.RunSchedule(r.ctx()); err != nil {
		r.t.Fatal(err)
	}
	r.wait()
}

func (r *runEnv) scheduled() int {
	r.t.Helper()
	return r.count(`SELECT count(*) FROM scan_run WHERE trigger = 'schedule'`)
}

func (r *runEnv) nextRun() string {
	r.t.Helper()
	v, err := r.svc.Config(r.ctx())
	if err != nil {
		r.t.Fatal(err)
	}
	if v.NextRun == nil {
		return "<nil>"
	}
	return *v.NextRun
}

func (r *runEnv) exec(q string, args ...any) {
	r.t.Helper()
	err := r.db.Write(r.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(r.ctx(), q, args...)
		return err
	})
	if err != nil {
		r.t.Fatal(err)
	}
}
