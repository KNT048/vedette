package sensoractive_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/schedule"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// comesDue plays the schedule inventory.sweep coming due: core/schedule calls the owner's Start inside its transaction.
func comesDue(e *env, trigger run.Trigger) (string, error) {
	e.t.Helper()
	o := e.svc.ScheduleOwner()
	var id string
	err := e.db.Write(e.ctx(), func(tx dbTx) error {
		var err error
		id, err = o.Start(e.ctx(), tx, schedule.Fire{OwnerKey: o.Key, Trigger: trigger, By: "admin@acme.example"})
		return err
	})
	return id, err
}

func TestSweepSchedule_IsRegisteredAsTheLANSweepWithItsDefault(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	o := e.svc.ScheduleOwner()
	if o.Key != "inventory.sweep" || o.Module != "sensor-active" || !o.DefaultOn || o.Default.Freq != schedule.Daily || *o.Default.At != "22:00" || o.Default.Window != schedule.WindowGlobal {
		t.Fatalf("owner %+v", o)
	}
}

// A due schedule queues one pass of the ranges, a pass that is going on is not doubled, and each refusal says why.
func TestSweepSchedule_QueuesOnePassAndSaysWhyItDidNot(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	id, err := comesDue(e, run.Schedule)
	if err != nil || id == "" {
		t.Fatalf("start: %q %v", id, err)
	}
	if n := e.count(`SELECT count(*) FROM core_run WHERE kind = 'lan_sweep' AND trigger = 'schedule' AND requested_by = 'system' AND status IN ('queued', 'running')`); n != 1 {
		t.Fatalf("%d passes queued", n)
	}
	_, err = comesDue(e, run.Schedule)
	var sk *schedule.SkipError
	if !errors.As(err, &sk) || !strings.Contains(sk.Reason, "pass that is going on") {
		t.Fatalf("a second pass: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM core_run WHERE kind = 'lan_sweep'`); n != 1 {
		t.Fatalf("%d passes", n)
	}
}

func TestSweepSchedule_SaysWhyItDoesNotStart(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		set  func(*sa.Settings)
		want string
	}{
		"scanning off":    {func(s *sa.Settings) { s.Enabled = false }, "Active scanning is off"},
		"scope not shown": {func(s *sa.Settings) { s.ScopeConfirmed = false }, "not confirmed"},
		"no ranges":       {func(s *sa.Settings) { s.LANRanges = nil }, "No network range"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, fakeOpts{})
			e.inv.set(c.set)
			_, err := comesDue(e, run.Schedule)
			var sk *schedule.SkipError
			if !errors.As(err, &sk) || !strings.Contains(sk.Reason, c.want) {
				t.Fatalf("%v, want a skip saying %q", err, c.want)
			}
			if n := e.count(`SELECT count(*) FROM core_run WHERE kind = 'lan_sweep'`); n != 0 {
				t.Fatalf("%d passes queued", n)
			}
		})
	}
}

// Without the schedule the window no longer starts a pass of its own: the tick only goes on with the pass that exists.
func TestSweepSchedule_TheWindowStartsNoPassOfItsOwn(t *testing.T) {
	t.Parallel()
	e := newEnv(t, fakeOpts{})
	markSweepDone(t, e, "saj-old") // not a new box: the first pass is behind it
	if err := e.svc.Tick(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM core_run WHERE kind = 'lan_sweep' AND id <> 'saj-old'`); n != 0 {
		t.Fatalf("the window started %d passes by itself", n)
	}
}
