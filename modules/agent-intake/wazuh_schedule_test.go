package agentintake_test

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/schedule"
)

func (r *wzRig) skip() string {
	r.t.Helper()
	v, err := r.sched.Get(r.t.Context(), "agent-intake.wazuh")
	if err != nil {
		r.t.Fatal(err)
	}
	if v.LastSkipReason == nil {
		return ""
	}
	return *v.LastSkipReason
}

// The pull is a schedule of its own, an interval of at least 5 minutes, and it says why a due time did nothing.
func TestWazuhSchedule_IsAnIntervalAndSaysWhyItSkipped(t *testing.T) {
	r := newWzRig(t)
	if _, err := r.sched.Save(t.Context(), "agent-intake.wazuh", schedule.Setting{Enabled: true, Rule: schedule.DailyAt("03:00")}, "admin@acme.example"); err == nil || !strings.Contains(err.Error(), "can only be interval") {
		t.Fatalf("a daily pull was accepted: %v", err)
	}
	if _, err := r.sched.Save(t.Context(), "agent-intake.wazuh", schedule.Setting{Enabled: true, Rule: schedule.Every(3)}, "admin@acme.example"); err == nil || !strings.Contains(err.Error(), "at least 5 minutes") || !strings.Contains(err.Error(), "answers slowly") {
		t.Fatalf("a 3 minute pull was accepted, or says no reason: %v", err)
	}
	// Nobody has connected a server: a due time is skipped and says so.
	if _, err := r.sched.Save(t.Context(), "agent-intake.wazuh", schedule.Setting{Enabled: true, Rule: schedule.Every(15)}, "admin@acme.example"); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(16 * time.Minute)
	r.pull()
	if got := r.skip(); !strings.Contains(got, "No Wazuh server is connected") {
		t.Fatalf("skip reason %q", got)
	}
}

// The schedule and the connection form are one setting: the form's interval is the schedule's, and a change in the editor shows in the form.
func TestWazuhSchedule_TheFormAndTheEditorAreOneSetting(t *testing.T) {
	r := newWzRig(t)
	r.save() // the form says every 60 minutes
	v, err := r.sched.Get(t.Context(), "agent-intake.wazuh")
	if err != nil || !v.Saved || v.Rule.EveryMinutes == nil || *v.Rule.EveryMinutes != 60 {
		t.Fatalf("schedule after the form: %+v %v", v, err)
	}
	if _, err := r.sched.Save(t.Context(), "agent-intake.wazuh", schedule.Setting{Enabled: true, Rule: schedule.Every(30)}, "admin@acme.example"); err != nil {
		t.Fatal(err)
	}
	if w, err := r.svc.Wazuh(t.Context()); err != nil || w == nil || w.IntervalMinutes != 30 {
		t.Fatalf("the form reads %+v %v, want the editor's 30", w, err)
	}
}
