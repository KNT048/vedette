package exposure

import (
	"errors"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/schedule"
)

// The box-ip form and the schedule editor are one setting (exposure.public_ip), limited to 5 minutes to 24 hours with the reason said.
func TestPublicIPSchedule_TheFormAndTheEditorAreOneSetting(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", true, 30); err != nil {
		t.Fatal(err)
	}
	v, err := e.sched.Get(e.ctx(), PublicIPScheduleKey)
	if err != nil || !v.Enabled || v.Rule.EveryMinutes == nil || *v.Rule.EveryMinutes != 30 || v.Limits.Reason == "" || v.NextDueAt == nil {
		t.Fatalf("schedule after the form: %+v %v", v, err)
	}
	if _, err := e.sched.Save(e.ctx(), PublicIPScheduleKey, schedule.Setting{Enabled: false, Rule: schedule.Every(120)}, "admin@acme.example"); err != nil {
		t.Fatal(err)
	}
	if b := e.settings(); b.Auto || b.IntervalMin != 120 {
		t.Fatalf("the form reads %+v, want off and 120", b)
	}
	for _, rule := range []schedule.Rule{schedule.Every(4), schedule.Every(1441), schedule.DailyAt("03:00")} {
		_, err := e.sched.Save(e.ctx(), PublicIPScheduleKey, schedule.Setting{Enabled: true, Rule: rule}, "admin@acme.example")
		var re *schedule.RuleError
		if !errors.As(err, &re) || !strings.Contains(re.Message, "rate-limit") {
			t.Errorf("%v: %v", rule.Freq, err)
		}
	}
}

// Run once now is the page's Detect now button; the schedule says so instead of doing nothing.
func TestPublicIPSchedule_RunOnceNowPointsToDetectNow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, err := e.sched.RunNow(e.ctx(), PublicIPScheduleKey, "admin@acme.example")
	var sk *schedule.SkipError
	if !errors.As(err, &sk) || !strings.Contains(sk.Reason, "Detect now") {
		t.Fatalf("%v", err)
	}
}
