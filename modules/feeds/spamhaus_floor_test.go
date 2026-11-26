package feeds

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/schedule"
)

// Spamhaus asks that the DROP list be downloaded at most once a day, and automated downloads at least an hour apart. The feed's schedule
// cannot be set below 24 hours (the editor says why), Fetch now inside 24 hours of the last good pull is refused with the time it
// becomes possible, the pull job never pulls it sooner, and a failed pull is retried no sooner than an hour after the attempt.
func TestSpamhausDROPIsFetchedAtMostOnceADay(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(dropFeedID)
	e.mirror(dropFeedID, o.url("/drop_v4.json"))
	o.body("/drop_v4.json", `"d1"`, dropBody)
	start := e.clock()

	// the schedule: 24 hours at least, for this feed only
	key := scheduleKey(dropFeedID)
	_, err := e.sched.Save(t.Context(), key, schedule.Setting{Enabled: true, Rule: schedule.Every(12 * 60)}, "admin@acme.example")
	var re *schedule.RuleError
	if !errors.As(err, &re) || re.Field != "every_minutes" || re.Message != "The interval is at least 1 day. Spamhaus DROP asks for at most one download every 24 hours." {
		t.Errorf("a 12-hour schedule: %v", err)
	}
	if v, err := e.sched.Get(t.Context(), key); err != nil || v.Limits.MinEveryMinutes != 24*60 {
		t.Errorf("the editor's floor: %+v %v", v.Limits, err)
	}
	if v, err := e.sched.Get(t.Context(), scheduleKey("et-open")); err != nil || v.Limits.MinEveryMinutes != 60 {
		t.Errorf("another feed's floor: %+v %v", v.Limits, err)
	}
	e.every(dropFeedID, 24)

	// the first pull, then Fetch now an hour later: refused, nothing asked
	if c, b := e.fetch(dropFeedID); c != 200 || at(b, "status") != "ok" {
		t.Fatalf("first pull: %d %v", c, b)
	}
	e.setNow(start.Add(time.Hour))
	c, b := e.fetch(dropFeedID)
	if c != http.StatusConflict || code(b) != "fetch_too_soon" || !strings.Contains(fmt.Sprint(at(b, "error", "message")), "Fetch it again after 6 Nov 2026, 12:00 UTC.") {
		t.Errorf("Fetch now after an hour: %d %v", c, b)
	}
	if n := o.count("/drop_v4.json"); n != 1 {
		t.Fatalf("%d requests, want 1", n)
	}

	// the job: not before 24 hours, then once
	e.setNow(start.Add(23*time.Hour + 55*time.Minute))
	if err := e.runPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := o.count("/drop_v4.json"); n != 1 {
		t.Errorf("pulled before 24 hours: %d requests", n)
	}
	e.setNow(start.Add(24 * time.Hour))
	if err := e.runPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := o.count("/drop_v4.json"); n != 2 {
		t.Errorf("after 24 hours: %d requests, want 2", n)
	}

	// Spamhaus fails: the retry waits an hour, not the 5 minutes of the usual back-off
	o.serve("/drop_v4.json", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	failed := start.Add(48 * time.Hour)
	e.setNow(failed)
	if err := e.runPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := o.count("/drop_v4.json"); n != 3 || e.feed(dropFeedID).Failures != 1 {
		t.Fatalf("the failing pull: %d requests, %d failures", n, e.feed(dropFeedID).Failures)
	}
	e.setNow(failed.Add(10 * time.Minute))
	if err := e.runPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if c, b := e.fetch(dropFeedID); c != http.StatusConflict || code(b) != "fetch_too_soon" {
		t.Errorf("Fetch now 10 minutes after a failed attempt: %d %v", c, b)
	}
	if n := o.count("/drop_v4.json"); n != 3 {
		t.Errorf("retried 10 minutes after a failure: %d requests", n)
	}
	e.setNow(failed.Add(time.Hour))
	if err := e.runPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := o.count("/drop_v4.json"); n != 4 {
		t.Errorf("an hour after the failure: %d requests, want 4", n)
	}
}
