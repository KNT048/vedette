package feeds

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/schedule"
)

// Every source has its schedule from the start: built-in ones at their default, a custom one at six hours; the interval the API shows
// is the schedule's.
func TestSchedule_EverySourceHasOneAndTheAPIShowsItsInterval(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, b := range BuiltinSources() {
		v, err := e.sched.Get(t.Context(), "feeds.source:"+b.ID)
		if err != nil || !v.Saved || !v.Enabled || v.Rule.EveryMinutes == nil || *v.Rule.EveryMinutes != b.IntervalHours*60 {
			t.Fatalf("%s: %+v %v", b.ID, v, err)
		}
	}
	e.every("ipsum", 12)
	if _, b := e.get("/feeds/sources"); true {
		var got any
		for _, it := range at(b, "items").([]any) {
			if at(it, "id") == "ipsum" {
				got = at(it, "interval_hours")
			}
		}
		if got != 12.0 {
			t.Fatalf("interval_hours of ipsum = %v, want the schedule's 12", got)
		}
	}
	if c, b, _ := e.do("POST", "/feeds/custom", "admin", customBody); c != 201 || at(b, "interval_hours") != float64(DefaultCustomHours) {
		t.Fatalf("custom feed: %d %v", c, b)
	}
	if n := count(t, e.db, `SELECT count(*) FROM core_schedule WHERE owner_key LIKE 'feeds.source:cf-%' AND every_minutes = 360`); n != 1 {
		t.Fatalf("%d schedules of custom feeds at six hours", n)
	}
}

// A custom feed's schedule goes with it.
func TestSchedule_DeletingACustomFeedDeletesItsSchedule(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, b, _ := e.do("POST", "/feeds/custom", "admin", customBody)
	id, _ := at(b, "id").(string)
	if id == "" {
		t.Fatalf("created: %v", b)
	}
	if c, _, _ := e.do("DELETE", "/feeds/custom/"+id, "admin", ""); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	if n := count(t, e.db, `SELECT count(*) FROM core_schedule WHERE owner_key = 'feeds.source:`+id+`'`); n != 0 {
		t.Fatalf("%d schedules left", n)
	}
	if _, err := e.sched.Get(t.Context(), "feeds.source:"+id); !errors.Is(err, schedule.ErrUnknownOwner) {
		t.Fatalf("a deleted feed has a schedule: %v", err)
	}
}

// Sources ask not to be polled more often than hourly: the editor refuses, with the reason; a source that is off skips its due
// time and says so.
func TestSchedule_LimitsAndSkips(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, err := e.sched.Save(t.Context(), "feeds.source:ipsum", schedule.Setting{Enabled: true, Rule: schedule.Every(10)}, "admin@acme.example")
	var re *schedule.RuleError
	if !errors.As(err, &re) || !strings.Contains(re.Message, "not to poll more often") || re.Field != "every_minutes" {
		t.Fatalf("10 minutes: %v", err)
	}
	if _, err = e.sched.Save(t.Context(), "feeds.source:ipsum", schedule.Setting{Enabled: true, Rule: schedule.Every(60).InWindow()}, "admin@acme.example"); !errors.As(err, &re) || re.Field != "window" {
		t.Fatalf("a feed in the scan window: %v", err)
	}
	if _, err = e.sched.Save(t.Context(), "feeds.source:ipsum", schedule.Setting{Enabled: true, Rule: schedule.DailyAt("03:00")}, "admin@acme.example"); !errors.As(err, &re) || re.Field != "freq" {
		t.Fatalf("daily: %v", err)
	}
	if c, _ := e.put("ipsum", `{"enabled":false}`); c != http.StatusOK {
		t.Fatal(c)
	}
	e.every("ipsum", 6)
	e.setNow(e.clock().Add(7 * time.Hour))
	if _, err := e.sched.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	v, err := e.sched.Get(t.Context(), "feeds.source:ipsum")
	if err != nil || v.LastSkipReason == nil || *v.LastSkipReason != "The source is turned off." {
		t.Fatalf("%+v %v", v, err)
	}
}
