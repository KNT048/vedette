package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/schedule"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/reports"
	"github.com/knt048/vedette/modules/scan"
)

// Every schedule a person can set is a core/schedule owner, with its limits and the reason for them.
func TestTheBoxRegistersTheScheduleOwners(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := testServices(t)
	scanService(d)
	exposureService(d)
	reportsService(d)
	newNotify(&d)
	fs, err := feedsService(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		key        string
		freqs      []schedule.Freq
		min, max   int
		defaultOn  bool
		wantReason bool
	}{
		{scan.ScheduleKey, nil, 1, 0, true, true},
		{exposure.PublicIPScheduleKey, []schedule.Freq{schedule.Interval}, 5, 1440, true, true},
		{agentintake.WazuhScheduleKey, []schedule.Freq{schedule.Interval}, 5, 0, false, true}, // off until a server is connected
		{"feeds.source:cisa-kev", []schedule.Freq{schedule.Interval}, 60, 168 * 60, true, true},
		{reports.ScheduleKey(reports.DefinitionID), []schedule.Freq{schedule.Weekly, schedule.Monthly}, 1, 0, false, true}, // off until a person turns it on
		{notify.SummaryScheduleKey, []schedule.Freq{schedule.Daily}, 1, 0, false, true},                                    // the daily summary: off until a person turns it on
	} {
		v, err := d.Schedules.Get(ctx, c.key)
		if err != nil {
			t.Errorf("%s: %v", c.key, err)
			continue
		}
		if v.Enabled != c.defaultOn || (c.defaultOn && v.NextDueAt == nil) {
			t.Errorf("%s: enabled %v, next due %v", c.key, v.Enabled, v.NextDueAt)
		}
		if c.freqs != nil && (len(v.Limits.Freqs) != len(c.freqs) || v.Limits.Freqs[0] != c.freqs[0]) {
			t.Errorf("%s: freqs %v, want %v", c.key, v.Limits.Freqs, c.freqs)
		}
		if v.Limits.MinEveryMinutes != c.min || (c.max != 0 && v.Limits.MaxEveryMinutes != c.max) || (v.Limits.Reason != "") != c.wantReason {
			t.Errorf("%s: limits %+v", c.key, v.Limits)
		}
	}
	// a source that does not exist has no schedule
	if _, err := d.Schedules.Get(ctx, "feeds.source:nope"); err == nil {
		t.Error("a schedule for a source that does not exist")
	}
	// the sources the box seeded all have their schedule row, and nothing else keeps their interval
	var sources, rows int
	if err := d.DB.Reader().QueryRowContext(ctx, `SELECT count(*) FROM feeds_source`).Scan(&sources); err != nil {
		t.Fatal(err)
	}
	if err := d.DB.Reader().QueryRowContext(ctx, `SELECT count(*) FROM core_schedule WHERE owner_key LIKE 'feeds.source:%'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if sources == 0 || rows != sources {
		t.Errorf("%d sources, %d schedules", sources, rows)
	}
}

// Every schedule of the spec's table that this version moves is registered with core/schedule by the box's wiring, whatever the old
// logic was renamed to: the keys the editor uses, and the wiring that registers each (the sweep needs the scan container's link, so it
// is registered where that service is built).
func TestEveryOwnerOfTheSpecTableIsRegistered(t *testing.T) {
	t.Parallel()
	wired := map[string]struct{ file, call string }{
		"scan.vuln":          {"scan.go", "svc.ScheduleOwner()"},
		"inventory.sweep":    {"sensoractive.go", "s.ScheduleOwner()"},
		"feeds.source":       {"feeds.go", "s.ScheduleOwner()"},
		"exposure.public_ip": {filepath.Join("..", "..", "modules", "exposure", "schedule.go"), "s.PublicIPScheduleOwner()"},
		"agent-intake.wazuh": {"wiring.go", "d.AgentIntake.ScheduleOwner()"},
		"reports.def":        {"reports.go", "svc.ScheduleOwner()"},
		"notify.summary":     {"notify.go", "svc.ScheduleOwner()"},
	}
	for key, w := range wired {
		b, err := os.ReadFile(w.file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "Schedules.Register("+w.call+")") {
			t.Errorf("%s: %s does not register %s", key, w.file, w.call)
		}
	}
	// the maintenance window: the shared window test, not a copy
	b, err := os.ReadFile(filepath.Join("..", "..", "modules", "core", "osmaint.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "schedule.Window{") {
		t.Error("the maintenance window does not use core/schedule's window")
	}
}

// ownLogic names, for each owner of a schedule, what its module kept before it moved to core/schedule: a stored slot, an interval column
// or a window of its own. The count test below finds none of it left.
var ownLogic = []struct {
	name, dir string
	marker    *regexp.Regexp
}{
	{"vulnerability checks: slots, window and next run", "modules/scan", regexp.MustCompile(`sched_(enabled|frequency|weekday|at|last)|func \(c Settings\) (slotOK|lastSlot|NextRun|slotWindowEnd)|func inTimeRange`)},
	{"LAN sweep: a pass per window, the window's own arithmetic", "modules/sensor-active", regexp.MustCompile(`func \(s \*Service\) sweptSince|slices\.Contains\(st\.Days|func minutes\(`)},
	{"feeds: an interval column and the next attempt", "modules/feeds", regexp.MustCompile(`interval_hours\s+INTEGER|func \(s State\) NextAttempt`)},
	{"public IP detection: an interval column and its own due test", "modules/exposure", regexp.MustCompile(`interval_min\s+INTEGER|func autoDue\(`)},
	{"Wazuh pull: an interval column and its own preset list", "modules/agent-intake", regexp.MustCompile(`interval_minutes\s+INTEGER|var WazuhIntervals`)},
	{"maintenance window: its own days-and-hours test", "modules/core", regexp.MustCompile(`func isoDay\(|slices\.Contains\(w\.Days, isoDay`)},
	{"reports: a weekday-and-hour schedule table and its own slots", "modules/reports", regexp.MustCompile(`rep_schedule|func slotAt\(|func nextRun\(`)},
}

// The count test of the schedule owners: how many of them still keep a slot, an interval or a window of their own instead of using
// core/schedule. The per-target schedule of exposure scans moves with its own work and is not counted here.
func TestNoOwnerKeepsItsOwnSlotOrWindowLogic(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	left := 0
	for _, o := range ownLogic {
		var hits []string
		err := filepath.WalkDir(filepath.Join(root, o.dir), func(path string, de fs.DirEntry, err error) error {
			if err != nil || de.IsDir() || strings.HasSuffix(path, "_test.go") || (!strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".sql")) {
				return err
			}
			b, err := os.ReadFile(path) //nolint:gosec // the module's own source files, found by the walk above
			if err != nil {
				return err
			}
			if o.marker.Match(b) {
				hits = append(hits, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) > 0 {
			left++
			t.Errorf("%s still has its own logic in %v", o.name, hits)
		}
	}
	t.Logf("owners with logic of their own left outside core/schedule: %d of %d", left, len(ownLogic))
}
