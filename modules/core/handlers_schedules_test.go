package core_test

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/schedule"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/core"
)

type schedulesComposite struct {
	server.Fallback
	*core.ScheduleHandlers
}

// The schedules API over a real service: one owner per subject (exposure targets, an operator's) and one limited owner (a
// feed source's refresh, an administrator's). The organization's zone is Europe/Berlin.
func TestSchedules_GetSavePreviewAndRunOnce(t *testing.T) {
	t.Parallel()
	db := migrated(t)
	log := slog.New(slog.DiscardHandler)
	reg, err := modreg.New(t.Context(), modreg.Config{DB: db, Audit: audit.New(nil), Manifests: modules.Manifests, Version: "test", Log: log})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO core_org (id, name, timezone, install_id) VALUES (1, 'Example', 'Europe/Berlin', 'ins-test')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	m, err := run.New(run.Config{DB: db, Gate: reg, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	noop := func(context.Context, *run.Exec) (run.Result, error) { return run.Result{}, nil }
	if err := m.Register(run.Kind{Module: "exposure", Name: "exposure_scan", Lane: "exposure", Run: noop}); err != nil {
		t.Fatal(err)
	}
	svc, err := schedule.New(schedule.Config{DB: db, Audit: audit.New(nil), Gate: reg, Log: log,
		Clock: func() time.Time { return time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Register(schedule.Owner{Module: "exposure", Key: "exposure.target", PerSubject: true, Default: schedule.WeeklyAt("02:30", 1).InWindow(),
		Start: func(ctx context.Context, tx *sql.Tx, f schedule.Fire) (string, error) {
			return m.CreateTx(ctx, tx, run.Spec{Module: "exposure", Kind: "exposure_scan", Title: "Scan of www.example.com", Trigger: f.Trigger, RequestedBy: f.By, ScheduleID: f.ScheduleID})
		}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Register(schedule.Owner{Module: "feeds", Key: "feeds.source", PerSubject: true, AdminOnly: true, Default: schedule.Every(60),
		Limits: schedule.Limits{Freqs: []schedule.Freq{schedule.Interval}, MinEveryMinutes: 60, Reason: "Sources ask clients not to poll more often."},
		Start:  func(context.Context, *sql.Tx, schedule.Fire) (string, error) { return "", nil }}); err != nil {
		t.Fatal(err)
	}
	s := &stack{t: t, db: db, reg: reg}
	s.h, err = server.New(server.Config{API: schedulesComposite{Fallback: server.Fallback{Log: log}, ScheduleHandlers: core.NewScheduleHandlers(svc)},
		Auth: &servertest.Auth{Users: servertest.StandardUsers()}, Modules: reg, Log: log})
	if err != nil {
		t.Fatal(err)
	}

	code, v := s.call("GET", "/schedules/exposure.target:tgt-1", "viewer", "")
	if code != http.StatusOK || v["saved"] != false || v["zone"] != "Europe/Berlin" || v["edit_role"] != "operator" {
		t.Fatalf("GET default = %d %v", code, v)
	}
	if code, _ := s.call("GET", "/schedules/nothing.here", "viewer", ""); code != http.StatusNotFound {
		t.Fatalf("unknown key = %d", code)
	}

	// The preview: every 3 days at 02:30 in a Monday to Friday window, read in Berlin.
	rule := `{"freq":"interval","every_minutes":4320,"at_time":"02:30","weekdays":null,"month_day":null,"once_at":null,"tz":"org",
		"window":"custom","window_days":[1,2,3,4,5],"window_from":"00:00","window_to":"00:00"}`
	code, p := s.call("POST", "/schedules/preview", "viewer", `{"rule":`+rule+`}`)
	if code != http.StatusOK || p["zone"] != "Europe/Berlin" || len(p["upcoming"].([]any)) != 3 || p["upcoming"].([]any)[0] != "2026-11-23T01:30:00Z" {
		t.Fatalf("preview = %d %v", code, p)
	}
	// The feed source refuses 10 minutes and says why.
	ten := `{"freq":"interval","every_minutes":10,"at_time":null,"weekdays":null,"month_day":null,"once_at":null,"tz":"org","window":"none","window_days":null,"window_from":null,"window_to":null}`
	code, e := s.call("POST", "/schedules/preview", "viewer", `{"owner_key":"feeds.source:nvd","rule":`+ten+`}`)
	if er := e["error"].(map[string]any); code != http.StatusBadRequest || er["code"] != "invalid" || er["field"] != "every_minutes" || !strings.Contains(er["message"].(string), "Sources ask clients") {
		t.Fatalf("limited preview = %d %v", code, e)
	}
	if code, _ := s.call("PUT", "/schedules/feeds.source:nvd", "operator", `{"enabled":true,"rule":`+ten+`}`); code != http.StatusForbidden {
		t.Fatalf("an operator's change of an admin's schedule = %d, want 403", code)
	}

	// Save, pause, then run once now.
	if code, _ := s.call("PUT", "/schedules/exposure.target:tgt-1", "viewer", `{"enabled":true,"rule":`+rule+`}`); code != http.StatusForbidden {
		t.Fatalf("a viewer's save = %d, want 403", code)
	}
	code, v = s.call("PUT", "/schedules/exposure.target:tgt-1", "operator", `{"enabled":true,"paused_until":"2026-11-24T00:00:00Z","rule":`+rule+`}`)
	if code != http.StatusOK || v["saved"] != true || v["next_due_at"] != "2026-11-27T01:30:00Z" || v["paused_until"] == nil {
		t.Fatalf("PUT = %d %v", code, v)
	}
	if code, e := s.call("POST", "/schedules/exposure.target:tgt-1/run", "operator", ""); code != http.StatusConflict || e["error"].(map[string]any)["code"] != "not_started" {
		t.Fatalf("run once with the exposure module off = %d %v", code, e)
	}
	turnOn(t, s, "exposure")
	code, r := s.call("POST", "/schedules/exposure.target:tgt-1/run", "operator", "")
	if code != http.StatusOK || r["run_id"] == nil {
		t.Fatalf("run once = %d %v", code, r)
	}
	if code, e := s.call("POST", "/schedules/exposure.target:tgt-1/run", "operator", ""); code != http.StatusConflict || e["error"].(map[string]any)["code"] != "busy" {
		t.Fatalf("second run once = %d %v", code, e)
	}
	if code, v = s.call("GET", "/schedules/exposure.target:tgt-1", "viewer", ""); code != http.StatusOK || v["last_run_id"] != r["run_id"] || v["next_due_at"] != "2026-11-27T01:30:00Z" {
		t.Fatalf("after run once = %d %v", code, v)
	}
	if n := count(t, s.db, `SELECT count(*) FROM core_audit WHERE action IN ('schedule.save', 'schedule.run_now')`); n != 2 {
		t.Errorf("audit rows = %d, want 2", n)
	}
	if n, err := schedule.NextDueMismatches(t.Context(), db.Reader()); err != nil || n != 0 {
		t.Fatalf("next due mismatches %d %v", n, err)
	}
}

// The organization's time zone is the column default of core_org.timezone before setup: core/schedule reads the same one.
func TestScheduleDefaultZoneIsTheOrgDefault(t *testing.T) {
	if core.DefaultTimezone != schedule.DefaultOrgZone {
		t.Fatalf("core %q, schedule %q", core.DefaultTimezone, schedule.DefaultOrgZone)
	}
}
