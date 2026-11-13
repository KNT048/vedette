package scan

import (
	"database/sql"
	"slices"
	"strings"
	"testing"
	"time"
)

// INV-4: dangerous checks cannot be turned on; the answer always says false, and nothing is saved or audited.
func TestContract_INV4_DangerousChecksLocked(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	code, b := e.call("PUT", "/scans/config", "admin", `{"dangerous_checks":true,"rate":7}`)
	if c, msg := errOf(b); code != 400 || c != "dangerous_locked" || msg != "Vedette has no dangerous checks: no exploitation, no denial of service. It cannot be turned on." {
		t.Fatalf("dangerous_checks true: %d %v", code, b)
	}
	if e.count(`SELECT rate FROM scan_setting`) != 5 || len(e.audits()) != 0 {
		t.Fatal("a refused change was saved or audited")
	}
	code, b = e.call("PUT", "/scans/config", "admin", `{"dangerous_checks":false,"rate":7}`)
	if code != 200 || b["dangerous_checks"] != false {
		t.Fatalf("dangerous_checks false: %d %v", code, b)
	}
	if _, b = e.call("GET", "/scans/config", "viewer", ""); b["dangerous_checks"] != false {
		t.Fatalf("GET says %v", b["dangerous_checks"])
	}
}

// INV-5: every rule of the configuration, with the mock's words; the merged configuration is checked as a whole.
func TestContract_INV5_ConfigRules(t *testing.T) {
	t.Parallel()
	i := func(v int) *int { return &v }
	s := func(v string) *string { return &v }
	b := func(v bool) *bool { return &v }
	cases := []struct {
		name string
		p    Patch
		msg  string // "" = accepted
	}{
		{"no day", Patch{Days: []int{}}, "Choose at least one day for the scan window."},
		{"day 0", Patch{Days: []int{0, 1}}, "Choose at least one day for the scan window."},
		{"day 8", Patch{Days: []int{8}}, "Choose at least one day for the scan window."},
		{"bad from", Patch{From: s("24:00")}, "Time must look like HH:MM, for example 22:00."},
		{"bad to", Patch{To: s("7:00")}, "Time must look like HH:MM, for example 22:00."},
		{"from equals to", Patch{From: s("05:00")}, "The start and end times must differ. To scan all day, set 00:00 to 23:59."},
		{"rate 0", Patch{Rate: i(0)}, "The rate must be 1 to 20 requests per second. A lower rate is safer for old devices."},
		{"rate 21", Patch{Rate: i(21)}, "The rate must be 1 to 20 requests per second. A lower rate is safer for old devices."},
		{"201 exclusions", Patch{Exclusions: slices.Repeat([]string{"10.0.0.1"}, 201)}, "The exclusion list can have at most 200 lines."},
		{"bad exclusion", Patch{Exclusions: []string{"192.168.10.5", "printer.local"}}, `Line 2: "printer.local" is not an IP or network range. For example 192.168.10.5 or 192.168.20.0/24.`},
		{"IPv6 exclusion", Patch{Exclusions: []string{"fe80::1"}}, `Line 1: "fe80::1" is not an IP or network range. For example 192.168.10.5 or 192.168.20.0/24.`},
		{"leading zero", Patch{Exclusions: []string{"010.0.0.1"}}, `Line 1: "010.0.0.1" is not an IP or network range. For example 192.168.10.5 or 192.168.20.0/24.`},
		{"long exclusion is cut", Patch{Exclusions: []string{strings.Repeat("x", 60)}}, `Line 1: "` + strings.Repeat("x", 40) + `" is not an IP or network range. For example 192.168.10.5 or 192.168.20.0/24.`},
		{"unresponsive 1", Patch{UnresponsiveAfter: i(1)}, "The number of non-responses before auto-stop must be 2 to 20."},
		{"unresponsive 21", Patch{UnresponsiveAfter: i(21)}, "The number of non-responses before auto-stop must be 2 to 20."},
		{"frequency", Patch{SchedFrequency: s("hourly")}, "The schedule must be daily or weekly."},
		{"schedule time", Patch{SchedAt: s("23:5")}, "The schedule time must look like HH:MM."},
		{"weekday", Patch{SchedWeekday: i(0)}, "The schedule day is not valid."},
		{"schedule outside window", Patch{SchedAt: s("12:00")}, "The schedule time 12:00 is outside the 22:00 to 05:00 window. Pick a time inside the window or widen the window."},
		{"weekly day not a window day", Patch{Days: []int{1, 2}}, "The weekly schedule day must be one of the scan window days."},
		{"off schedule may be outside", Patch{SchedEnabled: b(false), SchedAt: s("12:00"), Days: []int{1}}, ""},
		{"after midnight is inside", Patch{SchedAt: s("01:30")}, ""},
		{"CIDR with host bits", Patch{Exclusions: []string{"192.168.20.5/24", "10.0.0.1"}}, ""},
		{"200 exclusions", Patch{Exclusions: slices.Repeat([]string{"10.0.0.1"}, 200)}, ""},
		{"edges", Patch{Rate: i(20), UnresponsiveAfter: i(2), From: s("00:00"), To: s("23:59"), SchedAt: s("23:58")}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			_, err := e.svc.SaveConfig(e.ctx(), "admin@acme.example", c.p)
			if c.msg == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantAPI(t, err, 400, "invalid_config")
			if !strings.HasSuffix(err.Error(), c.msg) {
				t.Fatalf("message: %v\nwant: %s", err, c.msg)
			}
			if len(e.audits()) != 0 {
				t.Fatal("a refused change was audited")
			}
		})
	}
}

// INV-5: days are stored sorted, once each.
func TestContract_INV5_DaysNormalized(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v, err := e.svc.SaveConfig(e.ctx(), "admin@acme.example", Patch{Days: []int{7, 3, 3, 1}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(v.Config.Window.Days, []int{1, 3, 7}) {
		t.Fatalf("days = %v", v.Config.Window.Days)
	}
}

// INV-11: the scope and the commitment come from the inventory; scan only reads them (its Inventory port has no write).
// INV-2: without the commitment, or without a ready scanner, nothing can start and the page says why.
func TestContract_INV11_INV2_ScopeAndCommitmentFromInventory(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v, err := e.svc.Config(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if !v.CanScan || v.BlockReason != nil || v.Scope.Commitment == nil || v.Scope.Commitment.By != "admin@acme.example" ||
		v.Scope.Commitment.ConfirmedAt != "2026-11-01T08:00:00.000Z" || !slices.Equal(v.Scope.Networks, []string{"192.168.10.0/24", "192.168.20.0/24"}) {
		t.Fatalf("confirmed scope: %+v", v)
	}

	e.inv.set(Scope{Networks: []string{"10.20.0.0/24"}})
	v, _ = e.svc.Config(e.ctx())
	if v.CanScan || v.Scope.Commitment != nil || v.BlockReason == nil || *v.BlockReason != "The scan scope commitment is not ticked yet. Do it under Devices, Scope and sensors." {
		t.Fatalf("no commitment: %+v", v)
	}

	e.inv.set(confirmedScope())
	e.engine.setDown(errNoHeartbeat)
	v, _ = e.svc.Config(e.ctx())
	if v.CanScan || v.BlockReason == nil || *v.BlockReason != "The vulnerability scanner is not available: the scan container or its scanner is missing. Check the box's services, then try again." {
		t.Fatalf("scanner down: %+v", v)
	}
	e.inv.set(Scope{}) // the commitment is named first: it is what the user can fix here
	if v, _ = e.svc.Config(e.ctx()); *v.BlockReason != msgNoCommitment || v.Scope.Networks == nil {
		t.Fatalf("both missing: %+v", v)
	}
}

// INV-2: no Engine at all (production before the remote engine is wired) is "scanner not available", never "ready".
func TestContract_INV2_NoEngineIsUnavailable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	svc, err := NewService(Config{DB: e.db, Audit: e.svc.cfg.Audit, Inventory: e.inv, Log: e.svc.cfg.Log, Clock: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	v, err := svc.Config(e.ctx())
	if err != nil || v.CanScan || *v.BlockReason != msgScannerDown {
		t.Fatalf("%+v %v", v, err)
	}
}

// PRE-3, POST-3: admin only; a partial update keeps the other fields; the change and its audit row are one transaction.
func TestContract_PRE3_POST3_PartialUpdateAudited(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	for _, role := range []string{"viewer", "operator"} {
		if code, _ := e.call("PUT", "/scans/config", role, `{"rate":7}`); code != 403 {
			t.Fatalf("%s: %d", role, code)
		}
	}
	code, b := e.call("PUT", "/scans/config", "admin", `{"rate":7,"window":{"from":"21:00"},"schedule":{"frequency":"daily"},"exclusions":["192.168.10.250"]}`)
	if code != 200 {
		t.Fatalf("%d %v", code, b)
	}
	c := b["config"].(map[string]any)
	w := c["window"].(map[string]any)
	s := c["schedule"].(map[string]any)
	if c["rate"] != 7.0 || w["from"] != "21:00" || w["to"] != "05:00" || len(w["days"].([]any)) != 7 || s["frequency"] != "daily" || s["at"] != "23:00" ||
		c["auto_rescan"] != true || c["unresponsive_after"] != 3.0 || c["stop_on_unresponsive"] != true || len(c["exclusions"].([]any)) != 1 {
		t.Fatalf("merged config: %v", c)
	}
	a := e.audits()
	if len(a) != 1 || a[0].User != "admin@acme.example" || a[0].Action != "scan.config" || a[0].Target != "scan" ||
		a[0].Detail != `{"rate":7,"window":{"days":[1,2,3,4,5,6,7],"from":"21:00","to":"05:00"},"exclusions":1,"auto_rescan":true,"schedule":true}` {
		t.Fatalf("audit: %+v", a)
	}
	// an empty list clears; an absent one keeps
	if _, b = e.call("PUT", "/scans/config", "admin", `{"auto_rescan":false}`); len(b["config"].(map[string]any)["exclusions"].([]any)) != 1 {
		t.Fatalf("absent exclusions changed the list: %v", b)
	}
	if _, b = e.call("PUT", "/scans/config", "admin", `{"exclusions":[]}`); len(b["config"].(map[string]any)["exclusions"].([]any)) != 0 {
		t.Fatalf("an empty list did not clear: %v", b)
	}
	if _, b = e.call("GET", "/scans/config", "viewer", ""); b["config"].(map[string]any)["auto_rescan"] != false {
		t.Fatalf("not stored: %v", b)
	}
}

// POST-3: next_run is the next schedule time on a window day (and on the weekday for weekly), in the organization's time zone.
func TestContract_POST3_NextRun(t *testing.T) {
	t.Parallel()
	hcm, err := time.LoadLocation("Asia/Ho_Chi_Minh")
	if err != nil {
		t.Fatal(err)
	}
	base := Settings{Window: Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "22:00", To: "05:00"}, Schedule: Schedule{Enabled: true, Frequency: "weekly", Weekday: 7, At: "23:00"}}
	at := func(c Settings, now time.Time, loc *time.Location) string {
		t.Helper()
		r := c.NextRun(now, loc, false)
		if r == nil {
			return "null"
		}
		return r.UTC().Format(time.RFC3339)
	}
	tue := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC) // Tuesday 17:00 in Ho Chi Minh City
	if got := at(base, tue, hcm); got != "2026-11-15T16:00:00Z" {
		t.Fatalf("weekly Sunday 23:00 +07: %s", got)
	}
	daily := base
	daily.Schedule.Frequency = "daily"
	if got := at(daily, tue, hcm); got != "2026-11-10T16:00:00Z" {
		t.Fatalf("daily, later today: %s", got)
	}
	if got := at(daily, time.Date(2026, 11, 10, 16, 0, 0, 0, time.UTC), hcm); got != "2026-11-11T16:00:00Z" {
		t.Fatalf("daily, exactly now: %s", got)
	}
	weekdays := daily
	weekdays.Window.Days = []int{1, 2, 3, 4, 5}
	if got := at(weekdays, time.Date(2026, 11, 13, 17, 0, 0, 0, time.UTC), hcm); got != "2026-11-16T16:00:00Z" { // Friday 23:00 +07 has passed
		t.Fatalf("daily on window days only: %s", got)
	}
	off := base
	off.Schedule.Enabled = false
	if got := at(off, tue, hcm); got != "null" {
		t.Fatalf("off: %s", got)
	}
	e := newEnv(t)
	v, _ := e.svc.Config(e.ctx())
	if v.NextRun == nil || *v.NextRun != "2026-11-10T23:00:00.000Z" { // the env's zone is UTC; t0 is a Tuesday; no run yet: tonight (W3-6)
		t.Fatalf("view next_run: %v", v.NextRun)
	}
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error { return markSlot(e.ctx(), tx, t0.AddDate(0, 0, -2)) }); err != nil {
		t.Fatal(err)
	}
	if v, _ = e.svc.Config(e.ctx()); v.NextRun == nil || *v.NextRun != "2026-11-15T23:00:00.000Z" { // a slot ran: the weekly Sunday
		t.Fatalf("view next_run after a scheduled slot: %v", v.NextRun)
	}
}
