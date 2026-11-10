package scan

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

func TestMigrationsUsePrefix(t *testing.T) {
	t.Parallel()
	storetest.AssertMigrationsUsePrefix(t, ModuleID, Migrations, "scan_", storetest.Migration{Module: "core", FS: core.Migrations})
}

// The database refuses what INV-5 forbids, whatever the code does (DATA_MODEL section 6).
func TestMigrations_ConstraintsHold(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for name, q := range map[string]string{
		"second row":       `INSERT INTO scan_setting (id) VALUES (2)`,
		"rate 0":           `UPDATE scan_setting SET rate = 0`,
		"rate 21":          `UPDATE scan_setting SET rate = 21`,
		"no day":           `UPDATE scan_setting SET days = '[]'`,
		"days not array":   `UPDATE scan_setting SET days = '{}'`,
		"from 24:00":       `UPDATE scan_setting SET win_from = '24:00'`,
		"to 7:00":          `UPDATE scan_setting SET win_to = '7:00'`,
		"201 exclusions":   `UPDATE scan_setting SET exclusions = (SELECT json_group_array('10.0.0.1') FROM (WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 201) SELECT i FROM n))`,
		"unresponsive 1":   `UPDATE scan_setting SET unresponsive_after = 1`,
		"frequency hourly": `UPDATE scan_setting SET sched_frequency = 'hourly'`,
		"weekday 0":        `UPDATE scan_setting SET sched_weekday = 0`,
		"auto_rescan 2":    `UPDATE scan_setting SET auto_rescan = 2`,
	} {
		err := e.db.Write(e.ctx(), func(tx *sql.Tx) error { _, err := tx.ExecContext(e.ctx(), q); return err })
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The defaults are the clean install of the mock.
func TestMigrations_Defaults(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v, err := e.svc.Config(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	c := v.Config
	if len(c.Window.Days) != 7 || c.Window.From != "22:00" || c.Window.To != "05:00" || c.Rate != 5 || len(c.Exclusions) != 0 || c.Exclusions == nil ||
		!c.StopOnUnresponsive || c.UnresponsiveAfter != 3 || !c.AutoRescan || c.Schedule != (Schedule{Enabled: true, Frequency: "weekly", Weekday: 7, At: "23:00"}) {
		t.Fatalf("defaults: %+v", c)
	}
}

// Roles of the endpoints this slice owns; a module that is off has no routes (SYS-5).
func TestHandlers_RolesAndModuleGate(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	if code, _ := e.call("GET", "/scans/config", "", ""); code != 401 {
		t.Fatalf("no session: %d", code)
	}
	if code, b := e.call("GET", "/scans/config", "viewer", ""); code != 200 || b["can_scan"] != true {
		t.Fatalf("viewer GET: %d %v", code, b)
	}
	e.gate.Set(ModuleID, false)
	for _, c := range [][3]string{{"GET", "/scans/config", ""}, {"PUT", "/scans/config", `{"rate":6}`}} {
		if code, _ := e.call(c[0], c[1], "admin", c[2]); code != 404 {
			t.Errorf("%s %s with the module off: %d", c[0], c[1], code)
		}
	}
	e.gate.Set(ModuleID, true)
	if e.count(`SELECT rate FROM scan_setting`) != 5 {
		t.Fatal("a request to a module that is off changed data")
	}
}
