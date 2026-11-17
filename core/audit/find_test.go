package audit_test

import (
	"testing"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store/storetest"
)

// Find reads the lines of the given actions on one target within a time window, oldest first, and nothing else.
func TestFindReadsTheLinesOfATargetInAWindow(t *testing.T) {
	t.Parallel()
	db := storetest.NewMigrated(t, "core", coreMigrations)
	appendAll(t, db, audit.New(fixedClock()),
		audit.Entry{User: "system", Action: "module.disable", Target: "exposure"},
		audit.Entry{User: "a@acme.example", Action: "module.disable", Target: "feeds"},
		audit.Entry{User: "b@acme.example", Action: "module.enable", Target: "exposure"},
		audit.Entry{User: "c@acme.example", Action: "module.disable", Target: "exposure", Detail: "affected: none"},
		audit.Entry{User: "d@acme.example", Action: "module.disable", Target: "exposure"},
	)
	var ts []string
	rows, err := db.Reader().QueryContext(t.Context(), `SELECT ts FROM core_audit ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		ts = append(ts, v)
	}
	if err := rows.Close(); err != nil || len(ts) != 5 {
		t.Fatalf("ts %q, %v", ts, err)
	}
	got, err := audit.Find(t.Context(), db.Reader(), []string{"module.disable", "module.enable"}, "exposure", ts[1], ts[3], 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].User != "b@acme.example" || got[1].User != "c@acme.example" || got[1].Detail != "affected: none" || got[0].Detail != "" ||
		got[1].TS != ts[3] || got[1].Action != "module.disable" || got[1].Target != "exposure" {
		t.Fatalf("rows %+v", got)
	}
	if one, err := audit.Find(t.Context(), db.Reader(), []string{"module.disable"}, "exposure", "2026-11-09T00:00:00.000Z", "2026-11-10T00:00:00.000Z", 1); err != nil || len(one) != 1 || one[0].User != "system" {
		t.Fatalf("limit 1: %+v, %v", one, err)
	}
	if none, err := audit.Find(t.Context(), db.Reader(), nil, "exposure", "", "9", 10); err != nil || len(none) != 0 {
		t.Fatalf("no action: %+v, %v", none, err)
	}
}
