package core_test

import (
	"slices"
	"strings"
	"testing"
)

// GET /core/audit pages the matching rows on the box (offset, limit): every page is a slice of the same newest-first order, the total
// counts every match, and the text search runs over the whole log, not over a page.
func TestContract_INV17_AuditPagesAndSearchesTheWholeLog(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	w.auditRows(450, "bot@acme.example", "scan.run")

	targets := func(path string) []string {
		t.Helper()
		r := admin.get(path)
		wantOK(t, r, 200)
		var out []string
		for _, it := range r.JSON["items"].([]any) {
			out = append(out, it.(map[string]any)["target"].(string))
		}
		return out
	}
	// Three pages of 200, 200 and 50 rows of the 450, newest first, no row twice
	first := targets("/core/audit?user=bot@acme.example&limit=200")
	second := targets("/core/audit?user=bot@acme.example&offset=200&limit=200")
	third := targets("/core/audit?user=bot@acme.example&offset=400&limit=200")
	if len(first) != 200 || len(second) != 200 || len(third) != 50 {
		t.Fatalf("pages = %d, %d, %d", len(first), len(second), len(third))
	}
	if first[0] != "t449" || second[0] != "t249" || third[49] != "t0" {
		t.Fatalf("not one newest-first order: %s, %s, %s", first[0], second[0], third[49])
	}
	// A small page; a limit above 200 is 200; past the end is empty with the total kept
	if p := targets("/core/audit?user=bot@acme.example&offset=10&limit=25"); len(p) != 25 || p[0] != "t439" {
		t.Fatalf("offset 10, limit 25 = %v", p)
	}
	if p := targets("/core/audit?user=bot@acme.example&limit=999"); len(p) != 200 {
		t.Fatalf("limit 999 = %d rows", len(p))
	}
	if r := admin.get("/core/audit?user=bot@acme.example&offset=5000"); r.JSON["total"] != float64(450) || len(r.JSON["items"].([]any)) != 0 {
		t.Fatalf("past the end: %s", r.Raw)
	}
	// The search runs over the whole log, then pages: t17 and t170…t179 match (11 rows, far down the newest-first list); the second page
	// of 10 holds the oldest, t17
	r := admin.get("/core/audit?q=t17&user=bot@acme.example&limit=10")
	wantOK(t, r, 200)
	if r.JSON["total"] != float64(11) || len(r.JSON["items"].([]any)) != 10 {
		t.Fatalf("search: %s", r.Raw)
	}
	if p := targets("/core/audit?q=t17&user=bot@acme.example&offset=10&limit=10"); !slices.Equal(p, []string{"t17"}) {
		t.Fatalf("second page of the search = %v", p)
	}
	// Not a number: refused by the contract
	for _, bad := range []string{"offset=-1", "limit=abc", "offset=1e3"} {
		if r := admin.get("/core/audit?" + bad); r.Code != 400 {
			t.Fatalf("%s = %d", bad, r.Code)
		}
	}
}

// The screen shows each action by its label and the table stores its code, so a search for a word of a label ("synced") names the
// actions whose label holds it: their lines match, with the rest of the search unchanged; the list, its total and the export agree.
func TestAuditSearchMatchesTheActionsTheScreenNames(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	w.auditRows(3, "bot@acme.example", "inventory.software_sync")
	w.auditRows(2, "bot@acme.example", "scan.run")

	if r := admin.get("/core/audit?q=synced&user=bot@acme.example"); r.JSON["total"] != float64(0) {
		t.Fatalf("without the actions the code does not hold the word: %s", r.Raw)
	}
	r := admin.get("/core/audit?q=synced&actions=inventory.software_sync,core.general&user=bot@acme.example")
	wantOK(t, r, 200)
	if r.JSON["total"] != float64(3) || len(r.JSON["items"].([]any)) != 3 {
		t.Fatalf("search by label: %s", r.Raw)
	}
	if exp := admin.get("/core/audit/export?q=synced&actions=inventory.software_sync&user=bot@acme.example"); exp.Code != 200 || strings.Count(exp.Raw, "inventory.software_sync") != 3 {
		t.Fatalf("export of the search by label = %d: %s", exp.Code, exp.Raw)
	}
	// Without a search text the actions change nothing; a value that is not an action code is refused
	if r := admin.get("/core/audit?actions=inventory.software_sync&user=bot@acme.example"); r.JSON["total"] != float64(5) {
		t.Fatalf("actions without q: %s", r.Raw)
	}
	for _, bad := range []string{"x", "inventory.software_sync,%27%29%20OR%201%3D1", "INVENTORY.SYNC"} {
		if r := admin.get("/core/audit?q=s&actions=" + bad); r.Code != 400 {
			t.Fatalf("actions=%s = %d", bad, r.Code)
		}
	}
}
