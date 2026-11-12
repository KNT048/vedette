package core_test

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/modules/core"
)

func (w *world) auditRows(n int, user, action string) {
	w.t.Helper()
	if err := w.env.DB.Write(w.t.Context(), func(tx *sql.Tx) error {
		for i := range n {
			if err := w.env.Audit.Append(w.t.Context(), tx, audit.Entry{User: user, Action: action, Target: fmt.Sprintf("t%d", i)}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		w.t.Fatal(err)
	}
}

func TestContract_INV17_AuditListFiltersAndLimits(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	w.auditRows(250, "bot@acme.example", "scan.run")
	w.auditRows(2, "Zed@acme.example", "feeds.update")

	all := admin.get("/core/audit")
	wantOK(t, all, 200)
	items := all.JSON["items"].([]any)
	if len(items) != 200 {
		t.Fatalf("items = %d, want the 200-row cap", len(items))
	}
	total := all.JSON["total"].(float64)
	if total < 254 {
		t.Fatalf("total = %v", total)
	}
	first := items[0].(map[string]any)
	if first["action"] != "feeds.update" || first["user"] != "Zed@acme.example" || first["target"] != "t1" {
		t.Fatalf("not newest first: %v", first)
	}
	if first["id"] == "" || first["ts"] == nil {
		t.Fatalf("row = %v", first)
	}
	if _, has := first["detail"]; has {
		t.Fatal("a row without detail has a detail field")
	}
	has := func(list []any, want ...string) {
		t.Helper()
		for _, x := range want {
			found := false
			for _, v := range list {
				found = found || v == x
			}
			if !found {
				t.Errorf("%v lacks %q", list, x)
			}
		}
	}
	has(all.JSON["users"].([]any), "Zed@acme.example", "admin@acme.example", "bot@acme.example")
	has(all.JSON["groups"].([]any), "core", "feeds", "scan", "user", "module")
	if u := all.JSON["users"].([]any); fmt.Sprint(u[0]) != "Zed@acme.example" { // sorted, upper case first
		t.Errorf("users not sorted: %v", u)
	}

	// Filters: user, group, text (case-insensitive over action, target, detail and user), combinations.
	if r := admin.get("/core/audit?user=bot@acme.example"); r.JSON["total"] != float64(250) || len(r.JSON["items"].([]any)) != 200 {
		t.Fatalf("by user: %s", r.Raw[:120])
	}
	if r := admin.get("/core/audit?group=feeds"); r.JSON["total"] != float64(2) {
		t.Fatalf("by group: %s", r.Raw)
	}
	if r := admin.get("/core/audit?q=ZED"); r.JSON["total"] != float64(2) {
		t.Fatalf("by text: %s", r.Raw)
	}
	if r := admin.get("/core/audit?q=t1&group=feeds"); r.JSON["total"] != float64(1) {
		t.Fatalf("by text and group: %s", r.Raw)
	}
	if r := admin.get("/core/audit?q=" + strings.Repeat("a", 201)); r.Code != 400 {
		t.Fatalf("a 201-character search = %d", r.Code)
	}
	// Detail is searched and returned.
	if r := admin.get("/core/audit?q=bundle+smb"); r.JSON["total"] != float64(1) || r.JSON["items"].([]any)[0].(map[string]any)["detail"] == nil {
		t.Fatalf("by detail: %s", r.Raw)
	}
	// SQL metacharacters in the text are text.
	for _, q := range []string{"%25", "_", "'%3B+DROP+TABLE+core_audit%3B--", `"`} {
		if r := admin.get("/core/audit?q=" + q); r.Code != 200 {
			t.Fatalf("q=%s = %d", q, r.Code)
		}
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit"); n < 254 {
		t.Fatal("the table was touched")
	}
}

func TestContract_INV17_AuditDateFilters(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin() // 2026-11-09T08:00:00Z, time zone Asia/Ho_Chi_Minh (UTC+7)
	// A session idles out after 4 hours, so the administrator signs in again after each jump of the clock.
	jump := func(d time.Duration) {
		w.env.Clock.Advance(d)
		admin = w.client()
		wantOK(t, admin.login("admin@acme.example"), 200)
	}
	jump(24 * time.Hour)
	w.auditRows(1, "bot@acme.example", "scan.run") // 2026-11-10T08:00:00Z = 15:00 on the 10th in Ho Chi Minh
	jump(24 * time.Hour)
	w.auditRows(1, "bot@acme.example", "scan.late") // 2026-11-11T08:00:00Z

	count := func(q string) float64 {
		t.Helper()
		r := admin.get("/core/audit?" + q + "&group=scan")
		wantOK(t, r, 200)
		return r.JSON["total"].(float64)
	}
	if n := count("from=2026-11-10&to=2026-11-10"); n != 1 {
		t.Fatalf("a day = %v rows, want 1", n)
	}
	if n := count("from=2026-11-10"); n != 2 {
		t.Fatalf("from a day = %v", n)
	}
	if n := count("to=2026-11-10"); n != 1 {
		t.Fatalf("to a day = %v", n)
	}
	// Z timestamps are exact.
	if n := count("from=2026-11-10T08:00:00Z&to=2026-11-10T08:00:00Z"); n != 1 {
		t.Fatalf("an exact instant = %v", n)
	}
	if n := count("from=2026-11-10T08:00:00.001Z"); n != 1 {
		t.Fatalf("after an instant = %v", n)
	}
	// The day of the organization's zone: 2026-11-11T00:30+07:00 is still the 10th in UTC terms, the 11th in Ho Chi Minh.
	jump(-24*time.Hour - 8*time.Hour + 17*time.Hour + 30*time.Minute) // 2026-11-10T17:30:00Z = 00:30 on the 11th at UTC+7
	w.auditRows(1, "bot@acme.example", "scan.edge")
	if n := count("from=2026-11-11&to=2026-11-11"); n != 2 { // scan.edge (00:30 local) and scan.late (15:00 local)
		t.Fatalf("a day in the organization zone = %v, want 2", n)
	}
	// Offsets, a bare time, other shapes: refused.
	for _, q := range []string{"from=2026-11-10T08:00:00%2B07:00", "from=2026-11-10T08:00:00-05:00", "from=2026-11-10T08:00:00", "from=yesterday", "from=2026-13-40", "from=2026-11-10+08:00", "from=1"} {
		r := admin.get("/core/audit?" + q)
		wantStatus(t, r, 400, "invalid_from")
	}
	for _, q := range []string{"to=2026-11-10T08:00:00%2B07:00", "to=2026-11-10T08:00:00", "to=tomorrow", "to=2026-02-30"} {
		wantStatus(t, admin.get("/core/audit?"+q), 400, "invalid_to")
	}
	wantStatus(t, admin.get("/core/audit/export?from=2026-11-10T08:00:00%2B07:00"), 400, "invalid_from")
	wantStatus(t, admin.get("/core/audit/export?to=nope"), 400, "invalid_to")
	// from after to is an empty answer, not an error.
	if r := admin.get("/core/audit?from=2026-11-12&to=2026-11-01"); r.Code != 200 || r.JSON["total"] != float64(0) || len(r.JSON["items"].([]any)) != 0 {
		t.Fatalf("empty range = %s", r.Raw)
	}
}

func TestContract_INV17_AuditExportIsCSVAndIsAudited(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	if err := w.env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		for _, e := range []audit.Entry{
			{User: "bot@acme.example", Action: "scan.run", Target: "=HYPERLINK(\"http://evil\")", Detail: "line1\nline2, with \"quotes\""},
			{User: "bot@acme.example", Action: "scan.run", Target: "+1+1"},
			{User: "bot@acme.example", Action: "scan.run", Target: "plain"},
		} {
			if err := w.env.Audit.Append(t.Context(), tx, e); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := w.env.Count(t, "SELECT count(*) FROM core_audit")
	r := admin.get("/core/audit/export?group=scan")
	if r.Code != 200 {
		t.Fatalf("export = %d %s", r.Code, r.Raw)
	}
	if cd := r.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, "vedette-audit.csv") {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	if ct, cc := r.Header.Get("Content-Type"), r.Header.Get("Cache-Control"); ct != "text/csv; charset=utf-8" || cc != "no-store" {
		t.Fatalf("Content-Type = %q, Cache-Control = %q", ct, cc)
	}
	if !strings.HasPrefix(r.Raw, "\ufefftime,user,action,target,detail\r\n") {
		t.Fatalf("export does not start with the BOM and the header: %q", r.Raw[:40])
	}
	recs, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(r.Raw, "\ufeff"))).ReadAll()
	if err != nil {
		t.Fatalf("export is not CSV: %v\n%s", err, r.Raw)
	}
	if len(recs) != 4 || recs[1][3] != "plain" { // header + 3 rows, newest first
		t.Fatalf("records = %q", recs)
	}
	if recs[2][3] != "'+1+1" || !strings.HasPrefix(recs[3][3], "'=HYPERLINK") {
		t.Fatalf("formula cells are not defused: %q", recs)
	}
	if recs[3][4] != "line1\nline2, with \"quotes\"" {
		t.Fatalf("detail = %q", recs[3][4])
	}
	// The download is itself a core_audit row, written once, and the file is a snapshot taken before it.
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit"); n != before+1 {
		t.Fatalf("audit rows %d -> %d, want one new row", before, n)
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'audit.export' AND user = 'admin@acme.example' AND detail LIKE 'csv; filters group=scan'"); n != 1 {
		t.Fatal("no audit.export row")
	}
	// No 200-row cap and no memory of the whole log: more than one page of the export's reads (each Append is several
	// statements, seconds under -race for a few thousand rows, so it is one page and a bit, not several).
	bulk := core.AuditExportPageForTest + 100
	w.auditRows(bulk, "bot@acme.example", "scan.bulk")
	big := admin.get("/core/audit/export?group=scan")
	if got := strings.Count(big.Raw, "\r\n"); got != 1+3+bulk {
		t.Fatalf("export lines = %d, want %d", got, 1+3+bulk)
	}
	if !strings.Contains(big.Raw[:200], "scan.bulk") {
		t.Fatal("not newest first")
	}
}

func TestContract_INV17_GeneralGetPutAndErrors(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	r := admin.get("/core/general")
	wantOK(t, r, 200)
	if r.str("name") != "Acme Co" || r.str("timezone") != "Asia/Ho_Chi_Minh" {
		t.Fatalf("general = %s", r.Raw)
	}
	p := admin.putGeneral(map[string]any{"name": "  Acme Group  ", "timezone": "Europe/London"})
	wantOK(t, p, 200)
	if p.str("name") != "Acme Group" || p.str("timezone") != "Europe/London" {
		t.Fatalf("put = %s", p.Raw)
	}
	if g := admin.get("/core/general"); g.str("name") != "Acme Group" || g.str("timezone") != "Europe/London" {
		t.Fatalf("get after put = %s", g.Raw)
	}
	if me := admin.get("/me"); me.str("org") != "Acme Group" {
		t.Fatalf("/me org = %s", me.Raw)
	}
	wantOK(t, admin.putGeneral(map[string]any{"name": "Acme Group", "timezone": "UTC"}), 200)
	wantOK(t, admin.putGeneral(map[string]any{"name": "Acme Group", "timezone": "America/Argentina/Buenos_Aires"}), 200)
	for _, name := range []string{"A", strings.Repeat("x", 81), "a\x00b", "  "} {
		wantStatus(t, admin.putGeneral(map[string]any{"name": name, "timezone": "UTC"}), 400, "invalid_org")
	}
	for _, tz := range []string{"", "Mars/Olympus", "Local", "../../etc/passwd", "utc ", strings.Repeat("A", 65), "Asia/Ho_Chi_Minh\x00"} {
		wantStatus(t, admin.putGeneral(map[string]any{"name": "Acme", "timezone": tz}), 400, "invalid_timezone")
	}
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'core.general' AND target = 'Acme Group' AND detail = 'time zone Europe/London'"); n != 1 {
		t.Fatal("no core.general audit row")
	}
	// A viewer reads it, only an administrator writes it.
	v, _ := w.signIn("v@acme.example", "viewer")
	wantOK(t, v.get("/core/general"), 200)
	wantStatus(t, v.putGeneral(map[string]any{"name": "Acme", "timezone": "UTC"}), 403, "forbidden")
}

// The audit row of an export cuts its detail at 1000 bytes; the cut must not split a UTF-8 character, which
// audit.Append refuses (the export then failed with 500 for a long filter with multi-byte characters).
func TestAuditExport_DetailIsCutAtACharacterBoundary(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	for name, query := range map[string]string{
		"user": "user=" + url.QueryEscape("x"+strings.Repeat("é", 99)),
		"q+group+user": "q=" + url.QueryEscape(strings.Repeat("é", 100)) + "&group=" + url.QueryEscape(strings.Repeat("ü", 100)) +
			"&user=" + url.QueryEscape(strings.Repeat("ß", 100)) + "&from=2026-01-01&to=2026-12-31",
	} {
		r := admin.get("/core/audit/export?" + query)
		if r.Code != 200 {
			t.Fatalf("%s: export with a multi-byte filter = %d %s; log: %s", name, r.Code, r.Raw, w.logs.String())
		}
		var detail string
		if err := w.env.DB.Reader().QueryRowContext(t.Context(), "SELECT detail FROM core_audit WHERE action = 'audit.export' ORDER BY seq DESC LIMIT 1").Scan(&detail); err != nil {
			t.Fatal(err)
		}
		if !utf8.ValidString(detail) || len(detail) > 1000 {
			t.Fatalf("%s: audit.export detail is %d bytes, valid UTF-8 %v", name, len(detail), utf8.ValidString(detail))
		}
	}
}

// The user and group filters are capped like the text filter (at most 200 characters).
func TestAudit_FiltersAreCapped(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	long := strings.Repeat("a", 201)
	for _, param := range []string{"q", "user", "group"} {
		for _, path := range []string{"/core/audit?", "/core/audit/export?"} {
			if r := admin.get(path + param + "=" + long); r.Code != 400 || r.code() != "invalid" {
				t.Errorf("%s%s too long = %d %s", path, param, r.Code, r.Raw)
			}
			if r := admin.get(path + param + "=" + long[:200]); r.Code != 200 {
				t.Errorf("%s%s of 200 characters = %d %s", path, param, r.Code, r.Raw)
			}
		}
	}
}
