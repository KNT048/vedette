package core_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/store"
)

// lines is a fake source: the given JSON lines whose "ts" is inside the range (rows without ts always are).
func lines(rows ...string) logexport.Source {
	return func(_ context.Context, from, to time.Time, w io.Writer) error {
		for _, r := range rows {
			var m struct{ Ts string }
			_ = json.Unmarshal([]byte(r), &m)
			if m.Ts != "" && ((!from.IsZero() && m.Ts < store.FormatTS(from)) || (!to.IsZero() && m.Ts > store.FormatTS(to))) {
				continue
			}
			if _, err := io.WriteString(w, r+"\n"); err != nil {
				return err
			}
		}
		return nil
	}
}

// secretRow holds fake secrets; the test checks that they are removed.
const secretRow = `{"id":"r1","ts":"2026-11-09T09:00:00.000Z","password":"p","api_key":"k","key_last4":"7Qk2","tokens_in":5,"hash":"h","prev_hash":"ph","nested":{"webhook_url":"https://x.example","bot_token":"t","ok":1},"list":[{"secret":"s","x":1}]}` //nolint:gosec // fake values

func TestLogsExport_RefusesWhatTheMockRefuses(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	wantStatus(t, admin.get("/core/logs/export"), 400, "invalid_categories")
	wantStatus(t, admin.get("/core/logs/export?categories="), 400, "invalid_categories")
	wantStatus(t, admin.get("/core/logs/export?categories=,,&format=json"), 400, "invalid_categories")
	wantStatus(t, admin.get("/core/logs/export?categories=audit,passwords&format=json"), 400, "invalid_categories")
	wantStatus(t, admin.get("/core/logs/export?categories=audit&format=xml"), 400, "invalid_format")
	wantStatus(t, admin.get("/core/logs/export?categories=audit&from=2026-11-10&to=2026-11-09"), 400, "invalid_range")
	wantStatus(t, admin.get("/core/logs/export?categories=audit&from=yesterday"), 400, "invalid_range")
	wantStatus(t, admin.get("/core/logs/export?categories=audit&to=2026-13-40"), 400, "invalid_range")
	wantStatus(t, admin.get("/core/logs/export?categories=audit&from=2026-11-09T00:00:00Z"), 400, "invalid_range")
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'logs.export'"); n != 0 {
		t.Fatalf("a refused request left %d audit rows", n)
	}

	viewer, _ := w.signIn("viewer@acme.example", "viewer")
	wantStatus(t, viewer.get("/core/logs/export?categories=audit&format=json"), 403, "forbidden")
	operator, _ := w.signIn("operator@acme.example", "operator")
	wantStatus(t, operator.get("/core/logs/export?categories=audit&format=json"), 403, "forbidden")
	wantStatus(t, w.client().get("/core/logs/export?categories=audit&format=json"), 401, "unauthenticated")
}

func TestLogsExport_JSONEnvelopeFilenameAndMissing(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin() // 2026-11-09T08:00:00Z
	w.h.LogSourcesForTest().Register("response", lines(secretRow))

	r := admin.get("/core/logs/export?categories=response,ai_activity,audit&format=json&from=2026-11-01&to=2026-11-30")
	wantOK(t, r, 200)
	if cd := r.Header.Get("Content-Disposition"); cd != "attachment; filename=vedette-logs-2026-11-09.json" {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	if cc := r.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	var env struct {
		Format       string
		ExportedAt   string `json:"exported_at"`
		Verification string
		From, To     *string
		Missing      []string
		Categories   map[string][]map[string]any
	}
	if err := json.Unmarshal([]byte(r.Raw), &env); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, r.Raw)
	}
	if env.Format != "vedette-logs/1" || env.From == nil || *env.From != "2026-11-01" || env.To == nil || *env.To != "2026-11-30" || env.Verification != logexport.ChainNote {
		t.Fatalf("envelope = %+v", env)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", env.ExportedAt); err != nil {
		t.Fatalf("exported_at = %q", env.ExportedAt)
	}
	if len(env.Missing) != 1 || env.Missing[0] != "ai_activity" {
		t.Fatalf("missing = %v, want [ai_activity]", env.Missing)
	}
	if got := env.Categories["ai_activity"]; got == nil || len(got) != 0 {
		t.Fatalf("a category without a source must be an empty list, got %#v", got)
	}
	if len(env.Categories["response"]) != 1 || len(env.Categories["audit"]) == 0 {
		t.Fatalf("categories = %v", env.Categories)
	}
	if order := regexp.MustCompile(`"(response|ai_activity|audit)":\[`).FindAllStringSubmatch(r.Raw, -1); len(order) != 3 || order[0][1] != "response" || order[1][1] != "ai_activity" || order[2][1] != "audit" {
		t.Fatalf("categories are not in the requested order: %v", order)
	}

	// Without dates the envelope says null; the format defaults to JSON.
	r = admin.get("/core/logs/export?categories=response")
	wantOK(t, r, 200)
	if !strings.Contains(r.Raw, `"from":null,"to":null`) || !strings.Contains(r.Raw, `"missing":[]`) {
		t.Fatalf("envelope = %.300s", r.Raw)
	}
	// The same category twice is one block.
	if r = admin.get("/core/logs/export?categories=response,response&format=json"); strings.Count(r.Raw, `"response":[`) != 1 {
		t.Fatalf("duplicate category: %s", r.Raw)
	}
}

func TestLogsExport_SecretsAreRemovedAtAnyDepth(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	w.h.LogSourcesForTest().Register("honeypot", lines(secretRow))
	r := admin.get("/core/logs/export?categories=honeypot&format=json")
	wantOK(t, r, 200)
	for _, s := range []string{`"p"`, `"k"`, "https://x.example", `"t"`, `"s"`, "password", "api_key", "webhook_url", "bot_token", `"secret"`} {
		if strings.Contains(r.Raw, s) {
			t.Fatalf("the export holds %s: %s", s, r.Raw)
		}
	}
	for _, s := range []string{`"key_last4":"7Qk2"`, `"tokens_in":5`, `"hash":"h"`, `"prev_hash":"ph"`, `"ok":1`, `"x":1`} {
		if !strings.Contains(r.Raw, s) {
			t.Fatalf("the export lost %s: %s", s, r.Raw)
		}
	}
	// CSV too: the nested object is one cell, scrubbed.
	r = admin.get("/core/logs/export?categories=honeypot&format=csv")
	wantOK(t, r, 200)
	if strings.Contains(r.Raw, "https://x.example") || strings.Contains(r.Raw, "password") || !strings.Contains(r.Raw, "7Qk2") {
		t.Fatalf("csv: %s", r.Raw)
	}
}

func TestLogsExport_CSVHasTheShapeOfTheMock(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	w.h.LogSourcesForTest().Register("response", lines(`{"a":"x,y","b":1}`))
	w.h.LogSourcesForTest().Register("honeypot", lines(`{"id":"=1+1","n":-5,"z":null,"o":{"k":"v,w"},"t":true,"q":"say \"hi\"\nnow"}`, `{"id":"b","extra":"e"}`))
	r := admin.get("/core/logs/export?categories=response,honeypot,alerts,scan_probes&format=csv")
	wantOK(t, r, 200)
	want := "# response\na,b\n\"x,y\",1\n\n" +
		"# honeypot\nid,n,z,o,t,q,extra\n'=1+1,-5,,\"{\"\"k\"\":\"\"v,w\"\"}\",true,\"say \"\"hi\"\"\nnow\",\n" + "b,,,,,,e\n\n" +
		"# alerts (no source)\n\n\n" +
		"# scan_probes (no source)\n\n"
	if r.Raw != want {
		t.Fatalf("csv =\n%q\nwant\n%q", r.Raw, want)
	}
	if cd := r.Header.Get("Content-Disposition"); cd != "attachment; filename=vedette-logs-2026-11-09.csv" {
		t.Fatalf("Content-Disposition = %q", cd)
	}
}

func TestLogsExport_DatesAreWholeDaysInTheOrganizationTimeZone(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin() // 2026-11-09T08:00:00Z, Asia/Ho_Chi_Minh (UTC+7)
	jump := func(d time.Duration) {
		w.env.Clock.Advance(d)
		admin = w.client()
		wantOK(t, admin.login("admin@acme.example"), 200)
	}
	// Local days: 2026-11-10 runs from 2026-11-09T17:00:00Z to 2026-11-10T16:59:59.999Z.
	jump(8*time.Hour + 30*time.Minute) // 16:30Z the 9th = 23:30 local on the 9th
	w.auditRows(1, "bot@acme.example", "scan.before")
	jump(time.Hour) // 17:30Z = 00:30 local on the 10th
	w.auditRows(1, "bot@acme.example", "scan.first")
	jump(15*time.Hour + 20*time.Minute) // 08:50Z the 10th = 15:50 local
	w.auditRows(1, "bot@acme.example", "scan.mid")
	jump(8 * time.Hour) // 16:50Z the 10th = 23:50 local
	w.auditRows(1, "bot@acme.example", "scan.last")
	jump(time.Hour) // 17:50Z = 00:50 local on the 11th
	w.auditRows(1, "bot@acme.example", "scan.after")

	actions := func(query string) string {
		t.Helper()
		r := admin.get("/core/logs/export?categories=audit&format=json&" + query)
		wantOK(t, r, 200)
		var env struct {
			Categories struct{ Audit []struct{ Action string } }
		}
		if err := json.Unmarshal([]byte(r.Raw), &env); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, e := range env.Categories.Audit {
			if strings.HasPrefix(e.Action, "scan.") {
				got = append(got, strings.TrimPrefix(e.Action, "scan."))
			}
		}
		return strings.Join(got, ",")
	}
	if got := actions("from=2026-11-10&to=2026-11-10"); got != "first,mid,last" {
		t.Fatalf("the 10th = %q, want first,mid,last (both ends inclusive, local time)", got)
	}
	if got := actions("to=2026-11-10"); got != "before,first,mid,last" {
		t.Fatalf("up to the 10th = %q", got)
	}
	if got := actions("from=2026-11-10"); got != "first,mid,last,after" {
		t.Fatalf("from the 10th = %q", got)
	}
	if got := actions("from=2026-11-11&to=2026-11-11"); got != "after" {
		t.Fatalf("the 11th = %q", got)
	}
	// The sources get the same bounds: a fake one sees from = start and to = last millisecond of the local day.
	var gotFrom, gotTo time.Time
	w.h.LogSourcesForTest().Register("response", func(_ context.Context, from, to time.Time, _ io.Writer) error { gotFrom, gotTo = from, to; return nil })
	wantOK(t, admin.get("/core/logs/export?categories=response&from=2026-11-10&to=2026-11-10"), 200)
	if !gotFrom.Equal(time.Date(2026, 11, 9, 17, 0, 0, 0, time.UTC)) || !gotTo.Equal(time.Date(2026, 11, 10, 16, 59, 59, 999e6, time.UTC)) {
		t.Fatalf("source range = %v .. %v", gotFrom, gotTo)
	}
	wantOK(t, admin.get("/core/logs/export?categories=response"), 200)
	if !gotFrom.IsZero() || !gotTo.IsZero() {
		t.Fatalf("no dates must be open on both sides, got %v .. %v", gotFrom, gotTo)
	}
}

func TestLogsExport_TheDownloadIsAuditedAndTheChainVerifiesOffline(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	admin := w.setupAdmin()
	w.auditRows(30, "bot@acme.example", "scan.run")
	w.h.LogSourcesForTest().Register("response", lines(`{"id":"r1"}`, `{"id":"r2"}`))

	r := admin.get("/core/logs/export?categories=response,audit,alerts&format=json&from=2026-11-01")
	wantOK(t, r, 200)
	var env struct {
		Categories struct{ Audit []map[string]any }
	}
	if err := json.Unmarshal([]byte(r.Raw), &env); err != nil {
		t.Fatal(err)
	}
	rows := env.Categories.Audit
	if len(rows) < 30 {
		t.Fatalf("audit rows = %d", len(rows))
	}
	// Verify from the exported file alone: recompute every hash with the shared formula and walk the links.
	v := chain.NewVerifier("")
	for _, e := range rows {
		str := func(k string) string { s, _ := e[k].(string); return s }
		entry := map[string]any{"id": str("id"), "ts": str("ts"), "user": str("user"), "action": str("action"), "target": str("target"), "detail": nil}
		if d, ok := e["detail"].(string); ok {
			entry["detail"] = d
		}
		sum, err := chain.HashCanonical(str("prev_hash"), entry)
		if err != nil {
			t.Fatal(err)
		}
		v.Add(str("id"), str("prev_hash"), str("hash"), sum)
	}
	if res := v.Result(); !res.OK || res.Count != len(rows) {
		t.Fatalf("offline verification of the exported file: %+v", res)
	}
	// ...and a tampered copy does not verify (the check can fail).
	rows[10]["target"] = "tampered"
	v = chain.NewVerifier("")
	for _, e := range rows {
		str := func(k string) string { s, _ := e[k].(string); return s }
		entry := map[string]any{"id": str("id"), "ts": str("ts"), "user": str("user"), "action": str("action"), "target": str("target"), "detail": nil}
		if d, ok := e["detail"].(string); ok {
			entry["detail"] = d
		}
		sum, _ := chain.HashCanonical(str("prev_hash"), entry)
		v.Add(str("id"), str("prev_hash"), str("hash"), sum)
	}
	if v.Result().OK {
		t.Fatal("a tampered row verified")
	}

	// The download is one core_audit row (D-72): who, which categories, what format, how many rows.
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'logs.export'"); n != 1 {
		t.Fatalf("logs.export rows = %d, want 1", n)
	}
	var target, detail, user string
	if err := w.env.DB.Reader().QueryRowContext(t.Context(), "SELECT user, target, detail FROM core_audit WHERE action = 'logs.export'").Scan(&user, &target, &detail); err != nil {
		t.Fatal(err)
	}
	if user != "admin@acme.example" || target != "response,audit,alerts" || !regexp.MustCompile(`^json; \d+ rows; from 2026-11-01$`).MatchString(detail) {
		t.Fatalf("audit row = %q %q %q", user, target, detail)
	}
	if ok, err := auditVerify(t, w); err != nil || !ok {
		t.Fatalf("the chain of the box after the export: %v %v", ok, err)
	}
	// The row count in the audit row is the rows of the file (2 response rows + the audit rows exported).
	if want := 2 + len(rows); !strings.Contains(detail, " "+itoa(want)+" rows") {
		t.Fatalf("detail %q, want %d rows", detail, want)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestLogsExport_OverTheCapIsRefusedWithNothingSentOrAudited(t *testing.T) {
	// Not parallel: it points TMPDIR at its own directory to see that no spool is left behind.
	spool := t.TempDir()
	t.Setenv("TMPDIR", spool)
	w := newWorld(t)
	admin := w.setupAdmin()
	w.auditRows(100, "bot@acme.example", "scan.run")
	w.h.SetLogsCapForTest(4 << 10)

	r := admin.get("/core/logs/export?categories=audit&format=json")
	wantStatus(t, r, 413, "logs_too_large")
	if n := w.env.Count(t, "SELECT count(*) FROM core_audit WHERE action = 'logs.export'"); n != 0 {
		t.Fatalf("a refused export was audited %d times", n)
	}
	// A narrower question fits: the cap is on the size of the file, not a lockout.
	wantOK(t, admin.get("/core/logs/export?categories=response&format=json"), 200)
	left, _ := filepath.Glob(filepath.Join(spool, "vedette-logs-*"))
	if len(left) != 0 {
		t.Fatalf("spool left behind: %v", left)
	}
	_ = os.Remove(spool)
}
