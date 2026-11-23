package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

type fakeGuidance struct{ g Guide }

func (f fakeGuidance) Guidance(context.Context, Row) (Guide, error) { return f.g, nil }

type httpEnv struct {
	*env
	h    http.Handler
	gate *servertest.Gate
	fh   *FindingHandlers
}

type findingsOnly struct {
	server.Fallback
	*FindingHandlers
}

func newHTTPEnv(t *testing.T) *httpEnv {
	t.Helper()
	e := newEnv(t)
	gate := servertest.NewGate()
	fh := NewFindingHandlers(e.svc, e.inv, e.feeds, gate)
	h, err := server.New(server.Config{
		API:     findingsOnly{Fallback: server.Fallback{Log: slog.New(slog.DiscardHandler)}, FindingHandlers: fh},
		Auth:    &servertest.Auth{Users: servertest.StandardUsers()},
		Modules: gate,
		Log:     slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &httpEnv{env: e, h: h, gate: gate, fh: fh}
}

func (e *httpEnv) call(method, path, user, body string) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(e.t.Context(), method, server.Prefix+path, rd)
	r.Header.Set("Content-Type", "application/json")
	if user != "" {
		r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	r.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			e.t.Fatalf("%s %s: not JSON: %v: %s", method, path, err, w.Body)
		}
	}
	return w.Code, out
}

func errCode(b map[string]any) string {
	m, _ := b["error"].(map[string]any)
	c, _ := m["code"].(string)
	return c
}

func TestContract_POST3_GetFindingWithoutMitigation(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	id := e.seed()
	code, b := e.call("GET", "/findings/"+id, "viewer", "")
	if code != 200 {
		t.Fatalf("status %d: %v", code, b)
	}
	if b["id"] != id || b["cve"] != "CVE-2022-27593" || b["status"] != "suspected" || b["basis"] != "version" {
		t.Fatalf("body = %v", b)
	}
	// What to do: empty, not missing
	if b["pack"] != nil || b["compromise"] != nil {
		t.Fatalf("pack/compromise = %v %v", b["pack"], b["compromise"])
	}
	if r, _ := b["recheck"].(map[string]any); r == nil || len(r["steps"].([]any)) != 0 {
		t.Fatalf("recheck = %v", b["recheck"])
	}
	if a, _ := b["applied"].([]any); a == nil || len(a) != 0 {
		t.Fatalf("applied = %v", b["applied"])
	}
	if av, _ := b["ai_available"].(map[string]any); av["explain"] != false || av["config"] != false {
		t.Fatalf("ai_available = %v", b["ai_available"])
	}
	asset, _ := b["asset"].(map[string]any)
	kev, _ := b["kev"].(map[string]any)
	if asset["hostname"] != "nas01" || asset["kind"] != "nas" || kev["name"] != "QNAP Photo Station External Reference" || kev["display"] != "QNAP Photo Station" {
		t.Fatalf("asset/kev = %v / %v", asset, kev)
	}
}

func TestContract_INV8_KevComesFromFeeds(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.seed()
	delete(e.feeds.kev, "CVE-2022-27593") // the CVE left the list: finding stays, kev is null
	_, b := e.call("GET", "/findings", "viewer", "")
	items, _ := b["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["kev"] != nil {
		t.Fatalf("items = %v", b)
	}
}

// INV-22 (#825): every finding carries feeds' CVSS base score with its version, source and vector, on the list and the page; no score
// known is null ("No CVSS score"), never 0; a real 0.0 is a score.
func TestContract_INV22_CvssComesFromFeeds(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	id := e.seed()
	cvssOf := func(path string) any {
		t.Helper()
		code, b := e.call("GET", path, "viewer", "")
		if code != 200 {
			t.Fatalf("%s: %d %v", path, code, b)
		}
		if items, ok := b["items"].([]any); ok {
			if len(items) != 1 {
				t.Fatalf("items = %v", items)
			}
			b = items[0].(map[string]any)
		}
		v, ok := b["cvss"]
		if !ok {
			t.Fatalf("%s: no cvss field: %v", path, b)
		}
		return v
	}
	for _, p := range []string{"/findings", "/findings/" + id} {
		if v := cvssOf(p); v != nil {
			t.Fatalf("%s without a score: cvss = %v", p, v)
		}
	}
	ver, src, vec := "3.1", "nvd", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	e.feeds.cvss = map[string]CVSS{"CVE-2022-27593": {Score: 9.8, Version: ver, Source: src, Vector: vec}}
	for _, p := range []string{"/findings", "/findings/" + id} {
		if c, _ := cvssOf(p).(map[string]any); c["score"] != 9.8 || c["version"] != "3.1" || c["source"] != "nvd" || c["vector"] != vec {
			t.Fatalf("%s: cvss = %v", p, c)
		}
	}
	e.feeds.cvss = map[string]CVSS{"CVE-2022-27593": {Score: 0, Version: "3.1", Source: "cna", Vector: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"}}
	if c, _ := cvssOf("/findings").(map[string]any); c == nil || c["score"] != 0.0 || c["version"] != "3.1" || c["source"] != "cna" {
		t.Fatalf("a real 0.0: cvss = %v", c)
	}
}

func TestContract_POST3_GuidanceFollowsTheMitigationGate(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	id := e.seed()
	e.fh.SetGuidance(fakeGuidance{Guide{Recheck: Recheck{Steps: []string{"look"}}, AIAvailable: AIAvailable{Explain: true}}})
	_, b := e.call("GET", "/findings/"+id, "viewer", "")
	if r := b["recheck"].(map[string]any)["steps"].([]any); len(r) != 1 || b["ai_available"].(map[string]any)["explain"] != true {
		t.Fatalf("with mitigation on: %v", b)
	}
	e.gate.Set("mitigation", false)
	_, b = e.call("GET", "/findings/"+id, "viewer", "")
	if r := b["recheck"].(map[string]any)["steps"].([]any); len(r) != 0 || b["ai_available"].(map[string]any)["explain"] != false {
		t.Fatalf("with mitigation off: %v", b)
	}
}

func TestListFilterAndOrder(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.seed()
	e.advance(1000000000) // 1s later a second device is matched: newest first
	e.inv.assets["a-2"] = AssetView{ID: "a-2", IP: "192.168.10.22", Kind: "weird", Display: "x"}
	if _, err := e.svc.UpsertFromMatch(t.Context(), Asset{ID: "a-2", Name: "b", Software: nas("6.1.1").Software}, e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	_, b := e.call("GET", "/findings", "viewer", "")
	items := b["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["asset_id"] != "a-2" || items[1].(map[string]any)["asset_id"] != "a-1" {
		t.Fatalf("order = %v", b)
	}
	if k := items[0].(map[string]any)["asset"].(map[string]any)["kind"]; k != "unknown" {
		t.Fatalf("unknown kind shown as %v", k)
	}
	_, b = e.call("GET", "/findings?asset=a-1", "viewer", "")
	if items = b["items"].([]any); len(items) != 1 || items[0].(map[string]any)["asset_id"] != "a-1" {
		t.Fatalf("filter = %v", b)
	}
	_, b = e.call("GET", "/findings?asset=nobody", "viewer", "")
	if items, ok := b["items"].([]any); !ok || len(items) != 0 {
		t.Fatalf("empty filter = %v", b)
	}
}

func TestContract_POST4_StatusEndpoint(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	id := e.seed()
	for _, c := range []struct {
		name, user, path, body string
		status                 int
		code                   string
	}{
		{"viewer refused", "viewer", "/findings/" + id + "/status", `{"action":"patched","note":""}`, 403, "forbidden"},
		{"no session", "", "/findings/" + id + "/status", `{"action":"patched","note":""}`, 401, ""},
		{"unknown id", "operator", "/findings/f-nope/status", `{"action":"patched","note":""}`, 404, "not_found"},
		{"note required", "operator", "/findings/" + id + "/status", `{"action":"false_positive","note":"ab"}`, 400, "note_required"},
		{"already open", "operator", "/findings/" + id + "/status", `{"action":"reopen","note":""}`, 409, "already_open"},
		{"nul in note", "operator", "/findings/" + id + "/status", `{"action":"patched","note":"a\u0000b"}`, 400, "invalid"},
		{"bad action stays out", "operator", "/findings/" + id + "/status", `{"action":"explode","note":""}`, 400, ""},
	} {
		code, b := e.call("POST", c.path, c.user, c.body)
		if code != c.status || (c.code != "" && errCode(b) != c.code) {
			t.Errorf("%s: %d %v", c.name, code, b)
		}
	}
	if r, _ := e.svc.Get(t.Context(), id); r.Status != StatusSuspected {
		t.Fatalf("a refused request changed the finding: %+v", r)
	}
	code, b := e.call("POST", "/findings/"+id+"/status", "operator", `{"action":"mitigated","note":" proxy in front "}`)
	if code != 200 || b["status"] != "mitigated" || b["resolved_by"] != "it@acme.example" || b["resolution_note"] != "proxy in front" {
		t.Fatalf("%d %v", code, b)
	}
	if h := b["history"].([]any); len(h) != 2 || h[1].(map[string]any)["action"] != "mitigated" {
		t.Fatalf("history = %v", b["history"])
	}
}


func TestModuleOffMeansNoRoutes(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	id := e.seed()
	e.gate.Set("findings", false)
	for _, p := range []string{"/findings", "/findings/" + id} {
		if code, _ := e.call("GET", p, "viewer", ""); code != 404 {
			t.Errorf("GET %s = %d", p, code)
		}
	}
	if e.count(`SELECT count(*) FROM fnd_finding`) != 1 {
		t.Fatal("data must stay")
	}
}

// GET /findings/{id} says the fixed release for the device when NVD's range gives one, and null when it does not.
func TestFindingDetail_FixedIn(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	id := e.seed()
	if _, b := e.call("GET", "/findings/"+id, "viewer", ""); b["fixed_in"] != nil {
		t.Fatalf("no NVD range: fixed_in = %v", b["fixed_in"])
	}
	e.feeds.vulns = []Vuln{qnapVuln(Affected{CPE: "cpe:2.3:a:qnap:photo_station:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "6.0.0", EndExcl: "6.1.2"}})}
	_, b := e.call("GET", "/findings/"+id, "viewer", "")
	f, _ := b["fixed_in"].(map[string]any)
	if f["kind"] != "fixed" || f["version"] != "6.1.1" || f["fixed"] != "6.1.2" || f["source"] != "NVD affected versions" {
		t.Fatalf("fixed_in = %v", b["fixed_in"])
	}
}

// accept_risk goes through the API with its day: a bad day is 400 bad_until, a good one answers the finding with
// accepted_until.
func TestAcceptRiskEndpoint(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	id := e.seed()
	day := func(d int) string { return dayOf(t0).AddDate(0, 0, d).Format(time.DateOnly) }
	if code, b := e.call("POST", "/findings/"+id+"/status", "operator", `{"action":"accept_risk","note":"March window","until":"`+day(-1)+`"}`); code != 400 || errCode(b) != "bad_until" {
		t.Fatalf("yesterday: %d %v", code, b)
	}
	if code, b := e.call("POST", "/findings/handle", "operator", `{"ids":["`+id+`"],"resolution":"accepted","note":"March window"}`); code != 400 || errCode(b) != "bad_until" {
		t.Fatalf("handle without a day: %d %v", code, b)
	}
	code, b := e.call("POST", "/findings/"+id+"/status", "operator", `{"action":"accept_risk","note":"March window","until":"`+day(90)+`"}`)
	if code != 200 || b["status"] != "risk_accepted" || b["accepted_until"] != day(90) || b["resolution_note"] != "March window" {
		t.Fatalf("accept: %d %v", code, b)
	}
}

// The list says which software row each finding rests on and whether Vedette closed it by itself, from what the matcher stored, so a
// page can tell what a person's entered release closed. Nothing is guessed at read time.
func TestContract_ListNamesStoredSoftwareRowAndProof(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	v := []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})}
	run := func(ver string) {
		t.Helper()
		e.advance(time.Minute)
		if _, err := e.svc.UpsertFromMatch(t.Context(), nas(ver), v); err != nil {
			t.Fatal(err)
		}
	}
	row := func(path string) map[string]any {
		t.Helper()
		code, b := e.call("GET", path, "viewer", "")
		items, _ := b["items"].([]any)
		if code != 200 || len(items) != 1 {
			t.Fatalf("%s: %d %v", path, code, b)
		}
		return items[0].(map[string]any)
	}
	run("6.1.1")
	if r := row("/findings?asset=a-1"); r["software_id"] != "s-1" || r["resolution_reason"] != nil || r["proved_version"] != nil {
		t.Fatalf("open finding = %v", r)
	}
	run("6.2.0") // the device moved past the range: patched by Vedette, with the version it moved to
	if r := row("/findings?asset=a-1"); r["software_id"] != "s-1" || r["resolution_reason"] != ReasonFixedByUpdate || r["proved_version"] != "6.2.0" || r["status"] != "patched" {
		t.Fatalf("closed by proof = %v", r)
	}
	run("6.3.0") // a later release changes nothing: the credit names the move that fixed it, with no new history
	if r := row("/findings?asset=a-1"); r["proved_version"] != "6.2.0" {
		t.Fatalf("proved on = %v", r)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_event WHERE kind = 'handled'`); n != 1 {
		t.Fatalf("history rows %d", n)
	}
	// the same row on the all-devices list and on the single finding: one stored column, one answer
	if r := row("/findings"); r["software_id"] != "s-1" {
		t.Fatalf("all-devices row = %v", r)
	}
	id := row("/findings")["id"].(string)
	if _, b := e.call("GET", "/findings/"+id, "viewer", ""); b["software_id"] != "s-1" || b["proved_version"] != "6.2.0" {
		t.Fatalf("detail = %v", b)
	}
}

// A closure that compared no version (name only, age, an open platform question) carries no proved version, and a finding no match has
// reached yet (an older row) names no software row: the list never guesses one from the product.
func TestContract_ListDoesNotGuessSoftwareOrProof(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	id := e.seed()
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE fnd_finding SET state = 'handled', resolution = 'not_relevant', via = 'data_corrected', resolved_by = ?,
			resolved_at = last_seen, software_id = NULL WHERE id = ?`, SystemUser, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, b := e.call("GET", "/findings?asset=a-1", "viewer", "")
	r := b["items"].([]any)[0].(map[string]any)
	if r["software_id"] != "" || r["resolution_reason"] != ReasonNotAffectedVersion || r["proved_version"] != nil {
		t.Fatalf("row = %v", r)
	}
	// and the list does not read the device or the feeds for it: it answers while both are unreadable
	e.inv.idsErr = errors.New("inventory down")
	if code, _ := e.call("GET", "/findings?asset=a-1", "viewer", ""); code != 200 {
		t.Fatalf("list with the device unreadable: %d", code)
	}
}

