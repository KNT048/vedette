package feeds

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Every check of the CISA list asks both copies, cisa.gov and CISA's GitHub copy, each with
// its own validators, keeps the newer catalog (catalogVersion, then dateReleased), never rolls back, and records which copy the catalog
// came from. One copy failing is a note; both failing is a failed pull.

const (
	primaryPath = "/cisa/kev.json"
	mirrorPath  = "/mirror/kev.json"
)

// kevEnv is a pull env whose CISA list has two fake addresses on one origin: the primary and the mirror.
func kevEnv(t *testing.T) (*env, *origin) {
	t.Helper()
	e, o := pullEnv(t)
	return kevWire(t, e, o)
}

func kevWire(t *testing.T, e *env, o *origin) (*env, *origin) {
	t.Helper()
	e.only("cisa-kev")
	e.svc.KEVPrimary, e.svc.KEVFallback = o.url(primaryPath), o.url(mirrorPath)
	e.mirror("cisa-kev", o.url(primaryPath)) // the address the feed uses: the primary
	return e, o
}

func answer(w http.ResponseWriter, code int) { w.WriteHeader(code) }

func (e *env) answeredBy(t *testing.T) string {
	t.Helper()
	_, b := e.get("/feeds/sources")
	items, _ := b["items"].([]any)
	for _, it := range items {
		if at(it, "id") == "cisa-kev" {
			s, _ := at(it, "answered_by").(string)
			return s
		}
	}
	t.Fatal("no cisa-kev in the list")
	return ""
}

// kevWith is the fixture with another catalogVersion, dateReleased and first CVE.
func kevWith(t *testing.T, version, released, firstCVE string) string {
	t.Helper()
	k := testFile(t, "kev.json")
	k = strings.Replace(k, `"catalogVersion": "2026.11.04"`, `"catalogVersion": "`+version+`"`, 1)
	k = strings.Replace(k, `"dateReleased": "2026-11-04T14:20:11.1234Z"`, `"dateReleased": "`+released+`"`, 1)
	return strings.Replace(k, `"cveID": "CVE-2026-10001"`, `"cveID": "`+firstCVE+`"`, 1)
}

func TestContract_EveryCheckAsksBothCopies(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.body(primaryPath, `"p1"`, testFile(t, "kev.json"))
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	c, b := e.fetch("cisa-kev")
	// the same catalog from both: cisa.gov's is kept; nothing failed, so no note
	if msg, _ := at(b, "error").(string); c != 200 || at(b, "status") != "ok" || at(b, "answered_by") != AnsweredCISA || strings.Contains(msg, "copy") || strings.Contains(msg, "cisa.gov") {
		t.Fatalf("fetch = %d %v %v %v", c, at(b, "status"), at(b, "answered_by"), at(b, "error"))
	}
	if o.count(primaryPath) != 1 || o.count(mirrorPath) != 1 {
		t.Errorf("requests: cisa.gov %d, GitHub copy %d, want 1 and 1", o.count(primaryPath), o.count(mirrorPath))
	}
	if v, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10001"); !found || v.Vendor != "Synology" {
		t.Errorf("the list was not stored: %v %v", found, v)
	}
	if v := e.feed("cisa-kev").CatalogVersion; v == nil || *v != "2026.11.04" {
		t.Errorf("catalog version = %v", v)
	}
}

// timeoutTransport makes the cisa.gov copy time out and lets the GitHub copy through.
type timeoutTransport struct{ t *testing.T }

func (r timeoutTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == primaryPath {
		return nil, &url.Error{Op: "Get", URL: req.URL.String(), Err: context.DeadlineExceeded}
	}
	return onlyLoopback(r).RoundTrip(req)
}

// One copy failing, whatever the failure, is a quiet note on a pull that worked: the other copy's list is kept.
func TestContract_OneCopyFailingIsANote(t *testing.T) {
	t.Parallel()
	for code, why := range map[int]string{403: "cisa.gov refused this box (HTTP 403)", 404: "cisa.gov answered HTTP 404", 503: "cisa.gov answered HTTP 503"} {
		e, o := kevEnv(t)
		o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, code) })
		o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
		c, b := e.fetch("cisa-kev")
		if c != 200 || at(b, "status") != "ok" || at(b, "answered_by") != AnsweredMirror || !strings.HasPrefix(at(b, "error").(string), why+"; the other copy answered.") {
			t.Errorf("cisa.gov HTTP %d: %d %v %v %q", code, c, at(b, "status"), at(b, "answered_by"), at(b, "error"))
		}
	}
	e := newEnvFetcher(t, Fetcher{Client: &http.Client{Transport: timeoutTransport{t}}, Version: "test"})
	e, o := kevWire(t, e, newOrigin(t))
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	if c, b := e.fetch("cisa-kev"); c != 200 || at(b, "status") != "ok" || !strings.HasPrefix(at(b, "error").(string), "cisa.gov did not answer in time; the other copy answered.") {
		t.Errorf("timeout: %d %v %v", c, at(b, "status"), at(b, "error"))
	}
	// the other way round: the GitHub copy fails, cisa.gov answers
	e2, o2 := kevEnv(t)
	o2.body(primaryPath, `"p1"`, testFile(t, "kev.json"))
	o2.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
	if c, b := e2.fetch("cisa-kev"); c != 200 || at(b, "status") != "ok" || at(b, "answered_by") != AnsweredCISA ||
		!strings.HasPrefix(at(b, "error").(string), "CISA's GitHub copy answered HTTP 502; the other copy answered.") {
		t.Errorf("GitHub copy down: %d %v %v %v", c, at(b, "status"), at(b, "answered_by"), at(b, "error"))
	}
}

func TestContract_AnAdminsOwnAddressIsTheOnlyOneAsked(t *testing.T) {
	t.Parallel()
	// the owner's own mirror address is theirs to look after: no other host is asked
	e, o := kevEnv(t)
	o.serve("/own.json", func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	e.mirror("cisa-kev", o.url("/own.json"))
	if _, b := e.fetch("cisa-kev"); at(b, "status") != "error" || o.count(mirrorPath) != 0 || o.count(primaryPath) != 0 {
		t.Errorf("own address: status %v, requests cisa.gov %d GitHub copy %d", at(b, "status"), o.count(primaryPath), o.count(mirrorPath))
	}
}

// The newer copy wins in either direction: by catalogVersion, then by dateReleased.
func TestContract_TheNewerCopyWinsEitherWay(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.body(primaryPath, `"p1"`, kevWith(t, "2026.11.05", "2026-11-05T10:00:00Z", "CVE-2026-20005"))
	o.body(mirrorPath, `"m1"`, kevWith(t, "2026.11.04", "2026-11-04T10:00:00Z", "CVE-2026-20004"))
	if _, b := e.fetch("cisa-kev"); at(b, "answered_by") != AnsweredCISA {
		t.Fatalf("cisa.gov newer: %v %v", at(b, "answered_by"), at(b, "error"))
	}
	if _, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-20005"); !found {
		t.Error("cisa.gov's newer list was not stored")
	}
	// the GitHub copy moves ahead (cisa.gov unchanged: a 304)
	o.body(mirrorPath, `"m2"`, kevWith(t, "2026.11.06", "2026-11-06T10:00:00Z", "CVE-2026-20006"))
	if _, b := e.fetch("cisa-kev"); at(b, "answered_by") != AnsweredMirror || at(b, "status") != "ok" {
		t.Fatalf("GitHub copy newer: %v %v", at(b, "answered_by"), at(b, "error"))
	}
	if v := e.feed("cisa-kev").CatalogVersion; v == nil || *v != "2026.11.06" {
		t.Errorf("catalog version = %v", v)
	}
	// both unchanged: 304s, the list and where it came from stay
	if _, b := e.fetch("cisa-kev"); at(b, "answered_by") != AnsweredMirror || at(b, "status") != "ok" {
		t.Errorf("both 304: %v %v", at(b, "answered_by"), at(b, "status"))
	}
	// the same catalogVersion, released later on cisa.gov: dateReleased decides
	o.body(primaryPath, `"p2"`, kevWith(t, "2026.11.06", "2026-11-06T18:00:00Z", "CVE-2026-20007"))
	if _, b := e.fetch("cisa-kev"); at(b, "answered_by") != AnsweredCISA {
		t.Errorf("same version, later release on cisa.gov: %v", at(b, "answered_by"))
	}
	if _, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-20007"); !found {
		t.Error("the later release was not stored")
	}
}

// An older copy never replaces the catalog the box holds (no roll back), and is not news either: no note.
func TestContract_AnOlderCopyNeverReplacesTheList(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	kev := testFile(t, "kev.json")
	o.body(primaryPath, `"p1"`, kev)
	o.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusServiceUnavailable) })
	if c, b := e.fetch("cisa-kev"); c != 200 || at(b, "answered_by") != AnsweredCISA {
		t.Fatalf("first pull: %d %v", c, b)
	}
	before := rowsOf(t, e.db, "feeds_vuln")
	// cisa.gov goes dark; the GitHub copy is a release behind and has another entry
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.body(mirrorPath, `"m-old"`, kevWith(t, "2026.10.01", "2026-10-01T10:00:00Z", "CVE-2026-19999"))
	c, b := e.fetch("cisa-kev")
	if c != 200 || at(b, "status") != "ok" {
		t.Fatalf("older copy: %d %v %v", c, at(b, "status"), at(b, "error"))
	}
	if v := e.feed("cisa-kev").CatalogVersion; v == nil || *v != "2026.11.04" {
		t.Errorf("catalog version went back to %v", v)
	}
	if rowsOf(t, e.db, "feeds_vuln") != before {
		t.Errorf("rows %d -> %d: the older list changed the data", before, rowsOf(t, e.db, "feeds_vuln"))
	}
	if _, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-19999"); found {
		t.Error("an entry of the older list was stored")
	}
	if got := e.answeredBy(t); got != AnsweredCISA {
		t.Errorf("answered_by = %q: the data on the box still came from cisa.gov", got)
	}
}

func TestContract_BothDownIsAnErrorThatNamesBoth(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
	c, b := e.fetch("cisa-kev")
	msg, _ := at(b, "error").(string)
	if c != 200 || at(b, "status") != "error" || msg != "cisa.gov refused this box (HTTP 403), and CISA's GitHub copy answered HTTP 502." {
		t.Fatalf("both down: %d %v %q", c, at(b, "status"), msg)
	}
	if strings.Contains(msg, originHost) || strings.Contains(msg, "127.0.0.1") || strings.Contains(msg, "http") {
		t.Errorf("the message carries an address: %q", msg)
	}
	if e.feed("cisa-kev").Failures == 0 {
		t.Error("a pull that failed twice is not counted as failed")
	}
}

// Conditional requests per copy: each copy gets its own validators once the box knows the version it gave, never the other's.
func TestContract_ConditionalRequestsPerCopy(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.body(primaryPath, `"p1"`, testFile(t, "kev.json"))
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	e.fetch("cisa-kev")
	c, b := e.fetch("cisa-kev")
	if c != 200 || at(b, "status") != "ok" || at(b, "answered_by") != AnsweredCISA {
		t.Fatalf("second pull: %d %v %v", c, at(b, "status"), at(b, "answered_by"))
	}
	asks := map[string][]string{}
	for _, h := range o.all() {
		asks[h.path] = append(asks[h.path], h.header.Get("If-None-Match"))
	}
	if got := strings.Join(asks[primaryPath], ","); got != `,"p1"` {
		t.Errorf("cisa.gov asked with %q", got)
	}
	if got := strings.Join(asks[mirrorPath], ","); got != `,"m1"` {
		t.Errorf("the GitHub copy asked with %q", got)
	}
	if v, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10001"); !found || v.Vendor != "Synology" {
		t.Error("two 304s lost the list")
	}
}
