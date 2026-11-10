package feeds

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// D-91: when the CISA address answers 403, a server error or nothing in time, the box reads CISA's own GitHub mirror
// with the same parser and limits, records which address answered, and never rolls back to an older list.

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

func TestContract_D91_ForbiddenFallsBackToTheMirror(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	c, b := e.fetch("cisa-kev")
	if c != 200 || at(b, "status") != "ok" || at(b, "answered_by") != AnsweredMirror {
		t.Fatalf("fetch = %d status %v answered_by %v error %v", c, at(b, "status"), at(b, "answered_by"), at(b, "error"))
	}
	if o.count(primaryPath) != 1 || o.count(mirrorPath) != 1 {
		t.Errorf("requests: primary %d mirror %d, want 1 and 1", o.count(primaryPath), o.count(mirrorPath))
	}
	if v, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10001"); !found || v.Vendor != "Synology" {
		t.Errorf("the list from the mirror was not stored: %v %v", found, v)
	}
	if got := e.answeredBy(t); got != AnsweredMirror {
		t.Errorf("answered_by in the list = %q", got)
	}
	if v := e.feed("cisa-kev").CatalogVersion; v == nil || *v != "2026.11.04" {
		t.Errorf("catalog version = %v", v)
	}
}

func TestContract_D91_ServerErrorFallsBackToTheMirror(t *testing.T) {
	t.Parallel()
	for _, code := range []int{500, 502, 503, 504} {
		e, o := kevEnv(t)
		o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, code) })
		o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
		if c, b := e.fetch("cisa-kev"); c != 200 || at(b, "status") != "ok" || at(b, "answered_by") != AnsweredMirror {
			t.Errorf("HTTP %d: %d %v %v", code, c, at(b, "status"), at(b, "answered_by"))
		}
	}
}

// timeoutTransport makes the CISA address time out and lets the mirror through.
type timeoutTransport struct{ t *testing.T }

func (r timeoutTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == primaryPath {
		return nil, &url.Error{Op: "Get", URL: req.URL.String(), Err: context.DeadlineExceeded}
	}
	return onlyLoopback(r).RoundTrip(req)
}

func TestContract_D91_TimeoutFallsBackToTheMirror(t *testing.T) {
	t.Parallel()
	e := newEnvFetcher(t, Fetcher{Client: &http.Client{Transport: timeoutTransport{t}}, Version: "test"})
	e, o := kevWire(t, e, newOrigin(t))
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	c, b := e.fetch("cisa-kev")
	if c != 200 || at(b, "status") != "ok" || at(b, "answered_by") != AnsweredMirror {
		t.Fatalf("fetch = %d %v %v %v", c, at(b, "status"), at(b, "answered_by"), at(b, "error"))
	}
}

func TestContract_D91_CISAAnswersAndTheMirrorIsLeftAlone(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.body(primaryPath, `"p1"`, testFile(t, "kev.json"))
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	c, b := e.fetch("cisa-kev")
	if c != 200 || at(b, "answered_by") != AnsweredCISA || o.count(mirrorPath) != 0 {
		t.Fatalf("fetch = %d answered_by %v, mirror requests %d", c, at(b, "answered_by"), o.count(mirrorPath))
	}
}

func TestContract_D91_OtherFailuresAndOwnAddressesDoNotFallBack(t *testing.T) {
	t.Parallel()
	// a 404 is a broken address, not a blocked or sick server
	e, o := kevEnv(t)
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusNotFound) })
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	if _, b := e.fetch("cisa-kev"); at(b, "status") != "error" || o.count(mirrorPath) != 0 {
		t.Errorf("404: status %v, mirror requests %d", at(b, "status"), o.count(mirrorPath))
	}
	// the owner's own mirror address is theirs to look after: no silent switch to another host
	e2, o2 := kevEnv(t)
	o2.serve("/own.json", func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o2.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	e2.mirror("cisa-kev", o2.url("/own.json"))
	if _, b := e2.fetch("cisa-kev"); at(b, "status") != "error" || o2.count(mirrorPath) != 0 {
		t.Errorf("own address: status %v, mirror requests %d", at(b, "status"), o2.count(mirrorPath))
	}
}

func TestContract_D91_AnOlderMirrorNeverReplacesTheList(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	kev := testFile(t, "kev.json")
	o.body(primaryPath, `"p1"`, kev)
	if c, b := e.fetch("cisa-kev"); c != 200 || at(b, "answered_by") != AnsweredCISA {
		t.Fatalf("first pull: %d %v", c, b)
	}
	before := rowsOf(t, e.db, "feeds_vuln")
	// CISA goes dark; the mirror lags by a release and has fewer entries
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	older := strings.Replace(kev, `"catalogVersion": "2026.11.04"`, `"catalogVersion": "2026.10.01"`, 1)
	older = strings.Replace(older, `"cveID": "CVE-2026-10001"`, `"cveID": "CVE-2026-19999"`, 1)
	o.body(mirrorPath, `"m-old"`, older)
	c, b := e.fetch("cisa-kev")
	if c != 200 || at(b, "status") != "ok" {
		t.Fatalf("older mirror: %d %v %v", c, at(b, "status"), at(b, "error"))
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
	if v, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10001"); !found || v.Vendor != "Synology" {
		t.Error("the newer list lost an entry")
	}
	if msg, _ := at(b, "error").(string); !strings.Contains(msg, "older") {
		t.Errorf("the feed does not say the mirror was older: %q", msg)
	}
	if got := e.answeredBy(t); got != AnsweredCISA {
		t.Errorf("answered_by = %q: the data on the box still came from CISA", got)
	}
	// an equal or newer mirror is taken
	o.body(mirrorPath, `"m-new"`, strings.Replace(kev, `"catalogVersion": "2026.11.04"`, `"catalogVersion": "2026.11.05"`, 1))
	if _, b := e.fetch("cisa-kev"); at(b, "answered_by") != AnsweredMirror || at(b, "status") != "ok" {
		t.Errorf("newer mirror: %v %v", at(b, "status"), at(b, "answered_by"))
	}
	if v := e.feed("cisa-kev").CatalogVersion; v == nil || *v != "2026.11.05" {
		t.Errorf("catalog version = %v", v)
	}
}

func TestContract_D91_BothDownIsAnErrorThatNamesBoth(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
	c, b := e.fetch("cisa-kev")
	msg, _ := at(b, "error").(string)
	if c != 200 || at(b, "status") != "error" || !strings.Contains(msg, "403") || !strings.Contains(msg, "mirror") || !strings.Contains(msg, "502") {
		t.Fatalf("both down: %d %v %q", c, at(b, "status"), msg)
	}
	if strings.Contains(msg, "127.0.0.1") || strings.Contains(msg, "http") {
		t.Errorf("the message carries an address: %q", msg)
	}
	if e.feed("cisa-kev").Failures == 0 {
		t.Error("a pull that failed twice is not counted as failed")
	}
}

func TestContract_D91_ValidatorsOfTheMirrorAreNeverSentToCISA(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	e.fetch("cisa-kev") // answered by the mirror, which handed out the ETag "m1"
	o.body(primaryPath, `"p1"`, testFile(t, "kev.json"))
	e.fetch("cisa-kev")
	for _, h := range o.all() {
		if h.path == primaryPath && h.header.Get("If-None-Match") != "" {
			t.Errorf("CISA was asked with the mirror's validator %q", h.header.Get("If-None-Match"))
		}
	}
	if got := e.answeredBy(t); got != AnsweredCISA {
		t.Errorf("answered_by after CISA came back = %q", got)
	}
}

func TestD91_TimeoutErrorsAreRecognised(t *testing.T) {
	t.Parallel()
	for name, err := range map[string]error{
		"deadline":  context.DeadlineExceeded,
		"wrapped":   &url.Error{Op: "Get", Err: context.DeadlineExceeded},
		"forbidden": &StatusError{Code: 403},
		"gateway":   &StatusError{Code: 502},
	} {
		if !fallbackWorthy(err) {
			t.Errorf("%s is not fallback-worthy", name)
		}
	}
	for name, err := range map[string]error{
		"not found": &StatusError{Code: 404},
		"gone":      &StatusError{Code: 410},
		"redirect":  ErrRedirect,
		"plain":     errors.New("boom"),
	} {
		if fallbackWorthy(err) {
			t.Errorf("%s is fallback-worthy", name)
		}
	}
}
