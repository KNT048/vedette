package exposure

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// shodan is a fake InternetDB: it answers every request with status and body, and records the paths it was asked.
type shodan struct {
	mu     sync.Mutex
	status int
	body   string
	paths  []string
	onAsk  func() // called when a request arrives (a test cancels the person's request here)
}

func (f *shodan) set(status int, body string) {
	f.mu.Lock()
	f.status, f.body = status, body
	f.mu.Unlock()
}
func (f *shodan) asked() []string { f.mu.Lock(); defer f.mu.Unlock(); return slices.Clone(f.paths) }

func newShodan(t *testing.T) (*shodan, *InternetDB) {
	t.Helper()
	f := &shodan{status: 200, body: `{"ip":"8.8.8.8","ports":[443],"hostnames":[],"cpes":[],"tags":[],"vulns":[]}`}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		status, body, onAsk := f.status, f.body, f.onAsk
		f.mu.Unlock()
		if onAsk != nil {
			onAsk()
		}
		if status == http.StatusFound {
			http.Redirect(w, r, "https://example.com/", status)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	tr, ok := srv.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("no transport")
	}
	db, err := NewInternetDB(srv.URL, tr)
	if err != nil {
		t.Fatal(err)
	}
	return f, db
}

func TestInternetDB_ReadsTheAnswerAndDropsWhatDoesNotFit(t *testing.T) {
	t.Parallel()
	f, db := newShodan(t)
	f.set(200, `{"ip":"8.8.8.8","ports":[8443,443,443,0,70000,-1],"hostnames":["vpn.acme.example","bad name","<script>"],
		"cpes":["cpe:/o:fortinet:fortios","cpe:/a:x:y z","http://evil"],"tags":["self-signed","vpn","Bad Tag!"],
		"vulns":["CVE-2023-27997","CVE-2024-21762","cve-1","CVE-2023-27997<b>"],"new_field":{"x":1}}`)
	a, err := db.Lookup(t.Context(), netip.MustParseAddr(ipA))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Found || !slices.Equal(a.Ports, []int{443, 8443}) || !slices.Equal(a.Hostnames, []string{"vpn.acme.example"}) ||
		!slices.Equal(a.CPEs, []string{"cpe:/o:fortinet:fortios"}) || !slices.Equal(a.Tags, []string{"self-signed", "vpn"}) ||
		!slices.Equal(a.Vulns, []string{"CVE-2023-27997", "CVE-2024-21762"}) {
		t.Fatalf("answer = %+v", a)
	}
	if got := f.asked(); !slices.Equal(got, []string{"/" + ipA}) {
		t.Fatalf("asked %v, want only /%s", got, ipA)
	}
}

func TestInternetDB_NoRecordIsAnAnswer(t *testing.T) {
	t.Parallel()
	f, db := newShodan(t)
	f.set(404, `{"detail":"No information available"}`)
	a, err := db.Lookup(t.Context(), netip.MustParseAddr(ipA))
	if err != nil || a.Found || a.Ports == nil || len(a.Ports)+len(a.Vulns) != 0 {
		t.Fatalf("404 = %+v, %v; want found false with empty lists", a, err)
	}
}

func TestInternetDB_RefusesWhatItCannotTrust(t *testing.T) {
	t.Parallel()
	huge := `{"ip":"8.8.8.8","hostnames":["` + strings.Repeat("a", outsideMaxBody) + `"]}`
	for name, c := range map[string]struct {
		status int
		body   string
		want   *APIError
	}{
		"over 64 KiB":         {200, huge, ErrOutsideBad},
		"not JSON":            {200, `<html>blocked</html>`, ErrOutsideBad},
		"another address":     {200, `{"ip":"1.1.1.1","ports":[22]}`, ErrOutsideBad},
		"no address":          {200, `{"ports":[22]}`, ErrOutsideBad},
		"ports of the wrong":  {200, `{"ip":"8.8.8.8","ports":["22"]}`, ErrOutsideBad},
		"two objects":         {200, `{"ip":"8.8.8.8"}{"ip":"8.8.8.8"}`, ErrOutsideBad},
		"an array":            {200, `[{"ip":"8.8.8.8"}]`, ErrOutsideBad},
		"rate limited":        {429, `{"detail":"slow down"}`, ErrOutsideLimited},
		"404 of a proxy":      {404, `<html>Not Found</html>`, ErrOutsideBad},
		"404 without detail":  {404, `{"error":"x"}`, ErrOutsideBad},
		"server error":        {500, ``, ErrOutsideDown},
		"redirect not follow": {302, ``, ErrOutsideDown},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f, db := newShodan(t)
			f.set(c.status, c.body)
			_, err := db.Lookup(t.Context(), netip.MustParseAddr(ipA))
			if !errors.Is(err, c.want) {
				t.Fatalf("error %v, want %v", err, c.want)
			}
		})
	}
}

func TestNewInternetDB_OnlyAnHTTPSHost(t *testing.T) {
	t.Parallel()
	for _, base := range []string{"http://internetdb.shodan.io", "https://user@internetdb.shodan.io", "https://internetdb.shodan.io/x", "https://internetdb.shodan.io/?a=1"} {
		if _, err := NewInternetDB(base, nil); err == nil {
			t.Errorf("%s accepted", base)
		}
	}
	if d, err := NewInternetDB("", nil); err != nil || d.base != InternetDBURL {
		t.Fatalf("default = %+v, %v", d, err)
	}
}

// outsideEnv is an env whose service asks the fake Shodan.
func outsideEnv(t *testing.T) (*env, *shodan) {
	t.Helper()
	e := newEnv(t)
	f, db := newShodan(t)
	e.svc.cfg.Outside = db
	return e, f
}

// INV-21: only the box's own verified IP that it still goes out through is sent, at most once a minute, by an administrator's
// click; every request sent is audited; the answer is kept with the time and the person.
func TestContract_INV21_OnlyTheBoxsOwnCurrentIPIsSent(t *testing.T) {
	t.Parallel()
	e, f := outsideEnv(t)
	ctx, admin := e.ctx(), "admin@acme.example"

	dom := e.addVerifiedDomain()
	_, err := e.svc.CheckOutside(ctx, admin, dom.ID)
	wantAPI(t, err, 400, "bad_value")
	_, err = e.svc.CheckOutside(ctx, admin, "xt-none")
	wantAPI(t, err, 404, "not_found")

	ip := e.detect(ipA)[0]
	if v, err := e.svc.Outside(ctx, ip.ID); err != nil || v != nil {
		t.Fatalf("before any check = %+v, %v; want nil", v, err)
	}

	// Not seen for 31 days: expired, nothing sent.
	e.advance(31 * 24 * time.Hour)
	_, err = e.svc.CheckOutside(ctx, admin, ip.ID)
	wantAPI(t, err, 409, "expired")
	if !strings.Contains(err.Error(), "cannot be checked with Shodan") {
		t.Fatalf("refusal speaks of the wrong action: %v", err)
	}

	// Seen again, but the box now goes out through another address: paused (INV-13), nothing sent.
	e.detect(ipA)
	e.advance(10 * time.Minute)
	e.prober.set(ipB)
	_, err = e.svc.CheckOutside(ctx, admin, ip.ID)
	wantAPI(t, err, 409, "ip_not_current")
	if !strings.Contains(err.Error(), "not sent to Shodan") {
		t.Fatalf("refusal speaks of the wrong action: %v", err)
	}
	if got := f.asked(); len(got) != 0 {
		t.Fatalf("Shodan was asked %v before a check was allowed", got)
	}

	// The box goes out through it again: one request for exactly that IP, kept and audited.
	e.advance(10 * time.Minute)
	e.detect(ipA)
	f.set(200, `{"ip":"8.8.8.8","ports":[443,8443],"hostnames":["vpn.acme.example"],"cpes":[],"tags":["self-signed"],"vulns":["CVE-2023-27997"]}`)
	v, err := e.svc.CheckOutside(ctx, admin, ip.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Found || v.IP != ipA || v.CheckedBy != admin || !slices.Equal(v.Ports, []int{443, 8443}) || v.ScanPorts != nil || v.ScanAt != nil {
		t.Fatalf("view = %+v", v)
	}
	if got := f.asked(); !slices.Equal(got, []string{"/" + ipA}) {
		t.Fatalf("asked %v", got)
	}
	last := e.audits()[len(e.audits())-1]
	if last.User != admin || last.Action != "exposure.outside_view" || last.Target != ipA || !strings.Contains(last.Detail, "2 ports and 1 CVEs") {
		t.Fatalf("audit = %+v", last)
	}

	// A second click within a minute is refused before any request.
	_, err = e.svc.CheckOutside(ctx, admin, ip.ID)
	wantAPI(t, err, 429, "rate_limited")
	if n := len(f.asked()); n != 1 {
		t.Fatalf("asked %d times", n)
	}

	// After a minute: no record now; a failure is audited and keeps the last answer.
	e.advance(OutsideEvery)
	e.detect(ipA)
	f.set(404, `{"detail":"No information available"}`)
	if v, err = e.svc.CheckOutside(ctx, admin, ip.ID); err != nil || v.Found || len(v.Ports) != 0 {
		t.Fatalf("no record = %+v, %v", v, err)
	}
	e.advance(OutsideEvery)
	e.detect(ipA)
	f.set(500, "")
	_, err = e.svc.CheckOutside(ctx, admin, ip.ID)
	wantAPI(t, err, 502, "unreachable")
	if a := e.audits(); !strings.Contains(a[len(a)-1].Detail, "failed: no usable answer") {
		t.Fatalf("failure audit = %+v", a[len(a)-1])
	}
	if got, _ := e.svc.Outside(ctx, ip.ID); got == nil || got.Found {
		t.Fatalf("after a failure the last answer must stay: %+v", got)
	}

	// Deleting the target deletes its answer; the audit rows stay.
	if err := e.svc.Delete(ctx, admin, ip.ID); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM exp_outside`); n != 0 {
		t.Fatalf("%d answers left", n)
	}
}

// The view puts our own newest scan next to Shodan's answer, read now.
func TestOutside_ShowsOurNewestScanBesideIt(t *testing.T) {
	t.Parallel()
	e, f := outsideEnv(t)
	ip := e.detect(ipA)[0]
	r := &fakeRunner{content: Content{Ports: []PortRow{{IP: ipA, Port: 443, Service: "https"}, {IP: ipA, Port: 18443, Service: "http"}}}}
	e.svc.SetRunner(r)
	if _, err := e.commit(ip.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", ip.ID); err != nil {
		t.Fatal(err)
	}
	f.set(200, `{"ip":"8.8.8.8","ports":[443,10443]}`)
	v, err := e.svc.CheckOutside(e.ctx(), "admin@acme.example", ip.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(v.Ports, []int{443, 10443}) || !slices.Equal(v.ScanPorts, []int{443, 18443}) || v.ScanAt == nil {
		t.Fatalf("view = %+v", v)
	}
}

func TestOutside_NotWiredIs501(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := e.detect(ipA)[0]
	_, err := e.svc.CheckOutside(e.ctx(), "admin@acme.example", ip.ID)
	wantAPI(t, err, 501, "not_implemented")
}

func TestHandlers_OutsideRolesAndShapes(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	f, db := newShodan(t)
	e.svc.cfg.Outside = db
	ip := e.detect(ipA)[0]
	if code, body := e.call("GET", "/exposure/targets/"+ip.ID+"/outside", "viewer", ""); code != 200 || body != nil {
		t.Fatalf("GET before = %d %v", code, body)
	}
	for _, who := range []string{"viewer", "operator"} {
		if code, _ := e.call("POST", "/exposure/targets/"+ip.ID+"/outside", who, ""); code != 403 {
			t.Fatalf("%s POST = %d, want 403", who, code)
		}
	}
	if n := len(f.asked()); n != 0 {
		t.Fatalf("asked %d times", n)
	}
	code, body := e.call("POST", "/exposure/targets/"+ip.ID+"/outside", "admin", "")
	if code != 200 || body["ip"] != ipA || body["found"] != true || body["scan_ports"] != nil {
		t.Fatalf("POST = %d %v", code, body)
	}
	if code, body := e.call("GET", "/exposure/targets/"+ip.ID+"/outside", "viewer", ""); code != 200 || body["ip"] != ipA {
		t.Fatalf("GET after = %d %v", code, body)
	}
}

// A body that never ends hits the client's deadline: no answer, nothing kept (INV-10). It runs in a synctest bubble on the real
// 10 s outsideTimeout with no network: the body blocks until the client gives up, so the outcome never depends on the machine's
// speed (issue #775: a real TLS server and a 200 ms timeout failed once under load).
func TestInternetDB_SlowAnswerHitsTheDeadline(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		db := &InternetDB{base: "https://internetdb.test", client: &http.Client{Timeout: outsideTimeout, Transport: endlessBody{}}}
		start := time.Now()
		_, err := db.Lookup(t.Context(), netip.MustParseAddr(ipA))
		if !errors.Is(err, ErrOutsideDown) {
			t.Fatalf("error %v, want %v", err, ErrOutsideDown)
		}
		if waited := time.Since(start); waited != outsideTimeout {
			t.Fatalf("gave up after %v, want %v", waited, outsideTimeout)
		}
	})
}

// endlessBody answers 200 with a body that sends its first bytes and then nothing until the request is cancelled.
type endlessBody struct{}

func (endlessBody) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Request: r,
		Body: io.NopCloser(io.MultiReader(strings.NewReader(`{"ip":"8.8.8.8",`), blockUntil{r.Context()}))}, nil
}

type blockUntil struct{ ctx context.Context }

func (b blockUntil) Read([]byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

// M1 of review r1: once the request has gone to Shodan, the person closing the page does not lose the audit row or the answer.
func TestContract_INV21_ARequestSentIsKeptWhenThePersonLeaves(t *testing.T) {
	t.Parallel()
	e, f := outsideEnv(t)
	ip := e.detect(ipA)[0]
	ctx, cancel := context.WithCancel(e.ctx())
	defer cancel()
	f.mu.Lock()
	f.onAsk = cancel
	f.mu.Unlock()
	if _, err := e.svc.CheckOutside(ctx, "admin@acme.example", ip.ID); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Fatal("the request was not cancelled")
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'exposure.outside_view' AND target = ?`, ipA); n != 1 {
		t.Fatalf("%d audit rows, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM exp_outside WHERE target_id = ?`, ip.ID); n != 1 {
		t.Fatalf("%d answers kept, want 1", n)
	}
}

// The limit is one request a minute on the box, whatever the target, and two clicks at once send one request.
func TestContract_INV21_OneRequestAMinuteOnTheBox(t *testing.T) {
	t.Parallel()
	e, f := outsideEnv(t)
	items := e.detect(ipA, ipB)
	if len(items) != 2 {
		t.Fatalf("detected %d IPs", len(items))
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Go(func() { _, errs[i] = e.svc.CheckOutside(e.ctx(), "admin@acme.example", items[0].ID) })
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("two clicks at once: %v, %v; want one answer and one 429", errs[0], errs[1])
	}
	for _, err := range errs {
		if err != nil {
			wantAPI(t, err, 429, "rate_limited")
		}
	}
	_, err := e.svc.CheckOutside(e.ctx(), "admin@acme.example", items[1].ID)
	wantAPI(t, err, 429, "rate_limited")
	if n := len(f.asked()); n != 1 {
		t.Fatalf("asked %d times, want 1", n)
	}
}
