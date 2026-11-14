package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/server"
)

func TestHostAllowlist(t *testing.T) {
	t.Parallel()
	called := 0
	h := server.HostAllowlist([]string{"Box.Acme.Example", "192.0.2.10", "2001:db8::10", "ignored host!"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(204)
	}))
	for host, want := range map[string]int{
		// allowed: configured names without case or port or trailing dot, IP literals in any spelling, loopback always
		"box.acme.example": 204, "BOX.ACME.EXAMPLE:8443": 204, "box.acme.example.": 204, "192.0.2.10": 204, "192.0.2.10:443": 204,
		"[2001:db8::10]:443": 204, "[2001:db8:0:0:0:0:0:10]": 204, "localhost": 204, "LOCALHOST:8080": 204, "127.0.0.1:1": 204, "[::1]:1": 204, "127.0.0.2": 421,
		// refused: anything else, lookalikes, suffix tricks, the empty and the odd
		"evil.example": 421, "box.acme.example.evil.example": 421, "xbox.acme.example": 421, "acme.example": 421, "192.0.2.11": 421,
		"192.0.2.10.evil.example": 421, "box.acme.example@evil.example": 421, "box.acme.example/": 421, "[2001:db8::11]": 421,
		"ignored host!": 421, "": 421, " ": 421, "box.acme.example:80:90": 421,
	} {
		before := called
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/setup", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %q = %d, want %d", host, rec.Code, want)
		}
		if want == 421 {
			if called != before {
				t.Errorf("Host %q reached the next handler", host)
			}
			if !strings.Contains(rec.Body.String(), `"code":"misdirected_request"`) {
				t.Errorf("Host %q body = %s", host, rec.Body)
			}
		}
	}
}

// Every method and path is refused, not only the API: the check runs before routing.
func TestHostAllowlistCoversEveryRequest(t *testing.T) {
	t.Parallel()
	h := server.HostAllowlist(nil, http.NotFoundHandler())
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"} {
		for _, p := range []string{"/", "/api/v1/modules", "/assets/app.js", "/anything"} {
			req := httptest.NewRequestWithContext(t.Context(), m, p, nil)
			req.Host = "evil.example"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 421 {
				t.Errorf("%s %s = %d", m, p, rec.Code)
			}
		}
	}
}

// A "*." entry matches like the wildcard of a certificate: one label, never the bare domain, never deeper,
// never an IP literal. The default allowlist of an owner-supplied wildcard certificate is its names, so
// without this a box with a certificate for *.corp.example answered 421 to its own name.
func TestHostAllowlistWildcardMatchesOneLabel(t *testing.T) {
	t.Parallel()
	h := server.HostAllowlist([]string{"*.corp.example", "*.", "*.*.x.example", "*"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for host, want := range map[string]int{
		"vedette.corp.example": 204, "vedette.corp.example:8443": 204, "VEDETTE.CORP.EXAMPLE.": 204, "a-1.corp.example": 204,
		"a.b.corp.example": 421, "corp.example": 421, ".corp.example": 421, "xcorp.example": 421, "vedette.corp.example.evil.example": 421,
		"*.corp.example": 421, "a*.corp.example": 421, "*": 421, "192.0.2.10": 421, "x.example": 421, "a.x.example": 421, "": 421,
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/setup", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %q = %d, want %d", host, rec.Code, want)
		}
	}
}

// A browser opening a page by a refused name gets a short readable page (D-556); the API and other clients keep the JSON error.
// Either way it is 421 and nothing is routed.
func TestHostAllowlistBrowserPage(t *testing.T) {
	t.Parallel()
	h := server.HostAllowlist([]string{"box.acme.example"}, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("a refused Host reached the next handler")
	}))
	const browser = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	for _, c := range []struct {
		method, path, accept, host string
		page                       bool
	}{
		{"GET", "/", browser, "Walk3.LAN:8443", true},
		{"GET", "/devices", browser, "walk3.lan", true},
		{"HEAD", "/", browser, "walk3.lan", true},
		{"GET", "/", browser, "a<b>.example", true},
		{"GET", "/api/v1/setup", browser, "walk3.lan", false},
		{"GET", "/", "application/json", "walk3.lan", false},
		{"GET", "/", "", "walk3.lan", false},
		{"POST", "/", browser, "walk3.lan", false},
	} {
		req := httptest.NewRequestWithContext(t.Context(), c.method, c.path, nil)
		req.Host = c.host
		if c.accept != "" {
			req.Header.Set("Accept", c.accept)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		name := c.method + " " + c.path + " " + c.accept + " " + c.host
		if rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("%s = %d", name, rec.Code)
		}
		ct, body := rec.Header().Get("Content-Type"), rec.Body.String()
		if !c.page {
			if !strings.HasPrefix(ct, "application/json") || !strings.Contains(body, `"code":"misdirected_request"`) {
				t.Errorf("%s: want the JSON error, got %s %s", name, ct, body)
			}
			continue
		}
		if ct != "text/html; charset=utf-8" {
			t.Errorf("%s: Content-Type %q", name, ct)
		}
		if c.method == "HEAD" {
			continue
		}
		for _, want := range []string{"This address is not one Vedette answers to", "VEDETTE_HOSTS", "docs/INSTALL-CONTAINER.md"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: page lacks %q:\n%s", name, want, body)
			}
		}
		if strings.Contains(body, "box.acme.example") || strings.Contains(body, "<script") || strings.Contains(body, "style") {
			t.Errorf("%s: page lists an allowed name, a script or a style:\n%s", name, body)
		}
	}
	// the name the browser sent is shown normalised and escaped, never as markup
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	req.Host, req.Header["Accept"] = "a<b>.example", []string{browser}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if b := rec.Body.String(); strings.Contains(b, "<b>") || !strings.Contains(b, "a&lt;b&gt;.example") {
		t.Errorf("Host not escaped:\n%s", b)
	}
	req.Host = "Walk3.LAN:8443"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "<strong>walk3.lan</strong>") {
		t.Errorf("Host not shown normalised:\n%s", rec.Body)
	}
}
