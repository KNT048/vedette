package webui_test

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/internal/webui"
)

const indexHTML = `<!doctype html><div id="root"></div>`

// dist is a built interface; "outside.txt" is a sibling of it that no request may reach.
func distFS() http.Handler {
	m := fstest.MapFS{
		"dist/index.html":          {Data: []byte(indexHTML)},
		"dist/favicon.svg":         {Data: []byte("<svg/>")},
		"dist/assets/app-1a2b.js":  {Data: []byte("export{}")},
		"dist/assets/app-1a2b.css": {Data: []byte("a{}")},
		"dist/assets/f-9z.woff2":   {Data: []byte("wOF2")},
		"outside.txt":              {Data: []byte("SECRET")},
	}
	sub, err := fs.Sub(m, "dist")
	if err != nil {
		panic(err)
	}
	return webui.Handler(sub)
}

func do(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func body(rec *httptest.ResponseRecorder) string {
	b, _ := io.ReadAll(rec.Result().Body)
	return string(b)
}

func TestFallbackServesIndex(t *testing.T) {
	t.Parallel()
	h := distFS()
	for _, p := range []string{"/", "/findings/123", "/approve/tok", "/assets", "/assets/"} {
		rec := do(t, h, http.MethodGet, p)
		if rec.Code != 200 || body(rec) != indexHTML {
			t.Errorf("%s: %d %q, want index.html", p, rec.Code, body(rec))
		}
		if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("%s: Content-Type %q", p, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", p, got)
		}
	}
}

func TestFilesAndContentTypes(t *testing.T) {
	t.Parallel()
	h := distFS()
	for p, want := range map[string]string{
		"/assets/app-1a2b.js":  "text/javascript",
		"/assets/app-1a2b.css": "text/css",
		"/assets/f-9z.woff2":   "font/woff2",
		"/favicon.svg":         "image/svg+xml",
	} {
		rec := do(t, h, http.MethodGet, p)
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), want) {
			t.Errorf("%s: %d %q, want %s", p, rec.Code, rec.Header().Get("Content-Type"), want)
		}
	}
	if got := body(do(t, h, http.MethodGet, "/assets/app-1a2b.js")); got != "export{}" {
		t.Errorf("js body %q", got)
	}
}

func TestMissingFileIs404NotHTML(t *testing.T) {
	t.Parallel()
	h := distFS()
	for _, p := range []string{"/assets/missing.js", "/missing.css", "/a/b/c.map", "/mockServiceWorker.js"} {
		rec := do(t, h, http.MethodGet, p)
		if rec.Code != 404 || strings.Contains(body(rec), "root") {
			t.Errorf("%s: %d %q, want 404 without HTML", p, rec.Code, body(rec))
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: a 404 must not be cached, got %q", p, rec.Header().Get("Cache-Control"))
		}
	}
}

func TestOnlyGetAndHead(t *testing.T) {
	t.Parallel()
	h := distFS()
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		rec := do(t, h, m, "/")
		if rec.Code != 405 || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: %d Allow %q, want 405 GET, HEAD", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
}

func TestHeadHasNoBody(t *testing.T) {
	t.Parallel()
	h := distFS()
	for _, p := range []string{"/", "/findings/1", "/assets/app-1a2b.js"} {
		get, head := do(t, h, http.MethodGet, p), do(t, h, http.MethodHead, p)
		if head.Code != 200 || body(head) != "" {
			t.Errorf("HEAD %s: %d with body %q", p, head.Code, body(head))
		}
		if head.Header().Get("Content-Length") != get.Header().Get("Content-Length") || head.Header().Get("Cache-Control") != get.Header().Get("Cache-Control") {
			t.Errorf("HEAD %s headers differ from GET", p)
		}
	}
}

func TestCacheClasses(t *testing.T) {
	t.Parallel()
	h := distFS()
	for p, want := range map[string]string{
		"/assets/app-1a2b.js":  "public, max-age=31536000, immutable",
		"/assets/app-1a2b.css": "public, max-age=31536000, immutable",
		"/index.html":          "no-store",
		"/":                    "no-store",
		"/some/client/route":   "no-store",
		"/approve/x":           "no-store",
		"/favicon.svg":         "no-cache",
	} {
		if got := do(t, h, http.MethodGet, p).Header().Get("Cache-Control"); got != want {
			t.Errorf("%s: Cache-Control %q, want %q", p, got, want)
		}
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	t.Parallel()
	h := distFS()
	cases := []struct{ method, p string }{
		{"GET", "/"}, {"GET", "/approve/x"}, {"GET", "/assets/app-1a2b.js"}, {"GET", "/favicon.svg"},
		{"GET", "/assets/missing.js"}, {"GET", "/api/other"}, {"HEAD", "/"}, {"POST", "/"},
	}
	for _, c := range cases {
		hd := do(t, h, c.method, c.p).Header()
		csp := hd.Get("Content-Security-Policy")
		for _, need := range []string{"default-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'"} {
			if !strings.Contains(csp, need) {
				t.Errorf("%s %s: CSP %q lacks %s", c.method, c.p, csp, need)
			}
		}
		if strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "script-src") {
			t.Errorf("%s %s: CSP %q loosens scripts", c.method, c.p, csp)
		}
		for k, want := range map[string]string{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"} {
			if hd.Get(k) != want {
				t.Errorf("%s %s: %s = %q, want %q", c.method, c.p, k, hd.Get(k), want)
			}
		}
	}
}

func TestApproveIsNoStore(t *testing.T) {
	t.Parallel()
	rec := do(t, distFS(), http.MethodGet, "/approve/0123456789abcdef")
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("/approve/*: %d %v", rec.Code, rec.Header())
	}
}

func TestAPIPathsAreNeverIndex(t *testing.T) {
	t.Parallel()
	h := distFS()
	for _, p := range []string{"/api", "/api/", "/api/v1/nope", "/api/other", "/api/../api/x"} {
		rec := do(t, h, http.MethodGet, p)
		if rec.Code != 404 || strings.Contains(body(rec), "root") {
			t.Errorf("%s: %d %q, want 404", p, rec.Code, body(rec))
		}
	}
}

func TestDirectoriesAreNotListed(t *testing.T) {
	t.Parallel()
	h := distFS()
	for _, p := range []string{"/assets", "/assets/"} {
		b := body(do(t, h, http.MethodGet, p))
		if strings.Contains(b, "app-1a2b") || b != indexHTML {
			t.Errorf("%s lists or serves a directory: %q", p, b)
		}
	}
}

func TestTraversalCannotEscape(t *testing.T) {
	t.Parallel()
	h := distFS()
	for _, p := range []string{"/../outside.txt", "/assets/../../outside.txt", "/%2e%2e/outside.txt", "/assets/%2e%2e/%2e%2e/outside.txt", "/..%2foutside.txt", "//outside.txt", "/./../outside.txt"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.URL.Path, _ = url.PathUnescape(p) // what a client could make the server see, bypassing the mux clean-up
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if strings.Contains(body(rec), "SECRET") {
			t.Errorf("%s reached a file outside the interface", p)
		}
	}
}

func TestStubBuild(t *testing.T) {
	t.Parallel()
	h := webui.Handler(nil)
	for _, p := range []string{"/", "/findings/1", "/assets/x.js"} {
		rec := do(t, h, http.MethodGet, p)
		if rec.Code != 200 || !strings.Contains(body(rec), "This build has no web interface") {
			t.Errorf("%s: %d %q", p, rec.Code, body(rec))
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: headers %v", p, rec.Header())
		}
	}
	if rec := do(t, h, http.MethodGet, "/api/v1/x"); rec.Code != 404 {
		t.Errorf("stub answered an API path with %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/"); rec.Code != 405 {
		t.Errorf("stub POST %d", rec.Code)
	}
}

func TestEmptyDistIs500NotPanic(t *testing.T) {
	t.Parallel()
	rec := do(t, webui.Handler(fstest.MapFS{}), http.MethodGet, "/x")
	if rec.Code != 500 {
		t.Errorf("no index.html: %d", rec.Code)
	}
}

// A real approval link: v1.<22 base64url>.<22 base64url> (web TOKEN_RE). Its last segment has dots, but it is a client route, never a missing file.
const approveToken = //nolint:gosec // a made-up value in the token format, not a credential
"v1.AbCdEfGhIjKlMnOpQrStUv.0123456789_-abcdefghij"

func TestApprovalLinkIsTheInterface(t *testing.T) {
	t.Parallel()
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := do(t, distFS(), method, "/approve/"+approveToken)
		hd := rec.Header()
		if rec.Code != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "text/html") || hd.Get("Cache-Control") != "no-store" {
			t.Errorf("%s /approve/<token>: %d %q %q", method, rec.Code, hd.Get("Content-Type"), hd.Get("Cache-Control"))
		}
		if hd.Get("Content-Security-Policy") != webui.CSP || hd.Get("Referrer-Policy") != "no-referrer" || hd.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s /approve/<token>: headers %v", method, hd)
		}
		if method == http.MethodGet && body(rec) != indexHTML {
			t.Errorf("/approve/<token> body %q", body(rec))
		}
	}
}

func TestCSPShape(t *testing.T) {
	t.Parallel()
	rec := do(t, distFS(), http.MethodGet, "/")
	csp := rec.Header().Get("Content-Security-Policy")
	for _, need := range []string{"style-src 'self' 'unsafe-inline'", "form-action 'self'", "font-src 'self' data:", "default-src 'self'"} {
		if !strings.Contains(csp, need) {
			t.Errorf("CSP %q lacks %s", csp, need)
		}
	}
	if strings.Contains(csp, "script-src") || strings.Contains(csp, "unsafe-eval") || strings.Count(csp, "unsafe-inline") != 1 {
		t.Errorf("CSP %q: unsafe-inline is for style-src only, scripts stay on default-src 'self'", csp)
	}
	if got := rec.Header().Get("Cross-Origin-Opener-Policy"); got != "same-origin" {
		t.Errorf("Cross-Origin-Opener-Policy = %q", got)
	}
}

func TestUnhashedFilesRevalidateWithETag(t *testing.T) {
	t.Parallel()
	h := distFS()
	first := do(t, h, http.MethodGet, "/favicon.svg")
	etag := first.Header().Get("ETag")
	if first.Code != 200 || etag == "" {
		t.Fatalf("favicon: %d ETag %q", first.Code, etag)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/favicon.svg", nil)
	req.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified || body(rec) != "" || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("revalidation: %d %q Cache-Control %q, want 304 with no body", rec.Code, body(rec), rec.Header().Get("Cache-Control"))
	}
	if do(t, h, http.MethodGet, "/").Header().Get("ETag") != "" {
		t.Error("index.html must not carry an ETag (no-store)")
	}
}

func TestMissingFilesByExtension(t *testing.T) {
	t.Parallel()
	h := distFS()
	for p, want := range map[string]int{
		"/x.webmanifest": 404, "/font.TTF": 404, "/assets/anything": 404, "/assets/dir/x": 404,
		"/approve/" + approveToken: 200, "/report/v1.2": 200, "/a.b/c": 200,
	} {
		if rec := do(t, h, http.MethodGet, p); rec.Code != want {
			t.Errorf("%s: %d, want %d", p, rec.Code, want)
		}
	}
}
