package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/internal/webui"
)

// D-149: the SPA and the API share one listener. Built without the webui tag (the default for tests) the SPA side is the stub page; its
// headers and the routing are the same as the release build's, and the file handling is tested in internal/webui.
func TestTopHandlerServesSPAAndKeepsAPI(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	h := topHandler(slog.New(slog.DiscardHandler), s.h, nil, server.HostMatcher([]string{"localhost"}, nil), false)
	get := func(method, target string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
		req.Host = "localhost"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// The API still answers its own paths: JSON, no-store.
	rec := get(http.MethodGet, server.Prefix+"/nope")
	if rec.Code != 404 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") || strings.Contains(rec.Body.String(), "<html") {
		t.Errorf("/api/v1/nope: %d %q %q, want the API's 404 JSON", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("API Cache-Control %q, want no-store", got)
	}

	// Everything else is the SPA, with the security headers, and /approve/* is never cached.
	for _, p := range []string{"/", "/findings/1", "/approve/tok", "/approve/v1.AbCdEfGhIjKlMnOpQrStUv.0123456789_-abcdefghij"} { // the last: the real token format
		rec := get(http.MethodGet, p)
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			t.Errorf("%s: %d %q", p, rec.Code, rec.Header().Get("Content-Type"))
		}
		hd := rec.Header()
		if hd.Get("Cache-Control") != "no-store" || hd.Get("X-Frame-Options") != "DENY" || hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Referrer-Policy") != "no-referrer" || hd.Get("Content-Security-Policy") != webui.CSP || hd.Get("Cross-Origin-Opener-Policy") != "same-origin" {
			t.Errorf("%s: headers %v", p, hd)
		}
		if hd.Get("X-Request-Id") == "" {
			t.Errorf("%s: not wrapped by the Envelope", p)
		}
	}
	if rec := get(http.MethodGet, "/api/other"); rec.Code != 404 || strings.Contains(rec.Body.String(), "<html") {
		t.Errorf("/api/other: %d, want 404 and no HTML", rec.Code)
	}
	if rec := get(http.MethodPost, "/"); rec.Code != 405 || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST /: %d Allow %q", rec.Code, rec.Header().Get("Allow"))
	}
	if rec := get(http.MethodHead, "/"); rec.Code != 200 || rec.Body.Len() != 0 {
		t.Errorf("HEAD /: %d with %d body bytes", rec.Code, rec.Body.Len())
	}

	// The Host check still comes first, for the SPA too.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "evil.example"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 421 {
		t.Errorf("foreign Host on /: %d, want 421", rec.Code)
	}
}
