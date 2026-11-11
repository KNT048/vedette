package server_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

// D-320 (API_CONVENTIONS §8): public requests without a session are limited per client address (IPv6 per /64). A signed-in request
// (also to a public route), a 401 of a protected route, the osquery agents' routes and loopback are not counted. Past the limit: 429
// rate_limited with Retry-After.
func TestPublicRequestsAreLimitedPerAddress(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	h, err := server.New(server.Config{
		API:  composite{Fallback: server.Fallback{Log: log}, feedsHandler: feedsHandler{&seen{}}, coreHandler: coreHandler{&seen{}}},
		Auth: &servertest.Auth{Users: servertest.StandardUsers()}, Modules: servertest.NewGate(), Log: log, PublicPerMinute: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	get := func(path, from, user string) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, server.Prefix+path, nil)
		r.RemoteAddr = from
		if user != "" {
			r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	const a = "198.51.100.7:4000"
	for range 10 { // 401s are not counted, and stay 401 (the app goes to the sign-in page on them)
		if w := get("/modules", a, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("a protected route without a session: %d, want 401", w.Code)
		}
	}
	for range 3 {
		if w := get("/setup", a, ""); w.Code == http.StatusTooManyRequests {
			t.Fatal("limited early")
		}
	}
	w := get("/setup", a, "")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("4th public request without a session: %d %q, want 429 with Retry-After", w.Code, w.Header().Get("Retry-After"))
	}
	for range 5 { // a signed-in page polls GET /setup: never counted, also from an address over the limit
		if w := get("/setup", a, "viewer"); w.Code == http.StatusTooManyRequests {
			t.Fatal("a signed-in request to a public route was limited")
		}
	}
	if w := get("/intake/ca.pem", a, ""); w.Code == http.StatusTooManyRequests { // the agents' routes are not counted
		t.Fatal("the intake CA was limited")
	}
	if w := get("/setup", "198.51.100.8:4000", ""); w.Code == http.StatusTooManyRequests {
		t.Fatal("another address was limited")
	}
	for range 5 { // loopback is the box itself
		if w := get("/setup", "127.0.0.1:5000", ""); w.Code == http.StatusTooManyRequests {
			t.Fatal("loopback was limited")
		}
	}
	for i := range 3 { // IPv6 per /64
		get("/setup", "[2001:db8:1:2::"+string(rune('a'+i))+"]:4000", "")
	}
	if w := get("/setup", "[2001:db8:1:2::ffff]:4000", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("another address of the same /64: %d, want 429", w.Code)
	}
	if w := get("/setup", "[2001:db8:1:3::1]:4000", ""); w.Code == http.StatusTooManyRequests {
		t.Fatal("another /64 was limited")
	}
}
