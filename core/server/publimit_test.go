package server_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

// D-320 (API_CONVENTIONS §8): requests without a session are limited per client address (IPv6 per /64): public operations and
// 401s count, a signed-in request and the osquery agents' routes do not, nor does loopback. Past the limit: 429 rate_limited with
// Retry-After.
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
	for _, p := range []string{"/setup", "/modules", "/setup"} { // public, 401, public
		if w := get(p, a, ""); w.Code == http.StatusTooManyRequests {
			t.Fatalf("%s limited early", p)
		}
	}
	w := get("/modules", a, "")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("4th request without a session: %d %q, want 429 with Retry-After", w.Code, w.Header().Get("Retry-After"))
	}
	if w := get("/modules", a, "viewer"); w.Code == http.StatusTooManyRequests || w.Code == http.StatusUnauthorized { // a session is never counted
		t.Fatalf("signed in: %d", w.Code)
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
