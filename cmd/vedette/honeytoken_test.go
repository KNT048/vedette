package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/modules/honeypot"
)

// tokenRouter is the listener's real router (topHandler, as serve builds it) over the stack's API, with the URL token route and a
// limit of perMinute opens per address on a clock that does not move.
func tokenRouter(s *stack, perMinute int) http.Handler {
	now := time.Now()
	lim := server.NewAddrLimiter(perMinute, func() time.Time { return now })
	log := slog.New(slog.DiscardHandler)
	return topHandler(log, s.h, honeyTokenHandler(log, s.d.Honeypot, lim), server.HostMatcher([]string{"192.168.10.5"}, nil), false)
}

// open is a request from a LAN machine with no session, no CSRF header and no Origin.
func open(t *testing.T, h http.Handler, method, path, from, ua string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	r.Host = "192.168.10.5:8443"
	r.RemoteAddr = from
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// urlTokenStack is a stack with the honeypot on and one URL token; it returns the token's /t/<id> path and its name.
func urlTokenStack(t *testing.T) (*stack, string) {
	t.Helper()
	s := newStackWith(t, func(d *deps) {
		d.HoneypotDir = t.TempDir()
		d.BaseURL = func() string { return "https://192.168.10.5:8443" }
	})
	s.saveScope(t)
	s.setModule("honeypot", true)
	code, b := s.do("POST", "/honeypot/tokens", "admin", `{"type":"url","name":"Admin-VPN-wiki","plant_at":"Intranet wiki"}`)
	if code != 201 {
		t.Fatalf("create URL token: %d %v", code, b)
	}
	v := field(t, b, "value").(string)
	path, ok := strings.CutPrefix(v, "https://192.168.10.5:8443")
	if !ok || !strings.HasPrefix(path, "/t/") {
		t.Fatalf("URL token value %q", v)
	}
	return s, path
}

// sameAnswer fails unless w is the one answer of /t/...: a plain 404 that is not the Vedette app.
func sameAnswer(t *testing.T, what string, w *httptest.ResponseRecorder) {
	t.Helper()
	body := w.Body.String()
	if w.Code != http.StatusNotFound || body != "404 page not found\n" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") ||
		strings.Contains(strings.ToLower(body), "vedette") || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("%s: %d %q %v, want the plain 404", what, w.Code, body, w.Header())
	}
}

// W1-28 (D-507): opening a planted URL token from a LAN machine, with no session, records a real hit with the source address and
// the cleaned User-Agent, publishes it, and notify opens the Critical incident "<ip> opened the URL token <name>". The answer is a
// plain 404, never the app.
func TestURLTokenOpenFiresThroughTheRouter(t *testing.T) {
	t.Parallel()
	s, path := urlTokenStack(t)
	var got []honeypot.HitEventData
	s.d.Bus.Subscribe(honeypot.EventHitCreated, func(_ context.Context, e events.Event) error {
		got = append(got, e.Data.(honeypot.HitEventData))
		return nil
	})
	h := tokenRouter(s, honeyTokenPerMinute)
	sameAnswer(t, "the token", open(t, h, http.MethodGet, path, "192.168.10.107:51234", "Mozilla/5.0 \u202eevil\x00 "+strings.Repeat("x", 400)))

	if len(got) != 1 || got[0].Kind != honeypot.KindToken || got[0].SrcIP != "192.168.10.107" || got[0].Label != "URL token Admin-VPN-wiki" {
		t.Fatalf("published %+v, want one token hit from 192.168.10.107", got)
	}
	_, b := s.do("GET", "/honeypot/hits", "viewer", "")
	items := field(t, b, "items").([]any)
	if len(items) != 1 {
		t.Fatalf("%d hits, want 1", len(items))
	}
	hit := items[0].(map[string]any)
	ex, _ := hit["excerpt"].(string)
	if hit["kind"] != "token" || hit["is_test"] != false || hit["src_ip"] != "192.168.10.107" || hit["ts"] == "" ||
		!strings.Contains(ex, "User-Agent: Mozilla/5.0 evil") || strings.ContainsAny(ex, "\u202e\x00") || len(ex) > 600 {
		t.Fatalf("hit %v", hit)
	}
	if _, b = s.do("GET", "/honeypot/tokens", "viewer", ""); at(b, "items", 0, "triggers") != float64(1) || at(b, "items", 0, "last_triggered_at") == nil {
		t.Fatalf("token not triggered: %v", b)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE kind = 'trap' AND severity = 'critical' AND title = '192.168.10.107 opened the URL token Admin-VPN-wiki' AND link = ?`,
		"/honeypot/hits/"+got[0].ID); n != 1 {
		t.Fatalf("%d incidents named for the open, want 1", n)
	}

	// Any other /t/<x> answers the same and records nothing: an unknown id, a malformed one, another method. So does a deleted token.
	id := strings.TrimPrefix(path, "/t/")
	other := "zzzzzzzzzz"
	if id == other {
		other = "yyyyyyyyyy"
	}
	sameAnswer(t, "unknown id", open(t, h, http.MethodGet, "/t/"+other, "192.168.10.108:1", ""))
	sameAnswer(t, "malformed id", open(t, h, http.MethodGet, "/t/NOT-AN-ID", "192.168.10.108:2", ""))
	sameAnswer(t, "HEAD", open(t, h, http.MethodHead, "/t/"+other, "192.168.10.108:3", ""))
	sameAnswer(t, "POST", open(t, h, http.MethodPost, "/t/"+other, "192.168.10.108:4", ""))
	_, b = s.do("GET", "/honeypot/tokens", "viewer", "")
	if code, _ := s.do("DELETE", "/honeypot/tokens/"+at(b, "items", 0, "id").(string), "admin", ""); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	sameAnswer(t, "deleted token", open(t, h, http.MethodGet, path, "192.168.10.109:5", ""))
	if n := s.count(`SELECT count(*) FROM hp_hits`); n != 1 || len(got) != 1 {
		t.Fatalf("%d hits, %d events: only the real token's open counts", n, len(got))
	}
	// The rest of the box is unchanged: the app still answers its own paths, and the API still wants a session.
	if w := open(t, h, http.MethodGet, "/honeypot", "192.168.10.107:6", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "<") {
		t.Errorf("app: %d", w.Code)
	}
	if w := open(t, h, http.MethodGet, server.Prefix+"/honeypot/hits", "192.168.10.107:7", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("API without a session: %d", w.Code)
	}
}

// With the honeypot off the link answers the same and records nothing (the module is off: no route of its own).
func TestURLTokenOpenWhileTheModuleIsOff(t *testing.T) {
	t.Parallel()
	s, path := urlTokenStack(t)
	s.setModule("honeypot", false)
	sameAnswer(t, "module off", open(t, tokenRouter(s, honeyTokenPerMinute), http.MethodGet, path, "192.168.10.107:1", ""))
	if n := s.count(`SELECT count(*) FROM hp_hits`); n != 0 {
		t.Fatalf("%d hits while the module is off", n)
	}
}

// One address cannot make the box write without end: past the per-minute limit the answer is the same and nothing is recorded,
// while another address still fires.
func TestURLTokenOpenIsLimitedPerAddress(t *testing.T) {
	t.Parallel()
	s, path := urlTokenStack(t)
	h := tokenRouter(s, 2)
	for _, port := range []string{"1", "2", "3", "4"} {
		sameAnswer(t, "open "+port, open(t, h, http.MethodGet, path, "192.168.10.107:"+port, ""))
	}
	var conns int
	if err := s.d.DB.Reader().QueryRowContext(t.Context(), `SELECT conn_count FROM hp_hits WHERE src_ip = '192.168.10.107'`).Scan(&conns); err != nil {
		t.Fatal(err)
	}
	if conns != 2 {
		t.Fatalf("conn_count %d, want 2: the limit is 2 per minute", conns)
	}
	sameAnswer(t, "another address", open(t, h, http.MethodGet, path, "192.168.10.108:1", ""))
	if n := s.count(`SELECT count(*) FROM hp_hits WHERE src_ip = '192.168.10.108'`); n != 1 {
		t.Fatalf("another address: %d hits", n)
	}
}
