package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/honeypot"
	"github.com/knt048/vedette/modules/inventory"
)

// tokenRouter is the listener's real router (topHandler, as serve builds it) over the stack's API, with the URL token route, a
// limit of perMinute repeat opens per address on a clock that does not move, and an appliance whose host is 192.168.10.5 and whose
// bridge gateway is 10.89.0.1.
func tokenRouter(s *stack, perMinute int) http.Handler {
	return tokenRouterWith(s, perMinute, honeyTokenSources{machine: func() ([]netip.Addr, bool) {
		return []netip.Addr{netip.MustParseAddr("192.168.10.5"), netip.MustParseAddr("10.89.0.1")}, true
	}, appliance: true})
}

func tokenRouterWith(s *stack, perMinute int, src honeyTokenSources) http.Handler {
	now := time.Now()
	lim := server.NewAddrLimiter(perMinute, func() time.Time { return now })
	log := slog.New(slog.DiscardHandler)
	return topHandler(log, s.h, honeyTokenHandler(log, s.d.Honeypot, lim, src), server.HostMatcher([]string{"192.168.10.5"}, nil), false)
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
	clock := time.Now().UTC().Truncate(10 * time.Minute).Add(time.Minute) // fixed, well inside one 10-minute hit window
	s := newStackWith(t, func(d *deps) {
		d.HoneypotDir = t.TempDir()
		d.BaseURL = func() string { return "https://192.168.10.5:8443" }
		d.Clock = func() time.Time { return clock }
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

// One address cannot make the box write without end: the first open of a token in a window always records, past the per-minute
// limit a repeat open answers the same and records nothing, and another address still fires.
func TestURLTokenOpenIsLimitedPerAddress(t *testing.T) {
	t.Parallel()
	s, path := urlTokenStack(t)
	h := tokenRouter(s, 2)
	for _, port := range []string{"1", "2", "3", "4", "5"} {
		sameAnswer(t, "open "+port, open(t, h, http.MethodGet, path, "192.168.10.107:"+port, ""))
	}
	if n := s.count(`SELECT conn_count FROM hp_hits WHERE src_ip = '192.168.10.107'`); n != 3 {
		t.Fatalf("conn_count %d, want 3: the first open and 2 repeats per minute", n)
	}
	sameAnswer(t, "another address", open(t, h, http.MethodGet, path, "192.168.10.108:1", ""))
	if n := s.count(`SELECT count(*) FROM hp_hits WHERE src_ip = '192.168.10.108'`); n != 1 {
		t.Fatalf("another address: %d hits", n)
	}
}

// Review M1: made-up ids do not use up an address's limit, so they cannot silence the real link.
func TestURLTokenFakeIDsDoNotSilenceTheLink(t *testing.T) {
	t.Parallel()
	s, path := urlTokenStack(t)
	h := tokenRouter(s, honeyTokenPerMinute)
	for i := range honeyTokenPerMinute {
		sameAnswer(t, "fake id", open(t, h, http.MethodGet, "/t/"+strings.Repeat(string(rune('a'+i)), 10), "192.168.10.107:"+strconv.Itoa(100+i), ""))
	}
	sameAnswer(t, "the real link", open(t, h, http.MethodGet, path, "192.168.10.107:200", ""))
	if n := s.count(`SELECT count(*) FROM hp_hits WHERE src_ip = '192.168.10.107'`); n != 1 {
		t.Fatalf("%d hits after 10 made-up ids and the real link, want 1", n)
	}
}

// Review L1: the link with a trailing slash, a deeper path or punctuation an auto-linker glued on still fires, with the same 404.
func TestURLTokenOpenWithATailFires(t *testing.T) {
	t.Parallel()
	s, path := urlTokenStack(t)
	h := tokenRouter(s, honeyTokenPerMinute)
	for i, p := range []string{path + "/", path + ").", path + "/x/y", path + "%3E"} {
		sameAnswer(t, p, open(t, h, http.MethodGet, p, "192.168.10.107:"+strconv.Itoa(i+1), ""))
	}
	if n := s.count(`SELECT conn_count FROM hp_hits WHERE src_ip = '192.168.10.107'`); n != 4 {
		t.Fatalf("conn_count %d, want 4 opens of the one hit", n)
	}
	sameAnswer(t, "glued letters are another id", open(t, h, http.MethodGet, path+"x", "192.168.10.108:1", ""))
	if n := s.count(`SELECT count(*) FROM hp_hits WHERE src_ip = '192.168.10.108'`); n != 0 {
		t.Fatalf("%d hits for another id", n)
	}
}

// Review L2: the box itself never fires its own token: loopback (IPv4, IPv6, mapped), the box's address in the inventory (INV-3),
// and on the appliance the machine's addresses (its LAN address, the bridge gateway its host's requests come from). Any other IPv6
// address fires: hp_hits keeps IPv4 only, so the hit stores "unknown" and the event, line and incident carry the address.
func TestURLTokenOpenFromTheBoxItselfAndFromIPv6(t *testing.T) {
	t.Parallel()
	s, path := urlTokenStack(t)
	if _, err := s.d.Inventory.EnsureBox(t.Context(), inventory.BoxInfo{Hostname: "vedette", IP: "192.168.10.6"}); err != nil { // through the inventory (its INV-2), not its table
		t.Fatal(err)
	}
	h := tokenRouter(s, honeyTokenPerMinute)
	for _, from := range []string{"127.0.0.1:1", "[::1]:1", "[::ffff:127.0.0.1]:1", "192.168.10.6:1", "192.168.10.5:1", "10.89.0.1:1"} {
		sameAnswer(t, from, open(t, h, http.MethodGet, path, from, ""))
	}
	if n := s.count(`SELECT count(*) FROM hp_hits`); n != 0 {
		t.Fatalf("%d hits from the box itself", n)
	}
	sameAnswer(t, "IPv6", open(t, h, http.MethodGet, path, "[fd00::5]:44321", ""))
	if n := s.count(`SELECT count(*) FROM hp_hits WHERE src_ip = 'unknown' AND events LIKE '%[fd00::5]:44321%'`); n != 1 {
		t.Fatalf("%d IPv6 hits", n)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE title = 'fd00::5 opened the URL token Admin-VPN-wiki'`); n != 1 {
		t.Fatalf("%d incidents naming the IPv6 address", n)
	}
}

// Review L3: on a container-only install a port proxy may stand between the visitor and core; an open from the machine's address is
// recorded with the source "unknown (container-only port proxy)", never naming the gateway as the machine to unplug.
func TestURLTokenOpenThroughAContainerOnlyPortProxy(t *testing.T) {
	t.Parallel()
	s, path := urlTokenStack(t)
	h := tokenRouterWith(s, honeyTokenPerMinute, honeyTokenSources{machine: func() ([]netip.Addr, bool) {
		return []netip.Addr{netip.MustParseAddr("172.17.0.1")}, true
	}})
	sameAnswer(t, "proxied", open(t, h, http.MethodGet, path, "172.17.0.1:5000", ""))
	if n := s.count(`SELECT count(*) FROM hp_hits WHERE src_ip = 'unknown' AND events NOT LIKE '%172.17.0.1%'`); n != 1 {
		t.Fatalf("%d proxied hits", n)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE title = 'unknown (container-only port proxy) opened the URL token Admin-VPN-wiki'`); n != 1 {
		t.Fatalf("%d incidents with the unknown source", n)
	}
	sameAnswer(t, "a LAN address that reached core", open(t, h, http.MethodGet, path, "192.168.10.107:1", ""))
	if n := s.count(`SELECT count(*) FROM hp_hits WHERE src_ip = '192.168.10.107'`); n != 1 {
		t.Fatalf("%d hits naming a kept LAN address", n)
	}
}

// Review M2: the record is detached from the caller and the publish has its own budget with no write wait limit, so a visitor who
// hangs up, or a request budget spent waiting for the writer, does not lose the incident of a hit that was saved.
func TestURLTokenOpenOutlivesTheRequest(t *testing.T) {
	t.Parallel()
	s, path := urlTokenStack(t)
	var pubErr error
	s.d.Bus.Subscribe(honeypot.EventHitCreated, func(ctx context.Context, _ events.Event) error {
		pubErr = ctx.Err()
		return nil
	})
	ctx, cancel := context.WithCancel(store.LimitWriteWait(t.Context(), time.Nanosecond))
	cancel() // the visitor hung up before anything was written
	err := s.d.Honeypot.OpenURLToken(ctx, honeypot.URLTokenOpen{ID: strings.TrimPrefix(path, "/t/"), Src: netip.MustParseAddrPort("192.168.10.107:1")})
	if err != nil || pubErr != nil {
		t.Fatalf("open: %v, publish context: %v", err, pubErr)
	}
	if n := s.count(`SELECT count(*) FROM notify_incident WHERE title = '192.168.10.107 opened the URL token Admin-VPN-wiki'`); n != 1 {
		t.Fatalf("%d incidents", n)
	}
}
