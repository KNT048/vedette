package feeds

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
)

// D-208: a pull never connects to loopback or to the box's own addresses, and never reads past a short snippet of a feed value.

func boxOf(addrs ...string) func() ([]netip.Addr, bool) {
	var out []netip.Addr
	for _, a := range addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	return func() ([]netip.Addr, bool) { return out, true }
}

func countingServer(t *testing.T, tls bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var served atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { served.Add(1); _, _ = w.Write([]byte("secret")) })
	if tls {
		return httptest.NewTLSServer(h), &served
	}
	return httptest.NewServer(h), &served
}

func TestD208_LoopbackRefusedForHTTPAndHTTPS(t *testing.T) {
	t.Parallel()
	for _, tls := range []bool{false, true} {
		srv, served := countingServer(t, tls)
		f := Fetcher{Client: NewClient(5 * time.Second), BoxAddrs: boxOf("10.9.9.9")}
		if _, err := f.Fetch(context.Background(), Request{URL: srv.URL}); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("tls=%v: %v", tls, err)
		}
		srv.Close()
		if served.Load() != 0 {
			t.Errorf("tls=%v: loopback was contacted", tls)
		}
	}
	// the zero Fetcher (no box function) refuses loopback as well
	srv, served := countingServer(t, false)
	defer srv.Close()
	if _, err := (Fetcher{}).Fetch(context.Background(), Request{URL: srv.URL}); !errors.Is(err, ErrBlockedAddress) || served.Load() != 0 {
		t.Errorf("zero Fetcher: %v", err)
	}
}

func TestD208_BoxAddressAndNameResolvingToItAreRefused(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	c := newClient(2*time.Second, fixedResolver(&calls, map[string][]string{"api.lan": {"10.9.9.9"}, "v6.lan": {"fd00::9"}, "mapped.lan": {"::ffff:10.9.9.9"}}))
	f := Fetcher{Client: c, BoxAddrs: boxOf("10.9.9.9", "fd00::9")}
	for _, u := range []string{"http://10.9.9.9:8443/", "http://api.lan:8443/", "https://[fd00::9]:8444/", "http://v6.lan:80/", "http://mapped.lan/", "https://10.9.9.9/"} {
		start := time.Now()
		if _, err := f.Fetch(context.Background(), Request{URL: u}); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("%s: %v", u, err)
		}
		if time.Since(start) > time.Second {
			t.Errorf("%s: refusal took a connect attempt", u)
		}
	}
}

func TestD208_LANAddressOnTheBoxSubnetIsStillAllowed(t *testing.T) {
	t.Parallel()
	g := &destGuard{}
	box := []netip.Addr{netip.MustParseAddr("192.168.1.10")} // the box's /32, not its 192.168.1.0/24
	for ip, want := range map[string]bool{"192.168.1.10": true, "192.168.1.11": false, "192.168.1.1": false, "127.0.0.1": true, "127.5.5.5": true, "::1": true, "8.8.8.8": false} {
		if got := g.refused(netip.MustParseAddr(ip), box); got != want {
			t.Errorf("refused(%s) = %v, want %v", ip, got, want)
		}
		if ip == "192.168.1.11" || ip == "192.168.1.1" {
			if !dialAllowed(netip.MustParseAddr(ip), "http") {
				t.Errorf("http to LAN %s no longer allowed", ip)
			}
		}
	}
}

func TestD208_RedirectHopIsDialledThroughTheGuard(t *testing.T) {
	t.Parallel()
	var next atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/next", http.StatusFound)
			return
		}
		next.Add(1)
	}))
	defer srv.Close()
	guarded := newClient(2*time.Second, systemResolver).Transport
	c := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/start" { // the first hop stands for an allowed destination
			return http.DefaultTransport.RoundTrip(r)
		}
		return guarded.RoundTrip(r)
	})}
	if _, err := (Fetcher{Client: c}).Fetch(context.Background(), Request{URL: srv.URL + "/start"}); !errors.Is(err, ErrBlockedAddress) || next.Load() != 0 {
		t.Errorf("redirect to loopback: %v (served %d)", err, next.Load())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestD208_UnknownBoxAddressesFailClosed(t *testing.T) {
	t.Parallel()
	srv, served := countingServer(t, false)
	defer srv.Close()
	unknown := func() ([]netip.Addr, bool) { return nil, false }
	f := Fetcher{Client: NewClient(2 * time.Second), BoxAddrs: unknown, allowLoopback: true}
	_, err := f.Fetch(context.Background(), Request{URL: srv.URL})
	if !errors.Is(err, ErrBoxAddrsUnknown) || served.Load() != 0 {
		t.Fatalf("%v (served %d)", err, served.Load())
	}
	if msg := userError(err, srv.URL); !strings.Contains(msg, "does not know its own addresses") {
		t.Errorf("user text = %q", msg)
	}
	// once the host answers, the same fetcher connects
	known := true
	f.BoxAddrs = func() ([]netip.Addr, bool) { return nil, known }
	if _, err := f.Fetch(context.Background(), Request{URL: srv.URL}); err != nil || served.Load() != 1 {
		t.Errorf("after the answer: %v", err)
	}
}

func TestD208_HostileFieldValueIsCappedInRowErrors(t *testing.T) {
	t.Parallel()
	hostile := strings.Repeat("A\x00\n\r\u202e", 4000) // control characters and a bidi override, 20k runes
	body := `{"status":"OK","data":[{"cve":` + jsonQuote(hostile) + `,"epss":"0.5","percentile":"0.5"},{"cve":"CVE-2026-1","epss":` + jsonQuote(hostile) + `,"percentile":"0.5"}]}`
	d, err := ParseEPSS([]byte(body))
	if err != nil || len(d.Rejects) != 2 {
		t.Fatalf("%v %+v", err, d.Stats)
	}
	for _, x := range append(d.Rejects, rejectsOf(d.Reasons)...) {
		if n := len([]rune(x.Reason)); n > 90 {
			t.Errorf("reason of %d runes", n)
		}
		for _, r := range x.Reason {
			if unicode.IsControl(r) || r == '\u202e' {
				t.Errorf("unsafe rune %q in %q", r, x.Reason)
			}
		}
	}
}

func rejectsOf(rs []Reason) []Reject {
	var out []Reject
	for _, r := range rs {
		out = append(out, Reject{Reason: r.Reason})
	}
	return out
}

func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20:
			b.WriteString(`\u0000`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
