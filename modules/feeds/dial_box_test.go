package feeds

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { served.Add(1); _, _ = w.Write([]byte("45.33.32.156\n")) })
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

func deref(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// lanAddr is a private address this machine does not hold. The guard refuses the box's own interface addresses (D-208) whether the
// host has answered or not, and a CI runner's eth0 is itself a 10.x address: a fixed LAN address can be the runner, and its pull is
// then refused as the box, not left waiting.
func lanAddr(t *testing.T) string {
	t.Helper()
	ifs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	held := map[netip.Addr]bool{}
	for _, a := range ifs {
		if p, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(p.IP); ok {
				held[ip.Unmap()] = true
			}
		}
	}
	for _, c := range []string{"192.168.213.7", "172.30.213.7", "10.213.7.9"} {
		if !held[netip.MustParseAddr(c)] {
			return c
		}
	}
	t.Fatal("this machine holds every candidate LAN address")
	return ""
}

func TestD208_ColdStartPullsPublicFeedsAndWaitsForLANOnes(t *testing.T) {
	t.Parallel()
	plain, plainHits := countingServer(t, false)
	defer plain.Close()
	tlsSrv, tlsHits := countingServer(t, true)
	defer tlsSrv.Close()
	hostPort := func(s *httptest.Server) string { return "127.0.0.1:" + portOf(t, s.URL) }
	var calls atomic.Int32
	c := newClient(5*time.Second, fixedResolver(&calls, map[string][]string{"example.com": {"8.8.8.8"}, "intranet.lan": {lanAddr(t)}}))
	c.Transport.(*http.Transport).TLSClientConfig = tlsSrv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	var known atomic.Bool
	f := Fetcher{Client: c, Version: "test",
		BoxAddrs: func() ([]netip.Addr, bool) { return []netip.Addr{netip.MustParseAddr("10.1.1.9")}, known.Load() },
		dialOverride: func(ctx context.Context, network, addr string) (net.Conn, error) { // after every check: reach the test servers
			target := hostPort(plain)
			if strings.HasSuffix(addr, ":443") {
				target = hostPort(tlsSrv)
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		}}
	e := newEnvFetcher(t, f)
	e.only("tor-exit", "et-open")
	e.mirror("tor-exit", "https://example.com/list.txt")
	e.mirror("et-open", "http://intranet.lan/list.txt")

	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if tlsHits.Load() != 1 || e.feed("tor-exit").Status != "ok" {
		t.Errorf("the public feed was not pulled: hits %d, %+v", tlsHits.Load(), e.feed("tor-exit"))
	}
	if lan := e.feed("et-open"); plainHits.Load() != 0 || lan.Failures != 0 || lan.Status == "error" || lan.Error != nil {
		t.Errorf("the LAN feed while unknown: hits %d, %+v, error %v", plainHits.Load(), lan, deref(lan.Error))
	}
	known.Store(true)
	if err := e.svc.RunPull(t.Context()); err != nil { // the unknown pull left the feed due: no back-off to wait out
		t.Fatal(err)
	}
	if plainHits.Load() != 1 || e.feed("et-open").Status != "ok" {
		t.Errorf("the LAN feed once known: hits %d, %+v, error %v", plainHits.Load(), e.feed("et-open"), deref(e.feed("et-open").Error))
	}
}

func TestD208_TransitionFormsAreCheckedByTheirIPv4(t *testing.T) {
	t.Parallel()
	g := &destGuard{}
	box := []netip.Addr{netip.MustParseAddr("10.9.9.9")}
	for ip, want := range map[string]bool{
		"64:ff9b::7f00:1": true, "64:ff9b::a09:909": true, "64:ff9b::808:808": false, "64:ff9b:1::7f:0:1": false,
		"2002:7f00:1::": true, "2002:a09:909::1": true, "2002:808:808::1": false, "::127.0.0.1": true, "::10.9.9.9": true, "::8.8.8.8": false,
	} {
		if got := g.refused(netip.MustParseAddr(ip), box); got != want {
			t.Errorf("refused(%s) = %v, want %v", ip, got, want)
		}
	}
	for _, ip := range []string{"64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "::169.254.169.254"} { // metadata via a translator
		if !refusedAlways(netip.MustParseAddr(ip)) {
			t.Errorf("%s reaches the metadata address", ip)
		}
	}
	for ip, want := range map[string]bool{"8.8.8.8": true, "2606:4700:4700::1111": true, "10.1.1.1": false, "127.0.0.1": false, "100.64.0.1": false,
		"fd00::1": false, "fe80::1": false, "169.254.1.1": false, "192.0.2.1": false, "64:ff9b::a01:101": false, "2002:a01:101::": false, "64:ff9b::808:808": true} {
		if got := globalOnly(netip.MustParseAddr(ip)); got != want {
			t.Errorf("globalOnly(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestD208_GatewayIsTheBoxAndRefusedPullsHaveAPlainMessage(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	c := newClient(2*time.Second, fixedResolver(&calls, map[string][]string{"gw.lan": {"172.17.0.1"}}))
	f := Fetcher{Client: c, Gateway: func() (netip.Addr, bool) { return netip.MustParseAddr("172.17.0.1"), true }}
	_, err := f.Fetch(context.Background(), Request{URL: "http://gw.lan/"})
	if !errors.Is(err, ErrBlockedAddress) || !errors.Is(err, ErrOwnAddress) {
		t.Fatalf("%v", err)
	}
	// D-TBD-g10 (7): the gateway is the machine Docker runs on; the message says so instead of claiming loopback
	if msg := userError(err, "http://gw.lan/"); !strings.HasPrefix(msg, "This address is the machine Vedette runs on") {
		t.Errorf("message = %q", msg)
	}
	if msg := userError(ErrBlockedAddress, "http://x/"); !strings.HasPrefix(msg, "Vedette does not pull feeds from itself") {
		t.Errorf("loopback message = %q", msg)
	}
}

func TestD208_RedirectHostIsQuoted(t *testing.T) {
	t.Parallel()
	a := &http.Request{URL: mustURL(t, "http://evil\u202e.example/")}
	b := &http.Request{URL: mustURL(t, "http://feed.lan/")}
	err := checkRedirect(a, []*http.Request{b})
	if err == nil || strings.ContainsRune(err.Error(), '\u202e') {
		t.Errorf("%v", err)
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
