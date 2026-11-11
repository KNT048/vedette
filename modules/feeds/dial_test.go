package feeds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegress_DialRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ip     string
		scheme string
		want   bool
	}{
		{"169.254.169.254", "https", false}, {"169.254.169.254", "http", false}, {"169.254.1.1", "https", false},
		{"fe80::1", "https", false}, {"fd00:ec2::254", "https", false}, {"100.100.100.200", "https", false}, {"192.0.0.192", "https", false},
		{"::ffff:169.254.169.254", "https", false}, {"0.0.0.0", "https", false}, {"224.0.0.1", "https", false},
		{"127.0.0.1", "http", true}, {"10.1.2.3", "http", true}, {"172.20.0.1", "http", true}, {"192.168.1.1", "http", true},
		{"fd12:3456::1", "http", true}, {"::1", "http", true},
		{"8.8.8.8", "http", false}, {"2606:4700:4700::1111", "http", false}, {"100.64.0.1", "http", false},
		{"8.8.8.8", "https", true}, {"127.0.0.1", "https", true}, {"10.1.2.3", "https", true}, {"2606:4700:4700::1111", "https", true},
		{"8.8.8.8", "", true},
	}
	for _, c := range cases {
		if got := dialAllowed(netip.MustParseAddr(c.ip), c.scheme); got != c.want {
			t.Errorf("dialAllowed(%s, %q) = %v, want %v", c.ip, c.scheme, got, c.want)
		}
	}
	for addr, wantErr := range map[string]bool{"169.254.1.1:80": true, "[fe80::1]:443": true, "169.254.169.254:80": true, "127.0.0.1:80": false, "8.8.8.8:443": false, "nonsense": true, "evil.example.com:80": true} {
		if err := dialControl("tcp", addr, nil); (err != nil) != wantErr {
			t.Errorf("dialControl(%s) = %v", addr, err)
		}
	}
}

func fixedResolver(calls *atomic.Int32, table map[string][]string) resolver {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		calls.Add(1)
		var out []netip.Addr
		for _, s := range table[host] {
			out = append(out, netip.MustParseAddr(s))
		}
		if out == nil {
			return nil, errors.New("no such host")
		}
		return out, nil
	}
}

func portOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

func TestRegress_ClientRefusesLinkLocalAndMetadata(t *testing.T) {
	t.Parallel()
	var served atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { served.Add(1); _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	port := portOf(t, srv.URL)
	var calls atomic.Int32
	c := newClient(5*time.Second, fixedResolver(&calls, map[string][]string{
		"meta.example.com":   {"169.254.169.254"},
		"ll6.example.com":    {"fe80::1"},
		"mixed.lan":          {"169.254.169.254", "127.0.0.1"},
		"feeds.lan":          {"127.0.0.1"},
		"public-http.lan":    {"8.8.8.8"},
		"sneaky.example.com": {"169.254.169.254"},
	}))
	f := Fetcher{Client: c, allowLoopback: true}
	ctx := context.Background()

	for _, u := range []string{"https://meta.example.com/", "https://ll6.example.com/", "https://169.254.169.254/latest/meta-data/", "https://[fe80::1]/", "http://public-http.lan:" + port + "/"} {
		if _, err := f.Fetch(ctx, Request{URL: u}); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("%s: %v", u, err)
		}
	}
	if served.Load() != 0 {
		t.Fatal("a refused address was contacted")
	}
	// Allowed: http to a name that resolves to loopback, also when the answer lists a refused address first.
	for _, u := range []string{"http://feeds.lan:" + port + "/", "http://mixed.lan:" + port + "/", srv.URL + "/"} {
		if r, err := f.Fetch(ctx, Request{URL: u}); err != nil || string(r.Body) != "ok" {
			t.Errorf("%s: %v", u, err)
		}
	}
	if served.Load() != 3 {
		t.Errorf("served = %d", served.Load())
	}
}

func TestRegress_HostIsResolvedOncePerConnection(t *testing.T) {
	t.Parallel()
	// DNS rebinding: a second answer must never be used. The first (and only) lookup decides.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	var calls atomic.Int32
	res := func(_ context.Context, _ string) ([]netip.Addr, error) {
		if calls.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	c := newClient(5*time.Second, res)
	u := "http://rebind.lan:" + portOf(t, srv.URL) + "/"
	if _, err := (Fetcher{Client: c, allowLoopback: true}).Fetch(context.Background(), Request{URL: u}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Errorf("resolver called %d times for one connection", calls.Load())
	}
	// The rebound answer, had it come first, is refused.
	calls.Store(1)
	c2 := newClient(5*time.Second, res)
	if _, err := (Fetcher{Client: c2, allowLoopback: true}).Fetch(context.Background(), Request{URL: u}); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("rebound address: %v", err)
	}
}

func TestRegress_HTTPSToLoopbackNameIsAllowedButLinkLocalIsNot(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("tls ok")) }))
	defer srv.Close()
	var calls atomic.Int32
	c := newClient(5*time.Second, fixedResolver(&calls, map[string][]string{"example.com": {"127.0.0.1"}, "meta.example.net": {"169.254.169.254"}}))
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport type")
	}
	tr.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone() // trust the test certificate
	port := portOf(t, srv.URL)
	f := Fetcher{Client: c, allowLoopback: true}
	if r, err := f.Fetch(context.Background(), Request{URL: "https://example.com:" + port + "/"}); err != nil || string(r.Body) != "tls ok" {
		t.Fatalf("%v", err)
	}
	if _, err := f.Fetch(context.Background(), Request{URL: "https://meta.example.net:" + port + "/"}); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("metadata name over https: %v", err)
	}
}

func TestRegress_NewClientGuardsLiteralAddresses(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	f := Fetcher{Client: NewClient(5 * time.Second), allowLoopback: true}
	if r, err := f.Fetch(context.Background(), Request{URL: srv.URL}); err != nil || string(r.Body) != "ok" {
		t.Errorf("loopback http: %v", err)
	}
	if _, err := f.Fetch(context.Background(), Request{URL: "https://169.254.169.254/latest/meta-data/"}); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("metadata literal: %v", err)
	}
	// The zero Fetcher builds the guarded client itself.
	if _, err := (Fetcher{}).Fetch(context.Background(), Request{URL: "https://[fe80::1]/"}); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("zero Fetcher: %v", err)
	}
}

func TestRegress_BuiltinSourceLimits(t *testing.T) {
	t.Parallel()
	gen := func(n int) []byte {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "d%d.example.com\n", i)
		}
		return []byte(b.String())
	}
	hagezi, _ := BuiltinByID("hagezi-tif")
	if hagezi.URL != "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt" {
		t.Fatalf("hagezi address = %s (domains/tif.mini.txt no longer exists upstream)", hagezi.URL)
	}
	if hagezi.MaxRows != 250_000 || hagezi.rowLimit() != 250_000 { // the mini list has 186,000 entries and grows
		t.Fatalf("hagezi limit = %d", hagezi.MaxRows)
	}
	data := gen(60_000)
	r, err := ParseSource(context.Background(), hagezi, data)
	if err != nil || r.Accepted != 60_000 || r.Truncated {
		t.Errorf("hagezi 60k: %v %+v", err, r.Stats)
	}
	// The same list through a custom parser (50,000 rows) is cut.
	c, err := ParseFeed(context.Background(), data, KindIOC, DefaultParser(KindIOC, FormatLines))
	if err != nil || c.Accepted != MaxRows || !c.Truncated {
		t.Errorf("custom 60k: %v %+v", err, c.Stats)
	}
	if whole, err := ParseSource(context.Background(), hagezi, gen(186_200)); err != nil || whole.Accepted != 186_200 || whole.Truncated {
		t.Errorf("hagezi mini today (186,200 lines): %v %+v", err, whole.Stats)
	}
	big, err := ParseSource(context.Background(), hagezi, gen(250_005))
	if err != nil || big.Accepted != 250_000 || !big.Truncated {
		t.Errorf("hagezi over: %v %+v", err, big.Stats)
	}
	ipsum, _ := BuiltinByID("ipsum")
	if ipsum.rowLimit() != MaxRows {
		t.Errorf("ipsum limit = %d", ipsum.rowLimit())
	}
	kev, _ := BuiltinByID("cisa-kev")
	if _, err := ParseSource(context.Background(), kev, nil); !errors.Is(err, ErrBadConfig) {
		t.Errorf("dedicated decoder through ParseSource: %v", err)
	}
	if len(data) > MaxBodyBytes {
		t.Fatal("test data over the body cap")
	}
}
