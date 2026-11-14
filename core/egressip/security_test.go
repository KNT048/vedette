package egressip

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Tests of exposure's security review of the prober (H1, M1), moved here with the code (D-514).

// listener counts the connections made to it and closes them at once. It stands in for a proxy.
func listener(t *testing.T) (addr string, accepted *atomic.Int32) {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted = new(atomic.Int32)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), accepted
}

var invalidServices = []string{"https://a.invalid", "https://b.invalid", "https://c.invalid"}

// H1: a customer's HTTPS_PROXY (Zscaler and the like) must not decide the box's public IP: all three services
// would agree on the proxy vendor's address and the box would verify, then scan, somebody else's IP.
func TestProbe_IgnoresProxyEnvironment(t *testing.T) { // not parallel: it sets the environment
	addr, accepted := listener(t)
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"} {
		t.Setenv(k, "http://"+addr)
	}
	p, err := New(invalidServices, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if tr, ok := p.client.Transport.(*http.Transport); !ok || tr.Proxy != nil {
		t.Fatalf("the transport still has a proxy function: %+v", p.client.Transport)
	}
	if _, err := p.Round(t.Context()); err == nil {
		t.Fatal("a round over unresolvable names gave an address")
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections went to the proxy", n)
	}
}

func TestProbe_ProxyOfAPassedTransportIsCleared(t *testing.T) {
	t.Parallel()
	addr, accepted := listener(t)
	u, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(invalidServices, &http.Transport{Proxy: http.ProxyURL(u)}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if tr := p.client.Transport.(*http.Transport); tr.Proxy != nil || !tr.DisableKeepAlives {
		t.Fatalf("transport = proxy %v, keep-alives off %v", tr.Proxy != nil, tr.DisableKeepAlives)
	}
	_, _ = p.Round(t.Context())
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections went to the proxy", n)
	}
}

// M1: two of the three services on one host would be one vote cast twice.
func TestProbe_ConstructorRejectsTwoServicesOnOneHost(t *testing.T) {
	t.Parallel()
	for _, urls := range [][]string{
		{"https://a.example/x", "https://a.example/y", "https://c.example"},
		{"https://a.example", "https://A.EXAMPLE:8443/ip", "https://c.example"},
		{"https://a.example", "https://c.example", "https://c.example"},
	} {
		if _, err := New(urls, nil, 0); err == nil {
			t.Errorf("%v accepted", urls)
		}
	}
	if _, err := New([]string{"https://a.example", "https://b.example", "https://c.example"}, nil, 0); err != nil {
		t.Fatal(err)
	}
}

// L2: a request that carries nothing identifying: Go's own User-Agent, not the name of the product.
func TestProbe_SendsNoIdentifyingHeader(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var agents []string
	h := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		agents = append(agents, r.UserAgent())
		mu.Unlock()
		_, _ = w.Write([]byte(ipA))
	}
	p := prober(t, newFakeService(t, h), newFakeService(t, h), newFakeService(t, h))
	if _, err := round(t, p); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(agents) != 3 {
		t.Fatalf("%d requests", len(agents))
	}
	for _, a := range agents {
		if !strings.HasPrefix(a, "Go-http-client/") || strings.Contains(strings.ToLower(a), "vedette") {
			t.Errorf("User-Agent = %q", a)
		}
	}
}

// L6: the voting rule, for every combination of three answers (an address, another, a third, or no answer).
func TestProbe_RoundVotingProperty(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var say [3]string
	svc := func(i int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			a := say[i]
			mu.Unlock()
			if a == "" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(a))
		}
	}
	p := prober(t, newFakeService(t, svc(0)), newFakeService(t, svc(1)), newFakeService(t, svc(2)))
	choices := []string{ipA, ipB, ipC, ""}
	for _, x := range choices {
		for _, y := range choices {
			for _, z := range choices {
				mu.Lock()
				say = [3]string{x, y, z}
				mu.Unlock()
				votes := map[string]int{}
				answered := 0
				for _, a := range []string{x, y, z} {
					if a != "" {
						votes[a]++
						answered++
					}
				}
				want := ""
				for a, n := range votes {
					if n >= 2 {
						want = a
					}
				}
				got, err := round(t, p)
				switch {
				case want != "":
					if err != nil || got.String() != want {
						t.Fatalf("%q %q %q: got %v %v, want %s", x, y, z, got, err, want)
					}
				case answered == 0:
					if !errors.Is(err, ErrServicesDown) {
						t.Fatalf("%q %q %q: got %v %v, want services down", x, y, z, got, err)
					}
				default:
					if got.IsValid() || !errors.Is(err, ErrNoAgreement) {
						t.Fatalf("%q %q %q: got %v %v, want no agreement", x, y, z, got, err)
					}
				}
			}
		}
	}
}
