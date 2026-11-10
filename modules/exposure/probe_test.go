package exposure

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The three public services are httptest servers; no test contacts the real ones.

type fakeService struct {
	srv *httptest.Server
	mu  sync.Mutex
	hit []string // remote addresses of the requests
}

func newFakeService(t *testing.T, h http.HandlerFunc) *fakeService {
	t.Helper()
	f := &fakeService{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hit = append(f.hit, r.RemoteAddr)
		f.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func answer(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }
}

func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

// prober builds a PublicServiceProber over the three fake services, trusting their certificates.
func prober(t *testing.T, timeout time.Duration, fs ...*fakeService) *PublicServiceProber {
	t.Helper()
	pool := x509.NewCertPool()
	var urls []string
	// Each service gets a host name of its own (the constructor refuses two services on one host); every name dials the
	// local test server of that port, and the certificate of httptest is valid for example.com.
	for i, f := range fs {
		pool.AddCert(f.srv.Certificate())
		_, port, _ := net.SplitHostPort(f.srv.Listener.Addr().String())
		urls = append(urls, "https://svc"+strconv.Itoa(i)+".test:"+port)
	}
	tr := fs[0].srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.RootCAs = pool
	tr.TLSClientConfig.ServerName = "example.com"
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+port)
	}
	p, err := NewPublicServiceProber(urls, tr, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func round(t *testing.T, p *PublicServiceProber) (netip.Addr, error) {
	t.Helper()
	return p.Round(t.Context())
}

func TestProbe_AllAgree(t *testing.T) {
	t.Parallel()
	p := prober(t, 0, newFakeService(t, answer(ipA+"\n")), newFakeService(t, answer(ipA)), newFakeService(t, answer("  "+ipA+" \r\n")))
	if a, err := round(t, p); err != nil || a.String() != ipA {
		t.Fatalf("round = %v %v", a, err)
	}
}

func TestProbe_TwoAgreeOneDiffers(t *testing.T) {
	t.Parallel()
	for i := range 3 { // whichever one is wrong
		var fs []*fakeService
		for j := range 3 {
			body := ipA
			if j == i {
				body = ipB
			}
			fs = append(fs, newFakeService(t, answer(body)))
		}
		if a, err := round(t, prober(t, 0, fs...)); err != nil || a.String() != ipA {
			t.Fatalf("wrong service %d: %v %v", i, a, err)
		}
	}
}

func TestProbe_AllDiffer(t *testing.T) {
	t.Parallel()
	p := prober(t, 0, newFakeService(t, answer(ipA)), newFakeService(t, answer(ipB)), newFakeService(t, answer(ipC)))
	if a, err := round(t, p); !errors.Is(err, ErrNoAgreement) || a.IsValid() {
		t.Fatalf("round = %v %v", a, err)
	}
}

func TestProbe_OneDown(t *testing.T) {
	t.Parallel()
	redirect := func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) }
	for name, down := range map[string]http.HandlerFunc{"500": status(500), "404": status(404), "garbage": answer("<html>"), "empty": answer(""), "redirect": redirect} {
		agree := prober(t, 0, newFakeService(t, down), newFakeService(t, answer(ipA)), newFakeService(t, answer(ipA)))
		if a, err := round(t, agree); err != nil || a.String() != ipA {
			t.Fatalf("%s + two agree: %v %v", name, a, err)
		}
		disagree := prober(t, 0, newFakeService(t, down), newFakeService(t, answer(ipA)), newFakeService(t, answer(ipB)))
		if a, err := round(t, disagree); !errors.Is(err, ErrNoAgreement) || a.IsValid() {
			t.Fatalf("%s + two disagree: %v %v", name, a, err)
		}
	}
	// one answer alone is never enough
	lone := prober(t, 0, newFakeService(t, status(500)), newFakeService(t, status(500)), newFakeService(t, answer(ipA)))
	if a, err := round(t, lone); !errors.Is(err, ErrNoAgreement) || a.IsValid() {
		t.Fatalf("a single answer: %v %v", a, err)
	}
	// none answers: the services are down, which is not the same as disagreeing
	none := prober(t, 0, newFakeService(t, status(500)), newFakeService(t, status(503)), newFakeService(t, answer("nope")))
	if _, err := round(t, none); !errors.Is(err, ErrServicesDown) {
		t.Fatalf("all down: %v", err)
	}
}

func TestProbe_DeadlineAndSize(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	slow := func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		_, _ = w.Write([]byte(ipA))
	}
	// The per-call deadline must leave the two fast fakes time to answer on a loaded -race runner (150 ms flaked on CI);
	// the slow fake never answers before release, so the round still proves the deadline cuts it off.
	p := prober(t, time.Second, newFakeService(t, slow), newFakeService(t, answer(ipA)), newFakeService(t, answer(ipA)))
	start := time.Now()
	if a, err := round(t, p); err != nil || a.String() != ipA {
		t.Fatalf("slow service: %v %v", a, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the round waited %s for a slow service", time.Since(start))
	}
	// the answer cap is 64 bytes: a longer body is refused even when it starts with an address
	long := ipA + strings.Repeat(" ", maxAnswerBody)
	big := prober(t, 0, newFakeService(t, answer(long)), newFakeService(t, answer(long)), newFakeService(t, answer(long)))
	if _, err := round(t, big); !errors.Is(err, ErrServicesDown) {
		t.Fatalf("long answers: %v", err)
	}
	exact := ipA + strings.Repeat(" ", maxAnswerBody-len(ipA))
	ok := prober(t, 0, newFakeService(t, answer(exact)), newFakeService(t, answer(exact)), newFakeService(t, answer(ipA)))
	if a, err := round(t, ok); err != nil || a.String() != ipA {
		t.Fatalf("64 bytes: %v %v", a, err)
	}
}

func TestProbe_NoRedirectsAndOwnConnections(t *testing.T) {
	t.Parallel()
	target := newFakeService(t, answer(ipB))
	redirecting := func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.srv.URL, http.StatusFound) }
	a, b, c := newFakeService(t, redirecting), newFakeService(t, redirecting), newFakeService(t, redirecting)
	if _, err := round(t, prober(t, 0, a, b, c)); !errors.Is(err, ErrServicesDown) {
		t.Fatalf("redirects: %v", err)
	}
	target.mu.Lock()
	followed := len(target.hit)
	target.mu.Unlock()
	if followed != 0 {
		t.Fatal("a redirect was followed")
	}
	// two rounds, six requests, six connections: nothing is reused (a load balancer may answer differently each time)
	x, y, z := newFakeService(t, answer(ipA)), newFakeService(t, answer(ipA)), newFakeService(t, answer(ipA))
	p := prober(t, 0, x, y, z)
	for range 2 {
		if _, err := round(t, p); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for _, f := range []*fakeService{x, y, z} {
		f.mu.Lock()
		for _, h := range f.hit {
			seen[h] = true
		}
		f.mu.Unlock()
	}
	if len(seen) != 6 {
		t.Fatalf("%d distinct connections for 6 requests", len(seen))
	}
}

func TestProbe_NonGlobalAnswersAreRefused(t *testing.T) {
	t.Parallel()
	// three services agreeing on something that is not an address of the Internet is no answer at all
	for _, body := range []string{"127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "fe80::1", "::1", "::", "fe80::1%eth0", "1.2.3", "8.8.8.8 8.8.4.4", "ip=8.8.8.8"} {
		p := prober(t, 0, newFakeService(t, answer(body)), newFakeService(t, answer(body)), newFakeService(t, answer(body)))
		if a, err := round(t, p); !errors.Is(err, ErrServicesDown) || a.IsValid() {
			t.Errorf("%q: %v %v", body, a, err)
		}
	}
	// private addresses pass the parser (they are global unicast to net/netip) and are refused later, by INV-3
	p := prober(t, 0, newFakeService(t, answer("10.1.2.3")), newFakeService(t, answer("10.1.2.3")), newFakeService(t, answer("10.1.2.3")))
	if a, err := round(t, p); err != nil || a.String() != "10.1.2.3" {
		t.Fatalf("private: %v %v", a, err)
	}
	// an IPv4-mapped IPv6 address and the same IPv4 address vote together
	p = prober(t, 0, newFakeService(t, answer("::ffff:8.8.8.8")), newFakeService(t, answer("8.8.8.8")), newFakeService(t, answer(ipB)))
	if a, err := round(t, p); err != nil || a.String() != ipA {
		t.Fatalf("mapped: %v %v", a, err)
	}
}

func TestProbe_Constructor(t *testing.T) {
	t.Parallel()
	good := []string{"https://a.example", "https://b.example/ip", "https://c.example"}
	if _, err := NewPublicServiceProber(good, nil, 0); err != nil {
		t.Fatal(err)
	}
	if p, err := NewPublicServiceProber(nil, nil, 0); err != nil || len(p.urls) != 3 || p.urls[0] != "https://checkip.amazonaws.com" || p.urls[1] != "https://icanhazip.com" || p.urls[2] != "https://ifconfig.me/ip" {
		t.Fatalf("defaults = %+v %v", p, err)
	}
	for _, bad := range [][]string{
		good[:2], append(append([]string{}, good...), "https://d.example"), {"http://a.example", good[1], good[2]},
		{"https://u:p@a.example", good[1], good[2]}, {"ftp://a.example", good[1], good[2]}, {"https://", good[1], good[2]}, {"", good[1], good[2]},
	} {
		if _, err := NewPublicServiceProber(bad, nil, 0); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func FuzzParseAnswer(f *testing.F) {
	for _, s := range []string{"8.8.8.8", "8.8.8.8\n", " 8.8.8.8 ", "::1", "fe80::1%x", "", "\x00", "8.8.8.8\n8.8.4.4", "2606:4700:4700::1111", "::ffff:1.2.3.4"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := parseAnswer(b)
		if err != nil {
			return
		}
		want := netip.MustParseAddr(strings.TrimSpace(string(b))).Unmap()
		if a != want {
			t.Fatalf("parseAnswer(%q) = %v, want %v", b, a, want)
		}
		if len(b) > maxAnswerBody || !a.IsValid() || !a.IsGlobalUnicast() || a.Zone() != "" || a.Is4In6() {
			t.Fatalf("parseAnswer(%q) accepted %v", b, a)
		}
	})
}
