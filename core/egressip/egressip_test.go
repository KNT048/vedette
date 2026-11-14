package egressip

import (
	"context"
	"crypto/x509"
	"errors"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// The three public services are httptest servers; no test contacts the real ones.

const (
	ipA = "8.8.8.8"
	ipB = "8.8.4.4"
	ipC = "9.9.9.9"
)

type fakeService struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hit   []string // remote addresses of the requests
	conns int      // connections the server accepted
}

func newFakeService(t *testing.T, h http.HandlerFunc) *fakeService {
	t.Helper()
	f := &fakeService{}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hit = append(f.hit, r.RemoteAddr)
		f.mu.Unlock()
		h(w, r)
	}))
	// Count accepted connections on the server side: a client port can come back for a later connection
	// (to this or another fake service), so remote addresses alone cannot tell connections apart.
	f.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			f.mu.Lock()
			f.conns++
			f.mu.Unlock()
		}
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func answer(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }
}

func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

// prober builds a Prober over the three fake services, trusting their certificates.
func prober(t *testing.T, fs ...*fakeService) *Prober {
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
	p, err := New(urls, tr, 30*time.Second) // wall clock: a generous ceiling, not a speed check
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func round(t *testing.T, p *Prober) (netip.Addr, error) {
	t.Helper()
	return p.Round(t.Context())
}

// pipeRound is one round over three in-memory services answering with hs (see pipeProber). Call it inside a bubble.
func pipeRound(t *testing.T, hs ...http.HandlerFunc) (netip.Addr, error) {
	t.Helper()
	return round(t, pipeProber(t, 0, hs...))
}

// A round over the real loopback TLS: the certificate of every service is verified and each request has a connection of
// its own. Everything else runs over pipes inside a bubble, so no wall-clock deadline of the machine can fail a test.
func TestProbe_TLSAndOwnConnections(t *testing.T) {
	t.Parallel()
	x, y, z := newFakeService(t, answer(ipA)), newFakeService(t, answer(ipA)), newFakeService(t, answer(ipA))
	p := prober(t, x, y, z)
	// two rounds, six requests, six connections: nothing is reused (a load balancer may answer differently each time)
	for range 2 {
		if a, err := round(t, p); err != nil || a.String() != ipA {
			t.Fatalf("round = %v %v", a, err)
		}
	}
	for i, f := range []*fakeService{x, y, z} {
		f.mu.Lock()
		reqs, conns := len(f.hit), f.conns
		f.mu.Unlock()
		if reqs != 2 || conns != 2 {
			t.Fatalf("service %d: %d connections for %d requests, want 2 for 2", i, conns, reqs)
		}
	}
}

func TestProbe_AllAgree(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		if a, err := pipeRound(t, answer(ipA+"\n"), answer(ipA), answer("  "+ipA+" \r\n")); err != nil || a.String() != ipA {
			t.Fatalf("round = %v %v", a, err)
		}
	})
}

func TestProbe_TwoAgreeOneDiffers(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		for i := range 3 { // whichever one is wrong
			var hs []http.HandlerFunc
			for j := range 3 {
				body := ipA
				if j == i {
					body = ipB
				}
				hs = append(hs, answer(body))
			}
			if a, err := pipeRound(t, hs...); err != nil || a.String() != ipA {
				t.Fatalf("wrong service %d: %v %v", i, a, err)
			}
		}
	})
}

func TestProbe_AllDiffer(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		if a, err := pipeRound(t, answer(ipA), answer(ipB), answer(ipC)); !errors.Is(err, ErrNoAgreement) || a.IsValid() {
			t.Fatalf("round = %v %v", a, err)
		}
	})
}

func TestProbe_OneDown(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		redirect := func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) }
		for name, down := range map[string]http.HandlerFunc{"500": status(500), "404": status(404), "garbage": answer("<html>"), "empty": answer(""), "redirect": redirect} {
			if a, err := pipeRound(t, down, answer(ipA), answer(ipA)); err != nil || a.String() != ipA {
				t.Fatalf("%s + two agree: %v %v", name, a, err)
			}
			if a, err := pipeRound(t, down, answer(ipA), answer(ipB)); !errors.Is(err, ErrNoAgreement) || a.IsValid() {
				t.Fatalf("%s + two disagree: %v %v", name, a, err)
			}
		}
		// one answer alone is never enough
		if a, err := pipeRound(t, status(500), status(500), answer(ipA)); !errors.Is(err, ErrNoAgreement) || a.IsValid() {
			t.Fatalf("a single answer: %v %v", a, err)
		}
		// none answers: the services are down, which is not the same as disagreeing
		if _, err := pipeRound(t, status(500), status(503), answer("nope")); !errors.Is(err, ErrServicesDown) {
			t.Fatalf("all down: %v", err)
		}
	})
}

// pipeListener hands the server the far end of in-memory connections (net.Pipe), so a synctest bubble holds the client, the
// server and every timer of a round: the deadline is then the bubble's, whatever the load of the machine.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error { l.once.Do(func() { close(l.closed) }); return nil }

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

func (l *pipeListener) dial(ctx context.Context) (net.Conn, error) {
	c, srv := net.Pipe()
	select {
	case l.conns <- srv:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// pipeProber builds a Prober over three in-memory services, svc0.test .. svc2.test. The transport's TLS dial returns
// the plain pipe (TLS itself is covered by the httptest tests above). Call it inside a bubble; the servers stop with the test.
func pipeProber(t *testing.T, timeout time.Duration, hs ...http.HandlerFunc) *Prober {
	t.Helper()
	lns := map[string]*pipeListener{}
	var urls []string
	for i, h := range hs {
		host := "svc" + strconv.Itoa(i) + ".test:443"
		l := &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
		srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Minute}
		served := make(chan struct{})
		go func() { _ = srv.Serve(l); close(served) }()
		t.Cleanup(func() { _ = srv.Close(); <-served })
		lns[host] = l
		urls = append(urls, "https://"+host)
	}
	tr := &http.Transport{DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		l, ok := lns[addr]
		if !ok {
			return nil, errors.New("no such service: " + addr)
		}
		return l.dial(ctx)
	}}
	p, err := New(urls, tr, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProbe_DeadlineAndSize(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		// The slow service never answers before the end of the test: only the deadline ends its call. In the bubble the two fast ones
		// answer at once, so the round takes exactly the deadline and still has their two votes.
		release := make(chan struct{})
		slow := func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			_, _ = w.Write([]byte(ipA))
		}
		const deadline = 3 * time.Second
		p := pipeProber(t, deadline, slow, answer(ipA), answer(ipA))
		t.Cleanup(func() { close(release) }) // runs before the servers' cleanup: the slow handler returns, then they stop
		start := time.Now()
		if a, err := p.Round(t.Context()); err != nil || a.String() != ipA {
			t.Fatalf("slow service: %v %v", a, err)
		}
		if d := time.Since(start); d != deadline {
			t.Fatalf("the round took %s with a %s deadline", d, deadline)
		}
		// the answer cap is 64 bytes: a longer body is refused even when it starts with an address
		long := ipA + strings.Repeat(" ", maxAnswerBody)
		if _, err := pipeProber(t, 0, answer(long), answer(long), answer(long)).Round(t.Context()); !errors.Is(err, ErrServicesDown) {
			t.Fatalf("long answers: %v", err)
		}
		exact := ipA + strings.Repeat(" ", maxAnswerBody-len(ipA))
		if a, err := pipeProber(t, 0, answer(exact), answer(exact), answer(ipA)).Round(t.Context()); err != nil || a.String() != ipA {
			t.Fatalf("64 bytes: %v %v", a, err)
		}
	})
}

func TestProbe_NoRedirects(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var asked []string // every path any service was asked for: a followed redirect shows as /elsewhere
		redirecting := func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			asked = append(asked, r.URL.Path)
			mu.Unlock()
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}
		if _, err := pipeRound(t, redirecting, redirecting, redirecting); !errors.Is(err, ErrServicesDown) {
			t.Fatalf("redirects: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if slices.Contains(asked, "/elsewhere") || len(asked) != 3 {
			t.Fatalf("a redirect was followed: %v", asked)
		}
	})
}

func TestProbe_NonGlobalAnswersAreRefused(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		// three services agreeing on something that is not an address of the Internet is no answer at all
		for _, body := range []string{"127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "fe80::1", "::1", "::", "fe80::1%eth0", "1.2.3", "8.8.8.8 8.8.4.4", "ip=8.8.8.8"} {
			if a, err := pipeRound(t, answer(body), answer(body), answer(body)); !errors.Is(err, ErrServicesDown) || a.IsValid() {
				t.Errorf("%q: %v %v", body, a, err)
			}
		}
		// private addresses pass the parser (they are global unicast to net/netip) and are refused later, by INV-3
		if a, err := pipeRound(t, answer("10.1.2.3"), answer("10.1.2.3"), answer("10.1.2.3")); err != nil || a.String() != "10.1.2.3" {
			t.Fatalf("private: %v %v", a, err)
		}
		// an IPv4-mapped IPv6 address and the same IPv4 address vote together
		if a, err := pipeRound(t, answer("::ffff:8.8.8.8"), answer("8.8.8.8"), answer(ipB)); err != nil || a.String() != ipA {
			t.Fatalf("mapped: %v %v", a, err)
		}
	})
}

func TestProbe_Constructor(t *testing.T) {
	t.Parallel()
	good := []string{"https://a.example", "https://b.example/ip", "https://c.example"}
	if _, err := New(good, nil, 0); err != nil {
		t.Fatal(err)
	}
	if p, err := New(nil, nil, 0); err != nil || len(p.urls) != 3 || p.urls[0] != "https://checkip.amazonaws.com" || p.urls[1] != "https://icanhazip.com" || p.urls[2] != "https://ifconfig.me/ip" {
		t.Fatalf("defaults = %+v %v", p, err)
	}
	for _, bad := range [][]string{
		good[:2], append(append([]string{}, good...), "https://d.example"), {"http://a.example", good[1], good[2]},
		{"https://u:p@a.example", good[1], good[2]}, {"ftp://a.example", good[1], good[2]}, {"https://", good[1], good[2]}, {"", good[1], good[2]},
	} {
		if _, err := New(bad, nil, 0); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func FuzzParseAnswer(f *testing.F) {
	for _, s := range []string{"8.8.8.8", "8.8.8.8\n", " 8.8.8.8 ", "::1", "fe80::1%x", "", "\x00", "8.8.8.8\n8.8.4.4", "2606:4700:4700::1111", "::ffff:1.2.3.4"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := ParseAnswer(b)
		if err != nil {
			return
		}
		want := netip.MustParseAddr(strings.TrimSpace(string(b))).Unmap()
		if a != want {
			t.Fatalf("ParseAnswer(%q) = %v, want %v", b, a, want)
		}
		if len(b) > maxAnswerBody || !a.IsValid() || !a.IsGlobalUnicast() || a.Zone() != "" || a.Is4In6() {
			t.Fatalf("ParseAnswer(%q) accepted %v", b, a)
		}
	})
}

// IsPublicIPv4 refuses every address that is not on the Internet (exposure INV-3, nmapargv's external shape, D-514).
func TestIsPublicIPv4(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "100.128.0.1", "::ffff:8.8.8.8"} {
		if !IsPublicIPv4(netip.MustParseAddr(s)) {
			t.Errorf("%s refused", s)
		}
	}
	for _, s := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "0.0.0.1", "192.0.2.1",
		"198.51.100.1", "203.0.113.5", "198.18.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "2001:4860:4860::8888", "::1"} {
		if IsPublicIPv4(netip.MustParseAddr(s)) {
			t.Errorf("%s accepted", s)
		}
	}
}

// The sensor binary links this package (the worker's own-IP fence, D-514): standard library only, plus core/localnet (itself
// net/netip and slices only, its own TestIsALeaf), which holds the public-address rule (D-520).
func TestIsALeaf(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources found: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); strings.Contains(strings.SplitN(p, "/", 2)[0], ".") && p != "github.com/knt048/vedette/core/localnet" {
				t.Errorf("%s imports %q: only the standard library is allowed in egressip", f, p)
			}
		}
	}
}
