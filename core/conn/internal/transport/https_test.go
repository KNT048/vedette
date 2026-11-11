package transport_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/conn/internal/transport"
	"github.com/knt048/vedette/core/secrets"
)

// policy is what core/conn gives the dialer, as far as these tests need it: loopback is refused, so a fake is reachable only
// through the one socket that conntest.AllowLoopback opened.
func dialer() *transport.Dialer {
	return &transport.Dialer{Refuse: func(_ context.Context, a netip.Addr) string {
		if a.IsLoopback() {
			return "a loopback address"
		}
		return ""
	}}
}

func get(c *transport.Client, url string) (*transport.Response, error) {
	return c.Do(context.Background(), transport.Auth{Type: "none"}, transport.Request{URL: url})
}

// D-94 (1): trust on first use, then the pin; a changed certificate is refused and nothing is sent.
func TestHTTPSPinTOFUThenMismatch(t *testing.T) {
	t.Parallel()
	f := conntest.NewHTTPS(t, nil)

	first := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), TOFU: true})
	if _, err := get(first, f.URL+"/a"); err != nil {
		t.Fatal(err)
	}
	seen := first.Seen()
	if seen.SystemTrusted || seen.SPKISHA256 != f.SPKISHA256() {
		t.Fatalf("seen %+v, want the leaf %s and no public trust", seen, f.SPKISHA256())
	}

	pinned := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), Pin: seen.SPKISHA256})
	if _, err := get(pinned, f.URL+"/b"); err != nil {
		t.Fatalf("with the pin: %v", err)
	}
	before := len(f.Requests())

	f.Rotate(t)
	_, err := get(pinned, f.URL+"/c")
	if !errors.Is(err, transport.ErrPinMismatch) {
		t.Fatalf("a new certificate = %v, want ErrPinMismatch", err)
	}
	if n := len(f.Requests()); n != before {
		t.Fatalf("%d requests reached a server whose certificate changed", n-before)
	}
	// Even a first-use client with the pin set refuses it: TOFU only applies when there is no pin.
	both := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), Pin: seen.SPKISHA256, TOFU: true})
	if _, err := get(both, f.URL); !errors.Is(err, transport.ErrPinMismatch) {
		t.Fatalf("pin + TOFU = %v, want ErrPinMismatch", err)
	}
}

func TestHTTPSWithoutPinOrTrustIsRefused(t *testing.T) {
	t.Parallel()
	f := conntest.NewHTTPS(t, nil)
	c := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer()}) // not a first Test: no TOFU
	if _, err := get(c, f.URL); !errors.Is(err, transport.ErrUnverified) {
		t.Fatalf("err = %v, want ErrUnverified", err)
	}
	if n := len(f.Requests()); n != 0 {
		t.Fatalf("%d requests were sent to an unverified server", n)
	}
}

func TestHTTPSTrustedByRootsNeedsNoPin(t *testing.T) {
	t.Parallel()
	f := conntest.NewHTTPS(t, nil)
	c := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), Roots: f.Roots()})
	if _, err := get(c, f.URL); err != nil {
		t.Fatal(err)
	}
	if !c.Seen().SystemTrusted {
		t.Fatal("a certificate the roots vouch for was not reported as trusted")
	}
}

// D-94 (1): a redirect is an answer, never an instruction.
func TestHTTPSDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var landed atomic.Int32
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/landing" {
			landed.Add(1)
		}
		http.Redirect(w, r, "/landing", http.StatusFound)
	}))
	c := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), TOFU: true})
	resp, err := get(c, f.URL+"/start")
	if err != nil || resp.Status != http.StatusFound {
		t.Fatalf("resp %+v, err %v: want the 302 itself", resp, err)
	}
	if landed.Load() != 0 {
		t.Fatal("the redirect was followed")
	}
}

// D-94 (1): no proxy from the environment: it would carry the request past the address policy.
func TestHTTPSIgnoresProxyEnvironment(t *testing.T) { //nolint:paralleltest // t.Setenv
	var proxied atomic.Int32
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			proxied.Add(1)
			_ = c.Close()
		}
	}()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "HTTP_PROXY"} {
		t.Setenv(k, "http://"+ln.Addr().String())
	}
	t.Setenv("NO_PROXY", "")
	f := conntest.NewHTTPS(t, nil)
	c := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), TOFU: true})
	if _, err := get(c, f.URL); err != nil {
		t.Fatal(err)
	}
	if proxied.Load() != 0 || len(f.Requests()) != 1 {
		t.Fatalf("proxy saw %d connections, device %d requests: the request must go straight to the device", proxied.Load(), len(f.Requests()))
	}
}

func TestHTTPSCapsRequestAndResponse(t *testing.T) {
	t.Parallel()
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = io.WriteString(w, strings.Repeat("x", 2<<20))
			return
		}
		_, _ = io.WriteString(w, strings.Repeat("y", transport.MaxResponse)) // exactly the cap: allowed
	}))
	c := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), TOFU: true})
	var de *transport.DeviceError
	if _, err := get(c, f.URL+"/big"); !errors.As(err, &de) {
		t.Fatalf("a 2 MB answer = %v, want a DeviceError", err)
	}
	if r, err := get(c, f.URL+"/exact"); err != nil || len(r.Body) != transport.MaxResponse {
		t.Fatalf("an answer of exactly the cap: %v", err)
	}
	n := len(f.Requests())
	_, err := c.Do(context.Background(), transport.Auth{}, transport.Request{Method: "POST", URL: f.URL, Body: make([]byte, transport.MaxRequest+1)})
	if !errors.As(err, &de) || len(f.Requests()) != n {
		t.Fatalf("a request over the cap = %v (sent: %v)", err, len(f.Requests()) != n)
	}
}

func TestHTTPSDeadlineEndsAHungCall(t *testing.T) {
	t.Parallel()
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	c := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), TOFU: true})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Do(ctx, transport.Auth{}, transport.Request{URL: f.URL})
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("err = %v after %v: a hung device must not hold the call", err, time.Since(start))
	}
	if transport.CallTimeout != 15*time.Second || transport.ConnectTimeout != 5*time.Second || transport.MaxResponse != 1<<20 || transport.MaxRequest != 64<<10 {
		t.Fatal("the limits of D-94 changed")
	}
}

// A device that ends the call as the caller's time ends answers with an empty 200 (what net/http's server sends when a handler
// returns). net/http prefers a response that raced the context to the error, so the answer must be refused here: the outcome is
// the same whichever side wins the race.
func TestHTTPSAnswerAfterTheDeadlineIsATimeout(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cancel() // the caller's time is up, and the device answers anyway
		w.WriteHeader(http.StatusOK)
	}))
	c := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), TOFU: true})
	if r, err := c.Do(ctx, transport.Auth{}, transport.Request{URL: f.URL}); err == nil {
		t.Fatalf("an answer after the end of the call = %+v, want an error", r)
	}
}

func TestHTTPSSignsInAndRefusesForbiddenHeaders(t *testing.T) {
	t.Parallel()
	f := conntest.NewHTTPS(t, nil)
	c := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), TOFU: true})
	do := func(a transport.Auth, h http.Header) error {
		_, err := c.Do(context.Background(), a, transport.Request{URL: f.URL, Header: h})
		return err
	}
	if err := do(transport.Auth{Type: "token", Secret: secrets.NewValue("tok-0123456789")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := do(transport.Auth{Type: "basic", Username: "lan", Secret: secrets.NewValue("pw-0123456789")}, http.Header{"Content-Type": {"application/json"}}); err != nil {
		t.Fatal(err)
	}
	rs := f.Requests()
	if got := rs[0].Header.Get("Authorization"); got != "Bearer tok-0123456789" {
		t.Errorf("token request sent %q", got)
	}
	if u, p, ok := (&http.Request{Header: rs[1].Header}).BasicAuth(); !ok || u != "lan" || p != "pw-0123456789" {
		t.Errorf("basic request sent %v", rs[1].Header)
	}
	n := len(f.Requests())
	for _, h := range []string{"Authorization", "authorization", "Cookie", "Host", "Proxy-Authorization", "Proxy-Foo", "Connection", "Keep-Alive", "TE", "Transfer-Encoding", "Upgrade", "Proxy-Connection", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host"} {
		var de *transport.DeviceError
		if err := do(transport.Auth{}, http.Header{h: {"x"}}); !errors.As(err, &de) {
			t.Errorf("header %s was not refused: %v", h, err)
		}
		if !transport.ForbiddenHeader(h) {
			t.Errorf("ForbiddenHeader(%s) = false", h)
		}
	}
	if err := do(transport.Auth{}, http.Header{"X-Ok": {"a\r\nHost: evil"}}); err == nil {
		t.Error("a header value with a line break was sent")
	}
	if len(f.Requests()) != n {
		t.Error("a refused header still produced a request")
	}
	for _, h := range []string{"Content-Type", "Accept", "X-Custom"} {
		if transport.ForbiddenHeader(h) {
			t.Errorf("ForbiddenHeader(%s) = true", h)
		}
	}
}

// M2. One client is one trust decision: after its first handshake every later handshake must show the same public key, or the
// credential would go to whoever answers the second request.
func TestHTTPSOneClientTrustsOneKey(t *testing.T) {
	t.Parallel()
	f := conntest.NewHTTPS(t, nil)
	c := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), TOFU: true})
	if _, err := get(c, f.URL); err != nil {
		t.Fatal(err)
	}
	first := c.Seen().SPKISHA256
	f.Reissue(t) // another certificate for the same key is the same server
	if _, err := get(c, f.URL); err != nil {
		t.Fatalf("a certificate re-issued for the same key was refused: %v", err)
	}
	f.Rotate(t)
	n := len(f.Requests())
	if _, err := get(c, f.URL); !errors.Is(err, transport.ErrPinMismatch) {
		t.Fatalf("a new key in the middle of one test = %v, want ErrPinMismatch", err)
	}
	if len(f.Requests()) != n || c.Seen().SPKISHA256 != first {
		t.Fatal("a request went to the new key, or the first key was forgotten")
	}
	// A new client (the next Test) starts again.
	if _, err := get(transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), TOFU: true}), f.URL); err != nil {
		t.Fatal(err)
	}
}

// The pin is the SHA-256 of the SubjectPublicKeyInfo: it survives a re-issue with the same key and does not survive a new key.
func TestHTTPSPinIsThePublicKey(t *testing.T) {
	t.Parallel()
	f := conntest.NewHTTPS(t, nil)
	pin := f.SPKISHA256()
	c := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), Pin: pin})
	f.Reissue(t)
	if f.SPKISHA256() != pin {
		t.Fatal("the fake changed the key on a re-issue")
	}
	if _, err := get(c, f.URL); err != nil {
		t.Fatalf("pinned key, re-issued certificate: %v", err)
	}
	f.Rotate(t)
	if _, err := get(transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), Pin: pin}), f.URL); !errors.Is(err, transport.ErrPinMismatch) {
		t.Fatalf("a new key = %v, want ErrPinMismatch", err)
	}
}

// D-174: the names a token may not be sent in, one list with the mock of the GUI (both read auth_header_refused.json).
func TestValidAuthHeaderRefusesTheSharedList(t *testing.T) {
	raw, err := os.ReadFile("../../../../web/src/features/core/testdata/auth_header_refused.json")
	if err != nil {
		t.Fatal(err)
	}
	var l struct{ Refused, Valid []string }
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	for _, n := range l.Refused {
		if transport.ValidAuthHeader(n) {
			t.Errorf("%q was accepted", n)
		}
	}
	for _, n := range l.Valid {
		if !transport.ValidAuthHeader(n) {
			t.Errorf("%q was refused", n)
		}
	}
	for _, n := range []string{"", "X Key", "X-Key:", strings.Repeat("a", 65)} {
		if transport.ValidAuthHeader(n) {
			t.Errorf("%q was accepted", n)
		}
	}
}
