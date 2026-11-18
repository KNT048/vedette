package domainfence

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// ptrDNS adds reverse DNS to a fakeDNS.
type ptrDNS struct {
	*fakeDNS
	ptr map[string][]string
}

func (p ptrDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if v, ok := p.ptr[addr]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

// files serves proof files by URL.
type files struct {
	mu sync.Mutex
	m  map[string]string
}

func (f *files) Fetch(_ context.Context, rawURL string, _ netip.Addr) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.m[rawURL]; ok {
		return []byte(v), nil
	}
	return nil, errors.New("answered 404")
}

var typedIP = netip.MustParseAddr("9.9.9.9")

func typedFence(t *testing.T, r Resolver, f *files, listed ...string) *Fence {
	t.Helper()
	fence, err := New(key1, r, func(d string) bool {
		for _, l := range listed {
			if l == d {
				return true
			}
		}
		return false
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fence.SetFetcher(f)
	return fence
}

func fileJob() Job {
	return Job{Domain: typedIP.String(), Name: typedIP.String(), IP: typedIP, Token: Token(key1, typedIP.String()), Typed: &TypedProof{Method: MethodFile}}
}

func TestTypedFile_APassingProofIsAYes(t *testing.T) {
	t.Parallel()
	f := &files{m: map[string]string{"https://9.9.9.9" + ProofPath: Token(key1, "9.9.9.9") + "\n"}}
	if o := typedFence(t, world(), f, "9.9.9.9").Check(t.Context(), fileJob(), false); o.Reason != "" {
		t.Fatalf("%+v", o)
	}
}

func TestTypedFile_RefusalsFailClosed(t *testing.T) {
	t.Parallel()
	good := Token(key1, "9.9.9.9")
	cases := []struct {
		name   string
		edit   func(*Job, *files)
		listed []string
		want   string
	}{
		{"a forged token in the job", func(j *Job, f *files) { j.Token = Token(key2, "9.9.9.9"); f.m["http://9.9.9.9"+ProofPath] = j.Token }, []string{"9.9.9.9"}, TokenForeign},
		{"the IP is not on the host's list", func(*Job, *files) {}, nil, TokenForeign},
		{"the file is gone", func(_ *Job, f *files) { clear(f.m) }, []string{"9.9.9.9"}, NotOwned},
		{"the token is on another address", func(_ *Job, f *files) { clear(f.m); f.m["http://9.9.9.8"+ProofPath] = good }, []string{"9.9.9.9"}, NotOwned},
		{"the file holds another token", func(_ *Job, f *files) { clear(f.m); f.m["http://9.9.9.9"+ProofPath] = "0123456789abcdef" }, []string{"9.9.9.9"}, NotOwned},
		{"a private address", func(j *Job, _ *files) {
			j.IP = netip.MustParseAddr("10.0.0.1")
			j.Domain, j.Name = "10.0.0.1", "10.0.0.1"
		}, []string{"10.0.0.1"}, InvalidJob},
		{"a name for the IP", func(j *Job, _ *files) { j.Name = "acme.example" }, []string{"9.9.9.9"}, InvalidJob},
		{"a proof name", func(j *Job, _ *files) { j.ProofAt = "example.com" }, []string{"9.9.9.9"}, InvalidJob},
		{"an unknown method", func(j *Job, _ *files) { j.Typed.Method = "magic" }, []string{"9.9.9.9"}, InvalidJob},
	}
	for _, c := range cases {
		f := &files{m: map[string]string{"http://9.9.9.9" + ProofPath: good}}
		j := fileJob()
		c.edit(&j, f)
		if o := typedFence(t, world(), f, c.listed...).Check(t.Context(), j, false); o.Reason != c.want {
			t.Errorf("%s: reason %q (%s), want %q", c.name, o.Reason, o.Detail, c.want)
		}
	}
}

func ptrJob() Job {
	return Job{Domain: typedIP.String(), Name: typedIP.String(), IP: typedIP, Token: Token(key1, "9.9.9.9"),
		Typed: &TypedProof{Method: MethodPTR, PTRName: "edge.acme.example", CoverDomain: "acme.example", CoverToken: Token(key1, "acme.example")}}
}

func ptrWorld() ptrDNS {
	w := world()
	w.a["edge.acme.example"] = []netip.Addr{typedIP}
	return ptrDNS{fakeDNS: w, ptr: map[string][]string{"9.9.9.9": {"edge.acme.example."}}}
}

func TestTypedPTR_ForwardConfirmedUnderAProvedDomainIsAYes(t *testing.T) {
	t.Parallel()
	if o := typedFence(t, ptrWorld(), &files{m: map[string]string{}}, "9.9.9.9", "acme.example").Check(t.Context(), ptrJob(), false); o.Reason != "" {
		t.Fatalf("%+v", o)
	}
}

func TestTypedPTR_RefusalsFailClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		edit   func(*Job, ptrDNS)
		listed []string
		want   string
	}{
		{"the name does not resolve back to the IP", func(_ *Job, w ptrDNS) { w.a["edge.acme.example"] = []netip.Addr{ip} }, []string{"9.9.9.9", "acme.example"}, NameMoved},
		{"the PTR is another name", func(_ *Job, w ptrDNS) { w.ptr["9.9.9.9"] = []string{"other.acme.example."} }, []string{"9.9.9.9", "acme.example"}, NotOwned},
		{"no PTR at all", func(_ *Job, w ptrDNS) { delete(w.ptr, "9.9.9.9") }, []string{"9.9.9.9", "acme.example"}, NotOwned},
		{"an A record only, no PTR", func(_ *Job, w ptrDNS) { delete(w.ptr, "9.9.9.9"); w.a["www.acme.example"] = []netip.Addr{typedIP} }, []string{"9.9.9.9", "acme.example"}, NotOwned},
		{"the covering domain's record is gone", func(_ *Job, w ptrDNS) { delete(w.txt, "acme.example") }, []string{"9.9.9.9", "acme.example"}, NotOwned},
		{"a forged covering token", func(j *Job, _ ptrDNS) { j.Typed.CoverToken = Token(key2, "acme.example") }, []string{"9.9.9.9", "acme.example"}, TokenForeign},
		{"the covering domain is not on the host's list", func(*Job, ptrDNS) {}, []string{"9.9.9.9"}, TokenForeign},
		{"a name outside the covering domain", func(j *Job, _ ptrDNS) { j.Typed.PTRName = "edge.other.example" }, []string{"9.9.9.9", "acme.example"}, InvalidJob},
	}
	for _, c := range cases {
		w := ptrWorld()
		j := ptrJob()
		c.edit(&j, w)
		if o := typedFence(t, w, &files{m: map[string]string{}}, c.listed...).Check(t.Context(), j, false); o.Reason != c.want {
			t.Errorf("%s: reason %q (%s), want %q", c.name, o.Reason, o.Detail, c.want)
		}
	}
}

func TestTypedPTR_AResolverWithoutReverseLookupProvesNothing(t *testing.T) {
	t.Parallel()
	if o := typedFence(t, ptrWorld().fakeDNS, &files{m: map[string]string{}}, "9.9.9.9", "acme.example").Check(t.Context(), ptrJob(), false); o.Reason != Unchecked {
		t.Fatalf("%+v", o)
	}
}

func TestTheDomainListTakesDomainsAndTheIPListTakesIPs(t *testing.T) {
	t.Parallel()
	if l, err := ParseIPList([]byte("9.9.9.9\n1.1.1.1\n")); err != nil || !l["9.9.9.9"] {
		t.Fatalf("%v %v", l, err)
	}
	if _, err := ParseList([]byte("9.9.9.9\nacme.example\n")); err == nil {
		t.Error("an IP in the domain list: an older scan container would not parse the file")
	}
	for _, bad := range []string{"10.0.0.1\n", "9.9.9.09\n", "::1\n", "9.9.9.9/32\n", "acme.example\n"} {
		if _, err := ParseIPList([]byte(bad)); err == nil {
			t.Errorf("%q was accepted in the IP list", bad)
		}
	}
}

func TestTypedFile_OneFlakyAnswerIsRetriedAndANetworkFailureIsUnchecked(t *testing.T) {
	t.Parallel()
	old := fileRetryWait
	fileRetryWait = time.Millisecond
	t.Cleanup(func() { fileRetryWait = old })
	f := &flaky{ok: Token(key1, "9.9.9.9"), failFirst: 2}
	if o := typedFence(t, world(), &files{m: map[string]string{}}, "9.9.9.9").withFetcher(f).Check(t.Context(), fileJob(), false); o.Reason != "" {
		t.Fatalf("a flaky first look: %+v", o)
	}
	g := &flaky{ok: Token(key1, "9.9.9.9"), failFirst: 99}
	if o := typedFence(t, world(), &files{m: map[string]string{}}, "9.9.9.9").withFetcher(g).Check(t.Context(), fileJob(), false); o.Reason != Unchecked {
		t.Fatalf("a network failure: %+v", o)
	}
}

// flaky fails the first failFirst requests like a time-out, then serves the token.
type flaky struct {
	mu        sync.Mutex
	n         int
	failFirst int
	ok        string
}

func (f *flaky) Fetch(context.Context, string, netip.Addr) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.n <= f.failFirst {
		return nil, errors.New("request: i/o timeout")
	}
	return []byte(f.ok), nil
}

func (f *Fence) withFetcher(x FileFetcher) *Fence { f.fetcher = x; return f }

func TestHTTPFetcher_RedirectsStayOnTheAddressAndAWebPort(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/other-host":
			http.Redirect(w, r, "http://other.example.test/x", http.StatusFound)
		case "/other-port":
			http.Redirect(w, r, "http://127.0.0.1:22/x", http.StatusFound)
		case "/same":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			_, _ = w.Write([]byte("abcdef0123456789"))
		default:
			_, _ = w.Write([]byte(strings.Repeat("a", 5000)))
		}
	}))
	t.Cleanup(srv.Close)
	ip := netip.MustParseAddr("127.0.0.1")
	for path, want := range map[string]string{"/other-host": "another host", "/other-port": "another port"} {
		if _, err := (HTTPFetcher{}).Fetch(t.Context(), srv.URL+path, ip); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", path, err)
		}
	}
	if b, err := (HTTPFetcher{}).Fetch(t.Context(), srv.URL+"/same", ip); err != nil || !TokenInFile(b, "abcdef0123456789") {
		t.Errorf("same address: %q %v", b, err)
	}
	if b, err := (HTTPFetcher{}).Fetch(t.Context(), srv.URL+"/big", ip); err != nil || len(b) > ProofMaxBody+1 {
		t.Errorf("cap: %d %v", len(b), err)
	}
}
