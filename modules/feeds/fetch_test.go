package feeds

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type seen struct {
	method, uri string
	header      http.Header
	bodyLen     int64
}

func recorder(t *testing.T, h http.HandlerFunc) (*httptest.Server, *[]seen, *atomic.Int32) {
	t.Helper()
	var log []seen
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		log = append(log, seen{r.Method, r.RequestURI, r.Header.Clone(), r.ContentLength})
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &log, &n
}

func ok(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }
}

func TestContract_INV1_OnlyDeclaredSources(t *testing.T) {
	t.Parallel()
	srv, log, count := recorder(t, ok("1.2.3.4\n"))
	f := Fetcher{Client: srv.Client(), Version: "1.2.3"}
	declared := srv.URL + "/feeds/list.txt?x=1"
	resp, err := f.Fetch(context.Background(), Request{URL: declared})
	if err != nil || string(resp.Body) != "1.2.3.4\n" {
		t.Fatalf("%v %+v", err, resp)
	}
	if count.Load() != 1 || len(*log) != 1 {
		t.Fatalf("expected exactly one request, got %d", count.Load())
	}
	r := (*log)[0]
	if r.method != "GET" || r.uri != "/feeds/list.txt?x=1" || r.bodyLen > 0 {
		t.Errorf("request: %+v", r)
	}
	var names []string
	for k := range r.header {
		names = append(names, k)
	}
	sort.Strings(names)
	if got := strings.Join(names, ","); got != "Accept,Accept-Encoding,User-Agent" {
		t.Errorf("headers sent: %s", got)
	}
	if r.header.Get("User-Agent") != "Vedette/1.2.3" {
		t.Errorf("User-Agent = %q", r.header.Get("User-Agent"))
	}
	// A refused address never reaches the network.
	before := count.Load()
	for _, u := range []string{"http://example.com/feed", "ftp://x/y", "", "https://user:pw@example.com/"} {
		if _, err := f.Fetch(context.Background(), Request{URL: u}); !errors.Is(err, ErrInvalidURL) {
			t.Errorf("Fetch(%q) = %v", u, err)
		}
	}
	if count.Load() != before {
		t.Error("network used for a refused address")
	}
	if ua := (Fetcher{Version: "bad version\r\n"}).UserAgent(); ua != "Vedette/dev" {
		t.Errorf("unsafe version leaked into UA: %q", ua)
	}
}

func TestConditionalRequests(t *testing.T) {
	t.Parallel()
	srv, log, _ := recorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Mon, 02 Nov 2026 10:00:00 GMT")
		_, _ = w.Write([]byte("data"))
	})
	f := Fetcher{Client: srv.Client()}
	first, err := f.Fetch(context.Background(), Request{URL: srv.URL})
	if err != nil || first.NotModified || first.ETag != `"v1"` || first.LastModified != "Mon, 02 Nov 2026 10:00:00 GMT" {
		t.Fatalf("%v %+v", err, first)
	}
	second, err := f.Fetch(context.Background(), Request{URL: srv.URL, ETag: first.ETag, LastModified: first.LastModified})
	if err != nil || !second.NotModified || second.Body != nil {
		t.Fatalf("%v %+v", err, second)
	}
	h := (*log)[1].header
	if h.Get("If-None-Match") != `"v1"` || h.Get("If-Modified-Since") != "Mon, 02 Nov 2026 10:00:00 GMT" {
		t.Errorf("validators not sent: %v", h)
	}
	// Validators with control characters are dropped, not sent.
	if _, err := f.Fetch(context.Background(), Request{URL: srv.URL, ETag: "bad\r\nX: y"}); err != nil {
		t.Fatal(err)
	}
	if v := (*log)[2].header.Get("If-None-Match"); v != "" {
		t.Errorf("unsafe validator sent: %q", v)
	}
}

func TestUnexpectedNotModifiedIsAnError(t *testing.T) {
	t.Parallel()
	srv, _, _ := recorder(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotModified) })
	_, err := Fetcher{Client: srv.Client()}.Fetch(context.Background(), Request{URL: srv.URL})
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 304 {
		t.Fatalf("%v", err)
	}
}

func TestAuthInjection(t *testing.T) {
	t.Parallel()
	srv, log, _ := recorder(t, ok("x"))
	f := Fetcher{Client: srv.Client()}
	sec, _ := NewSecret("s3cret-value")
	cases := []struct {
		name string
		auth Auth
		hdr  string
		want string
	}{
		{"bearer", Auth{Type: AuthBearer, Secret: sec}, "Authorization", "Bearer s3cret-value"},
		{"header", Auth{Type: AuthHeader, HeaderName: "X-Api-Key", Secret: sec}, "X-Api-Key", "s3cret-value"},
		{"basic", Auth{Type: AuthBasic, Username: "bob", Secret: sec}, "Authorization", "Basic Ym9iOnMzY3JldC12YWx1ZQ=="},
		{"none", Auth{Type: AuthNone, Secret: sec}, "Authorization", ""},
		{"empty type", Auth{Secret: sec}, "Authorization", ""},
	}
	for i, c := range cases {
		if _, err := f.Fetch(context.Background(), Request{URL: srv.URL, Auth: c.auth}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := (*log)[i].header.Get(c.hdr); got != c.want {
			t.Errorf("%s: %s = %q, want %q", c.name, c.hdr, got, c.want)
		}
	}
	for name, a := range map[string]Auth{
		"bearer without secret": {Type: AuthBearer},
		"bad header name":       {Type: AuthHeader, HeaderName: "Host", Secret: sec},
		"basic without user":    {Type: AuthBasic, Secret: sec},
		"unknown type":          {Type: "digest", Secret: sec},
	} {
		n := len(*log)
		if _, err := f.Fetch(context.Background(), Request{URL: srv.URL, Auth: a}); !errors.Is(err, ErrInvalidAuth) {
			t.Errorf("%s: %v", name, err)
		}
		if len(*log) != n {
			t.Errorf("%s: request was sent", name)
		}
	}
}

func TestSizeCapEnforcedWhileReading(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("a", MaxBodyBytes+1)
	exact := strings.Repeat("a", MaxBodyBytes)
	srv, _, _ := recorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/exact":
			_, _ = w.Write([]byte(exact))
		case "/chunked": // no Content-Length: the cap must still hold
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte(big))
		default:
			_, _ = w.Write([]byte(big))
		}
	})
	f := Fetcher{Client: srv.Client()}
	if r, err := f.Fetch(context.Background(), Request{URL: srv.URL + "/exact"}); err != nil || len(r.Body) != MaxBodyBytes {
		t.Errorf("exact size: %v", err)
	}
	for _, p := range []string{"/big", "/chunked"} {
		if _, err := f.Fetch(context.Background(), Request{URL: srv.URL + p}); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", p, err)
		}
	}
	if _, err := f.Fetch(context.Background(), Request{URL: srv.URL + "/exact", MaxBytes: 1000}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("custom cap: %v", err)
	}
	if r, err := f.Fetch(context.Background(), Request{URL: srv.URL + "/exact", MaxBytes: MaxBodyBytes * 2}); err != nil || len(r.Body) != MaxBodyBytes {
		t.Errorf("raised cap: %v", err)
	}
}

func TestStatusErrors(t *testing.T) {
	t.Parallel()
	for _, code := range []int{204, 206, 301 + 100, 404, 429, 500, 503} {
		srv, _, _ := recorder(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code); _, _ = w.Write([]byte("body")) })
		_, err := Fetcher{Client: srv.Client()}.Fetch(context.Background(), Request{URL: srv.URL})
		var se *StatusError
		if !errors.As(err, &se) || se.Code != code || !strings.Contains(err.Error(), "HTTP") {
			t.Errorf("code %d: %v", code, err)
		}
	}
}

func TestRedirectPolicy(t *testing.T) {
	t.Parallel()
	other, _, otherCount := recorder(t, ok("other"))
	var srv *httptest.Server
	srv, _, _ = recorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/moved":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/away":
			http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
		case "/to-ftp":
			w.Header().Set("Location", "ftp://example.com/x")
			w.WriteHeader(http.StatusFound)
		case "/final":
			_, _ = w.Write([]byte("final:" + r.Header.Get("X-Api-Key"))) //nolint:gosec // test server echoing a header to the test client
		}
	})
	f := Fetcher{Client: srv.Client()}
	sec, _ := NewSecret("s3cret-value")
	auth := Auth{Type: AuthHeader, HeaderName: "X-Api-Key", Secret: sec}
	r, err := f.Fetch(context.Background(), Request{URL: srv.URL + "/moved", Auth: auth})
	if err != nil || string(r.Body) != "final:s3cret-value" || !strings.HasSuffix(r.FinalURL, "/final") {
		t.Fatalf("same-host redirect: %v %+v", err, r)
	}
	for _, p := range []string{"/away", "/loop", "/to-ftp"} {
		if _, err := f.Fetch(context.Background(), Request{URL: srv.URL + p, Auth: auth}); !errors.Is(err, ErrRedirect) {
			t.Errorf("%s: %v", p, err)
		}
	}
	if otherCount.Load() != 0 {
		t.Error("a cross-host redirect was followed; credentials would have been sent")
	}
	// A client without a redirect policy of its own is still covered.
	if _, err := (Fetcher{Client: &http.Client{CheckRedirect: nil, Timeout: time.Second}}).Fetch(context.Background(), Request{URL: srv.URL + "/away"}); !errors.Is(err, ErrRedirect) {
		t.Errorf("caller client: %v", err)
	}
}

func mustReq(t *testing.T, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Request{URL: u}
}

func TestCheckRedirectHops(t *testing.T) {
	t.Parallel()
	a := mustReq(t, "https://feeds.example.com/a")
	cases := []struct {
		name string
		next string
		via  []*http.Request
		ok   bool
	}{
		{"same host", "https://feeds.example.com/b", []*http.Request{a}, true},
		{"same host, other case", "https://FEEDS.example.com/b", []*http.Request{a}, true},
		{"downgrade", "http://feeds.example.com/b", []*http.Request{a}, false},
		{"other host", "https://cdn.example.net/b", []*http.Request{a}, false},
		{"www variant is another host", "https://www.feeds.example.com/b", []*http.Request{a}, false},
		{"other scheme", "ftp://feeds.example.com/b", []*http.Request{a}, false},
		{"userinfo", "https://u:p@feeds.example.com/b", []*http.Request{a}, false},
		{"upgrade", "https://box.lan/b", []*http.Request{mustReq(t, "http://box.lan/a")}, true},
		{"internal http stays http", "http://box.lan/b", []*http.Request{mustReq(t, "http://box.lan/a")}, true},
		{"too many", "https://feeds.example.com/b", []*http.Request{a, a, a, a, a, a}, false},
	}
	for _, c := range cases {
		err := checkRedirect(mustReq(t, c.next), c.via)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrRedirect)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// A downgrade after an upgrade is refused too.
	err := checkRedirect(mustReq(t, "http://box.lan/c"), []*http.Request{mustReq(t, "http://box.lan/a"), mustReq(t, "https://box.lan/b")})
	if !errors.Is(err, ErrRedirect) {
		t.Errorf("https->http mid-chain: %v", err)
	}
}

func TestDeadlineAndErrorsDoNotLeakQuery(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv, _, _ := recorder(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := Fetcher{Client: srv.Client()}.Fetch(ctx, Request{URL: srv.URL + "/?token=QUERYSECRET"})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "QUERYSECRET") {
		t.Fatalf("deadline: %v", err)
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	addr := dead.URL
	dead.Close()
	_, err = Fetcher{}.Fetch(context.Background(), Request{URL: addr + "/?token=QUERYSECRET"})
	if err == nil || strings.Contains(err.Error(), "QUERYSECRET") {
		t.Fatalf("connection error: %v", err)
	}
}

func TestNewClientHasTimeouts(t *testing.T) {
	t.Parallel()
	c := NewClient(0)
	tr, _ := c.Transport.(*http.Transport)
	if c.Timeout != DefaultFetchTimeout || tr == nil || tr.TLSHandshakeTimeout == 0 || tr.ResponseHeaderTimeout == 0 {
		t.Fatalf("%+v %+v", c, tr)
	}
	if NewClient(5*time.Second).Timeout != 5*time.Second {
		t.Error("custom timeout ignored")
	}
}
