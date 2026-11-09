package channel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

const whKey = "0123456789abcdef0123"

func wh(u string) WebhookConfig {
	return WebhookConfig{URL: secrets.NewValue(u), SigningKey: secrets.NewValue(whKey), allowLoopback: strings.HasPrefix(u, "http://127.0.0.1:")}
}

func TestContract_INV8_WebhookSchemeRules(t *testing.T) {
	t.Parallel()
	box := netip.MustParseAddr("192.168.10.2")
	for in, code := range map[string]string{
		"https://hooks.company.com/vedette":      "",
		"https://8.8.8.8/x":                      "",
		"https://192.168.1.10/siem":              "", // an internal SIEM over https is a normal target
		"https://10.0.0.5:8443/siem":             "",
		"https://172.20.0.5/siem":                "",
		"http://192.168.1.10:8080/hook":          "",
		"http://10.0.0.5/hook":                   "",
		"http://172.20.0.5/hook":                 "",
		"http://127.0.0.1:9000/h":                "", // package tests only (allowLoopback is set for the httptest servers)
		"http://localhost/h":                     "blocked_host",
		"http://wiki.internal/h":                 "",
		"http://printer.lan/h":                   "",
		"http://nas.local/h":                     "",
		"http://x.localhost/h":                   "blocked_host",
		"http://hooks.company.com/vedette":       "insecure_url",
		"http://8.8.8.8/x":                       "insecure_url",
		"http://172.32.0.1/x":                    "insecure_url",
		"http://192.168.1.10.evil.com/x":         "insecure_url",
		"http://evil.com/x?host=192.168.1.1":     "insecure_url",
		"ftp://hooks.company.com/x":              "bad_url",
		"file:///etc/passwd":                     "bad_url",
		"javascript:alert(1)":                    "bad_url",
		"//hooks.company.com/x":                  "bad_url",
		"https://":                               "bad_url",
		"":                                       "bad_url",
		"https://user:pw@hooks.company.com/x":    "bad_url",
		"https://hooks.company.com/x y":          "bad_url",
		"https://hooks.company.com/x\r\nHost: z": "bad_url",
		"https://hooks.company.com/x#frag":       "bad_url",
		// Forbidden targets over https.
		"https://127.0.0.1/x":         "blocked_host",
		"https://127.8.9.10/x":        "blocked_host",
		"https://[::1]/x":             "blocked_host",
		"https://[::ffff:127.0.0.1]/": "blocked_host",
		"https://localhost/x":         "blocked_host",
		"https://localhost./x":        "blocked_host",
		"https://app.localhost/x":     "blocked_host",
		"https://169.254.169.254/x":   "blocked_host",
		"https://[fe80::1]/x":         "blocked_host",
		"https://0.0.0.0/x":           "blocked_host",
		"https://[::]/x":              "blocked_host",
		"https://224.0.0.251/x":       "blocked_host",
		"https://[ff02::1]/x":         "blocked_host",
		"https://192.168.10.2/x":      "blocked_host", // the box itself
		"https://2130706433/x":        "bad_url",      // 127.0.0.1 spelled as one number
		"https://0x7f.1/x":            "bad_url",
		"https://127.1/x":             "bad_url",
		// The same classes over plain http (loopback stays allowed there).
		"http://169.254.1.1/x":  "insecure_url", // not on the internal list at all
		"http://0.0.0.0/x":      "insecure_url",
		"http://224.0.0.1/x":    "insecure_url",
		"http://192.168.10.2/x": "blocked_host",
	} {
		c := wh(in)
		c.BoxAddrs = []netip.Addr{box}
		_, err := NewWebhook(c)
		if code == "" {
			if err != nil {
				t.Errorf("NewWebhook(%q): %v", in, err)
			}
			continue
		}
		var ce *ConfigError
		if !errors.As(err, &ce) || ce.Code != code {
			t.Errorf("NewWebhook(%q) = %v, want %s", in, err, code)
		}
	}
	if _, err := NewWebhook(WebhookConfig{URL: secrets.NewValue("https://h.example.com/x")}); err == nil {
		t.Error("missing key accepted")
	}
	if _, err := NewWebhook(WebhookConfig{URL: secrets.NewValue("https://h.example.com/x"), SigningKey: secrets.NewValue("short")}); err == nil {
		t.Error("short key accepted")
	}
}

func TestWebhookRefusesLoopbackOnHttpToo(t *testing.T) {
	t.Parallel()
	for _, u := range []string{"http://127.0.0.1:8443/api/v1/x", "http://localhost:11434/api/generate", "http://svc.localhost/x"} {
		_, err := NewWebhook(WebhookConfig{URL: secrets.NewValue(u), SigningKey: secrets.NewValue(whKey)})
		var ce *ConfigError
		if !errors.As(err, &ce) || ce.Code != "blocked_host" {
			t.Errorf("NewWebhook(%q) = %v, want blocked_host", u, err)
		}
	}
}

func TestWebhookBoxAddrsFuncIsAskedAgain(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var box []netip.Addr
	get := func() []netip.Addr { mu.Lock(); defer mu.Unlock(); return box }
	ctl := dialControl(false, get)
	if err := ctl("tcp", "192.168.10.77:443", nil); err != nil {
		t.Fatalf("before: %v", err)
	}
	mu.Lock()
	box = []netip.Addr{netip.MustParseAddr("192.168.10.77")}
	mu.Unlock()
	if err := ctl("tcp", "192.168.10.77:443", nil); err == nil {
		t.Error("an address the box got later was not refused")
	}
	_, err := NewWebhook(WebhookConfig{URL: secrets.NewValue("https://192.168.10.77/x"), SigningKey: secrets.NewValue(whKey), BoxAddrsFunc: get})
	var ce *ConfigError
	if !errors.As(err, &ce) || ce.Code != "blocked_host" {
		t.Errorf("BoxAddrsFunc at config time: %v", err)
	}
}

func TestForbiddenAddrClasses(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"127.0.0.1": true, "::1": true, "169.254.0.1": true, "fe80::1": true, "0.0.0.0": true, "::": true,
		"224.0.0.1": true, "ff02::1": true, "::ffff:169.254.1.1": true,
		"10.1.1.1": false, "192.168.0.9": false, "172.16.5.5": false, "8.8.8.8": false, "2001:db8::1": false,
	} {
		if got := forbiddenAddr(netip.MustParseAddr(in), false, nil); got != want {
			t.Errorf("forbiddenAddr(%s) = %v, want %v", in, got, want)
		}
	}
	if forbiddenAddr(netip.MustParseAddr("127.0.0.1"), true, nil) || !forbiddenAddr(netip.MustParseAddr("169.254.1.1"), true, nil) {
		t.Error("allowLoopback must allow only loopback")
	}
}

func TestWebhookDialGuardRefusesResolvedAddresses(t *testing.T) {
	t.Parallel()
	box := []netip.Addr{netip.MustParseAddr("192.168.10.2")}
	for addr, wantErr := range map[string]bool{
		"127.0.0.1:443": true, "169.254.169.254:80": true, "0.0.0.0:80": true, "[::1]:443": true, "224.0.0.1:80": true,
		"192.168.10.2:443": true, "192.168.10.9:443": false, "8.8.8.8:443": false, "not-an-address": true, "example.com:443": true,
	} {
		if err := dialControl(false, func() []netip.Addr { return box })("tcp", addr, nil); (err != nil) != wantErr {
			t.Errorf("https %s: err = %v", addr, err)
		}
	}
	if err := dialControl(true, func() []netip.Addr { return nil })("tcp", "127.0.0.1:80", nil); err != nil {
		t.Errorf("http loopback: %v", err)
	}
	// The default client really dials through the guard: a loopback server is
	// reachable over http (allowed) and not when the guard is the https one.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(srv.Close)
	s, err := NewWebhook(wh(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send(context.Background(), sample); err != nil {
		t.Errorf("default client, http loopback: %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, nil)
	if resp, err := webhookClient(false, func() []netip.Addr { return nil }).Do(req); err == nil {
		_ = resp.Body.Close()
		t.Error("https-mode client dialled loopback")
	}
}

func TestWebhookSignsAndPosts(t *testing.T) {
	t.Parallel()
	var raw []byte
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		hdr = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	at := time.Unix(1_800_000_000, 0)
	c := wh(srv.URL + "/hook?token=abc")
	c.Client, c.Now = srv.Client(), func() time.Time { return at }
	s, err := NewWebhook(c)
	if err != nil {
		t.Fatal(err)
	}
	m := sample
	m.Items = []string{"CVE-2026-0001"}
	rec, err := s.Send(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if rec.To != srv.URL {
		t.Errorf("To = %q, want scheme://host only (%q)", rec.To, srv.URL)
	}
	// A receiver verifies exactly as documented.
	ts := hdr.Get(WebhookTimestampHeader)
	if ts != strconv.FormatInt(at.Unix(), 10) {
		t.Errorf("timestamp %q", ts)
	}
	mac := hmac.New(sha256.New, []byte(whKey))
	mac.Write([]byte(ts + "."))
	mac.Write(raw)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got := hdr.Get(WebhookSignatureHeader); !hmac.Equal([]byte(got), []byte(want)) {
		t.Errorf("signature %q, want %q", got, want)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if p["event"] != "incident.created" || p["id"] != "al-4" || p["severity"] != "critical" || p["url"] != m.Link || p["title"] != m.Title {
		t.Errorf("payload %v", p)
	}
	if hdr.Get("Content-Type") != "application/json" {
		t.Errorf("content type %q", hdr.Get("Content-Type"))
	}
}

// The webhook URL is a secret: a path token and a query key must not appear in
// the destination label, in any print of the sender, or in any error.
func TestContract_FORBID2_WebhookURLIsSecret(t *testing.T) {
	t.Parallel()
	const pathTok, queryKey = "PathTokenSecret987", "QueryKeySecret654"
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.RequestURI()
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "failed for "+r.URL.RequestURI()+" "+r.URL.Path) //nolint:gosec // test server echoing the request on purpose
	}))
	t.Cleanup(srv.Close)
	s, err := NewWebhook(wh(srv.URL + "/hooks/" + pathTok + "?api_key=" + queryKey))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Send(context.Background(), sample)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 500 {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(seen, pathTok) || !strings.Contains(seen, queryKey) {
		t.Fatalf("server did not get the full URL: %q", seen)
	}
	mustNot(t, err.Error(), pathTok, queryKey)
	mustNot(t, s.Dest(), pathTok, queryKey, "/hooks", "api_key")
	if s.Dest() != srv.URL {
		t.Errorf("Dest = %q, want %q", s.Dest(), srv.URL)
	}
	rec := fmt.Sprintf("%v|%+v|%#v|%s|%v", s, s, s, s, []Sender{s})
	mustNot(t, rec, pathTok, queryKey, whKey)

	// Transport failure: *url.Error would carry the whole URL.
	dead := httptest.NewServer(http.NotFoundHandler())
	base := dead.URL
	dead.Close()
	s2, _ := NewWebhook(wh(base + "/hooks/" + pathTok + "?api_key=" + queryKey))
	_, err = s2.Send(context.Background(), sample)
	if err == nil {
		t.Fatal("expected a connection error")
	}
	mustNot(t, err.Error(), pathTok, queryKey, "/hooks")
}

func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	hit := false
	inner := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	t.Cleanup(inner.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, inner.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	for name, client := range map[string]*http.Client{
		"default client":             nil,
		"caller client that follows": {}, // net/http follows redirects unless told not to
	} {
		hit = false
		c := wh(srv.URL)
		c.Client = client
		s, _ := NewWebhook(c)
		_, err := s.Send(context.Background(), sample)
		var se *StatusError
		if !errors.As(err, &se) || se.Code != http.StatusTemporaryRedirect || hit {
			t.Errorf("%s: err = %v, followed = %v", name, err, hit)
		}
	}
}

func TestContract_FORBID2_WebhookErrorHasNoKey(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom "+whKey+" "+r.Header.Get(WebhookSignatureHeader)) //nolint:gosec // test server echoing the request on purpose
	}))
	t.Cleanup(srv.Close)
	s, _ := NewWebhook(wh(srv.URL))
	_, err := s.Send(context.Background(), sample)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 500 {
		t.Fatalf("err = %v", err)
	}
	mustNot(t, err.Error(), whKey)
}

func FuzzNewWebhookURL(f *testing.F) {
	for _, s := range []string{"https://a.example/x", "http://10.0.0.1/", "http://evil.com", "https://[::1]/x", "http://0x7f.1/", "https://a b/", "HTTP://LOCALHOST", "https://169.254.169.254/", "https://[::ffff:7f00:1]/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		s, err := NewWebhook(wh(raw))
		if err != nil {
			return
		}
		w := s.(*webhookSender)
		u := w.url.Reveal()
		if strings.ContainsAny(u, " \r\n\t") {
			t.Fatalf("accepted url with whitespace")
		}
		host := strings.TrimPrefix(strings.TrimPrefix(w.to, "https://"), "http://")
		host = strings.Trim(strings.SplitN(host, "]", 2)[0], "[")
		if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host, "::") && !strings.Contains(host, "]") {
			host = host[:i]
		}
		if a, err := netip.ParseAddr(host); err == nil {
			if a = a.Unmap(); a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || (a.IsLoopback() && strings.HasPrefix(w.to, "https://")) {
				t.Fatalf("accepted forbidden address %s over %s", a, w.to[:5])
			}
		}
		if strings.HasPrefix(w.to, "http://") && !internalHost(strings.Split(strings.TrimPrefix(w.to, "http://"), ":")[0]) {
			t.Fatalf("plain http accepted for non-internal host %q", w.to)
		}
		if strings.Contains(w.to, "/") && strings.Count(w.to, "/") != 2 {
			t.Fatalf("Dest carries a path: %q", w.to)
		}
	})
}
