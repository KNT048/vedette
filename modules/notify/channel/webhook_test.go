package channel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const whKey = "0123456789abcdef0123"

func TestContract_INV8_WebhookSchemeRules(t *testing.T) {
	t.Parallel()
	key := NewSecret(whKey)
	for in, code := range map[string]string{
		"https://hooks.company.com/vedette":      "",
		"https://8.8.8.8/x":                      "",
		"http://192.168.1.10:8080/hook":          "",
		"http://10.0.0.5/hook":                   "",
		"http://172.20.0.5/hook":                 "",
		"http://127.0.0.1:9000/h":                "",
		"http://localhost/h":                     "",
		"http://wiki.internal/h":                 "",
		"http://printer.lan/h":                   "",
		"http://nas.local/h":                     "",
		"http://x.localhost/h":                   "",
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
	} {
		_, err := NewWebhook(WebhookConfig{URL: in, SigningKey: key})
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
	if _, err := NewWebhook(WebhookConfig{URL: "https://h.example.com/x"}); err == nil {
		t.Error("missing key accepted")
	}
	if _, err := NewWebhook(WebhookConfig{URL: "https://h.example.com/x", SigningKey: NewSecret("short")}); err == nil {
		t.Error("short key accepted")
	}
}

func TestWebhookSignsAndPosts(t *testing.T) {
	t.Parallel()
	var raw []byte
	var hdr http.Header
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		hdr = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	at := time.Unix(1_800_000_000, 0)
	s, err := NewWebhook(WebhookConfig{URL: srv.URL + "/hook?token=abc", SigningKey: NewSecret(whKey), Client: srv.Client(), Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	m := sample
	m.Items = []string{"CVE-2026-0001"}
	rec, err := s.Send(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec.To, "token=") || !strings.HasSuffix(rec.To, "/hook") {
		t.Errorf("To leaks the query: %q", rec.To)
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
	if p["event"] != "incident" || p["id"] != "al-4" || p["severity"] != "critical" || p["url"] != m.Link || p["title"] != m.Title {
		t.Errorf("payload %v", p)
	}
	if hdr.Get("Content-Type") != "application/json" {
		t.Errorf("content type %q", hdr.Get("Content-Type"))
	}
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
	s, _ := NewWebhook(WebhookConfig{URL: srv.URL, SigningKey: NewSecret(whKey)}) // default client
	_, err := s.Send(context.Background(), sample)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusTemporaryRedirect || hit {
		t.Fatalf("err = %v, followed = %v", err, hit)
	}
}

func TestContract_FORBID2_WebhookErrorHasNoKey(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom "+whKey+" "+r.Header.Get(WebhookSignatureHeader))
	}))
	t.Cleanup(srv.Close)
	s, _ := NewWebhook(WebhookConfig{URL: srv.URL, SigningKey: NewSecret(whKey)})
	_, err := s.Send(context.Background(), sample)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 500 {
		t.Fatalf("err = %v", err)
	}
	mustNot(t, err.Error(), whKey)
}

func FuzzNewWebhookURL(f *testing.F) {
	for _, s := range []string{"https://a.example/x", "http://10.0.0.1/", "http://evil.com", "https://[::1]/x", "http://0x7f.1/", "https://a b/", "HTTP://LOCALHOST"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		s, err := NewWebhook(WebhookConfig{URL: raw, SigningKey: NewSecret(whKey)})
		if err != nil {
			return
		}
		w := s.(*webhookSender)
		if strings.ContainsAny(w.url, " \r\n\t") {
			t.Fatalf("accepted url with whitespace: %q", w.url)
		}
		if strings.HasPrefix(w.url, "http://") {
			host := strings.TrimPrefix(w.url, "http://")
			host = strings.FieldsFunc(host, func(r rune) bool { return r == '/' || r == ':' || r == '?' })[0]
			if !internalHost(host) {
				t.Fatalf("plain http accepted for non-internal host: %q", w.url)
			}
		}
	})
}
