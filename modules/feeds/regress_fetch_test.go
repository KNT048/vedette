package feeds

// Ports of the reviewer's CheckURL, gzip-bomb and secret-visibility probes.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegress_CheckURLReviewerCases(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		u  string
		ok bool
	}{
		{"https://evil.com#@cisa.gov", true},
		{"http://evil.com#@localhost/", false},
		{"http://2130706433/", false},
		{"http://0x7f.1/", false},
		{"http://127.1/", false},
		{"http://[::ffff:127.0.0.1]/", false},
		{"http://localhost.evil.com/", false},
		{"http://evil.local./", false},
		{"HTTP://10.0.0.1/", true},
		{"http://[fe80::1%25eth0]/", false},
		{"http://evil.com%2elocal/", false},
		{"https://user@cisa.gov/", false},
		{"ftp://cisa.gov/", false},
		{"https:cisa.gov", false},
		{"https:///cisa.gov", false},
		{"//cisa.gov/x", false},
		// Accepted by the address rule on purpose: the dial guard refuses these at connect time (dial_test.go).
		{"https://169.254.169.254/", true},
		{"http://metadata.google.internal/computeMetadata/v1/", true},
		{"http://instance-data.ec2.internal/latest/meta-data/", true},
		{"https://cisa.gov:0/", true},
	} {
		if err := CheckURL(c.u); (err == nil) != c.ok {
			t.Errorf("CheckURL(%q) err=%v, expected ok=%v", c.u, err, c.ok)
		}
	}
}

func TestRegress_GzipBombCapIsOnTheDecompressedBody(t *testing.T) {
	// peakHeap reads the process-wide heap, which other tests would inflate: the body runs in a process of its own.
	if !inOwnProcess(t) {
		return
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	zero := make([]byte, 1<<20)
	for i := 0; i < 20; i++ {
		_, _ = w.Write(zero)
	}
	_ = w.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Encoding", "gzip")
		_, _ = rw.Write(gz.Bytes())
	}))
	defer srv.Close()
	if gz.Len() > MaxBodyBytes {
		t.Fatal("fixture is itself over the cap")
	}
	var err error
	peak := peakHeap(func() { _, err = Fetcher{Client: srv.Client()}.Fetch(context.Background(), Request{URL: srv.URL}) })
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("20 MB decompressed body: %v", err)
	}
	if peak > 32<<20 {
		t.Errorf("peak heap %d MB while refusing a gzip bomb", peak>>20)
	}
}

func TestRegress_RequestAndAuthNeverShowTheSecret(t *testing.T) {
	t.Parallel()
	const raw = "s3cr3t-value-123"
	sec, err := NewSecret(raw)
	if err != nil {
		t.Fatal(err)
	}
	req := Request{URL: "https://example.com/x?token=abc", Auth: Auth{Type: AuthHeader, HeaderName: "X-Api-Key", Secret: sec}, ETag: `"e1"`}
	for _, s := range []string{
		fmt.Sprintf("%v", req), fmt.Sprintf("%+v", req), fmt.Sprintf("%#v", req), fmt.Sprintf("%s", req.Auth),
		fmt.Sprintf("%x", req.Auth.Secret), fmt.Sprintf("%q", req.Auth), fmt.Sprintf("%d", req.Auth.Secret),
	} {
		if strings.Contains(s, "s3cr3t") || strings.Contains(s, fmt.Sprintf("%x", raw)) {
			t.Errorf("secret visible: %s", s)
		}
	}
	js, _ := json.Marshal(req)
	if strings.Contains(string(js), "s3cr3t") {
		t.Errorf("secret in JSON: %s", js)
	}
	_, err = Fetcher{}.Fetch(context.Background(), Request{URL: "https://127.0.0.1:1/x?token=abc", Auth: req.Auth})
	if err != nil && (strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "token=abc")) {
		t.Errorf("error leaks: %v", err)
	}
}

func TestRegress_RedirectWithUserinfoIsRefused(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Location", "http://u:p@"+r.Host+"/x")
		rw.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	if _, err := (Fetcher{Client: srv.Client()}).Fetch(context.Background(), Request{URL: srv.URL}); !errors.Is(err, ErrRedirect) {
		t.Errorf("redirect with userinfo: %v", err)
	}
}
