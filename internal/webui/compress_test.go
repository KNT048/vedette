package webui_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/internal/webui"
)

func compressFixture() (http.Handler, string) {
	js := strings.Repeat("export const a = 'hello world';\n", 400)
	m := fstest.MapFS{
		"index.html":         {Data: []byte(strings.Repeat("<p>page</p>", 200))},
		"favicon.svg":        {Data: []byte(strings.Repeat("<path d='M0 0'/>", 100))},
		"assets/app-1a2b.js": {Data: []byte(js)},
		"assets/tiny-1.js":   {Data: []byte("export{}")},
		"assets/f-9z.woff2":  {Data: bytes.Repeat([]byte("wOF2"), 500)},
	}
	var fsys fs.FS = m
	return webui.Handler(fsys), js
}

func fetch(t *testing.T, h http.Handler, target, accept string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if accept != "" {
		req.Header.Set("Accept-Encoding", accept)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAssetsAreServedGzippedWhenAccepted(t *testing.T) {
	t.Parallel()
	h, js := compressFixture()
	rec := fetch(t, h, "/assets/app-1a2b.js", "gzip, deflate, br")
	if rec.Header().Get("Content-Encoding") != "gzip" || rec.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatalf("headers %v", rec.Header())
	}
	if rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || !strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("cache or type changed: %v", rec.Header())
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(zr)
	if string(got) != js {
		t.Fatal("decoded bytes differ")
	}
	if cl := rec.Header().Get("Content-Length"); cl == "" || cl == "13200" {
		t.Errorf("Content-Length %q", cl)
	}

	plain := fetch(t, h, "/assets/app-1a2b.js", "")
	if plain.Header().Get("Content-Encoding") != "" || plain.Body.String() != js || plain.Header().Get("Vary") != "Accept-Encoding" {
		t.Errorf("identity request: %v", plain.Header())
	}
	if r := fetch(t, h, "/assets/app-1a2b.js", "gzip;q=0"); r.Header().Get("Content-Encoding") != "" {
		t.Error("q=0 was compressed")
	}
}

func TestIndexStaysUncachedAndEtagDiffersPerEncoding(t *testing.T) {
	t.Parallel()
	h, _ := compressFixture()
	rec := fetch(t, h, "/anything/route", "gzip")
	if rec.Header().Get("Content-Encoding") != "gzip" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("index: %v", rec.Header())
	}
	a, b := fetch(t, h, "/favicon.svg", "gzip"), fetch(t, h, "/favicon.svg", "")
	if a.Header().Get("ETag") == "" || a.Header().Get("ETag") == b.Header().Get("ETag") || b.Header().Get("ETag") == "" {
		t.Errorf("etags %q %q", a.Header().Get("ETag"), b.Header().Get("ETag"))
	}
	if a.Header().Get("Cache-Control") != "no-cache" {
		t.Error("favicon caching changed")
	}
}

func TestSmallAndAlreadyCompressedFilesAreNotEncoded(t *testing.T) {
	t.Parallel()
	h, _ := compressFixture()
	for _, p := range []string{"/assets/tiny-1.js", "/assets/f-9z.woff2"} {
		if rec := fetch(t, h, p, "gzip"); rec.Header().Get("Content-Encoding") != "" {
			t.Errorf("%s encoded", p)
		}
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/assets/app-1a2b.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Range", "bytes=0-9")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusPartialContent || rec.Header().Get("Content-Encoding") != "" {
		t.Errorf("range: %d %v", rec.Code, rec.Header())
	}
}
