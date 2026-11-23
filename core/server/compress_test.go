package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func big() string { return `{"items":[` + strings.Repeat(`{"name":"device","ok":true},`, 200) + `{}]}` }

func get(t *testing.T, h http.Handler, method, accept string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, "/x", nil)
	if accept != "" {
		r.Header.Set("Accept-Encoding", accept)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func jsonHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("ETag", `"v1"`)
		_, _ = io.WriteString(w, body)
	})
}

func TestCompressJSONGzipsLargeBodiesForAcceptingClients(t *testing.T) {
	want := big()
	w := get(t, compressJSON(jsonHandler(want)), "GET", "gzip, br", nil)
	if w.Header().Get("Content-Encoding") != "gzip" || !strings.Contains(w.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("headers: %v", w.Header())
	}
	if w.Header().Get("Content-Length") != "" || w.Header().Get("ETag") != `W/"v1"` {
		t.Fatalf("length/etag: %v", w.Header())
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(zr)
	if string(got) != want {
		t.Fatal("decoded bytes differ")
	}
	if w.Body.Len() >= len(want)/2 {
		t.Fatalf("not smaller: %d of %d", w.Body.Len(), len(want))
	}
}

func TestCompressJSONLeavesTheRestAlone(t *testing.T) {
	h := compressJSON(jsonHandler(big()))
	for name, w := range map[string]*httptest.ResponseRecorder{
		"no accept":  get(t, h, "GET", "", nil),
		"identity":   get(t, h, "GET", "identity", nil),
		"gzip q=0":   get(t, h, "GET", "gzip;q=0", nil),
		"range":      get(t, h, "GET", "gzip", map[string]string{"Range": "bytes=0-9"}),
		"head":       get(t, h, "HEAD", "gzip", nil),
		"small body": get(t, compressJSON(jsonHandler(`{"a":1}`)), "GET", "gzip", nil),
	} {
		if w.Header().Get("Content-Encoding") != "" {
			t.Errorf("%s: encoded", name)
		}
	}
	if w := get(t, h, "GET", "", nil); w.Body.String() != big() {
		t.Error("identity body changed")
	}
	if w := get(t, compressJSON(jsonHandler(`{"a":1}`)), "GET", "gzip", nil); w.Body.String() != `{"a":1}` {
		t.Error("small body changed")
	}
}

func TestCompressJSONSkipsNonJSONStreamsAndEncodedBodies(t *testing.T) {
	text := strings.Repeat("data: tick\n\n", 300)
	sse := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, text)
	})
	if w := get(t, compressJSON(sse), "GET", "gzip", nil); w.Header().Get("Content-Encoding") != "" || w.Body.String() != text {
		t.Error("event stream was touched")
	}
	// A JSON stream that flushes is committed unchanged, even when it is large.
	flushing := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"first":1}`+"\n")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, big())
	})
	if w := get(t, compressJSON(flushing), "GET", "gzip", nil); w.Header().Get("Content-Encoding") != "" || !strings.HasSuffix(w.Body.String(), big()) {
		t.Error("flushed stream was compressed")
	}
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	_, _ = zw.Write([]byte(big()))
	_ = zw.Close()
	pre := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(raw.Bytes())
	})
	if w := get(t, compressJSON(pre), "GET", "gzip", nil); !bytes.Equal(w.Body.Bytes(), raw.Bytes()) {
		t.Error("an already encoded body was encoded twice")
	}
	nc := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	if w := get(t, compressJSON(nc), "GET", "gzip", nil); w.Code != 204 || w.Header().Get("Content-Encoding") != "" {
		t.Error("204 changed")
	}
}

func TestCompressJSONFlushPushesGzipData(t *testing.T) {
	h := compressJSON(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, big()) // past the hold-back: gzip is active
		w.(http.Flusher).Flush()
		// the handler is still running: what was written must already be decodable
		zr, err := gzip.NewReader(bytes.NewReader(w.(*compressWriter).ResponseWriter.(*httptest.ResponseRecorder).Body.Bytes()))
		if err != nil {
			t.Errorf("header: %v", err)
			return
		}
		buf := make([]byte, 100)
		if n, _ := io.ReadFull(zr, buf); n != 100 {
			t.Errorf("only %d bytes readable after Flush", n)
		}
	}))
	w := get(t, h, "GET", "gzip", nil)
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("not gzipped")
	}
}

func TestCompressJSONPanicWritesNoTrailerAndKeepsTheStatusOpen(t *testing.T) {
	// after the gzip commit: the stream ends without a trailer
	h := compressJSON(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, big())
		panic(http.ErrAbortHandler)
	}))
	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler { //nolint:errorlint // net/http documents comparing the value itself
				t.Error("the panic was swallowed")
			}
		}()
		r := httptest.NewRequestWithContext(t.Context(), "GET", "/x", nil)
		r.Header.Set("Accept-Encoding", "gzip")
		h.ServeHTTP(rec, r)
	}()
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(zr); err == nil {
		t.Error("a truncated body ended as a complete gzip stream")
	}
	// before the hold-back is full: nothing is committed, so an outer layer can still answer 500
	small := compressJSON(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"a":`)
		panic("boom")
	}))
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		small.ServeHTTP(w, r)
	})
	if w := get(t, outer, "GET", "gzip", nil); w.Code != 500 || w.Body.Len() != 0 {
		t.Errorf("got %d with %d body bytes", w.Code, w.Body.Len())
	}
}

type statusLog struct {
	http.ResponseWriter
	codes []int
}

func (s *statusLog) WriteHeader(c int) { s.codes = append(s.codes, c) }

func TestCompressJSONInformationalStatusKeepsTheFinalOne(t *testing.T) {
	h := compressJSON(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, big())
	}))
	rec := httptest.NewRecorder()
	sl := &statusLog{ResponseWriter: rec}
	r := httptest.NewRequestWithContext(t.Context(), "GET", "/x", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(sl, r)
	if len(sl.codes) != 2 || sl.codes[0] != 103 || sl.codes[1] != 404 || rec.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("statuses %v, encoding %q", sl.codes, rec.Header().Get("Content-Encoding"))
	}
}

func TestCompressJSONHonoursQParameters(t *testing.T) {
	h := compressJSON(jsonHandler(big()))
	for _, v := range []string{"gzip;Q=0", "gzip;foo=1;q=0"} {
		if w := get(t, h, "GET", v, nil); w.Header().Get("Content-Encoding") != "" {
			t.Errorf("%q was compressed", v)
		}
	}
}
