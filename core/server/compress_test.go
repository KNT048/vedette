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
	r := httptest.NewRequest(method, "/x", nil)
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
