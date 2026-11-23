package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// compressMin is the smallest JSON body worth compressing: below it the gzip header and the CPU cost outweigh the saving.
const compressMin = 1024

var gzipPool = sync.Pool{New: func() any {
	zw, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
	return zw
}}

// compressJSON gzips JSON responses of at least compressMin bytes for a client that sends Accept-Encoding: gzip.
// It never touches a response that is already encoded, has no body (HEAD, 204, 304, 1xx), answers a Range request, is not JSON
// (downloads, event streams), or whose handler flushes (a stream: the first Flush commits the response as it is).
// The decision is taken on the first write after up to compressMin bytes are held back, so small answers keep their Content-Length.
func compressJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
		if r.Method == http.MethodHead || r.Header.Get("Range") != "" || !acceptsGzip(r.Header.Get("Accept-Encoding")) {
			next.ServeHTTP(w, r)
			return
		}
		cw := &compressWriter{ResponseWriter: w}
		defer cw.finish()
		next.ServeHTTP(cw, r)
	})
}

// acceptsGzip reports whether an Accept-Encoding value allows gzip (a q=0 refuses it).
func acceptsGzip(v string) bool {
	for _, part := range strings.Split(v, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(name), "gzip") {
			continue
		}
		q := strings.TrimSpace(params)
		if rest, ok := strings.CutPrefix(q, "q="); ok {
			if f, err := strconv.ParseFloat(rest, 64); err == nil && f <= 0 {
				return false
			}
		}
		return true
	}
	return false
}

type compressWriter struct {
	http.ResponseWriter
	status  int
	buf     bytes.Buffer
	decided bool
	zw      *gzip.Writer
}

func (c *compressWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c *compressWriter) WriteHeader(code int) {
	if c.decided || c.status != 0 {
		return
	}
	if code < 200 || code == http.StatusNoContent || code == http.StatusNotModified {
		c.decided = true // no body: pass through
		c.ResponseWriter.WriteHeader(code)
		return
	}
	c.status = code
}

func (c *compressWriter) Write(p []byte) (int, error) {
	if c.decided {
		if c.zw != nil {
			return c.zw.Write(p)
		}
		return c.ResponseWriter.Write(p)
	}
	if c.status == 0 {
		c.status = http.StatusOK
	}
	c.buf.Write(p)
	if c.buf.Len() >= compressMin {
		c.commit(true)
	}
	return len(p), nil
}

// Flush commits the response unchanged: a handler that flushes is streaming.
func (c *compressWriter) Flush() {
	if !c.decided {
		if c.status == 0 {
			c.status = http.StatusOK
		}
		c.commit(false)
	}
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *compressWriter) finish() {
	if !c.decided {
		if c.status == 0 {
			return // the handler wrote nothing: let the server send its default answer
		}
		c.commit(false)
	}
	if c.zw != nil {
		_ = c.zw.Close()
		gzipPool.Put(c.zw)
		c.zw = nil
	}
}

// commit sends the status and the held-back bytes, gzipped when allowed and the body is JSON.
func (c *compressWriter) commit(allow bool) {
	c.decided = true
	h := c.ResponseWriter.Header()
	if allow && h.Get("Content-Encoding") == "" && isJSON(h.Get("Content-Type")) {
		h.Set("Content-Encoding", "gzip")
		h.Del("Content-Length")
		if et := h.Get("ETag"); et != "" && !strings.HasPrefix(et, "W/") {
			h.Set("ETag", "W/"+et)
		}
		c.ResponseWriter.WriteHeader(c.status)
		c.zw = gzipPool.Get().(*gzip.Writer)
		c.zw.Reset(c.ResponseWriter)
		_, _ = c.zw.Write(c.buf.Bytes())
		return
	}
	c.ResponseWriter.WriteHeader(c.status)
	_, _ = c.ResponseWriter.Write(c.buf.Bytes())
}

func isJSON(ct string) bool {
	ct, _, _ = strings.Cut(ct, ";")
	ct = strings.ToLower(strings.TrimSpace(ct))
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}
