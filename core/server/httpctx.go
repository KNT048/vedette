package server

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/knt048/vedette/core/apierr"
)

// The generated handler interface gives a handler a context and a decoded request, not the HTTP exchange.
// Handlers that must read the client address, the User-Agent or a cookie, or set a cookie or a download
// header (sign-in, sign-out, the audit export) get them through Exchange. Everything else stays free of
// net/http.

type exchangeKey struct{}

// Exchange is the raw HTTP exchange of the request being served.
type Exchange struct {
	R *http.Request
	W http.ResponseWriter
}

func withExchange(ctx context.Context, w http.ResponseWriter, r *http.Request) context.Context {
	return context.WithValue(ctx, exchangeKey{}, Exchange{R: r, W: w})
}

// typedWriter lets a handler choose the media type of a file download. The generated encoder of a "file" response sets
// application/octet-stream itself, after the handler has returned, so a header set by the handler is overwritten; this writer puts
// the handler's choice (Exchange.SetContentType) back when the status line is written. It passes everything else through, and
// Unwrap lets http.ResponseController reach the connection (write deadlines).
type typedWriter struct {
	http.ResponseWriter
	ct    string
	wrote bool
}

func (t *typedWriter) WriteHeader(code int) {
	if !t.wrote {
		t.wrote = true
		if t.ct != "" {
			t.Header().Set("Content-Type", t.ct)
		}
	}
	t.ResponseWriter.WriteHeader(code)
}

func (t *typedWriter) Write(b []byte) (int, error) {
	if !t.wrote {
		t.WriteHeader(http.StatusOK)
	}
	return t.ResponseWriter.Write(b) //nolint:wrapcheck // the connection's own error
}

func (t *typedWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// SetContentType makes the response a download of that media type, whatever the generated encoder sets. Call it before the
// handler returns, and only on success.
func (e Exchange) SetContentType(ct string) {
	if t, ok := e.W.(*typedWriter); ok {
		t.ct = ct
	}
}

// ExchangeFrom returns the HTTP exchange the server put in the context of an API request.
func ExchangeFrom(ctx context.Context) (Exchange, bool) {
	e, ok := ctx.Value(exchangeKey{}).(Exchange)
	return e, ok
}

// ClientAddr is the address of the peer that opened the connection (r.RemoteAddr). Forwarded headers are
// never read: Vedette is not behind a proxy, and a header the client can write must not pick the key of a
// rate limit. The zero Addr is returned when the address cannot be parsed.
func (e Exchange) ClientAddr() netip.Addr {
	ap, err := netip.ParseAddrPort(e.R.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap().WithZone("")
}

// SetCookie adds a Set-Cookie header. It must be called before the handler returns, while the response
// has not been written.
func (e Exchange) SetCookie(c *http.Cookie) { http.SetCookie(e.W, c) }

// setRetryAfter puts the Retry-After header on a 429 or 503 that names a wait (API_CONVENTIONS section 8).
// apierr.Write does it for errors the server writes itself; an error a handler returns is encoded by the
// generated server, which has no header to carry it, so the header goes on the response here.
func setRetryAfter(ctx context.Context, e *apierr.Error) {
	x, ok := ExchangeFrom(ctx)
	if !ok {
		return
	}
	if n, ok := e.Extra["retry_after"].(int); ok && n > 0 && (e.Status == http.StatusTooManyRequests || e.Status == http.StatusServiceUnavailable) {
		x.W.Header().Set("Retry-After", strconv.Itoa(n))
	}
}
