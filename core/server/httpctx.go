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
