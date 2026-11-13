package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/honeypot"
)

const (
	// honeyTokenPath is the route of a URL honey token's link (honeypot POST-4, D-507): one path segment after /t/.
	honeyTokenPath = "/t/{id}"
	// honeyTokenPerMinute is how many opens of /t/... one address may have recorded per minute; past it the answer is the
	// same and nothing is written (D-507).
	honeyTokenPerMinute = 10
	// honeyTokenWait bounds the recording of one open; the answer does not wait longer, and a client that hangs up does not
	// cancel it.
	honeyTokenWait = 5 * time.Second
)

// honeyTokenHandler answers /t/<id>, the link of a URL honey token, with no session and no CSRF check (D-507). Every request
// to /t/<anything>, any method, gets the same plain 404, whether the id names a token, names none, is malformed, the module
// is off or the address is over its limit: the answer never shows the Vedette app (that would say "this is a trap") and never
// tells a real id from a guessed one. Before answering, a well-formed id is handed to the honeypot (svc may be nil: nothing
// is recorded), with the peer address of the connection (never a forwarded header) and the User-Agent.
func honeyTokenHandler(log *slog.Logger, svc *honeypot.Service, lim *server.AddrLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if svc != nil && honeypot.ValidURLTokenID(id) && lim.Allow(r) {
			if src, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), honeyTokenWait)
				ctx = store.LimitWriteWait(ctx, store.RequestWriteWait)
				if err := svc.OpenURLToken(ctx, id, src, r.UserAgent()); err != nil {
					log.WarnContext(ctx, "honeypot: could not record a URL token open", "error", err) // no path: the id is the token
				}
				cancel()
			}
		}
		http.NotFound(w, r) // the Envelope's no-store applies: every open reaches the box again
	})
}
