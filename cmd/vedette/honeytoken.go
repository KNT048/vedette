package main

import (
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/modules/honeypot"
)

const (
	// urlTrapPath is the route of a URL honey token's link (honeypot POST-4, D-507); urlTrapDeeper is the same link with
	// anything after it (a trailing slash, a path a link checker added): both fire on the id.
	urlTrapPath   = "/t/{id}"
	urlTrapDeeper = "/t/{id}/{rest...}"
	// honeyTokenPerMinute is how many repeat opens one address may have recorded per minute (D-507). The first open of a token
	// from a source in a 10-minute window is never limited.
	honeyTokenPerMinute = 10
	// urlTrapTrail is what an auto-linker or a sentence may glue to the end of a pasted link.
	urlTrapTrail = `.,;:!?'")]}>*`
)

// honeyTokenSources tells the handler who the box itself is. machine is the machine's addresses (machineAddrs: what vedette-host
// reports, the container's default gateways, the -hosts literals, the host aliases); appliance is true when vedette-host is there.
// On the appliance the published port keeps the visitor's address (rootful DNAT, D-167), so a machine address is the box itself
// (its host opening the link, through the bridge gateway) and records nothing. On a container-only install a port proxy may stand
// between the visitor and core: an open from a machine address is recorded with the source "unknown (container-only port proxy)",
// never naming the gateway as the machine to unplug.
type honeyTokenSources struct {
	machine   func() ([]netip.Addr, bool)
	appliance bool
}

// honeyTokenHandler answers /t/<id> and /t/<id>/..., the link of a URL honey token, with no session and no CSRF check (D-507).
// Every such request, any method, gets the same plain 404, whether the id names a token, names none, is malformed, the module
// is off or the address is over its limit: the answer never shows the Vedette app (that would say "this is a trap") and never
// tells a real id from a guessed one. Before answering, the id is handed to the honeypot (svc may be nil: nothing is recorded)
// with the peer address of the connection (never a forwarded header) and the User-Agent. The limit is asked only for a repeat
// open of a token that exists (review M1).
func honeyTokenHandler(log *slog.Logger, svc *honeypot.Service, lim *server.AddrLimiter, src honeyTokenSources) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer http.NotFound(w, r) // the Envelope's no-store applies: every open reaches the box again
		id := strings.TrimRight(r.PathValue("id"), urlTrapTrail)
		peer, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || svc == nil || !honeypot.ValidURLTokenID(id) {
			return
		}
		self := src.machine != nil && slices.Contains(machineList(src.machine), peer.Addr().Unmap().WithZone(""))
		if self && src.appliance {
			return // the box itself
		}
		o := honeypot.URLTokenOpen{ID: id, Src: peer, UserAgent: r.UserAgent(), Proxied: self, RepeatOK: func() bool { return lim.Allow(r) }}
		if err := svc.OpenURLToken(r.Context(), o); err != nil {
			log.WarnContext(r.Context(), "honeypot: could not record a URL token open", "error", err) // no path: the id is the token
		}
	})
}

func machineList(f func() ([]netip.Addr, bool)) []netip.Addr {
	l, _ := f()
	out := make([]netip.Addr, 0, len(l))
	for _, a := range l {
		out = append(out, a.Unmap().WithZone(""))
	}
	return out
}
