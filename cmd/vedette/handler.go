package main

import (
	"log/slog"
	"net/http"

	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/core"
)

// handler is the composite of oas.Handler: server.Fallback answers 501 for every operation and gives
// the default error response (its oas.UnimplementedHandler sits one level deeper), and each module's
// handlers sit beside it and shadow the stubs for the operations they implement. Two modules that
// implement the same operation make the method ambiguous and this file stops compiling. Add a module
// by embedding its handler struct here.
type handler struct {
	server.Fallback
	*core.ModuleHandlers
}

func newHandler(log *slog.Logger, db *store.DB, reg *modreg.Registry) handler {
	return handler{
		Fallback:       server.Fallback{Log: log},
		ModuleHandlers: core.NewModuleHandlers(db, reg),
	}
}

// noSessions refuses every request that needs a session. It is the safe stand-in until WP-04b
// brings the session authenticator: public operations work (the ones that are implemented),
// everything else is 401.
type noSessions struct{}

func (noSessions) Authenticate(*http.Request) (server.Principal, error) {
	return server.Principal{}, server.ErrNoSession
}

func (noSessions) CheckCSRF(*http.Request, server.Principal) error { return server.ErrNoSession }
