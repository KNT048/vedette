package main

import (
	"net/http"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
	sensorpassive "github.com/knt048/vedette/modules/sensor-passive"
)

// handler is the composite of oas.Handler: server.Fallback answers 501 for every operation and gives
// the default error response (its oas.UnimplementedHandler sits one level deeper), and each module's
// handlers sit beside it and shadow the stubs for the operations they implement. Two modules that
// implement the same operation make the method ambiguous and this file stops compiling. Add a module
// by embedding its handler struct here.
type handler struct {
	server.Fallback
	*core.ModuleHandlers
	*inventory.Handlers
	*sensorpassive.SensorHandlers
}

// newHandler builds every module's handlers from the shared deps. Adding a module = one field above
// and one line here (issue #33).
func newHandler(d deps) handler {
	return handler{
		Fallback:       server.Fallback{Log: d.Log},
		ModuleHandlers: core.NewModuleHandlers(d.DB, d.Reg),
		Handlers:       inventory.NewHandlers(newInventory(d)),
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
