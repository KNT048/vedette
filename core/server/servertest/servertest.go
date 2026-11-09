// Package servertest holds fakes for tests of code behind core/server: an Authenticator that needs
// no database and a module gate backed by a map.
package servertest

import (
	"net/http"
	"sync"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/server"
)

// CookieName is the session cookie the ogen server insists on seeing for non-public operations.
const CookieName = "vedette_session"

// CSRFHeader and CSRFValue are what Auth.CheckCSRF accepts.
const (
	CSRFHeader = "X-CSRF-Token"
	CSRFValue  = "csrf-ok"
)

// Auth is a fake server.Authenticator: the value of the session cookie names a user in Users.
// Unknown or missing cookie means no session. CheckCSRF wants the header CSRFHeader: CSRFValue.
type Auth struct {
	Users map[string]server.Principal

	mu    sync.Mutex
	calls int
}

// Authenticate implements server.Authenticator.
func (a *Auth) Authenticate(r *http.Request) (server.Principal, error) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	c, err := r.Cookie(CookieName)
	if err != nil {
		return server.Principal{}, server.ErrNoSession
	}
	p, ok := a.Users[c.Value]
	if !ok {
		return server.Principal{}, server.ErrNoSession
	}
	return p, nil
}

// CheckCSRF implements server.Authenticator.
func (a *Auth) CheckCSRF(r *http.Request, _ server.Principal) error {
	if r.Header.Get(CSRFHeader) != CSRFValue {
		return server.ErrNoSession // any error is refused as csrf_invalid
	}
	return nil
}

// Calls returns how many times Authenticate ran.
func (a *Auth) Calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// StandardUsers has one user per role, keyed by the cookie value "viewer", "operator", "admin".
func StandardUsers() map[string]server.Principal {
	return map[string]server.Principal{
		"viewer":   {ID: "u-view", Email: "director@acme.example", Role: routes.Viewer},
		"operator": {ID: "u-op", Email: "it@acme.example", Role: routes.Operator},
		"admin":    {ID: "u-admin", Email: "admin@acme.example", Role: routes.Admin},
	}
}

// Gate is a fake server.ModuleGate: modules are on unless listed in Off.
type Gate struct {
	mu  sync.Mutex
	off map[string]bool
}

// NewGate returns a gate with the given modules off.
func NewGate(off ...string) *Gate {
	g := &Gate{off: map[string]bool{}}
	for _, id := range off {
		g.off[id] = true
	}
	return g
}

// Enabled implements server.ModuleGate.
func (g *Gate) Enabled(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.off[id]
}

// Set turns a module on or off.
func (g *Gate) Set(id string, on bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.off[id] = !on
}
