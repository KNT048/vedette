package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/knt048/vedette/core/api/routes"
)

// Principal is the signed-in user of a request. WP-04b's session authenticator fills it; the role
// is read from the database on every request (API_CONVENTIONS 7.4), never from the cookie.
type Principal struct {
	ID    string
	Email string
	Role  routes.Role
}

// ErrNoSession is what an Authenticator returns when the request carries no valid session:
// the response is 401 unauthenticated.
var ErrNoSession = errors.New("server: no valid session")

// Authenticator is the hook WP-04b implements with sessions and CSRF tokens.
type Authenticator interface {
	// Authenticate returns the principal of the request. ErrNoSession (or any error wrapping it)
	// gives 401; an *apierr.Error is sent as it is (for example 403 disabled); anything else is a 500.
	Authenticate(r *http.Request) (Principal, error)
	// CheckCSRF is called for authenticated POST, PUT, PATCH and DELETE requests, after the role
	// check. Any error refuses the request (403 csrf_invalid unless it is an *apierr.Error).
	CheckCSRF(r *http.Request, p Principal) error
}

type principalKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal the middleware put in the request context. Handlers of
// non-public operations can rely on it being there.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// rank orders the roles; an unknown role ranks below everything and is refused everywhere.
func rank(r routes.Role) int {
	switch r {
	case routes.Public:
		return 0
	case routes.Viewer:
		return 1
	case routes.Operator:
		return 2
	case routes.Admin:
		return 3
	}
	return -1
}

type requestIDKey struct{}

// RequestIDFrom returns the request id (also sent as X-Request-Id), or "" outside a request.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func contextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}
