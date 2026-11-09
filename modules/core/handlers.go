package core

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	// The zone list of the box must not depend on the host (a slim container has none): PUT /core/general
	// validates time zone names and the audit filters turn a day into hours with them.
	_ "time/tzdata"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
)

// APIHandlers implements the sign-in, account, user, first-run setup, audit and general-settings operations of
// the core module (S-CORE-1 and S-CORE-3). Embed it in the composite handler beside ModuleHandlers; the two
// implement disjoint operations. The handlers are thin: the rules live in core/auth, the checks of the
// contract (route table, roles, CSRF) in core/server.
type APIHandlers struct {
	db      *store.DB
	auth    *auth.Service
	reg     *modreg.Registry
	audit   *audit.Log
	secrets *secrets.Store
	log     *slog.Logger
	now     func() time.Time
}

// HandlersConfig wires APIHandlers; every field but Clock is required.
type HandlersConfig struct {
	DB      *store.DB
	Auth    *auth.Service
	Reg     *modreg.Registry
	Audit   *audit.Log
	Secrets *secrets.Store
	Log     *slog.Logger
	Clock   func() time.Time // nil: time.Now
}

// NewAPIHandlers returns the handlers.
func NewAPIHandlers(c HandlersConfig) (*APIHandlers, error) {
	if c.DB == nil || c.Auth == nil || c.Reg == nil || c.Audit == nil || c.Secrets == nil || c.Log == nil {
		return nil, errors.New("core: HandlersConfig needs DB, Auth, Reg, Audit, Secrets and Log")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	return &APIHandlers{db: c.DB, auth: c.Auth, reg: c.Reg, audit: c.Audit, secrets: c.Secrets, log: c.Log, now: c.Clock}, nil
}

// caller is who a signed-in request acts as.
type caller struct {
	server.Principal
	SessionID string
}

// caller returns the principal the server authenticated and the id of the session the request came in on.
// Both exist for every non-public operation; their absence is a wiring bug, not a client error.
func (h *APIHandlers) caller(ctx context.Context) (caller, error) { return callerOf(ctx, h.auth) }

// callerOf is caller for any handler set that holds the auth service.
func callerOf(ctx context.Context, a *auth.Service) (caller, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return caller{}, apierr.Unauthenticated()
	}
	x, ok := server.ExchangeFrom(ctx)
	if !ok {
		return caller{}, errors.New("core: no HTTP exchange in the request context")
	}
	sid, err := a.Sessions.CurrentID(x.R)
	if errors.Is(err, server.ErrNoSession) {
		return caller{}, apierr.Unauthenticated()
	}
	if err != nil {
		return caller{}, err
	}
	return caller{Principal: p, SessionID: sid}, nil
}

// exchange returns the HTTP exchange and the client address; the address must parse (a request without a
// usable peer address cannot be rate limited and is refused as an internal error, never keyed to a shared value).
func exchange(ctx context.Context) (server.Exchange, netip.Addr, error) {
	x, ok := server.ExchangeFrom(ctx)
	if !ok {
		return server.Exchange{}, netip.Addr{}, errors.New("core: no HTTP exchange in the request context")
	}
	ip := x.ClientAddr()
	if !ip.IsValid() {
		return server.Exchange{}, netip.Addr{}, errors.New("core: the client address is not an IP address")
	}
	return x, ip, nil
}

// setSession sends the session, CSRF and device cookies of a sign-in.
func setSession(x server.Exchange, s auth.Issued, device string) {
	for _, c := range s.Cookies() {
		x.SetCookie(c)
	}
	if device != "" {
		x.SetCookie(auth.DeviceCookie(device))
	}
}

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

// renewSession sends the cookies of the session that replaced the caller's (password change, two-step turned
// on or off): the old tokens no longer work, the user stays signed in. device is a new device cookie value
// to set along ("" for none).
func renewSession(ctx context.Context, fresh auth.Issued, device string) error {
	x, ok := server.ExchangeFrom(ctx)
	if !ok {
		return errors.New("core: no HTTP exchange in the request context")
	}
	setSession(x, fresh, device)
	return nil
}
