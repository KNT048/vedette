package authoidc

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
)

// Deps are what the module needs from core.
type Deps struct {
	DB      *store.DB
	Secrets *secrets.Store
	Auth    *auth.Service
	Audit   *audit.Log
	Log     *slog.Logger
	Clock   func() time.Time  // nil: time.Now
	IDPBase http.RoundTripper // nil: the default transport; tests pass the httptest TLS server's
}

// Service is the auth-oidc module. Create it once with New.
type Service struct {
	db      *store.DB
	secrets *secrets.Store
	auth    *auth.Service
	audit   *audit.Log
	log     *slog.Logger
	now     func() time.Time
	client  *http.Client
	limit   *limiter

	mu    sync.Mutex
	cache *idp
}

// New builds the module service.
func New(d Deps) (*Service, error) {
	if d.DB == nil || d.Secrets == nil || d.Auth == nil || d.Audit == nil || d.Log == nil {
		return nil, errors.New("authoidc: Deps needs DB, Secrets, Auth, Audit and Log")
	}
	if d.Clock == nil {
		d.Clock = time.Now
	}
	return &Service{db: d.DB, secrets: d.Secrets, auth: d.Auth, audit: d.Audit, log: d.Log, now: d.Clock, client: newClient(d.IDPBase), limit: newLimiter(d.Clock)}, nil
}

// Endpoints is the result of Test (POST /core/oidc/test).
type Endpoints struct{ Authorization, Token, JWKS string }

// Test reads the discovery document again (POST-1) and writes oidc.test. 400 not_configured before a save; 502 discovery_failed
// with the reason, so the administrator can tell the issuer from the network path.
func (s *Service) Test(ctx context.Context, actor string) (Endpoints, error) {
	c, err := s.load(ctx)
	if errors.Is(err, errNotConfigured) {
		return Endpoints{}, apierr.New(400, "not_configured", "Save the OIDC configuration before testing.")
	}
	if err != nil {
		return Endpoints{}, err
	}
	d, derr := s.discover(ctx, c.Issuer, true)
	if err := s.db.Write(ctx, func(tx *sql.Tx) error {
		detail := "ok"
		if derr != nil {
			detail = "failed"
		}
		return s.audit.Append(ctx, tx, audit.Entry{User: actor, Action: "oidc.test", Target: c.Issuer, Detail: detail})
	}); err != nil {
		return Endpoints{}, err
	}
	if derr != nil {
		return Endpoints{}, apierr.New(502, "discovery_failed", "Cannot read "+c.Issuer+"/.well-known/openid-configuration: "+reason(derr)+". Check the issuer and the network path from the box to the identity provider.")
	}
	ep := d.provider.Endpoint()
	return Endpoints{Authorization: ep.AuthURL, Token: ep.TokenURL, JWKS: d.jwksURL}, nil
}

// reason is an error of the identity provider as one short line for a person (never a token or secret: none is in these errors).
func reason(err error) string {
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return msg
}

// clientIP is the address the limiter counts; an invalid one counts under the zero address.
func clientIP(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	return a.Unmap().WithZone("").String()
}
