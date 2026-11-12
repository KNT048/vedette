package authoidc

import (
	"context"
	"errors"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// OIDCHandlers implement the operations of the auth-oidc module (CONTRACT "Endpoints owned"). The server answers 404 for all of them
// while the module is off (SYS-5); the role and CSRF checks of the admin ones run before these methods.
type OIDCHandlers struct{ s *Service }

// NewHandlers wraps the service; nil gives 501 for every operation (server.Fallback), like a module that is not wired.
func NewHandlers(s *Service) *OIDCHandlers { return &OIDCHandlers{s: s} }

// origin is scheme://host of the request: the scheme this process serves (never a forwarded header) and the Host the server let
// through its allowlist (core INV-9), as checkOrigin uses them.
func origin(x server.Exchange) string {
	scheme := "http"
	if x.R.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + x.R.Host
}

func exchange(ctx context.Context) (server.Exchange, error) {
	x, ok := server.ExchangeFrom(ctx)
	if !ok {
		return server.Exchange{}, errors.New("authoidc: no HTTP exchange in the request context")
	}
	return x, nil
}

func actor(ctx context.Context) (string, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return "", apierr.Unauthenticated()
	}
	return p.Email, nil
}

// CoreGetCoreOidc implements GET /core/oidc (admin).
func (h *OIDCHandlers) CoreGetCoreOidc(ctx context.Context) (*oas.CoreGetCoreOidcOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	x, err := exchange(ctx)
	if err != nil {
		return nil, err
	}
	c, n, err := h.s.View(ctx, origin(x))
	if err != nil {
		return nil, err
	}
	out := &oas.CoreGetCoreOidcOK{
		Issuer: c.Issuer, ClientID: c.ClientID, Scopes: c.Scopes, GroupsClaim: c.GroupsClaim, RedirectURI: c.RedirectURI, SSOUsers: n,
		SecretLast4: oas.NilString{Null: true}, DefaultRole: oas.NilCoreGetCoreOidcOKDefaultRole{Null: true},
		RoleMap: make([]oas.CoreGetCoreOidcOKRoleMapItem, 0, len(c.RoleMap)), CaPem: c.CAPEM, CaCerts: []oas.CoreGetCoreOidcOKCaCertsItem{},
	}
	for _, x := range c.CACerts() {
		out.CaCerts = append(out.CaCerts, oas.CoreGetCoreOidcOKCaCertsItem{Subject: x.Subject, ExpiresAt: x.NotAfter})
	}
	if c.SecretLast4 != "" {
		out.SecretLast4 = oas.NewNilString(c.SecretLast4)
	}
	if c.DefaultRole != "" {
		out.DefaultRole = oas.NewNilCoreGetCoreOidcOKDefaultRole(oas.CoreGetCoreOidcOKDefaultRole(c.DefaultRole))
	}
	for _, r := range c.RoleMap {
		out.RoleMap = append(out.RoleMap, oas.CoreGetCoreOidcOKRoleMapItem{Group: r.Group, Role: oas.CoreGetCoreOidcOKRoleMapItemRole(r.Role)})
	}
	return out, nil
}

// CorePutCoreOidc implements PUT /core/oidc (admin).
func (h *OIDCHandlers) CorePutCoreOidc(ctx context.Context, req *oas.CorePutCoreOidcReq) (*oas.CorePutCoreOidcOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	x, err := exchange(ctx)
	if err != nil {
		return nil, err
	}
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in := Save{Issuer: req.Issuer, ClientID: req.ClientID, ClientSecret: req.ClientSecret, Scopes: req.Scopes, GroupsClaim: req.GroupsClaim}
	if !req.DefaultRole.Null {
		in.DefaultRole = routes.Role(req.DefaultRole.Value)
	}
	for _, r := range req.RoleMap {
		in.RoleMap = append(in.RoleMap, RoleRow{Group: r.Group, Role: routes.Role(r.Role)})
	}
	if v, ok := req.CaPem.Get(); ok {
		in.CAPEM = &v
	}
	if _, err := h.s.Store(ctx, who, origin(x), in); err != nil {
		return nil, err
	}
	c, n, err := h.s.View(ctx, origin(x))
	if err != nil {
		return nil, err
	}
	out := &oas.CorePutCoreOidcOK{
		Issuer: c.Issuer, ClientID: c.ClientID, Scopes: c.Scopes, GroupsClaim: c.GroupsClaim, RedirectURI: c.RedirectURI, SSOUsers: n,
		SecretLast4: oas.NewNilString(c.SecretLast4), DefaultRole: oas.NilCorePutCoreOidcOKDefaultRole{Null: true},
		RoleMap: make([]oas.CorePutCoreOidcOKRoleMapItem, 0, len(c.RoleMap)), CaPem: c.CAPEM, CaCerts: []oas.CorePutCoreOidcOKCaCertsItem{},
	}
	for _, x := range c.CACerts() {
		out.CaCerts = append(out.CaCerts, oas.CorePutCoreOidcOKCaCertsItem{Subject: x.Subject, ExpiresAt: x.NotAfter})
	}
	if c.DefaultRole != "" {
		out.DefaultRole = oas.NewNilCorePutCoreOidcOKDefaultRole(oas.CorePutCoreOidcOKDefaultRole(c.DefaultRole))
	}
	for _, r := range c.RoleMap {
		out.RoleMap = append(out.RoleMap, oas.CorePutCoreOidcOKRoleMapItem{Group: r.Group, Role: oas.CorePutCoreOidcOKRoleMapItemRole(r.Role)})
	}
	return out, nil
}

// CorePostCoreOidcTest implements POST /core/oidc/test (admin).
func (h *OIDCHandlers) CorePostCoreOidcTest(ctx context.Context) (*oas.CorePostCoreOidcTestOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	ep, err := h.s.Test(ctx, who)
	if err != nil {
		return nil, err
	}
	return &oas.CorePostCoreOidcTestOK{Ok: true, Endpoints: oas.CorePostCoreOidcTestOKEndpoints{"authorization": ep.Authorization, "token": ep.Token, "jwks": ep.JWKS}}, nil
}

// CorePostAuthOidcStart implements POST /auth/oidc/start (public).
func (h *OIDCHandlers) CorePostAuthOidcStart(ctx context.Context) (*oas.CorePostAuthOidcStartOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	x, err := exchange(ctx)
	if err != nil {
		return nil, err
	}
	st, err := h.s.Start(ctx, origin(x), x.ClientAddr())
	if err != nil {
		return nil, err
	}
	return &oas.CorePostAuthOidcStartOK{AuthorizeURL: st.AuthorizeURL, Binding: st.Binding}, nil
}

// CorePostAuthOidcCallback implements POST /auth/oidc/callback (public): on success the session and CSRF cookies, never the device
// cookie (D-196 (2)).
func (h *OIDCHandlers) CorePostAuthOidcCallback(ctx context.Context, req *oas.CorePostAuthOidcCallbackReq) (*oas.CorePostAuthOidcCallbackOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	x, err := exchange(ctx)
	if err != nil {
		return nil, err
	}
	sess, err := h.s.Callback(ctx, CallbackRequest{Code: req.Code, State: req.State, Binding: req.Binding, IP: x.ClientAddr(), UserAgent: x.R.UserAgent()})
	if err != nil {
		return nil, err
	}
	for _, c := range sess.Cookies() {
		x.SetCookie(c)
	}
	return &oas.CorePostAuthOidcCallbackOK{Ok: true}, nil
}
