package authoidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/store"
)

const (
	flowLifetime = 10 * time.Minute
	maxFlows     = 1000
	maxGroups    = 200
	maxGroupLen  = 256
	clockSkew    = time.Minute
	maxCodeLen   = 4096
)

func oidcOff() *apierr.Error {
	return apierr.New(400, "oidc_off", "SSO sign-in is not set up. Sign in with your email and password, or ask an administrator.")
}

func ssoExpired() *apierr.Error {
	return apierr.New(400, "sso_expired", "This sign-in has expired or was already used. Start again from the sign-in page.")
}

func ssoFailed() *apierr.Error {
	return apierr.New(400, "sso_failed", "The identity provider's answer could not be verified. Ask an administrator to check the SSO settings; the audit log has the reason.")
}

func idpUnreachable(issuer string) *apierr.Error {
	return apierr.New(502, "idp_unreachable", "Vedette cannot reach the identity provider at "+issuer+". Try again; if it keeps failing, sign in with your email and password or ask an administrator.")
}

func rateLimited(wait time.Duration) *apierr.Error {
	secs := max(1, int(math.Ceil(wait.Seconds())))
	return apierr.New(429, "rate_limited", fmt.Sprintf("Too many SSO sign-in attempts from this address. Try again in %d minutes.", max(1, (secs+59)/60))).With("retry_after", secs)
}

// token is 32 random bytes, base64url without padding (256 bits: state, binding, nonce).
func token() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("authoidc: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// Started is the answer of POST /auth/oidc/start.
type Started struct{ AuthorizeURL, Binding string }

// Start begins a sign-in (D-194, INV-5, INV-6): origin is scheme://host of the request; it must be the origin of the pinned
// redirect URI (409 sso_wrong_address). The flow is stored with SHA-256 of state and binding; the page keeps the binding.
func (s *Service) Start(ctx context.Context, origin string, ip netip.Addr) (Started, error) {
	if ok, wait := s.limit.allow(limitKey("start", ip)); !ok {
		return Started{}, rateLimited(wait)
	}
	c, err := s.load(ctx)
	if errors.Is(err, errNotConfigured) {
		return Started{}, oidcOff()
	}
	if err != nil {
		return Started{}, err
	}
	if callbackURL(origin) != c.RedirectURI {
		at := strings.TrimSuffix(c.RedirectURI, "/sso/callback")
		return Started{}, apierr.New(409, "sso_wrong_address", "SSO sign-in works at "+at+". Open Vedette there to sign in with SSO.").With("address", at)
	}
	d, err := s.discover(ctx, c.Issuer, false)
	if err != nil {
		s.log.WarnContext(ctx, "SSO discovery failed", "issuer", c.Issuer, "err", reason(err))
		return Started{}, idpUnreachable(c.Issuer)
	}
	state, err := token()
	if err != nil {
		return Started{}, err
	}
	binding, err := token()
	if err != nil {
		return Started{}, err
	}
	nonce, err := token()
	if err != nil {
		return Started{}, err
	}
	verifier := oauth2.GenerateVerifier()
	now := s.now()
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_flow WHERE expires_at <= ?`, store.FormatTS(now)); err != nil {
			return fmt.Errorf("authoidc: prune flows: %w", err)
		}
		// At most maxFlows pending: the oldest go first (a flood of starts cannot grow the table).
		if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_flow WHERE state_hash IN (SELECT state_hash FROM oidc_flow ORDER BY created_at DESC, state_hash LIMIT -1 OFFSET ?)`, maxFlows-1); err != nil {
			return fmt.Errorf("authoidc: cap flows: %w", err)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO oidc_flow (state_hash, binding_hash, nonce, verifier, issuer, client_id, redirect_uri, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			sha(state), sha(binding), nonce, verifier, c.Issuer, c.ClientID, c.RedirectURI, store.FormatTS(now), store.FormatTS(now.Add(flowLifetime)))
		if err != nil {
			return fmt.Errorf("authoidc: store flow: %w", err)
		}
		return nil
	})
	if err != nil {
		return Started{}, err
	}
	oc := oauth2.Config{ClientID: c.ClientID, Endpoint: d.provider.Endpoint(), RedirectURL: c.RedirectURI, Scopes: strings.Fields(c.Scopes)}
	return Started{AuthorizeURL: oc.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), Binding: binding}, nil
}

// flow is a pending sign-in, taken out of oidc_flow by the callback.
type flow struct {
	bindingHash, nonce, verifier, issuer, clientID, redirectURI string
	expiresAt                                                   string
}

// take deletes and returns the flow of state (single use, INV-5): found=false when there is none.
func (s *Service) take(ctx context.Context, state string) (flow, bool, error) {
	var f flow
	found := false
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `DELETE FROM oidc_flow WHERE state_hash = ? RETURNING binding_hash, nonce, verifier, issuer, client_id, redirect_uri, expires_at`, sha(state)).
			Scan(&f.bindingHash, &f.nonce, &f.verifier, &f.issuer, &f.clientID, &f.redirectURI, &f.expiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("authoidc: take flow: %w", err)
		}
		found = true
		return nil
	})
	return f, found, err
}

// CallbackRequest is POST /auth/oidc/callback with what the handler knows of the browser.
type CallbackRequest struct {
	Code, State, Binding string
	IP                   netip.Addr
	UserAgent            string
}

// Callback finishes a sign-in (D-194, D-195, INV-1, INV-5, INV-7, INV-8): the flow must exist, be fresh, belong to the
// configuration of now and to this tab (binding); the code is exchanged with the PKCE verifier and the client secret; the ID token
// is verified (signature with the issuer's keys, alg, iss, aud, azp, exp, nonce); the groups give the role; core/auth signs the
// person in. An unknown state answers sso_expired and writes nothing (anyone can send one, INV-5); every other refusal is audited.
func (s *Service) Callback(ctx context.Context, in CallbackRequest) (auth.Issued, error) {
	if ok, wait := s.limit.allow(limitKey("callback", in.IP)); !ok {
		return auth.Issued{}, rateLimited(wait)
	}
	c, err := s.load(ctx)
	if errors.Is(err, errNotConfigured) {
		return auth.Issued{}, oidcOff()
	}
	if err != nil {
		return auth.Issued{}, err
	}
	if len(in.State) > 128 || len(in.Binding) > 128 {
		return auth.Issued{}, ssoExpired()
	}
	f, found, err := s.take(ctx, in.State)
	if err != nil {
		return auth.Issued{}, err
	}
	if !found {
		return auth.Issued{}, ssoExpired()
	}
	refuse := func(why string, e *apierr.Error) (auth.Issued, error) {
		if err := s.auth.RefuseSSO(ctx, c.Issuer, why); err != nil {
			return auth.Issued{}, err
		}
		return auth.Issued{}, e
	}
	if f.expiresAt <= store.FormatTS(s.now()) || f.issuer != c.Issuer || f.clientID != c.ClientID || f.redirectURI != c.RedirectURI {
		return refuse("state", ssoExpired())
	}
	if subtle.ConstantTimeCompare([]byte(sha(in.Binding)), []byte(f.bindingHash)) != 1 {
		return refuse("binding", apierr.New(400, "sso_expired", "This sign-in was started in another tab or browser. Start again from the sign-in page."))
	}
	if in.Code == "" || len(in.Code) > maxCodeLen {
		return refuse("token", ssoFailed())
	}
	d, err := s.discover(ctx, c.Issuer, false)
	if err != nil {
		s.log.WarnContext(ctx, "SSO discovery failed", "issuer", c.Issuer, "err", reason(err))
		return refuse("token", idpUnreachable(c.Issuer))
	}
	secret, err := s.secrets.Open(ctx, s.db.Reader(), c.secretID, secretPurpose)
	if err != nil {
		return auth.Issued{}, fmt.Errorf("authoidc: open client secret: %w", err)
	}
	ep := d.provider.Endpoint()
	ep.AuthStyle = d.authStyle // D-194 (1): the method the provider names, never a retry with the secret in another place
	oc := oauth2.Config{ClientID: c.ClientID, ClientSecret: string(secret), Endpoint: ep, RedirectURL: f.redirectURI}
	tok, err := oc.Exchange(oidc.ClientContext(ctx, s.client), in.Code, oauth2.VerifierOption(f.verifier))
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) { // the identity provider answered and refused the code
			s.log.WarnContext(ctx, "SSO code exchange refused", "issuer", c.Issuer, "status", re.Response.StatusCode, "error", re.ErrorCode)
			return refuse("token", ssoFailed())
		}
		s.log.WarnContext(ctx, "SSO token endpoint unreachable", "issuer", c.Issuer, "err", reason(err))
		return refuse("token", idpUnreachable(c.Issuer))
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return refuse("id_token", ssoFailed())
	}
	claims, why := s.verify(ctx, d, c.ClientID, f.nonce, raw)
	if why != "" {
		s.log.WarnContext(ctx, "SSO ID token refused", "issuer", c.Issuer, "reason", why)
		return refuse("id_token", ssoFailed())
	}
	return s.auth.SSOSignIn(ctx, auth.SSOIdentity{
		// Issuer: the configured one, which iss was checked against (go-oidc also lets Google's bare host through).
		Issuer: c.Issuer, Subject: claims.sub, Email: claims.email, EmailVerified: claims.emailVerified, Name: claims.name,
		Role: MapRole(claims.groups(c.GroupsClaim), c.RoleMap, c.DefaultRole), IP: in.IP, UserAgent: in.UserAgent,
	})
}

// idClaims are the claims of a verified ID token that Vedette reads.
type idClaims struct {
	iss, sub, email, name string
	emailVerified         *bool
	all                   map[string]json.RawMessage
}

// verify checks the ID token (INV-1) and returns its claims, or a short reason for the log (never the token).
func (s *Service) verify(ctx context.Context, d *idp, clientID, nonce, raw string) (idClaims, string) {
	// Verifier reuses the provider's key set, fetched once and again only for an unknown key id; the token comes from the token
	// endpoint over TLS, so a stranger cannot pick the key id.
	v := d.provider.Verifier(&oidc.Config{
		ClientID:             clientID,
		SupportedSigningAlgs: d.algs,
		Now:                  func() time.Time { return s.now().Add(-clockSkew) }, // exp may be up to 1 minute behind this clock
	})
	t, err := v.Verify(ctx, raw)
	if err != nil {
		return idClaims{}, reason(err)
	}
	if subtle.ConstantTimeCompare([]byte(t.Nonce), []byte(nonce)) != 1 {
		return idClaims{}, "nonce does not match"
	}
	var all map[string]json.RawMessage
	if err := t.Claims(&all); err != nil {
		return idClaims{}, "claims: " + reason(err)
	}
	c := idClaims{iss: t.Issuer, sub: t.Subject, all: all}
	if c.sub == "" || len(c.sub) > 255 {
		return idClaims{}, "sub is missing or longer than 255 bytes"
	}
	// OIDC Core 3.1.3.7 (3)-(5): when azp is present it is this client; a token for several audiences must name this client as azp.
	azpRaw, hasAzp := all["azp"]
	if hasAzp {
		var azp string
		if json.Unmarshal(azpRaw, &azp) != nil || azp != clientID {
			return idClaims{}, "azp is not this client"
		}
	}
	if len(t.Audience) > 1 && !hasAzp {
		return idClaims{}, "several audiences and no azp"
	}
	_ = json.Unmarshal(all["email"], &c.email)
	_ = json.Unmarshal(all["name"], &c.name)
	if raw, ok := all["email_verified"]; ok {
		var b bool
		var str string
		switch {
		case json.Unmarshal(raw, &b) == nil:
		case json.Unmarshal(raw, &str) == nil && (str == "true" || str == "false"): // some providers send a string
			b = str == "true"
		default:
			b = false // anything else is not a yes
		}
		c.emailVerified = &b
	}
	return c, ""
}

// groups reads the groups claim (D-195 (4)): a top-level claim named exactly claim (not a path), a string or an array of strings;
// only the first maxGroups entries count, and an entry longer than maxGroupLen is dropped, never cut.
func (c idClaims) groups(claim string) []string {
	raw, ok := c.all[claim]
	if !ok {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		raw = json.RawMessage(`[` + string(raw) + `]`)
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	out := make([]string, 0, min(len(list), maxGroups))
	for _, item := range list[:min(len(list), maxGroups)] {
		var g string
		if json.Unmarshal(item, &g) == nil && g != "" && len(g) <= maxGroupLen {
			out = append(out, g)
		}
	}
	return out
}

// MapRole is D-195 (1): the highest role among the rows whose group the person is in; no row → def ("" = no access).
func MapRole(groups []string, rows []RoleRow, def routes.Role) routes.Role {
	best := routes.Role("")
	for _, r := range rows {
		if slices.Contains(groups, r.Group) && rank(r.Role) > rank(best) {
			best = r.Role
		}
	}
	if best == "" {
		return def
	}
	return best
}

func rank(r routes.Role) int {
	switch r {
	case routes.Viewer:
		return 1
	case routes.Operator:
		return 2
	case routes.Admin:
		return 3
	}
	return 0
}
