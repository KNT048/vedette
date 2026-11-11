package authoidc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	authoidc "github.com/knt048/vedette/modules/auth-oidc"
	core "github.com/knt048/vedette/modules/core"
)

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// wantCode fails unless err is an *apierr.Error with that status and code.
func wantCode(t *testing.T, err error, status int, code string) {
	t.Helper()
	e, ok := apierr.As(err)
	if !ok || e.Status != status || e.Code != code {
		t.Fatalf("err = %v, want %d %s", err, status, code)
	}
}

func userByEmail(t *testing.T, w *world) (role string, iss, sub *string, found bool) {
	t.Helper()
	err := w.env.DB.Reader().QueryRowContext(t.Context(), `SELECT role, sso_issuer, sso_subject FROM core_user WHERE email = 'ana@acme.example'`).Scan(&role, &iss, &sub)
	return role, iss, sub, err == nil
}

func TestContract_TablesUseThePrefix(t *testing.T) {
	storetest.AssertMigrationsUsePrefix(t, "auth-oidc", authoidc.Migrations, "oidc_", storetest.Migration{Module: "core", FS: core.Migrations})
}

// INV-1, INV-7, INV-8, INV-9, INV-10: the happy path. Highest mapped role, (iss, sub) identity, a session like a password sign-in,
// the email stored lower case, audit rows; PKCE verifier and client secret reached the token endpoint.
func TestContract_INV1_SignInCreatesTheAccountWithTheHighestRole(t *testing.T) {
	w := newWorld(t)
	sess, err := w.signIn()
	if err != nil {
		t.Fatal(err)
	}
	if sess.Token == "" || sess.CSRFToken == "" {
		t.Fatalf("session = %+v", sess)
	}
	role, iss, sub, ok := userByEmail(t, w)
	if !ok || role != "operator" || iss == nil || *iss != w.idp.issuer() || *sub != "user-1" {
		t.Fatalf("user: ok=%v role=%s iss=%v sub=%v", ok, role, iss, sub)
	}
	if !w.idp.gotAuth || len(w.idp.gotVerify) < 43 {
		t.Fatalf("token endpoint: secret ok=%v verifier=%q", w.idp.gotAuth, w.idp.gotVerify)
	}
	for _, a := range [][2]string{{"user.create", "SSO, role operator"}, {"auth.login", "SSO"}} {
		if !w.auditHas(a[0], a[1]) {
			t.Errorf("no audit %s %q", a[0], a[1])
		}
	}
	// D-195 (5): no password works for this account, and the second sign-in reuses it.
	if _, err := w.env.Svc.Login(t.Context(), auth.LoginRequest{Email: "ana@acme.example", Password: authtest.Password, IP: netip.MustParseAddr("192.0.2.1")}); err == nil {
		t.Fatal("password sign-in of an SSO account worked")
	}
	if _, err := w.signIn(); err != nil {
		t.Fatal(err)
	}
	if n := w.env.Count(t, `SELECT count(*) FROM core_user WHERE email = 'ana@acme.example'`); n != 1 {
		t.Fatalf("%d accounts", n)
	}
}

// INV-5: unknown state (no audit row), replay, wrong binding (spent), expired, configuration changed in between.
func TestContract_INV5_StateBindingAndReplay(t *testing.T) {
	w := newWorld(t)
	before := w.env.Count(t, `SELECT count(*) FROM core_audit`)
	_, err := w.callback("no-such-state", "x")
	wantCode(t, err, 400, "sso_expired")
	if after := w.env.Count(t, `SELECT count(*) FROM core_audit`); after != before {
		t.Fatal("an unknown state wrote to the audit log")
	}

	s, b := w.start()
	if _, err := w.callback(s, b); err != nil {
		t.Fatal(err)
	}
	_, err = w.callback(s, b) // replay of a used state
	wantCode(t, err, 400, "sso_expired")

	s, b = w.start()
	_, err = w.callback(s, "another-tab")
	wantCode(t, err, 400, "sso_expired")
	if !w.auditHas("auth.login_failed", "SSO: binding") {
		t.Fatal("no audit for the wrong binding")
	}
	_, err = w.callback(s, b) // the right binding after a wrong one: the flow is spent
	wantCode(t, err, 400, "sso_expired")

	s, b = w.start()
	w.env.Clock.Advance(11 * time.Minute)
	_, err = w.callback(s, b)
	wantCode(t, err, 400, "sso_expired")
	if !w.auditHas("auth.login_failed", "SSO: state") {
		t.Fatal("no audit for the expired flow")
	}

	w.claim("exp", w.env.Clock.Now().Add(5*time.Minute).Unix())
	s, b = w.start()
	w.configure(authoidc.Save{ClientID: "vedette", RoleMap: []authoidc.RoleRow{{Group: "staff", Role: routes.Viewer}}, Issuer: w.idp.issuer() + "/realm-2"})
	_, err = w.callback(s, b)
	wantCode(t, err, 400, "sso_expired")
}

// INV-1: every ID-token check refuses with sso_failed and writes "SSO: id_token"; nothing is created.
func TestContract_INV1_IDTokenRejections(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	cases := []struct {
		name string
		set  func(w *world)
	}{
		{"wrong nonce", func(w *world) { w.claim("nonce", "not-the-nonce") }},
		{"wrong audience", func(w *world) { w.claim("aud", "someone-else") }},
		{"audience list with another azp", func(w *world) { w.claim("aud", []string{"vedette", "x"}); w.claim("azp", "x") }},
		{"azp alone not this client", func(w *world) { w.claim("azp", "x") }},
		{"wrong issuer", func(w *world) { w.claim("iss", "https://evil.example") }},
		{"expired", func(w *world) { w.claim("exp", w.env.Clock.Now().Add(-2*time.Minute).Unix()) }},
		{"alg none", func(w *world) {
			w.idp.set(func(f *fakeIDP) {
				f.sign = func(claims string) string {
					return b64([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + b64([]byte(claims)) + "."
				}
			})
		}},
		{"HS256 keyed with the public key", func(w *world) {
			w.idp.set(func(f *fakeIDP) {
				f.sign = func(claims string) string { return f.signWith(jose.HS256, f.pubDER(), f.kid, []byte(claims)) }
			})
		}},
		{"signed by another key with the same kid", func(w *world) {
			w.idp.set(func(f *fakeIDP) {
				f.sign = func(claims string) string { return f.signWith(jose.RS256, other, f.kid, []byte(claims)) }
			})
		}},
		{"ES256 when the provider says RS256", func(w *world) {
			w.idp.set(func(f *fakeIDP) {
				f.sign = func(claims string) string { return f.signWith(jose.ES256, ec, f.kid, []byte(claims)) }
			})
		}},
		{"no sub", func(w *world) { w.claim("sub", "") }},
		{"sub over 255 bytes", func(w *world) { w.claim("sub", strings.Repeat("s", 256)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			tc.set(w)
			_, err := w.signIn()
			wantCode(t, err, 400, "sso_failed")
			if !w.auditHas("auth.login_failed", "SSO: id_token") {
				t.Fatal("no audit row")
			}
			if _, _, _, ok := userByEmail(t, w); ok {
				t.Fatal("an account was created")
			}
		})
	}
	// Inside the 1-minute skew the token still counts.
	w := newWorld(t)
	w.claim("exp", w.env.Clock.Now().Add(-30*time.Second).Unix())
	if _, err := w.signIn(); err != nil {
		t.Fatalf("within skew: %v", err)
	}
}

// The token endpoint refusing the code (or the PKCE verifier) is sso_failed "SSO: token"; a token endpoint that cannot be reached is
// idp_unreachable.
func TestContract_TokenEndpoint(t *testing.T) {
	w := newWorld(t)
	w.idp.set(func(f *fakeIDP) { f.tokenErr = 400 })
	_, err := w.signIn()
	wantCode(t, err, 400, "sso_failed")
	if !w.auditHas("auth.login_failed", "SSO: token") {
		t.Fatal("no audit row")
	}
	w.idp.set(func(f *fakeIDP) { f.tokenErr = 0 })
	s, b := w.start()
	w.idp.set(func(f *fakeIDP) { f.challenge = "tampered" }) // the verifier no longer matches what the IdP saw
	_, err = w.callback(s, b)
	wantCode(t, err, 400, "sso_failed")

	s, b = w.start()
	w.idp.srv.Close()
	_, err = w.callback(s, b)
	wantCode(t, err, 502, "idp_unreachable")
}

// INV-7: no mapped group and no default role → no_access, no account; for an existing account, its sessions end. A default role
// lets a person in no group in. The role follows the groups at every sign-in and a change ends the old sessions.
func TestContract_INV7_RolesFollowTheGroups(t *testing.T) {
	w := newWorld(t)
	w.claim("groups", []string{"someone-else"})
	_, err := w.signIn()
	wantCode(t, err, 403, "no_access")
	if _, _, _, ok := userByEmail(t, w); ok {
		t.Fatal("an account was created without access")
	}

	w.claim("groups", "vedette-admins") // a single string counts as one group
	first, err := w.signIn()
	if err != nil {
		t.Fatal(err)
	}
	if role, _, _, _ := userByEmail(t, w); role != "admin" {
		t.Fatalf("role = %s", role)
	}
	w.claim("groups", []any{"staff", 7, strings.Repeat("v", 257), "vedette-operators"}) // non-strings and over-long names are dropped
	if _, err := w.signIn(); err != nil {
		t.Fatal(err)
	}
	if role, _, _, _ := userByEmail(t, w); role != "operator" {
		t.Fatalf("role = %s", role)
	}
	if _, err := w.env.Svc.Sessions.Lookup(t.Context(), first.Token); err == nil {
		t.Fatal("the session of the old role is still live")
	}
	if !w.auditHas("user.role", "admin to operator (SSO groups)") {
		t.Fatal("no user.role row")
	}

	live, err := w.signIn()
	if err != nil {
		t.Fatal(err)
	}
	w.claim("groups", []string{})
	_, err = w.signIn()
	wantCode(t, err, 403, "no_access")
	if _, err := w.env.Svc.Sessions.Lookup(t.Context(), live.Token); err == nil {
		t.Fatal("leaving the groups left a session live")
	}

	w.configure(authoidc.Save{DefaultRole: routes.Viewer})
	if _, err := w.signIn(); err != nil {
		t.Fatal(err)
	}
	if role, _, _, _ := userByEmail(t, w); role != "viewer" {
		t.Fatalf("default role: %s", role)
	}
}

// INV-8: never linked to a password account; an unverified email cannot make an account or move one; an old issuer's SSO account
// moves to the new issuer only with a verified email; a disabled account is refused.
func TestContract_INV8_AccountsAndEmail(t *testing.T) {
	w := newWorld(t)
	w.env.User(t, "ana@acme.example", routes.Admin)
	_, err := w.signIn()
	wantCode(t, err, 409, "email_in_use")

	w2 := newWorld(t)
	w2.claim("email_verified", false)
	_, err = w2.signIn()
	wantCode(t, err, 403, "email_unverified")
	w2.claim("email_verified", "true") // some providers send a string
	if _, err := w2.signIn(); err != nil {
		t.Fatal(err)
	}

	// The IdP changes: the account made by the old issuer moves only with email_verified true.
	w2.claim("sub", "user-1-new")
	w2.configure(authoidc.Save{Issuer: w2.idp.issuer() + "/new", RoleMap: []authoidc.RoleRow{{Group: "staff", Role: routes.Viewer}}})
	w2.claim("iss", w2.idp.issuer()+"/new")
	w2.idp.set(func(f *fakeIDP) { delete(f.claims, "email_verified") })
	_, err = w2.signIn()
	wantCode(t, err, 409, "email_in_use")
	w2.claim("email_verified", true)
	if _, err := w2.signIn(); err != nil {
		t.Fatal(err)
	}
	if _, iss, sub, _ := userByEmail(t, w2); *iss != w2.idp.issuer()+"/new" || *sub != "user-1-new" {
		t.Fatalf("not relinked: %s %s", *iss, *sub)
	}
	if w2.env.Count(t, `SELECT count(*) FROM core_audit WHERE action = 'user.sso_relink'`) != 1 {
		t.Fatal("no relink audit row")
	}

	// Disabled: refused whatever the IdP says.
	if err := w2.env.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE core_user SET disabled = 1 WHERE email = 'ana@acme.example'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, err = w2.signIn()
	wantCode(t, err, 403, "disabled")
}

// INV-2, INV-3, INV-6: validation, the secret kept (last 4 only, empty keeps it), redirect pinned at save, start from another
// address refused, module not configured.
func TestContract_INV2_SaveAndView(t *testing.T) {
	w := newWorld(t)
	bad := []struct {
		s    authoidc.Save
		code string
	}{
		{authoidc.Save{Issuer: "http://idp.example", ClientID: "c", ClientSecret: "12345678", Scopes: "openid", GroupsClaim: "groups"}, "invalid_issuer"},
		{authoidc.Save{Issuer: "https://idp.example?x=1", ClientID: "c", ClientSecret: "12345678", Scopes: "openid", GroupsClaim: "groups"}, "invalid_issuer"},
		{authoidc.Save{Issuer: "https://idp.example", ClientID: "", ClientSecret: "12345678", Scopes: "openid", GroupsClaim: "groups"}, "invalid_client"},
		{authoidc.Save{Issuer: "https://idp.example", ClientID: "c", ClientSecret: "short", Scopes: "openid", GroupsClaim: "groups"}, "invalid_secret"},
		{authoidc.Save{Issuer: "https://idp.example", ClientID: "c", ClientSecret: "12345678", Scopes: "email profile", GroupsClaim: "groups"}, "invalid_scopes"},
		{authoidc.Save{Issuer: "https://idp.example", ClientID: "c", ClientSecret: "12345678", Scopes: "openid", GroupsClaim: "a b"}, "invalid_claim"},
		{authoidc.Save{Issuer: "https://idp.example", ClientID: "c", ClientSecret: "12345678", Scopes: "openid", GroupsClaim: "g", DefaultRole: "root"}, "invalid_role"},
	}
	for _, b := range bad {
		_, err := w.svc.Store(t.Context(), "admin@acme.example", origin, b.s)
		wantCode(t, err, 400, b.code)
	}
	rows := make([]authoidc.RoleRow, 11)
	for i := range rows {
		rows[i] = authoidc.RoleRow{Group: strings.Repeat("g", i+1), Role: routes.Viewer}
	}
	_, err := w.svc.Store(t.Context(), "admin@acme.example", origin, authoidc.Save{Issuer: "https://idp.example", ClientID: "c", Scopes: "openid", GroupsClaim: "g", RoleMap: rows})
	wantCode(t, err, 400, "too_many")

	c, _, err := w.svc.View(t.Context(), "https://other.test")
	if err != nil {
		t.Fatal(err)
	}
	if c.SecretLast4 != "-123" || c.Issuer != w.idp.issuer() || c.RedirectURI != origin+"/sso/callback" {
		t.Fatalf("view = %+v", c)
	}
	// Empty secret keeps the stored one; the plain secret is nowhere in the database but the encrypted row.
	w.configure(authoidc.Save{ClientSecret: "", RoleMap: []authoidc.RoleRow{{Group: "staff", Role: routes.Viewer}}})
	if n := w.env.Count(t, `SELECT count(*) FROM oidc_config WHERE secret_last4 = '-123'`); n != 1 {
		t.Fatal("the secret was not kept")
	}
	if _, err := w.signIn(); err != nil {
		t.Fatalf("after keeping the secret: %v", err)
	}
	// D-194 (5): another address of the box cannot start.
	_, err = w.svc.Start(t.Context(), "https://192.0.2.99", w.addr)
	wantCode(t, err, 409, "sso_wrong_address")
}

func TestContract_PRE3_NotConfigured(t *testing.T) {
	env := authtest.New(t)
	if err := storeMigrate(t, env); err != nil {
		t.Fatal(err)
	}
	svc, err := authoidc.New(authoidc.Deps{DB: env.DB, Secrets: env.Secrets, Auth: env.Svc, Audit: env.Audit, Log: discard(), Clock: env.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if on, err := svc.Configured(t.Context()); err != nil || on {
		t.Fatalf("Configured = %v, %v", on, err)
	}
	_, err = svc.Start(t.Context(), origin, netip.MustParseAddr("192.0.2.1"))
	wantCode(t, err, 400, "oidc_off")
	_, err = svc.Test(t.Context(), "admin@acme.example")
	wantCode(t, err, 400, "not_configured")
	c, n, err := svc.View(t.Context(), origin)
	if err != nil || c.Scopes != authoidc.DefaultScopes || c.GroupsClaim != "groups" || c.DefaultRole != "" || c.RedirectURI != origin+"/sso/callback" || n != 0 {
		t.Fatalf("defaults = %+v %d %v", c, n, err)
	}
}

// INV-11 and POST-1: discovery through Test. Endpoints read; a non-https endpoint, an issuer that is not ours, a redirect, an
// answer over 1 MiB and a provider that only signs with HS256 all fail with discovery_failed; each test is audited.
func TestContract_INV11_Discovery(t *testing.T) {
	w := newWorld(t)
	ep, err := w.svc.Test(t.Context(), "admin@acme.example")
	if err != nil || ep.JWKS != w.idp.issuer()+"/jwks" || ep.Token != w.idp.issuer()+"/token" {
		t.Fatalf("Test = %+v, %v", ep, err)
	}
	for name, set := range map[string]func(f *fakeIDP){
		"http token endpoint": func(f *fakeIDP) { f.discovery = map[string]any{"token_endpoint": "http://plain.example/token"} }, //nolint:gosec // an address, not a credential
		"another issuer":      func(f *fakeIDP) { f.discovery = map[string]any{"issuer": "https://evil.example"} },
		"redirect":            func(f *fakeIDP) { f.redirect = true },
		"over 1 MiB":          func(f *fakeIDP) { f.big = true },
		"HS256 only": func(f *fakeIDP) {
			f.discovery = map[string]any{"id_token_signing_alg_values_supported": []string{"HS256", "none"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.idp.set(set)
			_, err := w.svc.Test(t.Context(), "admin@acme.example")
			wantCode(t, err, 502, "discovery_failed")
			_, err = w.svc.Start(t.Context(), origin, w.addr)
			wantCode(t, err, 502, "idp_unreachable")
		})
	}
	if w.env.Count(t, `SELECT count(*) FROM core_audit WHERE action = 'oidc.test'`) != 1 || w.env.Count(t, `SELECT count(*) FROM core_audit WHERE action = 'oidc.update'`) < 1 {
		t.Fatal("audit rows of oidc.test / oidc.update")
	}
}

// INV-5: start and callback are counted per address.
func TestContract_INV5_RateLimit(t *testing.T) {
	w := newWorld(t)
	for i := range 30 {
		if _, err := w.svc.Start(t.Context(), origin, w.addr); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	_, err := w.svc.Start(t.Context(), origin, w.addr)
	wantCode(t, err, 429, "rate_limited")
	if _, err := w.svc.Start(t.Context(), origin, netip.MustParseAddr("192.0.2.11")); err != nil {
		t.Fatalf("another address: %v", err)
	}
	w.env.Clock.Advance(16 * time.Minute)
	if _, err := w.svc.Start(t.Context(), origin, w.addr); err != nil {
		t.Fatalf("after the window: %v", err)
	}
	if n := w.env.Count(t, `SELECT count(*) FROM oidc_flow`); n > 1000 {
		t.Fatalf("%d flows", n)
	}
}

func TestMapRole(t *testing.T) {
	rows := []authoidc.RoleRow{{Group: "a", Role: routes.Viewer}, {Group: "b", Role: routes.Admin}, {Group: "c", Role: routes.Operator}}
	for _, tc := range []struct {
		groups []string
		def    routes.Role
		want   routes.Role
	}{
		{[]string{"a", "c"}, "", routes.Operator},
		{[]string{"c", "b"}, "", routes.Admin},
		{[]string{"z"}, "", ""},
		{nil, routes.Viewer, routes.Viewer},
		{[]string{"A"}, "", ""}, // group names match exactly
	} {
		if got := authoidc.MapRole(tc.groups, rows, tc.def); got != tc.want {
			t.Errorf("MapRole(%v, %q) = %q, want %q", tc.groups, tc.def, got, tc.want)
		}
	}
}

func storeMigrate(t *testing.T, env *authtest.Env) error {
	t.Helper()
	return store.Migrate(t.Context(), env.DB, "auth-oidc", authoidc.Migrations)
}
