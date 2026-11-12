package authoidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/store"
)

// secretPurpose is the core_secret purpose of the client secret (INV-3).
const secretPurpose = "oidc_config.client_secret" //nolint:gosec // the name of a core_secret purpose, not a credential

// DefaultScopes and DefaultGroupsClaim are what an unsaved configuration shows (D-194 (7), D-195 (1)).
const (
	DefaultScopes      = "openid email profile"
	DefaultGroupsClaim = "groups"
	maxRoleRows        = 10
)

// RoleRow maps one group at the identity provider to a role.
type RoleRow struct {
	Group string      `json:"group"`
	Role  routes.Role `json:"role"`
}

// Config is the saved configuration. DefaultRole "" is no access. The secret itself never leaves core_secret except to the token
// endpoint (INV-3).
type Config struct {
	Issuer, ClientID, SecretLast4 string
	Scopes, GroupsClaim           string
	DefaultRole                   routes.Role
	RoleMap                       []RoleRow
	RedirectURI                   string
	CAPEM                         string // D-378: normalised PEM of the identity provider's CA; "" = system roots only
	secretID                      string
}

// Save is PUT /core/oidc. ClientSecret "" keeps the stored one.
type Save struct {
	Issuer, ClientID, ClientSecret string
	Scopes, GroupsClaim            string
	DefaultRole                    routes.Role
	RoleMap                        []RoleRow
	CAPEM                          *string // D-378: nil keeps the saved CA, "" removes it
}

var (
	scopeRE = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]{1,64}$`) // RFC 6749 3.3 scope-token
	claimRE = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,64}$`)
)

// errNotConfigured: nothing saved yet.
var errNotConfigured = errors.New("authoidc: not configured")

// load reads the configuration; errNotConfigured when there is none.
func (s *Service) load(ctx context.Context) (Config, error) {
	var c Config
	var def sql.NullString
	var roleMap string
	err := s.db.Reader().QueryRowContext(ctx, `SELECT issuer, client_id, secret_id, secret_last4, scopes, groups_claim, default_role, role_map, redirect_uri, ca_pem FROM oidc_config WHERE id = 1`).
		Scan(&c.Issuer, &c.ClientID, &c.secretID, &c.SecretLast4, &c.Scopes, &c.GroupsClaim, &def, &roleMap, &c.RedirectURI, &c.CAPEM)
	if errors.Is(err, sql.ErrNoRows) {
		return Config{}, errNotConfigured
	}
	if err != nil {
		return Config{}, fmt.Errorf("authoidc: read config: %w", err)
	}
	c.DefaultRole = routes.Role(def.String)
	if err := json.Unmarshal([]byte(roleMap), &c.RoleMap); err != nil {
		return Config{}, fmt.Errorf("authoidc: role_map: %w", err)
	}
	return c, nil
}

// Configured reports whether an issuer is saved (auth-options, INV-4). The caller checks that the module is on.
func (s *Service) Configured(ctx context.Context) (bool, error) {
	_, err := s.load(ctx)
	if errors.Is(err, errNotConfigured) {
		return false, nil
	}
	return err == nil, err
}

// View is GET /core/oidc: the saved configuration, or the defaults with the redirect URI this request would pin (INV-6).
func (s *Service) View(ctx context.Context, origin string) (Config, int, error) {
	n, err := s.auth.CountSSOUsers(ctx)
	if err != nil {
		return Config{}, 0, err
	}
	c, err := s.load(ctx)
	if errors.Is(err, errNotConfigured) {
		return Config{Scopes: DefaultScopes, GroupsClaim: DefaultGroupsClaim, RedirectURI: callbackURL(origin)}, n, nil
	}
	return c, n, err
}

// callbackURL is the redirect URI of an origin: the SPA page the identity provider sends the browser back to (D-194 (4)).
func callbackURL(origin string) string { return origin + "/sso/callback" }

// validIssuer is INV-2's issuer: https, a host, no user info, query or fragment; the trailing / dropped.
func validIssuer(raw string) (string, bool) {
	iss := strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(iss)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(iss) > 2048 || auth.HasInvisible(iss) {
		return "", false
	}
	return iss, true
}

// normalize checks a Save (INV-2) and returns it trimmed, with the scopes deduplicated and empty mapping rows dropped. An empty secret
// keeps the stored one only for the same issuer and client: otherwise a changed issuer (an attacker's host, from a stolen admin
// session) would receive the real secret at its token endpoint (INV-3).
func normalize(in Save, cur Config, now time.Time) (Save, *apierr.Error) {
	var ok bool
	if in.Issuer, ok = validIssuer(in.Issuer); !ok {
		return Save{}, apierr.New(400, "invalid_issuer", "The issuer must be an https address, for example https://sso.example.com/realms/main.")
	}
	in.ClientID = strings.TrimSpace(in.ClientID)
	if n := utf8.RuneCountInString(in.ClientID); n < 1 || n > 200 || auth.HasInvisible(in.ClientID) {
		return Save{}, apierr.New(400, "invalid_client", "Enter the Client ID (at most 200 characters).")
	}
	keep := cur.secretID != "" && cur.Issuer == in.Issuer && cur.ClientID == in.ClientID
	switch {
	case in.ClientSecret != "" && (len(in.ClientSecret) < 8 || len(in.ClientSecret) > 1024):
		return Save{}, apierr.New(400, "invalid_secret", "Enter the Client secret (at least 8 characters).")
	case in.ClientSecret == "" && cur.secretID != "" && !keep:
		return Save{}, apierr.New(400, "invalid_secret", "The issuer or Client ID changed: enter the Client secret again.")
	case in.ClientSecret == "" && !keep:
		return Save{}, apierr.New(400, "invalid_secret", "Enter the Client secret (at least 8 characters).")
	}
	var scopes []string
	for _, sc := range strings.Fields(in.Scopes) {
		if !slices.Contains(scopes, sc) {
			scopes = append(scopes, sc)
		}
	}
	if !slices.Contains(scopes, "openid") || len(scopes) > 10 || slices.ContainsFunc(scopes, func(x string) bool { return !scopeRE.MatchString(x) }) {
		return Save{}, apierr.New(400, "invalid_scopes", "Scopes are words separated by spaces, at most 10, and must include openid.")
	}
	in.Scopes = strings.Join(scopes, " ")
	in.GroupsClaim = strings.TrimSpace(in.GroupsClaim)
	if !claimRE.MatchString(in.GroupsClaim) {
		return Save{}, apierr.New(400, "invalid_claim", "Enter the name of the groups claim, for example groups (letters, digits and _ . : / -, at most 64).")
	}
	if in.DefaultRole != "" && !validRole(in.DefaultRole) {
		return Save{}, apierr.New(400, "invalid_role", "Choose a default role, or No access.")
	}
	rows := make([]RoleRow, 0, len(in.RoleMap))
	for _, r := range in.RoleMap {
		g := strings.TrimSpace(r.Group)
		if g == "" {
			continue
		}
		if !validRole(r.Role) || len(g) > 256 || auth.HasInvisible(g) {
			return Save{}, apierr.New(400, "invalid_role", "One mapping row has an invalid role or a group name longer than 256 characters.")
		}
		rows = append(rows, RoleRow{Group: g, Role: r.Role})
	}
	if len(rows) > maxRoleRows {
		return Save{}, apierr.New(400, "too_many", "At most 10 role mapping rows.")
	}
	in.RoleMap = rows
	if in.CAPEM == nil {
		in.CAPEM = &cur.CAPEM
	} else {
		ca, err := parseCA(*in.CAPEM, now)
		if err != nil {
			return Save{}, err
		}
		in.CAPEM = &ca
	}
	return in, nil
}

func validRole(r routes.Role) bool {
	return r == routes.Viewer || r == routes.Operator || r == routes.Admin
}

// Store saves the configuration (PUT /core/oidc, admin): the secret through core/secrets, the redirect URI pinned from origin
// (INV-6), oidc.update in the audit log, the discovery cache dropped. Sessions are not touched (POST-3).
func (s *Service) Store(ctx context.Context, actor, origin string, in Save) (Config, error) {
	cur, err := s.load(ctx)
	if err != nil && !errors.Is(err, errNotConfigured) {
		return Config{}, err
	}
	in, verr := normalize(in, cur, s.now())
	if verr != nil {
		return Config{}, verr
	}
	roleMap, err := json.Marshal(in.RoleMap)
	if err != nil {
		return Config{}, fmt.Errorf("authoidc: role_map: %w", err)
	}
	var def any
	if in.DefaultRole != "" {
		def = string(in.DefaultRole)
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		secretID, last4 := cur.secretID, cur.SecretLast4
		switch {
		case in.ClientSecret != "" && secretID == "":
			if secretID, last4, err = s.secrets.Seal(ctx, tx, secretPurpose, []byte(in.ClientSecret), true); err != nil {
				return err
			}
		case in.ClientSecret != "":
			if last4, err = s.secrets.Replace(ctx, tx, secretID, secretPurpose, []byte(in.ClientSecret), true); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO oidc_config (id, issuer, client_id, secret_id, secret_last4, scopes, groups_claim, default_role, role_map, redirect_uri, ca_pem, updated_at)
			VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET issuer = excluded.issuer, client_id = excluded.client_id, secret_id = excluded.secret_id,
				secret_last4 = excluded.secret_last4, scopes = excluded.scopes, groups_claim = excluded.groups_claim,
				default_role = excluded.default_role, role_map = excluded.role_map, redirect_uri = excluded.redirect_uri, ca_pem = excluded.ca_pem,
				updated_at = excluded.updated_at`,
			in.Issuer, in.ClientID, secretID, last4, in.Scopes, in.GroupsClaim, def, string(roleMap), callbackURL(origin), *in.CAPEM, store.FormatTS(s.now()))
		if err != nil {
			return fmt.Errorf("authoidc: save config: %w", err)
		}
		return s.audit.Append(ctx, tx, audit.Entry{User: actor, Action: "oidc.update", Target: in.Issuer})
	})
	if err != nil {
		return Config{}, err
	}
	s.forget()
	return s.load(ctx)
}
