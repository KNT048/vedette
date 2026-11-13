package channel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// User sign-ins (D-480): the mailbox's own user signs in once, without a redirect to the box, and the box keeps the refresh token.
const (
	AuthMicrosoftUser = "microsoft_user" // device authorization grant (RFC 8628) with the customer's own public client
	AuthGoogleUser    = "google_user"    // the customer's own Desktop OAuth client: loopback redirect + PKCE, the address pasted back
)

const (
	microsoftDeviceURL = "https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode"
	// microsoftUserScope asks for SMTP as the user, a refresh token, and the id_token claims that name the mailbox.
	microsoftUserScope = "https://outlook.office.com/SMTP.Send offline_access openid profile email"
	googleAuthURL      = "https://accounts.google.com/o/oauth2/v2/auth"
	googleUserScope    = "https://mail.google.com/ openid email"
	// microsoftDeviceLogin is shown when Microsoft names a verification page Vedette does not know.
	microsoftDeviceLogin = "https://microsoft.com/devicelogin"
	maxPasted            = 4096
	maxDeviceWait        = 15 * time.Minute
)

var (
	googleClientRE = regexp.MustCompile(`^[0-9]{6,30}-[a-z0-9]{10,64}\.apps\.googleusercontent\.com$`)
	userCodeRE     = regexp.MustCompile(`^[A-Za-z0-9-]{4,20}$`)
	authCodeRE     = regexp.MustCompile(`^[\x21-\x7e]+$`) // with a length check: Go's regexp repeats at most 1000 times
	stateRE        = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	// verificationHosts are the pages Microsoft sends people to for a device code; another host is replaced by microsoftDeviceLogin.
	verificationHosts = map[string]bool{"microsoft.com": true, "www.microsoft.com": true, "login.microsoftonline.com": true, "login.live.com": true}
)

// userGrant is the channel secret of a user sign-in, JSON: the refresh token and, for Google, the client secret of the customer's
// Desktop client (Google calls it not confidential, but it stays in core/secrets all the same).
type userGrant struct {
	RefreshToken string `json:"refresh_token"`
	ClientSecret string `json:"client_secret,omitempty"`
}

func (g userGrant) secret() secrets.Value {
	b, _ := json.Marshal(g) //nolint:gosec // G117: this JSON is the channel secret, sealed by core/secrets; it is never logged or returned
	return secrets.NewValue(string(b))
}

func parseGrant(raw string, google bool) (userGrant, bool) {
	var g userGrant
	if len(raw) > maxKeyFile || json.Unmarshal([]byte(raw), &g) != nil || len(g.RefreshToken) > maxAccess || !accessRE.MatchString(g.RefreshToken) {
		return userGrant{}, false
	}
	if google != (g.ClientSecret != "") || (google && (len(g.ClientSecret) > 256 || !accessRE.MatchString(g.ClientSecret))) {
		return userGrant{}, false
	}
	return g, true
}

// validTenant accepts a Microsoft tenant: a GUID, a domain, or one of the shared names of the identity platform.
func validTenant(t string) bool {
	switch t {
	case "organizations", "common", "consumers":
		return true
	}
	return guidRE.MatchString(t) || validDomain(strings.ToLower(t))
}

func (e *emailSender) user() bool { return e.auth == AuthMicrosoftUser || e.auth == AuthGoogleUser }

func (e *emailSender) currentGrant() userGrant {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.grant
}

// rotate keeps a new refresh token: in memory at once, and in the saved channel through EmailConfig.SaveSecret. A failed save is
// not fatal: Microsoft keeps the previous refresh token valid, and the next refresh tries again.
func (e *emailSender) rotate(ctx context.Context, refresh string) {
	e.mu.Lock()
	old := e.grant
	if old.RefreshToken == refresh {
		e.mu.Unlock()
		return
	}
	e.grant.RefreshToken = refresh
	next := e.grant
	e.mu.Unlock()
	if e.cfg.SaveSecret != nil {
		_ = e.cfg.SaveSecret(ctx, old.secret(), next.secret())
	}
}

// UserSignIn is a finished user sign-in: the mailbox it is for and the channel secret to save.
type UserSignIn struct {
	Mailbox string
	Secret  secrets.Value
}

// Device sign-in states (Poll).
const (
	SigninWaiting  = "waiting"
	SigninSignedIn = "signed_in"
	SigninExpired  = "expired"
	SigninDeclined = "declined"
)

// MicrosoftDevice is a started device authorization: the person opens VerificationURI and types UserCode; the box polls.
type MicrosoftDevice struct {
	UserCode        string
	VerificationURI string
	ExpiresIn       time.Duration
	Interval        time.Duration
	tenant, client  string
	deviceCode      secrets.Value
}

// StartMicrosoftDevice asks Microsoft for a device code for the customer's own public client (D-480).
func StartMicrosoftDevice(ctx context.Context, hc *http.Client, tenant, clientID string) (*MicrosoftDevice, error) {
	if !validTenant(tenant) {
		return nil, cfgErr("bad_tenant_id", "The tenant ID is the Directory (tenant) ID of the app registration, a domain such as company.onmicrosoft.com, or organizations.")
	}
	if !guidRE.MatchString(clientID) {
		return nil, cfgErr("bad_client_id", "The client ID is the Application (client) ID of the app registration, for example 0a1b2c3d-4e5f-6789-abcd-ef0123456789.")
	}
	a, err := postToken(ctx, tokenClient(hc), fmt.Sprintf(microsoftDeviceURL, url.PathEscape(tenant)), url.Values{"client_id": {clientID}, "scope": {microsoftUserScope}}, "Microsoft")
	var tr *tokenRefused
	if errors.As(err, &tr) {
		return nil, &SignInError{Msg: deviceRefusal(tr.code, tr.status)}
	}
	if err != nil {
		return nil, err
	}
	if a.DeviceCode == "" || !userCodeRE.MatchString(a.UserCode) {
		return nil, &SignInError{Msg: "Microsoft's sign-in service sent an answer Vedette cannot read."}
	}
	d := &MicrosoftDevice{UserCode: a.UserCode, VerificationURI: microsoftDeviceLogin, ExpiresIn: seconds(a.ExpiresIn, maxDeviceWait), Interval: seconds(a.Interval, time.Minute),
		tenant: tenant, client: clientID, deviceCode: secrets.NewValue(a.DeviceCode)}
	if u, err := url.Parse(a.VerificationURI); err == nil && u.Scheme == "https" && verificationHosts[u.Host] && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
		d.VerificationURI = u.String()
	}
	if d.ExpiresIn == 0 {
		d.ExpiresIn = maxDeviceWait
	}
	if d.Interval < 5*time.Second { // RFC 8628 3.2: 5 seconds when the service names none
		d.Interval = 5 * time.Second
	}
	return d, nil
}

// Poll asks Microsoft once whether the person finished. It returns the state; with SigninSignedIn, the sign-in. slow_down
// lengthens Interval by 5 seconds (RFC 8628 3.5).
func (d *MicrosoftDevice) Poll(ctx context.Context, hc *http.Client) (string, UserSignIn, error) {
	endpoint := fmt.Sprintf(microsoftTokenURL, url.PathEscape(d.tenant))
	a, err := postToken(ctx, tokenClient(hc), endpoint, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {d.client},
		"device_code": {d.deviceCode.Reveal()}}, "Microsoft")
	var tr *tokenRefused
	if errors.As(err, &tr) {
		switch tr.code {
		case "authorization_pending":
			return SigninWaiting, UserSignIn{}, nil
		case "slow_down":
			d.Interval += 5 * time.Second
			return SigninWaiting, UserSignIn{}, nil
		case "authorization_declined":
			return SigninDeclined, UserSignIn{}, nil
		case "expired_token", "bad_verification_code":
			return SigninExpired, UserSignIn{}, nil
		}
		return "", UserSignIn{}, &SignInError{Msg: deviceRefusal(tr.code, tr.status)}
	}
	if err != nil {
		return "", UserSignIn{}, err
	}
	return finishUser(a, userGrant{}, "Microsoft")
}

// deviceRefusal is the sentence for a refusal while signing in with a device code.
func deviceRefusal(code string, status int) string {
	switch code {
	case "invalid_client", "unauthorized_client":
		return "Microsoft refused the app registration. Check the client ID and the tenant ID, and turn on Allow public client flows under Authentication of the app registration."
	case "invalid_scope":
		return "Microsoft refused the permission. Add the delegated permission SMTP.Send (Office 365 Exchange Online) to the app registration."
	case "invalid_request":
		return "Microsoft refused the sign-in request. Check the tenant ID: the Directory (tenant) ID of the app registration, or organizations."
	}
	return fmt.Sprintf("Microsoft refused the sign-in (HTTP %d%s).", status, codeSuffix(code))
}

// finishUser turns a token answer into a sign-in: it needs a refresh token and an id_token that names the mailbox. The id_token
// came straight from the token endpoint over TLS, so its claims are read without checking its signature (OpenID Connect Core 3.1.3.7).
func finishUser(a tokenAnswer, g userGrant, who string) (string, UserSignIn, error) {
	if a.RefreshToken == "" {
		return "", UserSignIn{}, &SignInError{Msg: who + " sent no refresh token, so Vedette could not keep the sign-in. Sign in again."}
	}
	mailbox := idTokenMailbox(a.IDToken)
	if mailbox == "" {
		return "", UserSignIn{}, &SignInError{Msg: who + " did not say which mailbox signed in. Sign in again."}
	}
	g.RefreshToken = a.RefreshToken
	return SigninSignedIn, UserSignIn{Mailbox: mailbox, Secret: g.secret()}, nil
}

// idTokenMailbox reads the email (or, for Microsoft, preferred_username) claim of an id_token; "" when there is no valid address.
func idTokenMailbox(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	if json.Unmarshal(b, &c) != nil {
		return ""
	}
	for _, m := range []string{c.Email, c.PreferredUsername} {
		if validEmail(m) {
			return strings.ToLower(m)
		}
	}
	return ""
}

// GoogleConsent is a started Google sign-in with the customer's own Desktop client: the person opens URL, approves, and pastes the
// address their browser could not load (http://127.0.0.1:<port>/?code=…&state=…) back into Vedette.
type GoogleConsent struct {
	URL          string
	client       string
	clientSecret secrets.Value
	state        string
	verifier     secrets.Value
	redirect     string
}

// StartGoogleConsent builds the consent address with a fresh state and PKCE S256 verifier (RFC 7636). The redirect is the loopback
// address on a random high port, which nothing on the person's computer is likely to serve.
func StartGoogleConsent(clientID, clientSecret string) (*GoogleConsent, error) {
	if !googleClientRE.MatchString(clientID) {
		return nil, cfgErr("bad_client_id", "The client ID of a Google OAuth client ends with .apps.googleusercontent.com. Copy it from Google Auth Platform, Clients.")
	}
	if clientSecret == "" || len(clientSecret) > 256 || !accessRE.MatchString(clientSecret) {
		return nil, cfgErr("bad_secret", "Enter the client secret of the Desktop OAuth client (Google Auth Platform, Clients).")
	}
	var b [66]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("notify: email: random: %w", err)
	}
	state, verifier := base64.RawURLEncoding.EncodeToString(b[:32]), base64.RawURLEncoding.EncodeToString(b[32:])
	port := 49152 + (int(b[64])<<8|int(b[65]))%16384 // 49152..65535
	sum := sha256.Sum256([]byte(verifier))
	g := &GoogleConsent{client: clientID, clientSecret: secrets.NewValue(clientSecret), state: state, verifier: secrets.NewValue(verifier),
		redirect: "http://127.0.0.1:" + strconv.Itoa(port)}
	g.URL = googleAuthURL + "?" + url.Values{"client_id": {clientID}, "redirect_uri": {g.redirect}, "response_type": {"code"}, "scope": {googleUserScope},
		"access_type": {"offline"}, "prompt": {"consent"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"}}.Encode()
	return g, nil
}

// pastedCode reads the address the person pasted. It is untrusted text: only an http address on 127.0.0.1 or localhost at this
// sign-in's port is accepted, the state must be this sign-in's, and only code and state are read from it.
func (g *GoogleConsent) pastedCode(pasted string) (string, error) {
	pasted = strings.TrimSpace(pasted)
	notOurs := cfgErr("bad_url", "Paste the whole address your browser shows after you approved, starting with "+g.redirect+"/?")
	if pasted == "" || len(pasted) > maxPasted {
		return "", notOurs
	}
	u, err := url.Parse(pasted)
	if err != nil || u.Scheme != "http" || u.User != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || "http://127.0.0.1:"+u.Port() != g.redirect ||
		(u.Path != "" && u.Path != "/") {
		return "", notOurs
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", notOurs
	}
	if state := q.Get("state"); !stateRE.MatchString(state) || subtle.ConstantTimeCompare([]byte(state), []byte(g.state)) != 1 {
		return "", cfgErr("bad_state", "This address belongs to another sign-in. Press Sign in with Google again and paste the address of that sign-in.")
	}
	if q.Get("error") != "" {
		return "", cfgErr("declined", "Google says the access was not granted. Press Sign in with Google again and approve on Google's page.")
	}
	code := q.Get("code")
	if len(code) > 2048 || !authCodeRE.MatchString(code) {
		return "", cfgErr("bad_url", "The address has no sign-in code. Paste the whole address from the browser after you approved.")
	}
	return code, nil
}

// Finish exchanges the pasted code with the PKCE verifier for a refresh token.
func (g *GoogleConsent) Finish(ctx context.Context, hc *http.Client, pasted string) (UserSignIn, error) {
	code, err := g.pastedCode(pasted)
	if err != nil {
		return UserSignIn{}, err
	}
	a, err := postToken(ctx, tokenClient(hc), googleTokenURL, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {g.client},
		"client_secret": {g.clientSecret.Reveal()}, "redirect_uri": {g.redirect}, "code_verifier": {g.verifier.Reveal()}}, "Google")
	var tr *tokenRefused
	if errors.As(err, &tr) {
		switch tr.code {
		case "invalid_grant":
			return UserSignIn{}, &SignInError{Msg: "Google refused the code: it was used already or is too old. Press Sign in with Google again."}
		case "invalid_client", "unauthorized_client":
			return UserSignIn{}, &SignInError{Msg: "Google refused the OAuth client. Check the client ID and the client secret: the client must be of type Desktop app."}
		}
		return UserSignIn{}, &SignInError{Msg: fmt.Sprintf("Google refused the sign-in (HTTP %d%s).", tr.status, codeSuffix(tr.code))}
	}
	if err != nil {
		return UserSignIn{}, err
	}
	_, s, err := finishUser(a, userGrant{ClientSecret: g.clientSecret.Reveal()}, "Google")
	return s, err
}
