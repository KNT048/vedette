package channel

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// How the email channel signs in (D-449). Each preset of the email dialog has one; see EmailAuth.
const (
	AuthPassword    = "password"        // AUTH PLAIN or LOGIN with a password, an app password or an API key
	AuthTokenAsUser = "token_as_user"   // the same, with the secret as both username and password (Postmark's server token)
	AuthMicrosoft   = "microsoft_oauth" // OAuth2 client credentials (Microsoft 365), XOAUTH2 or OAUTHBEARER
	AuthGoogle      = "google_oauth"    // OAuth2 service account with domain-wide delegation (Google Workspace), XOAUTH2 or OAUTHBEARER
)

// emailProviders are the presets of the email dialog (web/src/features/notify/emailProviders.ts fills host, port and security):
// the box only needs to know how each one signs in. "" is a channel saved before the presets.
var emailProviders = map[string]string{
	"": AuthPassword, "custom": AuthPassword,
	"gmail": AuthPassword, "yahoo": AuthPassword, "icloud": AuthPassword, "zoho": AuthPassword, "fastmail": AuthPassword,
	"sendgrid": AuthPassword, "mailgun": AuthPassword, "ses": AuthPassword, "brevo": AuthPassword,
	"postmark":     AuthTokenAsUser,
	"microsoft365": AuthMicrosoft, "google-workspace": AuthGoogle,
	"microsoft365-user": AuthMicrosoftUser, "outlook": AuthMicrosoftUser, "gmail-oauth": AuthGoogleUser, // D-480
}

// EmailAuth returns how the email preset p signs in; ok is false for a preset the box does not know.
func EmailAuth(p string) (auth string, ok bool) {
	auth, ok = emailProviders[p]
	return auth, ok
}

// The token endpoints. They are fixed: the Microsoft tenant is the only part that comes from the configuration (a GUID or a domain
// name, checked by NewEmail), and the token_uri of a Google key file is never used, so no configuration sends a secret elsewhere.
// Tests point an *http.Client at a fake (helpers_test.go rewrite).
const (
	microsoftTokenURL = "https://login.microsoftonline.com/%s/oauth2/v2.0/token" //nolint:gosec // G101: an endpoint, not a credential
	microsoftScope    = "https://outlook.office365.com/.default"
	googleTokenURL    = "https://oauth2.googleapis.com/token" //nolint:gosec // G101: an endpoint, not a credential
	googleScope       = "https://mail.google.com/"
)

const (
	maxTokenBody = 64 << 10 // a token answer is a few KiB
	maxKeyFile   = 16 << 10 // a Google service account key file is about 2.4 KiB
	maxAccess    = 8 << 10  // Microsoft access tokens run to about 3 KiB
	tokenSkew    = 5 * time.Minute
	maxTokenLife = 24 * time.Hour
)

var (
	guidRE      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	oauthCodeRE = regexp.MustCompile(`^[a-z_]{1,40}$`)
	accessRE    = regexp.MustCompile(`^[\x21-\x7e]+$`) // printable ASCII, no space: it goes on one SMTP line
	keyIDRE     = regexp.MustCompile(`^[0-9a-f]{1,64}$`)
)

// SignInError is a sign-in failure of the email channel. Msg is a fixed sentence written here, for people (it never carries what
// the server or the token service wrote); Err, when set, is the SMTP refusal under it.
type SignInError struct {
	Msg string
	Err error
}

func (e *SignInError) Error() string { return "notify: email: " + e.Msg }
func (e *SignInError) Unwrap() error { return e.Err }

var (
	errUnencryptedAuth = errors.New("refusing to authenticate on an unencrypted connection")
	errNoMechanism     = errors.New("no supported sign-in mechanism")
)

// googleKey is what Vedette uses of a Google service account key file.
type googleKey struct {
	email string // client_email: the issuer of the assertion
	kid   string // private_key_id, sent as the kid header when present
	key   *rsa.PrivateKey
}

// parseGoogleKey reads a service account key file (JSON, as Google Cloud downloads it). Only type, client_email, private_key_id and
// private_key are read; token_uri is ignored (the endpoint is fixed).
func parseGoogleKey(raw string) (googleKey, error) {
	bad := cfgErr("bad_secret", "This is not a service account key file from Google Cloud. In the Google Cloud console open IAM & Admin, "+
		"Service accounts, the account, Keys, Add key, JSON, and choose the downloaded file.")
	if len(raw) > maxKeyFile {
		return googleKey{}, bad
	}
	var f struct {
		Type         string `json:"type"`
		ClientEmail  string `json:"client_email"`
		PrivateKeyID string `json:"private_key_id"`
		PrivateKey   string `json:"private_key"`
	}
	if err := json.Unmarshal([]byte(raw), &f); err != nil || f.Type != "service_account" || !validEmail(f.ClientEmail) {
		return googleKey{}, bad
	}
	if f.PrivateKeyID != "" && !keyIDRE.MatchString(f.PrivateKeyID) {
		return googleKey{}, bad
	}
	block, _ := pem.Decode([]byte(f.PrivateKey))
	if block == nil {
		return googleKey{}, bad
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return googleKey{}, bad
	}
	rk, ok := key.(*rsa.PrivateKey)
	if err != nil || !ok || rk.N.BitLen() < 2048 || rk.N.BitLen() > 4096 { // Google makes 2048-bit keys; a huge key is a slow signature per token
		return googleKey{}, bad
	}
	return googleKey{email: f.ClientEmail, kid: f.PrivateKeyID, key: rk}, nil
}

// googleAssertion is the signed JWT of the JWT bearer grant (RFC 7523) for the mailbox sub, valid one hour.
func googleAssertion(k googleKey, sub string, now time.Time) (string, error) {
	head := map[string]string{"alg": "RS256", "typ": "JWT"}
	if k.kid != "" {
		head["kid"] = k.kid
	}
	claims := map[string]any{"iss": k.email, "sub": sub, "scope": googleScope, "aud": googleTokenURL, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	hj, err := json.Marshal(head)
	if err != nil {
		return "", err
	}
	cj, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(hj) + "." + enc.EncodeToString(cj)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// TokenCache keeps OAuth2 access tokens until shortly before they expire (tokenSkew), shared by every email sender the service
// builds (alerts, approval mails, two-step codes). The key is a hash of everything that identifies the token, the secret included,
// so a changed configuration never reuses an old token. Tokens live in memory only.
type TokenCache struct {
	mu      sync.Mutex
	m       map[[32]byte]cachedToken
	flights map[[32]byte]*tokenFlight // fetches under way: one per key, the other senders wait for it
}

type tokenFlight struct {
	done chan struct{}
	tok  secrets.Value
	err  error
}

type cachedToken struct {
	token secrets.Value
	until time.Time
}

const maxCachedTokens = 16

// NewTokenCache returns an empty cache.
func NewTokenCache() *TokenCache {
	return &TokenCache{m: map[[32]byte]cachedToken{}, flights: map[[32]byte]*tokenFlight{}}
}

// Clear forgets every token (the service calls it when the email channel is saved or removed).
func (c *TokenCache) Clear() {
	c.mu.Lock()
	clear(c.m)
	c.mu.Unlock()
}

// once returns the cached token of key k, or waits for the fetch of k under way, or runs fetch (which caches what it gets) while the
// others wait: one request per key at a time. The cache is read under the same lock that starts a fetch, so a sender that comes after
// a fetch ended finds its token. A waiter stops at its own ctx; the fetch runs under the context of the sender that started it.
func (c *TokenCache) once(ctx context.Context, k [32]byte, now time.Time, fetch func() (secrets.Value, error)) (secrets.Value, error) {
	c.mu.Lock()
	if t, ok := c.m[k]; ok && now.Before(t.until) {
		c.mu.Unlock()
		return t.token, nil
	}
	if f, ok := c.flights[k]; ok {
		c.mu.Unlock()
		select {
		case <-f.done:
			return f.tok, f.err
		case <-ctx.Done():
			return secrets.Value{}, fmt.Errorf("notify: email: token: %s", transportReason(ctx.Err(), nil))
		}
	}
	f := &tokenFlight{done: make(chan struct{})}
	c.flights[k] = f
	c.mu.Unlock()
	f.tok, f.err = fetch()
	c.mu.Lock()
	delete(c.flights, k)
	c.mu.Unlock()
	close(f.done)
	return f.tok, f.err
}

func (c *TokenCache) put(k [32]byte, tok secrets.Value, until, now time.Time) {
	if !now.Before(until) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= maxCachedTokens { // ponytail: 16 entries, then start over; one box has one email channel
		clear(c.m)
	}
	c.m[k] = cachedToken{token: tok, until: until}
}

func (c *TokenCache) drop(k [32]byte) {
	c.mu.Lock()
	delete(c.m, k)
	c.mu.Unlock()
}

func (e *emailSender) tokenKey() [32]byte {
	h := sha256.New()
	sec := e.cfg.Password.Reveal()
	if e.user() { // the refresh token rotates; the token belongs to the client and the mailbox (SaveChannel clears the cache)
		sec = e.currentGrant().ClientSecret
	}
	for _, p := range []string{e.auth, e.cfg.TenantID, e.cfg.ClientID, e.cfg.Username, sec} {
		_, _ = io.WriteString(h, strconv.Itoa(len(p))+":"+p)
	}
	var k [32]byte
	h.Sum(k[:0])
	return k
}

// token returns an OAuth2 access token for the mailbox, from the cache or from the token service.
func (e *emailSender) token(ctx context.Context) (secrets.Value, [32]byte, error) {
	k := e.tokenKey()
	now := e.cfg.Now()
	t, err := e.tokens.once(ctx, k, now, func() (secrets.Value, error) { return e.fetchToken(ctx, k, now) })
	return t, k, err
}

// fetchToken asks the token service for a new token and caches it. A user sign-in (D-480) refreshes its grant; a rotated refresh
// token is kept (rotate).
func (e *emailSender) fetchToken(ctx context.Context, k [32]byte, now time.Time) (secrets.Value, error) {
	var form url.Values
	var endpoint, who string
	switch e.auth {
	case AuthMicrosoft:
		endpoint, who = fmt.Sprintf(microsoftTokenURL, url.PathEscape(e.cfg.TenantID)), "Microsoft"
		form = url.Values{"grant_type": {"client_credentials"}, "client_id": {e.cfg.ClientID}, "client_secret": {e.cfg.Password.Reveal()}, "scope": {microsoftScope}}
	case AuthGoogle:
		endpoint, who = googleTokenURL, "Google"
		jwt, err := googleAssertion(e.gkey, e.cfg.Username, now)
		if err != nil {
			return secrets.Value{}, fmt.Errorf("notify: email: sign the token request: %w", err)
		}
		form = url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {jwt}}
	case AuthMicrosoftUser:
		endpoint, who = fmt.Sprintf(microsoftTokenURL, url.PathEscape(e.cfg.TenantID)), "Microsoft"
		form = url.Values{"grant_type": {"refresh_token"}, "client_id": {e.cfg.ClientID}, "refresh_token": {e.currentGrant().RefreshToken}, "scope": {microsoftUserScope}}
	default: // AuthGoogleUser
		g := e.currentGrant()
		endpoint, who = googleTokenURL, "Google"
		form = url.Values{"grant_type": {"refresh_token"}, "client_id": {e.cfg.ClientID}, "client_secret": {g.ClientSecret}, "refresh_token": {g.RefreshToken}}
	}
	ans, err := postToken(ctx, e.client, endpoint, form, who)
	var tr *tokenRefused
	if errors.As(err, &tr) {
		return secrets.Value{}, &SignInError{Msg: e.tokenRefusal(tr.code, tr.status)}
	}
	if err != nil {
		return secrets.Value{}, err
	}
	if ans.AccessToken == "" {
		return secrets.Value{}, &SignInError{Msg: who + "'s sign-in service sent an answer Vedette cannot read."}
	}
	if ans.RefreshToken != "" && e.user() {
		e.rotate(ctx, ans.RefreshToken)
	}
	tok := secrets.NewValue(ans.AccessToken)
	if d := ans.life(); d > tokenSkew {
		e.tokens.put(k, tok, now.Add(d-tokenSkew), now) // a token that lives less than the skew is used once and not kept
	}
	return tok, nil
}

// tokenAnswer is what Vedette reads of a token or device-code answer (RFC 6749 5.1 and 5.2, RFC 8628 3.2); everything is checked
// before use (postToken).
type tokenAnswer struct {
	AccessToken     string          `json:"access_token"`
	RefreshToken    string          `json:"refresh_token"`
	IDToken         string          `json:"id_token"`
	TokenType       string          `json:"token_type"`
	ExpiresIn       json.RawMessage `json:"expires_in"` // a number; some services send it as a string
	Error           string          `json:"error"`
	DeviceCode      string          `json:"device_code"`
	UserCode        string          `json:"user_code"`
	VerificationURI string          `json:"verification_uri"`
	Interval        json.RawMessage `json:"interval"`
}

func seconds(raw json.RawMessage, most time.Duration) time.Duration {
	n, _ := strconv.Atoi(strings.Trim(string(raw), `"`))
	return time.Duration(min(max(n, 0), int(most/time.Second))) * time.Second
}

func (a tokenAnswer) life() time.Duration { return seconds(a.ExpiresIn, maxTokenLife) }

// tokenRefused is a non-200 answer of a token service; code is its OAuth2 error code when it looks like one, else "".
type tokenRefused struct {
	status int
	code   string
}

func (e *tokenRefused) Error() string {
	return fmt.Sprintf("notify: email: the sign-in service refused (HTTP %d%s)", e.status, codeSuffix(e.code))
}

// postToken posts form to a token endpoint and reads the bounded answer: a *tokenRefused for a refusal, a *SignInError when the
// service cannot be reached or answers what Vedette cannot read. Tokens are printable ASCII without spaces, bounded.
func postToken(ctx context.Context, client *http.Client, endpoint string, form url.Values, who string) (tokenAnswer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenAnswer{}, fmt.Errorf("notify: email: token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return tokenAnswer{}, fmt.Errorf("notify: email: token: %s", transportReason(ctx.Err(), nil))
		}
		return tokenAnswer{}, &SignInError{Msg: "Vedette could not reach " + who + "'s sign-in service (" + req.URL.Host + "). Check the box's internet access and DNS."}
	}
	defer func() { _ = resp.Body.Close() }()
	unreadable := &SignInError{Msg: who + "'s sign-in service sent an answer Vedette cannot read."}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBody+1))
	if err != nil || len(body) > maxTokenBody {
		return tokenAnswer{}, unreadable
	}
	var a tokenAnswer
	jerr := json.Unmarshal(body, &a)
	if resp.StatusCode != http.StatusOK {
		r := &tokenRefused{status: resp.StatusCode}
		if jerr == nil && oauthCodeRE.MatchString(a.Error) {
			r.code = a.Error
		}
		return tokenAnswer{}, r
	}
	ok := func(s string, most int) bool { return s == "" || (len(s) <= most && accessRE.MatchString(s)) }
	if jerr != nil || !ok(a.AccessToken, maxAccess) || !ok(a.RefreshToken, maxAccess) || !ok(a.IDToken, maxAccess) || !ok(a.DeviceCode, maxAccess) ||
		(a.TokenType != "" && !strings.EqualFold(a.TokenType, "bearer")) {
		return tokenAnswer{}, unreadable
	}
	return a, nil
}

// tokenRefusal is the sentence for a refusal of the token service. code is the OAuth2 error code (RFC 6749 5.2) when it looks like
// one, else ""; the error_description is never shown (it is the provider's text).
func (e *emailSender) tokenRefusal(code string, status int) string {
	switch {
	case e.auth == AuthMicrosoftUser && code == "invalid_grant":
		return "Microsoft no longer accepts the saved sign-in: it expired, the password changed or it was revoked. Open the Email channel and sign in with Microsoft again."
	case e.auth == AuthMicrosoftUser:
		return deviceRefusal(code, status)
	case e.auth == AuthGoogleUser && code == "invalid_grant":
		return "Google no longer accepts the saved sign-in: it was revoked or expired (an OAuth client left in Testing loses its sign-ins after 7 days). Open the Email channel and sign in with Google again."
	case e.auth == AuthGoogleUser:
		return fmt.Sprintf("Google refused the OAuth client (HTTP %d%s). Check the client ID and the client secret of the Desktop client.", status, codeSuffix(code))
	}
	if e.auth == AuthMicrosoft {
		switch code {
		case "invalid_client":
			return "Microsoft refused the client ID or the client secret. Check them in the app registration; a client secret expires, so create a new one if it has."
		case "unauthorized_client":
			return "Microsoft does not know this client ID in this tenant. Check the tenant ID and the client ID of the app registration."
		case "invalid_request", "invalid_scope":
			return "Microsoft refused the sign-in request (" + code + "). Check the tenant ID: it is the Directory (tenant) ID of the app registration."
		}
		return fmt.Sprintf("Microsoft refused the sign-in (HTTP %d%s). Check the tenant ID, the client ID and the client secret.", status, codeSuffix(code))
	}
	switch code {
	case "unauthorized_client":
		return "Google refused: the service account may not act for this mailbox. In the Google Admin console, Security, API controls, " +
			"Domain-wide delegation, add the service account's client ID with the scope https://mail.google.com/."
	case "invalid_grant":
		return "Google refused the key or the mailbox. The key may have been deleted, or the mailbox is not a user of your Google Workspace domain."
	case "invalid_client":
		return "Google does not know this service account or key. The key may have been deleted: create a new JSON key and save it."
	}
	return fmt.Sprintf("Google refused the sign-in (HTTP %d%s). Check the service account key and the mailbox.", status, codeSuffix(code))
}

func codeSuffix(code string) string {
	if code == "" {
		return ""
	}
	return ", " + code
}

// saslAuth signs in with the first mechanism of mechs that the server offers. It refuses outright when the connection is not
// encrypted, whatever net/smtp or the configuration says: credentials and tokens are never sent in the clear.
type saslAuth struct {
	mechs      []string
	user, pass string // PLAIN and LOGIN
	token      string // XOAUTH2 and OAUTHBEARER
	host       string
	port       int
	mech       string // the mechanism in use
	step       int
}

func (a *saslAuth) Start(si *smtp.ServerInfo) (string, []byte, error) {
	if !si.TLS {
		return "", nil, errUnencryptedAuth
	}
	for _, m := range a.mechs {
		for _, offered := range si.Auth {
			if !strings.EqualFold(m, offered) {
				continue
			}
			a.mech = m
			switch m {
			case "PLAIN":
				return m, []byte("\x00" + a.user + "\x00" + a.pass), nil
			case "LOGIN":
				return m, nil, nil
			case "XOAUTH2":
				return m, []byte("user=" + a.user + "\x01auth=Bearer " + a.token + "\x01\x01"), nil
			case "OAUTHBEARER": // RFC 7628 3.1
				gs2 := "n,a=" + strings.NewReplacer("=", "=3D", ",", "=2C").Replace(a.user) + ","
				return m, []byte(gs2 + "\x01host=" + a.host + "\x01port=" + strconv.Itoa(a.port) + "\x01auth=Bearer " + a.token + "\x01\x01"), nil
			}
		}
	}
	return "", nil, errNoMechanism
}

func (a *saslAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch {
	case a.mech == "LOGIN" && a.step == 1: // "Username:"
		return []byte(a.user), nil
	case a.mech == "LOGIN" && a.step == 2: // "Password:"
		return []byte(a.pass), nil
	case a.mech == "XOAUTH2" && a.step == 1: // the server's JSON error: an empty answer, then it sends the 535 (Google's XOAUTH2 page)
		return []byte{}, nil
	case a.mech == "OAUTHBEARER" && a.step == 1: // RFC 7628 3.2.3: the client answers the error with a single %x01
		return []byte{0x01}, nil
	}
	return nil, errors.New("unexpected challenge from the server")
}

// oauthToken is an access token and its key in the TokenCache.
type oauthToken struct {
	value secrets.Value
	key   [32]byte
}

// signIn runs AUTH on the encrypted session c (deliver checked TLS; saslAuth checks it again). tok is the OAuth2 token of an OAuth
// provider, nil otherwise.
func (e *emailSender) signIn(c *smtp.Client, tok *oauthToken) error {
	a := &saslAuth{host: e.cfg.Host, port: e.cfg.Port, user: e.cfg.Username, pass: e.cfg.Password.Reveal(), mechs: []string{"PLAIN", "LOGIN"}}
	if e.auth == AuthTokenAsUser {
		a.user = a.pass
	}
	if tok != nil {
		a.mechs, a.pass, a.token = []string{"XOAUTH2", "OAUTHBEARER"}, "", tok.value.Reveal()
	}
	err := c.Auth(a)
	if err == nil {
		return nil
	}
	if tok != nil {
		e.tokens.drop(tok.key) // a refused token is not used again
	}
	switch {
	case errors.Is(err, errUnencryptedAuth):
		return fmt.Errorf("notify: email: %w", err)
	case errors.Is(err, errNoMechanism):
		want := "PLAIN or LOGIN"
		if e.oauth() {
			want = "XOAUTH2 or OAUTHBEARER"
		}
		return &SignInError{Msg: "The mail server does not offer a sign-in Vedette can use (" + want + ") on the encrypted connection. Check the server and the port."}
	}
	var te *textproto.Error
	if !errors.As(err, &te) {
		return fmt.Errorf("notify: email: login: %s", transportReason(err, []secrets.Value{e.cfg.Password, secrets.NewValue(a.token)}))
	}
	code := te.Code
	// An OAuth server's text stays out even of the log: it may echo the token. A person reads our sentence either way.
	under := &StatusError{Channel: Email, Code: code}
	if !e.oauth() {
		under.Reason = reasonFrom([]byte(te.Msg), e.cfg.Password)
	}
	switch e.auth {
	case AuthMicrosoftUser:
		return &SignInError{Err: under, Msg: fmt.Sprintf("Microsoft refused the sign-in (SMTP code %d). Check that SMTP AUTH is on for the mailbox and that the app "+
			"registration has the delegated permission SMTP.Send.", code)}
	case AuthGoogleUser:
		return &SignInError{Err: under, Msg: fmt.Sprintf("Google refused the sign-in (SMTP code %d). Sign in with Google again with the mailbox that sends.", code)}
	case AuthMicrosoft:
		return &SignInError{Err: under, Msg: fmt.Sprintf("Microsoft 365 refused the sign-in (SMTP code %d). Check that SMTP AUTH is on for the mailbox, and that "+
			"the admin registered the app's service principal in Exchange Online and gave it access to the mailbox.", code)}
	case AuthGoogle:
		return &SignInError{Err: under, Msg: fmt.Sprintf("Google refused the sign-in (SMTP code %d). Check the mailbox: it must be a user of the "+
			"Google Workspace domain that granted domain-wide delegation.", code)}
	}
	return &SignInError{Err: under, Msg: fmt.Sprintf("The mail server refused the sign-in (SMTP code %d). Check the username and the password, app password or API key.", code)}
}

func (e *emailSender) oauth() bool {
	return e.auth == AuthMicrosoft || e.auth == AuthGoogle || e.user()
}

// tokenClient is the client of the token requests: the configured one without redirects (the request carries the secret, and a
// 307 would resend it elsewhere), or a plain one with a timeout.
func tokenClient(c *http.Client) *http.Client {
	out := &http.Client{Timeout: emailTimeout}
	if c != nil {
		cp := *c
		out = &cp
	}
	out.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return out
}
