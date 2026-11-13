package channel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// ZaloConfig configures an official Zalo OA channel (customer-service message to a follower).
type ZaloConfig struct {
	OAID   string // Official Account ID, 6 to 20 digits
	UserID string // recipient: the Zalo user_id of a person who followed or messaged the OA
	// AppID is the Zalo app of the refresh-token flow (D-483); "" for a channel that only has a pasted access token.
	AppID string
	// Token is the channel secret: a ZaloGrant (JSON, the refresh-token flow, D-483), or, saved before it, a plain access token.
	Token  secrets.Value
	Client *http.Client // nil = NewHTTPClient()
	Now    func() time.Time
	// SaveSecret keeps a rotated grant (a refresh token works once): called with the grant before and after; nil = memory only.
	SaveSecret func(ctx context.Context, old, next secrets.Value) error
}

var (
	zaloOARE   = regexp.MustCompile(`^\d{6,20}$`)
	zaloUserRE = regexp.MustCompile(`^\d{6,25}$`)
	zaloAppRE  = regexp.MustCompile(`^\d{6,25}$`)
)

// Checked against the OA API docs on 2026-11-12:
// https://stc-developers.zdn.vn/docs/v2/official-account/tin-nhan/tin-tu-van/gui-tin-tu-van-dang-van-ban/index.html
// The token endpoint is the OA one of OAuth v4 (https://developers.zalo.me/docs/official-account/bat-dau/xac-thuc-va-uy-quyen-cho-ung-dung-new):
// POST, header secret_key, form refresh_token, app_id, grant_type=refresh_token; the answer has a new access token (about 25 hours)
// and a new refresh token (about 3 months, single use).
const (
	zaloAPI       = "https://openapi.zalo.me"
	zaloSendPath  = "/v3.0/oa/message/cs"
	zaloTokenURL  = "https://oauth.zaloapp.com/v4/oa/access_token" //nolint:gosec // G101: the public token endpoint, not a credential
	zaloTextMax   = 2000
	zaloMinToken  = 20
	zaloMaxToken  = 2048
	zaloMinKey    = 8
	zaloMaxKey    = 128
	zaloRefreshAt = time.Hour // refresh this long before the access token ends
	// zaloDefaultLife is the access token life assumed when Zalo does not say (OA tokens last 25 hours).
	zaloDefaultLife = 25 * time.Hour
)

// ZaloGrant is the secret of a Zalo OA channel with the refresh-token flow (D-483), JSON in core/secrets. ID is random per grant the
// admin saved; it stays through rotations, so a rotation is written back only while the saved grant is the same one.
type ZaloGrant struct {
	ID           string    `json:"id"`
	SecretKey    string    `json:"secret_key"`
	RefreshToken string    `json:"refresh_token"`
	AccessToken  string    `json:"access_token,omitempty"`
	Expires      time.Time `json:"expires_at,omitzero"`
}

func (g ZaloGrant) secret() secrets.Value {
	b, _ := json.Marshal(g) //nolint:gosec // G117: this JSON is the channel secret, sealed by core/secrets; it is never logged or returned
	return secrets.NewValue(string(b))
}

// ParseZaloGrant reads a saved Zalo OA secret; ok is false for a plain access token (saved before D-483) or anything else.
func ParseZaloGrant(raw string) (ZaloGrant, bool) {
	var g ZaloGrant
	if !strings.HasPrefix(strings.TrimSpace(raw), "{") || len(raw) > 3*zaloMaxToken+zaloMaxKey+256 || json.Unmarshal([]byte(raw), &g) != nil || !grantIDRE.MatchString(g.ID) {
		return ZaloGrant{}, false
	}
	return g, true
}

// zaloTokenText checks one token or key: printable ASCII without spaces, within its length.
func zaloTokenText(s string, lo, hi int) bool {
	if len(s) < lo || len(s) > hi {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r > '~' {
			return false
		}
	}
	return true
}

// ZaloOASecret is the secret to save for a Zalo OA channel (D-483) from what the admin typed and what is saved: an empty field keeps
// the saved value. With a refresh token (typed or saved) the result is a ZaloGrant, with a new id whenever something was typed, so
// a rotation in flight of the old grant is not written over it; with only an access token it stays a plain token, as before.
// It returns "" when nothing was typed and nothing changes.
func ZaloOASecret(saved, secretKey, refresh, access string) (string, error) {
	secretKey, refresh, access = strings.TrimSpace(secretKey), strings.TrimSpace(refresh), strings.TrimSpace(access)
	if secretKey == "" && refresh == "" && access == "" {
		return "", nil
	}
	g, isGrant := ParseZaloGrant(saved)
	if !isGrant && refresh == "" && secretKey == "" {
		return access, nil // a pasted access token only, as before D-483
	}
	if secretKey != "" {
		g.SecretKey = secretKey
	}
	if refresh != "" {
		g.RefreshToken, g.AccessToken, g.Expires = refresh, "", time.Time{}
	}
	if access != "" {
		g.AccessToken, g.Expires = access, time.Time{} // its age is not known: refreshed before it is 24 hours old at the latest (zaloSender)
	}
	if g.SecretKey == "" {
		return "", cfgErr("bad_secret_key", "Enter the Secret key of the Zalo app (Zalo Developers, your app, Settings).")
	}
	if g.RefreshToken == "" {
		return "", cfgErr("bad_refresh_token", "Enter the refresh token of the OA (Zalo Developers, API Explorer, OA access token). It lasts about 3 months.")
	}
	g.ID = newGrantID()
	return string(g.secret().Reveal()), nil
}

// newGrantID is a random grant id (the form of grantIDRE). crypto/rand.Read never fails (Go 1.24).
func newGrantID() string {
	var id [16]byte
	_, _ = rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

type zaloSender struct {
	noPrint
	oa, user, app string
	endpoint      string
	tokenURL      string
	client        *http.Client
	now           func() time.Time
	save          func(ctx context.Context, old, next secrets.Value) error

	mu      sync.Mutex // one refresh at a time: a refresh token works once
	token   secrets.Value
	grant   ZaloGrant
	isGrant bool
	since   time.Time // when this sender took an access token whose end is not known
}

// NewZalo validates cfg and returns the adapter.
func NewZalo(cfg ZaloConfig) (Sender, error) {
	oa, user, app := strings.TrimSpace(cfg.OAID), strings.TrimSpace(cfg.UserID), strings.TrimSpace(cfg.AppID)
	if !zaloOARE.MatchString(oa) {
		return nil, cfgErr("bad_oa_id", "OA ID is a string of digits, shown in the Official Account management page.")
	}
	if !zaloUserRE.MatchString(user) {
		return nil, cfgErr("bad_user_id", "The Zalo recipient ID (user_id) is the number of a person who followed or messaged the OA.")
	}
	z := &zaloSender{oa: oa, user: user, app: app, endpoint: zaloAPI + zaloSendPath, tokenURL: zaloTokenURL, client: clientOrDefault(cfg.Client), now: cfg.Now, save: cfg.SaveSecret}
	if z.now == nil {
		z.now = time.Now
	}
	raw := strings.TrimSpace(cfg.Token.Reveal())
	if g, ok := ParseZaloGrant(raw); ok {
		if !zaloAppRE.MatchString(app) {
			return nil, cfgErr("bad_app_id", "App ID is the number of your Zalo app, shown in Zalo Developers next to the app name.")
		}
		if !zaloTokenText(g.SecretKey, zaloMinKey, zaloMaxKey) {
			return nil, cfgErr("bad_secret_key", "The Secret key of the Zalo app is a string of letters and digits. Copy it again from Zalo Developers (your app, Settings).")
		}
		if !zaloTokenText(g.RefreshToken, zaloMinToken, zaloMaxToken) {
			return nil, cfgErr("bad_refresh_token", "The refresh token is too short or has a character that is not allowed. Copy the whole string again from Zalo Developers.")
		}
		if g.AccessToken != "" && !zaloTokenText(g.AccessToken, zaloMinToken, zaloMaxToken) {
			return nil, cfgErr("bad_token", "The Zalo access token has a character that is not allowed. Copy it again without spaces, or leave it empty.")
		}
		z.grant, z.isGrant, z.token, z.since = g, true, secrets.NewValue(g.AccessToken), z.now()
		return z, nil
	}
	if raw == "" {
		return nil, cfgErr("secret_required", "Enter the refresh token, or an access token. This channel has no saved key yet.")
	}
	if len(raw) < zaloMinToken {
		return nil, cfgErr("bad_token", "The Zalo access token is too short. Copy the whole string from Zalo Developers.")
	}
	if !zaloTokenText(raw, zaloMinToken, zaloMaxToken) {
		return nil, cfgErr("bad_token", "The Zalo access token has a character that is not allowed. Copy it again without spaces.")
	}
	z.token = secrets.NewValue(raw)
	return z, nil
}

// zaloRefreshText says what to do when Zalo refuses the refresh token.
const zaloRefreshText = "Zalo refused the refresh token. It works once and lasts about 3 months; get a new one in Zalo Developers (API Explorer, OA access token) and save it with the App ID and Secret key."

// accessToken returns the access token to send with, refreshed first when there is none, it ends within zaloRefreshAt, or force is
// set (Zalo said it is invalid). A plain token (no grant) is returned as it is.
func (z *zaloSender) accessToken(ctx context.Context, force bool) (secrets.Value, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if !z.isGrant {
		return z.token, nil
	}
	now := z.now()
	end := z.grant.Expires
	if end.IsZero() && z.grant.AccessToken != "" {
		end = z.since.Add(zaloDefaultLife) // pasted: its age is unknown, so refresh within a day of taking it
	}
	if !force && z.grant.AccessToken != "" && now.Before(end.Add(-zaloRefreshAt)) {
		return z.token, nil
	}
	old := z.grant
	form := url.Values{"refresh_token": {old.RefreshToken}, "app_id": {z.app}, "grant_type": {"refresh_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, z.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return secrets.Value{}, fmt.Errorf("notify: zalo: build token request: %s", transportReason(err, z.hide()))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("secret_key", old.SecretKey)
	code, ans, err := do(z.client, Zalo, req, z.hide()...)
	if err != nil {
		return secrets.Value{}, err
	}
	var out struct {
		AccessToken  string          `json:"access_token"`
		RefreshToken string          `json:"refresh_token"`
		ExpiresIn    json.RawMessage `json:"expires_in"` // Zalo writes it as a string of digits; a number is taken too
		Error        int             `json:"error"`
	}
	if code < 200 || code > 299 || json.Unmarshal(ans, &out) != nil || out.Error != 0 ||
		!zaloTokenText(out.AccessToken, zaloMinToken, zaloMaxToken) || !zaloTokenText(out.RefreshToken, zaloMinToken, zaloMaxToken) {
		return secrets.Value{}, &SignInError{Msg: zaloRefreshText, Err: &ProviderError{Channel: Zalo, Code: out.Error, Reason: "the token endpoint refused the refresh token"}}
	}
	life := zaloDefaultLife
	if n, err := strconv.Atoi(strings.Trim(string(out.ExpiresIn), `"`)); err == nil && n > 0 && n <= 30*24*3600 {
		life = time.Duration(n) * time.Second
	}
	z.grant.AccessToken, z.grant.RefreshToken, z.grant.Expires = out.AccessToken, out.RefreshToken, now.Add(life)
	z.token = secrets.NewValue(out.AccessToken)
	if z.save != nil { // the old refresh token no longer works: the new one must be kept
		_ = z.save(ctx, old.secret(), z.grant.secret())
	}
	return z.token, nil
}

func (z *zaloSender) hide() []secrets.Value {
	return []secrets.Value{secrets.NewValue(z.grant.SecretKey), secrets.NewValue(z.grant.RefreshToken), z.token}
}

func (*zaloSender) Type() Type { return Zalo }

func (z *zaloSender) Send(ctx context.Context, m Message) (Receipt, error) {
	if err := m.check(); err != nil {
		return Receipt{}, err
	}
	link, _ := safeLink(m.Link)
	body, err := json.Marshal(map[string]any{
		"recipient": map[string]string{"user_id": z.user},
		"message":   map[string]string{"text": fit(m.norm().mapText(defang).lines(link), zaloTextMax)},
	})
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: zalo: encode message: %w", err)
	}
	tok, err := z.accessToken(ctx, false)
	if err != nil {
		return Receipt{}, err
	}
	r, err := z.post(ctx, body, tok)
	var pe *ProviderError
	if errors.As(err, &pe) && (pe.Code == -216 || pe.Code == -220) && z.isGrant { // the token was revoked or ended early: refresh once
		if tok, err = z.accessToken(ctx, true); err != nil {
			return Receipt{}, err
		}
		r, err = z.post(ctx, body, tok)
	}
	return r, err
}

func (z *zaloSender) post(ctx context.Context, body []byte, tok secrets.Value) (Receipt, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, z.endpoint, bytes.NewReader(body))
	if err != nil {
		return Receipt{}, fmt.Errorf("notify: zalo: build request: %s", transportReason(err, []secrets.Value{tok}))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("access_token", tok.Reveal())
	code, ans, err := do(z.client, Zalo, req, tok)
	if err != nil {
		return Receipt{}, err
	}
	if code < 200 || code > 299 {
		return Receipt{}, statusErr(Zalo, code, ans, tok)
	}
	// The Open API answers HTTP 200 for most failures and puts the verdict in "error" (0 = success).
	var out struct {
		Error   *int   `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(ans, &out) != nil || out.Error == nil {
		return Receipt{}, &ProviderError{Channel: Zalo, Reason: "the answer did not confirm delivery"}
	}
	if *out.Error != 0 {
		pe := &ProviderError{Channel: Zalo, Code: *out.Error, Reason: reasonFrom([]byte(out.Message), tok)}
		if *out.Error == -32 { // "the app or the OA called Zalo too often": a rate limit that names no wait (D-483)
			return Receipt{}, &RateLimitError{Channel: Zalo, Err: pe}
		}
		return Receipt{}, pe
	}
	return Receipt{To: "OA " + z.oa, Detail: fmt.Sprintf("Zalo OA %s sent the message to recipient %s.", z.oa, z.user)}, nil
}

func (z *zaloSender) Dest() string { return "OA " + z.oa }
