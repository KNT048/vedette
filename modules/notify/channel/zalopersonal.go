package channel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// ZaloPersonalConfig is the stored configuration of the unofficial Zalo personal
// channel (D-46). UserID is the numeric ID of the recipient (a person, or a group
// when Group is true). Session is the secret: the JSON of a logged-in Zalo web
// session, see parseZaloSession.
//
// The protocol is reverse-engineered, not published by Zalo, and may change or be
// blocked at any time. Zalo may lock an account that uses it: use a separate
// account (IMPACT.md, "Zalo personal").
type ZaloPersonalConfig struct {
	UserID  string
	Group   bool // UserID is a group ID, not a person
	Session secrets.Value
	Client  *http.Client // nil = NewHTTPClient()
}

var zaloPersonalUserRE = regexp.MustCompile(`^\d{6,25}$`)

const (
	zaloPersonalLoginBase = "https://wpa.chat.zalo.me"
	zaloLoginTTL          = 12 * time.Hour // ponytail: fixed lifetime, a refused send signs in once more; upgrade: honour the keep-alive settings
	zaloMaxCookies        = 64
)

type zaloPersonalSender struct {
	noPrint
	user      string
	group     bool
	raw       secrets.Value
	sess      zaloSession
	client    *http.Client
	loginBase string
	now       func() time.Time

	mu  sync.Mutex // serialises Send: one sign-in at a time, cookies and key are shared
	jar []zaloCookie
	li  *zaloLogin
}

// zaloLogin is the signed-in state: the secret key of the session (zpw_enk) and
// the base URL of the one service the message goes to.
type zaloLogin struct {
	key    []byte
	keyB64 string
	base   string
	at     time.Time
}

// NewZaloPersonal validates the stored configuration (INV-8) without touching the network.
func NewZaloPersonal(cfg ZaloPersonalConfig) (Sender, error) {
	user := strings.TrimSpace(cfg.UserID)
	if !zaloPersonalUserRE.MatchString(user) {
		return nil, cfgErr("bad_user_id", "The recipient is the numeric Zalo ID of a user or a group (6 to 25 digits).")
	}
	if !isSet(cfg.Session) {
		return nil, cfgErr("secret_required", "Scan the QR code with the Zalo app first. This channel has no saved session yet.")
	}
	sess, err := parseZaloSession(cfg.Session.Reveal())
	if err != nil {
		return nil, cfgErr("bad_session", "The saved Zalo session is not usable. Sign in to Zalo again.")
	}
	return &zaloPersonalSender{
		user: user, group: cfg.Group, raw: cfg.Session, sess: sess, jar: append([]zaloCookie(nil), sess.cookies...),
		client: clientOrDefault(cfg.Client), loginBase: zaloPersonalLoginBase, now: time.Now,
	}, nil
}

func (*zaloPersonalSender) Type() Type { return ZaloPersonal }

func (z *zaloPersonalSender) Dest() string { return "Zalo " + z.user }

// Send signs in (or reuses the session of an earlier send) and sends plain text.
// A refusal on a reused session may mean it expired, so Send signs in once more
// and tries once more; a refusal on a fresh session is final.
func (z *zaloPersonalSender) Send(ctx context.Context, m Message) (Receipt, error) {
	if err := m.check(); err != nil {
		return Receipt{}, err
	}
	link, _ := safeLink(m.Link)
	text := fit(m.norm().mapText(defang).lines(link), zaloTextMax)

	z.mu.Lock()
	defer z.mu.Unlock()
	for {
		fresh := z.li == nil || z.now().Sub(z.li.at) > zaloLoginTTL
		if fresh {
			if err := z.signIn(ctx); err != nil {
				return Receipt{}, err
			}
		}
		err := z.post(ctx, text)
		if err == nil {
			return Receipt{To: z.Dest(), Detail: "Zalo (personal account) sent the message to " + z.user + "."}, nil
		}
		var pe *ProviderError
		if fresh || !errors.As(err, &pe) {
			return Receipt{}, err
		}
		z.li = nil
	}
}

// signIn runs the sign-in of the Zalo web client with the saved session: one
// signed GET that returns the session key and the service map, then the server
// info request the web client makes next (its answer is not used).
func (z *zaloPersonalSender) signIn(ctx context.Context) error {
	q, enk, err := zaloLoginQuery(z.sess.imei, z.sess.language, z.now(), zaloRandHex())
	if err != nil {
		return fmt.Errorf("notify: zalo-personal: sign in: %w", err)
	}
	hide := secrets.NewValue(enk)
	body, err := z.call(ctx, http.MethodGet, z.loginBase+"/api/login/getLoginInfo?"+q.Encode(), nil, hide)
	if err != nil {
		return err
	}
	data, err := openZaloAnswer(body, []byte(enk), append(z.hide(), hide)...)
	if err != nil {
		return err
	}
	key, base, err := parseZaloLoginInfo(data, z.group)
	if err != nil {
		return err
	}
	z.li = &zaloLogin{key: key, keyB64: encodeB64(key), base: base, at: z.now()}
	// Best effort: the web client asks for the server info after the sign-in; a
	// failure here does not stop the alert.
	_, _ = z.call(ctx, http.MethodGet, z.loginBase+"/api/login/getServerInfo?"+zaloServerInfoQuery(z.sess.imei).Encode(), nil)
	return nil
}

// post sends the text through the signed-in session.
func (z *zaloPersonalSender) post(ctx context.Context, text string) error {
	plain := zaloMessageParams(z.sess.imei, z.user, text, z.group, z.now())
	enc, err := zaloEncrypt(z.li.key, plain)
	if err != nil {
		return fmt.Errorf("notify: zalo-personal: encrypt message: %w", err)
	}
	path := "/api/message/sms"
	if z.group {
		path = "/api/group/sendmsg"
	}
	body, err := z.call(ctx, http.MethodPost, z.li.base+path+"?"+zaloVersionQuery().Encode(), strings.NewReader(url.Values{"params": {enc}}.Encode()))
	if err != nil {
		return err
	}
	return confirmZaloSend(body, z.li.key, z.hide()...)
}

// call sends one request as the Zalo web client would: the saved cookies that
// belong to the host, the saved user agent, Origin and Referer of chat.zalo.me.
// It reads at most maxResponseBody bytes under its own deadline, keeps the
// cookies Zalo sets, and returns errors with no URL and no secret.
func (z *zaloPersonalSender) call(ctx context.Context, method, rawURL string, body io.Reader, more ...secrets.Value) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	hide := append(z.hide(), more...)
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("notify: zalo-personal: build request: %s", transportReason(err, hide))
	}
	host := req.URL.Hostname()
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Origin", "https://chat.zalo.me")
	req.Header.Set("Referer", "https://chat.zalo.me/")
	req.Header.Set("User-Agent", z.sess.userAgent)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c := z.cookieHeader(host); c != "" {
		req.Header.Set("Cookie", c)
	}
	resp, err := z.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("notify: zalo-personal: send failed: %s", transportReason(err, hide))
	}
	defer func() { _ = resp.Body.Close() }()
	z.absorb(host, resp.Cookies())
	ans, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("notify: zalo-personal: read answer: %s", transportReason(err, hide))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, statusErr(ZaloPersonal, resp.StatusCode, ans, hide...)
	}
	return ans, nil
}

// hide lists every secret that must never appear in an error: the session as
// saved, the device id, each cookie value (as saved and as rotated) and the
// session key.
func (z *zaloPersonalSender) hide() []secrets.Value {
	h := []secrets.Value{z.raw, secrets.NewValue(z.sess.imei)}
	for _, c := range append(z.sess.cookies[:len(z.sess.cookies):len(z.sess.cookies)], z.jar...) {
		h = append(h, secrets.NewValue(c.value))
	}
	if z.li != nil {
		h = append(h, secrets.NewValue(z.li.keyB64))
	}
	return h
}

// cookieHeader returns the cookies that belong to host, in the order saved.
func (z *zaloPersonalSender) cookieHeader(host string) string {
	var parts []string
	for _, c := range z.jar {
		if c.domain == "" || host == c.domain || strings.HasSuffix(host, "."+c.domain) {
			parts = append(parts, c.name+"="+c.value)
		}
	}
	return strings.Join(parts, "; ")
}

// absorb keeps the cookies Zalo sets, as the web client does (the session
// cookies can rotate during sign-in). Only valid cookies for a zalo.me host are
// kept, at most zaloMaxCookies, in memory: the saved session is not rewritten.
func (z *zaloPersonalSender) absorb(host string, set []*http.Cookie) {
	for _, c := range set {
		if !zaloCookieNameRE.MatchString(c.Name) || !zaloCookieValueOK(c.Value) {
			continue
		}
		d := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		if d == "" {
			d = host
		}
		if !zaloHostOK(d) || (host != d && !strings.HasSuffix(host, "."+d)) {
			continue
		}
		i := -1
		for j, o := range z.jar {
			if o.name == c.Name && o.domain == d {
				i = j
			}
		}
		switch {
		case c.MaxAge < 0 && i >= 0:
			z.jar = append(z.jar[:i], z.jar[i+1:]...)
		case c.MaxAge < 0:
		case i >= 0:
			z.jar[i].value = c.Value
		case len(z.jar) < zaloMaxCookies:
			z.jar = append(z.jar, zaloCookie{c.Name, c.Value, d})
		}
	}
}
