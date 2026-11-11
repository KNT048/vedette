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
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// ZaloPersonalConfig is the stored configuration of the unofficial Zalo personal
// channel (D-46). UserID is the numeric ID of the recipient (a person, or a group
// when Group is true). Session is the secret: the JSON of a logged-in Zalo web
// session, see parseZaloSession.
//
// The protocol is reverse-engineered, not published by Zalo, and may change or be
// blocked at any time. Zalo may lock an account that uses it, and repeated
// sign-ins make that more likely: use a separate account (IMPACT.md, "Zalo
// personal").
type ZaloPersonalConfig struct {
	UserID  string
	Group   bool // UserID is a group ID, not a person
	Session secrets.Value
	Client  *http.Client // nil = NewHTTPClient()
}

var zaloPersonalUserRE = regexp.MustCompile(`^\d{6,25}$`)

const (
	zaloPersonalLoginBase = "https://wpa.chat.zalo.me"
	zaloLoginTTL          = 12 * time.Hour // ponytail: fixed lifetime; upgrade: honour the keep-alive settings of getServerInfo
	zaloMaxCookies        = 64
	zaloBackoffFloor      = time.Minute
	zaloBackoffCeiling    = time.Hour
	zaloInfoTimeout       = 3 * time.Second
)

// BackoffError is returned while sign-ins are paused after a failed or refused
// one (D-46: repeated sign-ins can get the account locked). Nothing was sent to
// Zalo. Until is when the next sign-in is allowed.
type BackoffError struct {
	Channel Type
	Until   time.Time
}

func (e *BackoffError) Error() string {
	return fmt.Sprintf("notify: %s: signing in is paused after a failure, next try after %s", e.Channel, e.Until.UTC().Format(time.RFC3339))
}

type zaloPersonalSender struct {
	noPrint
	user      string
	group     bool
	raw       secrets.Value
	sess      zaloSession
	client    *http.Client
	loginBase string
	now       func() time.Time

	sem chan struct{} // capacity 1: one Send at a time; waiting honours the context. Guards everything below.
	jar []zaloCookie
	li  *zaloLogin

	failures  int       // sign-ins or sessions refused in a row
	notBefore time.Time // no sign-in before this
}

// zaloLogin is the signed-in state: the secret key of the session (zpw_enk), the
// base URL of the service of the configured recipient (chat or group), and the
// chat service for direct messages ("" when the answer named none).
type zaloLogin struct {
	key    []byte
	keyB64 string
	base   string
	chat   string
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
		sem: make(chan struct{}, 1),
	}, nil
}

func (*zaloPersonalSender) Type() Type { return ZaloPersonal }

func (z *zaloPersonalSender) Dest() string { return "Zalo " + z.user }

// Send signs in (or reuses the session of an earlier send) and sends plain text.
//
// Sign-ins are rationed. A failed or refused sign-in, or a session Zalo refuses
// (HTTP 401/403, or an error_code on the request as a whole), pauses sign-ins
// for 1 minute, doubling per consecutive failure up to 1 hour; during the pause
// Send returns *BackoffError without calling Zalo. The one exception is the
// first refusal of a reused session by error_code: Send signs in once and tries
// once more. A message is never posted twice: an answer that cannot be read
// (the message may be delivered) or a refusal of the message itself is final.
func (z *zaloPersonalSender) Send(ctx context.Context, m Message) (Receipt, error) {
	if err := m.check(); err != nil {
		return Receipt{}, err
	}
	if m.ReplyCodes != nil { // codes are for one approver: never to the configured user or group (ZaloPersonalTo)
		return Receipt{}, fmt.Errorf("%w: reply codes go only to the approver they belong to", ErrInvalidMessage)
	}
	return z.send(ctx, m, z.user, z.group, false)
}

// ZaloPersonalTo returns a sender that posts to one person, userID (the Zalo user ID, digits, never a phone number), through the
// session of snd, which must be a Zalo personal sender: same sign-in, same sign-in pause, one send at a time with it. It is how an
// approver gets their own reply codes (spec approval-tokens.md 7), and how a resend of that message reaches the same approver.
func ZaloPersonalTo(snd Sender, userID string) (Sender, error) {
	z, ok := snd.(*zaloPersonalSender)
	if !ok {
		return nil, errors.New("notify: zalo-personal: a direct message needs the Zalo personal channel")
	}
	if !zaloPersonalUserRE.MatchString(userID) || ZaloPhoneLike(userID) {
		return nil, cfgErr("bad_user_id", "The approver is the numeric Zalo user ID (6 to 25 digits), not a phone number.")
	}
	return &zaloDirect{z: z, user: userID}, nil
}

// ZaloPhoneLike reports whether s has the form of a Vietnamese phone number (0 and 9 digits, or 84 and 9 digits, with or without +).
// A reply carries the sender's user ID, never their phone number, so such an address could never match (D-242).
func ZaloPhoneLike(s string) bool { return zaloPhoneRE.MatchString(s) }

var zaloPhoneRE = regexp.MustCompile(`^(\+?84\d{9}|0\d{9})$`)

// zaloDirect is the sender of ZaloPersonalTo.
type zaloDirect struct {
	noPrint
	z    *zaloPersonalSender
	user string
}

func (*zaloDirect) Type() Type { return ZaloPersonal }

func (d *zaloDirect) Dest() string { return "Zalo " + d.user }

func (d *zaloDirect) Send(ctx context.Context, m Message) (Receipt, error) {
	if err := m.check(); err != nil {
		return Receipt{}, err
	}
	return d.z.send(ctx, m, d.user, false, true)
}

// send posts m to one user, or to one group when group is true. direct is a message to an approver (ZaloPersonalTo).
func (z *zaloPersonalSender) send(ctx context.Context, m Message, to string, group, direct bool) (Receipt, error) {
	link, _ := safeLink(m.Link)
	lines := m.norm().mapText(defang).lines(link)
	if m.ReplyCodes != nil { // the box's own text, not feed text: kept whole with the link line, which fit never cuts
		lines[len(lines)-1] += "\n" + m.ReplyCodes.line()
	}
	text := fit(lines, zaloTextMax)

	select {
	case z.sem <- struct{}{}:
	case <-ctx.Done():
		return Receipt{}, fmt.Errorf("notify: zalo-personal: waiting for an earlier send: %s", transportReason(ctx.Err(), nil))
	}
	defer func() { <-z.sem }()

	retried := false
	for {
		fresh := z.li == nil || z.now().Sub(z.li.at) > zaloLoginTTL
		if fresh {
			if now := z.now(); now.Before(z.notBefore) {
				return Receipt{}, &BackoffError{Channel: ZaloPersonal, Until: z.notBefore}
			}
			if err := z.signIn(ctx); err != nil {
				z.fail()
				return Receipt{}, err
			}
		}
		err := z.post(ctx, text, to, group)
		if err == nil {
			z.failures = 0
			return Receipt{To: "Zalo " + to, Detail: "Zalo (personal account) sent the message to " + to + "."}, nil
		}
		var pe *ProviderError
		var se *StatusError
		switch {
		case errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden):
			z.li = nil // the session is refused: no retry, and the next sign-in waits
			z.fail()
			return Receipt{}, err
		case errors.As(err, &pe) && pe.requestRefused && direct && fresh:
			// The session was just accepted at sign-in, so the refusal is about this one approver (a wrong ID, a block, not a
			// friend): a message failure. It must not pause sign-ins for the channel's alerts and the other approvers.
			return Receipt{}, err
		case errors.As(err, &pe) && pe.requestRefused:
			z.li = nil
			if fresh || retried {
				z.fail()
				return Receipt{}, err
			}
			retried = true // first refusal of a reused session: sign in once and try once more
		default:
			return Receipt{}, err
		}
	}
}

// fail records a failed sign-in or a refused session and arms the pause.
func (z *zaloPersonalSender) fail() {
	z.failures++
	d := zaloBackoffFloor
	for i := 1; i < z.failures && d < zaloBackoffCeiling; i++ {
		d *= 2
	}
	z.notBefore = z.now().Add(min(d, zaloBackoffCeiling))
}

// signIn runs the sign-in of the Zalo web client with the saved session: one
// signed GET that returns the session key and the service map, then the server
// info request the web client makes next. Upstream treats the server info as part
// of signing in but a text message uses nothing from it, so it is best effort
// under a short deadline: its answer is ignored and its failure does not stop
// the alert.
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
	chat := base
	if z.group { // a group channel still sends direct messages (reply codes): keep the chat service too, when the answer names one
		if _, c, err := parseZaloLoginInfo(data, false); err == nil {
			chat = c
		} else {
			chat = ""
		}
	}
	z.li = &zaloLogin{key: key, keyB64: encodeB64(key), base: base, chat: chat, at: z.now()}
	infoCtx, cancel := context.WithTimeout(ctx, zaloInfoTimeout)
	defer cancel()
	_, _ = z.call(infoCtx, http.MethodGet, z.loginBase+"/api/login/getServerInfo?"+zaloServerInfoQuery(z.sess.imei).Encode(), nil)
	return nil
}

// post sends the text to one user or one group through the signed-in session.
func (z *zaloPersonalSender) post(ctx context.Context, text, to string, group bool) error {
	base, path := z.li.chat, "/api/message/sms"
	if group {
		base, path = z.li.base, "/api/group/sendmsg"
	}
	if base == "" {
		return badAnswer("the sign-in answer named no service for a direct message")
	}
	plain := zaloMessageParams(z.sess.imei, to, text, group, z.now())
	enc, err := zaloEncrypt(z.li.key, plain)
	if err != nil {
		return fmt.Errorf("notify: zalo-personal: encrypt message: %w", err)
	}
	body, err := z.call(ctx, http.MethodPost, base+path+"?"+zaloVersionQuery().Encode(), strings.NewReader(url.Values{"params": {enc}}.Encode()))
	if err != nil {
		return err
	}
	return confirmZaloSend(body, z.li.key, z.hide()...)
}

// call sends one request as the Zalo web client would: the saved cookies that
// belong to the host, the saved user agent, Origin and Referer of chat.zalo.me.
// The host is checked again here, whatever built the URL: cookies only ever go to
// wpa.chat.zalo.me and *.chat.zalo.me. It reads at most maxResponseBody bytes
// under its own deadline, keeps the cookies Zalo sets, and returns errors with no
// URL and no secret (the secrets are listed after the cookies of the answer have
// been kept).
func (z *zaloPersonalSender) call(ctx context.Context, method, rawURL string, body io.Reader, more ...secrets.Value) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("notify: zalo-personal: build request: %s", transportReason(err, append(z.hide(), more...)))
	}
	host := req.URL.Hostname()
	if req.URL.Scheme != "https" || !zaloServiceHostOK(host) || req.URL.User != nil {
		return nil, errors.New("notify: zalo-personal: refused to send to an address that is not a Zalo chat host")
	}
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
		return nil, fmt.Errorf("notify: zalo-personal: send failed: %s", transportReason(err, append(z.hide(), more...)))
	}
	defer func() { _ = resp.Body.Close() }()
	z.absorb(host, resp.Cookies(), z.now())
	hide := append(z.hide(), more...) // after absorb: a rotated cookie echoed in the body is scrubbed too
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

// cookieHeader returns the cookies that belong to host, in the order saved. A
// host-only cookie goes to exactly its host, any other to its domain and the
// hosts below it.
func (z *zaloPersonalSender) cookieHeader(host string) string {
	var parts []string
	for _, c := range z.jar {
		if host == c.domain || (!c.hostOnly && strings.HasSuffix(host, "."+c.domain)) {
			parts = append(parts, c.name+"="+c.value)
		}
	}
	return strings.Join(parts, "; ")
}

// absorb keeps the cookies Zalo sets, as the web client does (the session
// cookies can rotate during sign-in). Only valid cookies for a zalo.me host are
// kept, at most zaloMaxCookies, in memory: the saved session is not rewritten. A
// cookie without a Domain attribute is host-only. Max-Age of 0 or less, or an
// Expires in the past when there is no Max-Age, deletes the cookie.
func (z *zaloPersonalSender) absorb(host string, set []*http.Cookie, now time.Time) {
	for _, c := range set {
		if !zaloCookieNameRE.MatchString(c.Name) {
			continue
		}
		d, hostOnly := strings.TrimPrefix(strings.ToLower(c.Domain), "."), false
		if d == "" {
			d, hostOnly = host, true
		}
		if !zaloHostOK(d) || (host != d && !strings.HasSuffix(host, "."+d)) {
			continue
		}
		del := c.MaxAge < 0 || (c.MaxAge == 0 && !c.Expires.IsZero() && !c.Expires.After(now))
		if !del && !zaloCookieValueOK(c.Value) {
			continue
		}
		i := -1
		for j, o := range z.jar {
			if o.name == c.Name && o.domain == d && o.hostOnly == hostOnly {
				i = j
			}
		}
		switch {
		case del && i >= 0:
			z.jar = append(z.jar[:i], z.jar[i+1:]...)
		case del:
		case i >= 0:
			z.jar[i].value = c.Value
		case len(z.jar) < zaloMaxCookies:
			z.jar = append(z.jar, zaloCookie{c.Name, c.Value, d, hostOnly})
		}
	}
}
