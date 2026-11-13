package channel

// QR sign-in of the unofficial Zalo web client (D-447), read from zca-js v2.2.0 (MIT, github.com/RFS-ADRENO/zca-js) src/apis/loginQR.ts
// and the loginQR of src/zalo.ts, and re-implemented here with the standard library: the login page gives the version of the login
// script, three form posts to id.zalo.me make a QR code, two long polls wait for the scan and the confirmation on the phone, then
// checksession and jr.chat.zalo.me/jr/userinfo finish it. The cookies the browser would keep, a new device id and the user agent make the
// session the channel saves; it is signed in once (getLoginInfo, the same as a send) before it counts. Every answer is untrusted: sizes
// are capped, decoding fails closed, redirects stay on https zalo.me hosts.

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // the device id ends with the MD5 of the user agent, as the web client makes it; not a security control
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

const (
	zaloIDBase = "https://id.zalo.me"
	zaloJRBase = "https://jr.chat.zalo.me"
	// ZaloQRUserAgent is the user agent of a QR sign-in and of the session it saves (zca-js's default).
	ZaloQRUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
	// ZaloQRLife is how long a QR code waits for its scan and confirmation (zca-js: 100 s, then it has expired).
	ZaloQRLife       = 100 * time.Second
	zaloQRMaxPage    = 1 << 20
	zaloQRMaxImage   = 256 << 10
	zaloQRMaxSide    = 1024
	zaloQRGrid       = 200 // the drawn QR code has at most this many cells a side
	zaloQRPolls      = 200 // waiting requests per phase
	zaloMaxRedirects = 5
)

var (
	// ErrZaloQRDeclined: the person pressed Decline in the Zalo app.
	ErrZaloQRDeclined = errors.New("notify: zalo-personal: the sign-in was declined in the Zalo app")
	// ErrZaloQRExpired: the code was not scanned and confirmed in time.
	ErrZaloQRExpired = errors.New("notify: zalo-personal: the QR code expired")

	zaloLoginVersionRE = regexp.MustCompile(`https://stc-zlogin\.zdn\.vn/main-([\d.]{1,20})\.js`)
	zaloQRCodeRE       = regexp.MustCompile(`^[A-Za-z0-9_.-]{4,128}$`)
)

// ZaloQRImage is the QR code Zalo made, redrawn as an SVG path of dark cells: the browser never decodes Zalo's image (the PNG is read
// here), and the page's Content-Security-Policy allows no data: image. Size is the side of the square view box, quiet zone included.
type ZaloQRImage struct {
	Size int    `json:"size"`
	Path string `json:"path"`
}

// ZaloSignedIn is a finished QR sign-in: Session is the secret to save (the JSON parseZaloSession reads), Name the account's display
// name, Account a sender over that session, signed in, for the contact list (ZaloContacts) until the channel is saved.
type ZaloSignedIn struct {
	Session secrets.Value
	Name    string
	Account Sender
}

// ZaloQR is one QR sign-in. One goroutine drives it: StartZaloQR, WaitScan, WaitConfirm, Finish, in that order.
type ZaloQR struct {
	noPrint
	client  *http.Client
	jar     *cookiejar.Jar
	ver     string
	code    string
	pollGap time.Duration // the least time between two waiting requests (a server that answers "wait" at once is not hammered)
	Image   ZaloQRImage
}

// StartZaloQR asks Zalo for a QR code. client nil = NewHTTPClient(); redirects are followed here, never by the client.
func StartZaloQR(ctx context.Context, client *http.Client) (*ZaloQR, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	q := &ZaloQR{client: clientOrDefault(client), jar: jar, pollGap: time.Second}
	page, err := q.do(ctx, http.MethodGet, zaloIDBase+"/account?continue="+url.QueryEscape("https://chat.zalo.me/"), nil, "https://chat.zalo.me/", zaloQRMaxPage)
	if err != nil {
		return nil, err
	}
	m := zaloLoginVersionRE.FindSubmatch(page)
	if m == nil {
		return nil, badAnswer("the Zalo login page did not name its version")
	}
	q.ver = string(m[1])
	ref := "https://id.zalo.me/account?continue=" + url.QueryEscape("https://zalo.me/pc")
	// zca-js reads nothing from these two answers: they set the cookies the next steps need.
	if _, err := q.do(ctx, http.MethodPost, zaloIDBase+"/account/logininfo", url.Values{"continue": {"https://zalo.me/pc"}, "v": {q.ver}}, ref, maxResponseBody); err != nil {
		return nil, err
	}
	if _, err := q.do(ctx, http.MethodPost, zaloIDBase+"/account/verify-client", url.Values{"type": {"device"}, "continue": {"https://zalo.me/pc"}, "v": {q.ver}}, ref, maxResponseBody); err != nil {
		return nil, err
	}
	body, err := q.do(ctx, http.MethodPost, zaloIDBase+"/account/authen/qr/generate", url.Values{"continue": {"https://zalo.me/pc"}, "v": {q.ver}}, ref, zaloQRMaxImage*2)
	if err != nil {
		return nil, err
	}
	var gen struct {
		ErrorCode *int   `json:"error_code"`
		Message   string `json:"error_message"`
		Data      *struct {
			Code  string `json:"code"`
			Image string `json:"image"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &gen) != nil || gen.ErrorCode == nil {
		return nil, badAnswer("the QR code answer was not understood")
	}
	if *gen.ErrorCode != 0 || gen.Data == nil {
		return nil, &ProviderError{Channel: ZaloPersonal, Code: *gen.ErrorCode, Reason: reasonFrom([]byte(gen.Message))}
	}
	if !zaloQRCodeRE.MatchString(gen.Data.Code) {
		return nil, badAnswer("the QR code answer had no usable code")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(gen.Data.Image, "data:image/png;base64,"))
	if err != nil || len(raw) > zaloQRMaxImage {
		return nil, badAnswer("the QR code image was not understood")
	}
	if q.Image, err = zaloQRPath(raw); err != nil {
		return nil, err
	}
	q.code = gen.Data.Code
	return q, nil
}

// QR is the code to show.
func (q *ZaloQR) QR() ZaloQRImage { return q.Image }

// WaitScan waits until the code is scanned and returns the name the app shows for the account that scanned it ("" when Zalo gave none).
// It returns ErrZaloQRExpired when ctx ends first: the caller gives ctx the deadline of the code (ZaloQRLife).
func (q *ZaloQR) WaitScan(ctx context.Context) (string, error) {
	data, err := q.wait(ctx, "/account/authen/qr/waiting-scan", url.Values{"code": {q.code}, "continue": {"https://chat.zalo.me/"}, "v": {q.ver}})
	if err != nil {
		return "", err
	}
	var d struct {
		Name string `json:"display_name"`
	}
	_ = json.Unmarshal(data, &d) // no name is not an error
	return Line(d.Name, 64), nil
}

// WaitConfirm waits until the person confirms the sign-in on the phone: ErrZaloQRDeclined when they decline, ErrZaloQRExpired when ctx ends.
func (q *ZaloQR) WaitConfirm(ctx context.Context) error {
	_, err := q.wait(ctx, "/account/authen/qr/waiting-confirm", url.Values{"code": {q.code}, "gToken": {""}, "gAction": {"CONFIRM_QR"}, "continue": {"https://chat.zalo.me/"}, "v": {q.ver}})
	return err
}

// wait long-polls one phase: error_code 8 means "not yet, ask again"; -13 is a decline; 0 ends the phase with its data.
func (q *ZaloQR) wait(ctx context.Context, path string, form url.Values) (json.RawMessage, error) {
	ref := "https://id.zalo.me/account?continue=" + url.QueryEscape("https://chat.zalo.me/")
	for range zaloQRPolls {
		started := time.Now()
		body, err := q.do(ctx, http.MethodPost, zaloIDBase+path, form, ref, maxResponseBody)
		if ctx.Err() != nil {
			return nil, ErrZaloQRExpired
		}
		if err == nil {
			env, ok := parseZaloEnvelope(body)
			switch {
			case !ok || env.ErrorCode == nil:
				return nil, badAnswer("the sign-in answer was not understood")
			case *env.ErrorCode == 0:
				return env.Data, nil
			case *env.ErrorCode == -13:
				return nil, ErrZaloQRDeclined
			case *env.ErrorCode != 8:
				return nil, &ProviderError{Channel: ZaloPersonal, Code: *env.ErrorCode, Reason: reasonFrom([]byte(env.ErrorMessage))}
			}
		} else {
			var se *StatusError
			if errors.As(err, &se) { // Zalo refused the request: asking again would not change that
				return nil, err
			}
		} // a transport error (the long poll timed out on our side) is asked again, as a browser would
		if wait := q.pollGap - time.Since(started); wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ErrZaloQRExpired
			case <-t.C:
			}
		}
	}
	return nil, ErrZaloQRExpired
}

// Finish ends a confirmed sign-in: checksession (whose redirects set the chat cookies), the account's name from jr.chat.zalo.me, then the
// session as the channel will save it, signed in once with getLoginInfo. Only then is the sign-in real.
func (q *ZaloQR) Finish(ctx context.Context) (ZaloSignedIn, error) {
	if _, err := q.do(ctx, http.MethodGet, zaloIDBase+"/account/checksession?continue="+url.QueryEscape("https://chat.zalo.me/index.html"), nil,
		"https://id.zalo.me/account?continue="+url.QueryEscape("https://chat.zalo.me/"), zaloQRMaxPage); err != nil {
		return ZaloSignedIn{}, err
	}
	body, err := q.do(ctx, http.MethodGet, zaloJRBase+"/jr/userinfo", nil, "https://chat.zalo.me/", maxResponseBody)
	if err != nil {
		return ZaloSignedIn{}, err
	}
	var info struct {
		ErrorCode *int `json:"error_code"`
		Data      *struct {
			Logged bool `json:"logged"`
			Info   struct {
				Name string `json:"name"`
			} `json:"info"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &info) != nil || info.ErrorCode == nil || *info.ErrorCode != 0 || info.Data == nil || !info.Data.Logged {
		return ZaloSignedIn{}, badAnswer("Zalo did not confirm the sign-in")
	}
	sess, err := q.session()
	if err != nil {
		return ZaloSignedIn{}, err
	}
	acct, err := NewZaloAccount(sess, q.client)
	if err != nil {
		return ZaloSignedIn{}, badAnswer("the session Zalo gave is not usable")
	}
	z := acct.(*zaloPersonalSender)
	if err := z.query(ctx, func(bool) error { return nil }); err != nil { // signs in, as a send would
		return ZaloSignedIn{}, err
	}
	return ZaloSignedIn{Session: sess, Name: Line(info.Data.Info.Name, 64), Account: acct}, nil
}

// session builds the saved session: the cookies the chat hosts would get (as domain cookies of chat.zalo.me, which is where the
// channel's requests go), a new device id as the web client makes it (a random UUID, "-", the MD5 of the user agent) and the user agent.
func (q *ZaloQR) session() (secrets.Value, error) {
	type ck struct {
		Name   string `json:"name"`
		Value  string `json:"value"`
		Domain string `json:"domain"`
	}
	var list []ck
	for _, c := range q.jar.Cookies(&url.URL{Scheme: "https", Host: "chat.zalo.me", Path: "/"}) {
		if zaloCookieNameRE.MatchString(c.Name) && zaloCookieValueOK(c.Value) && len(list) < zaloMaxCookies {
			list = append(list, ck{c.Name, c.Value, "chat.zalo.me"})
		}
	}
	if len(list) == 0 {
		return secrets.Value{}, badAnswer("Zalo set no session cookie")
	}
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return secrets.Value{}, err
	}
	u[6], u[8] = u[6]&0x0f|0x40, u[8]&0x3f|0x80
	h := hex.EncodeToString(u[:])
	sum := md5.Sum([]byte(ZaloQRUserAgent)) //nolint:gosec // see import
	imei := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:] + "-" + hex.EncodeToString(sum[:])
	raw, err := json.Marshal(struct {
		IMEI      string `json:"imei"`
		UserAgent string `json:"userAgent"`
		Language  string `json:"language"`
		Cookie    []ck   `json:"cookie"`
	}{imei, ZaloQRUserAgent, "vi", list})
	if err != nil {
		return secrets.Value{}, err
	}
	return secrets.NewValue(string(raw)), nil
}

// do sends one request of the sign-in as the browser would (the cookies of the jar for that address, the user agent, Origin and the given
// Referer) and follows up to 5 redirects with GET, each to an https zalo.me host. It reads at most limit bytes of the last answer, keeps
// every cookie a zalo.me host sets, and never puts an address or a cookie in its errors.
func (q *ZaloQR) do(ctx context.Context, method, rawURL string, form url.Values, referer string, limit int64) ([]byte, error) {
	for hop := 0; ; hop++ {
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme != "https" || u.User != nil || !zaloHostOK(u.Hostname()) || (u.Port() != "" && u.Port() != "443") {
			return nil, errors.New("notify: zalo-personal: refused to sign in at an address that is not a Zalo host")
		}
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		rctx, cancel := context.WithTimeout(ctx, defaultTimeout)
		req, err := http.NewRequestWithContext(rctx, method, u.String(), body)
		if err != nil {
			cancel()
			return nil, errors.New("notify: zalo-personal: build sign-in request")
		}
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "vi-VN,vi;q=0.9,en-US;q=0.6,en;q=0.5")
		req.Header.Set("Origin", "https://chat.zalo.me")
		req.Header.Set("Referer", referer)
		req.Header.Set("User-Agent", ZaloQRUserAgent)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		var parts []string
		for _, c := range q.jar.Cookies(u) {
			parts = append(parts, c.Name+"="+c.Value)
		}
		if len(parts) > 0 {
			req.Header.Set("Cookie", strings.Join(parts, "; "))
		}
		resp, err := q.client.Do(req)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("notify: zalo-personal: sign in: %s", transportReason(err, nil))
		}
		q.keep(u, resp.Cookies())
		ans, rerr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		_ = resp.Body.Close()
		cancel()
		if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			if hop == zaloMaxRedirects {
				return nil, badAnswer("the sign-in was redirected too many times")
			}
			next, err := u.Parse(loc)
			if err != nil {
				return nil, badAnswer("the sign-in was redirected to an address that is not understood")
			}
			rawURL, method, form, referer = next.String(), http.MethodGet, nil, "https://id.zalo.me/"
			continue
		}
		switch {
		case rerr != nil:
			return nil, fmt.Errorf("notify: zalo-personal: read sign-in answer: %s", transportReason(rerr, nil))
		case int64(len(ans)) > limit:
			return nil, badAnswer("the sign-in answer was too large")
		case resp.StatusCode < 200 || resp.StatusCode > 299:
			return nil, statusErr(ZaloPersonal, resp.StatusCode, nil)
		}
		return ans, nil
	}
}

// keep stores the cookies an answer from u set, as zca-js does: a cookie that names a domain other than zalo.me is kept for that domain
// (Zalo's sign-in sets the chat cookies from id.zalo.me), any other for u. Only zalo.me hosts are accepted.
func (q *ZaloQR) keep(u *url.URL, set []*http.Cookie) {
	for _, c := range set {
		d := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		at := u
		if d != "" && d != "zalo.me" {
			if !zaloHostOK(d) || !zaloDomainRE.MatchString(d) {
				continue
			}
			at = &url.URL{Scheme: "https", Host: d, Path: "/"}
		}
		q.jar.SetCookies(at, []*http.Cookie{c})
	}
}

// zaloQRPath reads Zalo's QR image (a PNG of at most 1024 pixels a side) and redraws its dark pixels: cropped to them, sampled at the
// centre of each module (or of each pixel, at most zaloQRGrid a side, when the module size cannot be read), with a quiet zone of 4 cells,
// as one SVG path of horizontal runs ("M x y h n v1 h-n z").
func zaloQRPath(raw []byte) (ZaloQRImage, error) {
	bad := badAnswer("the QR code image was not understood")
	cfg, err := png.DecodeConfig(bytes.NewReader(raw))
	if err != nil || cfg.Width < 21 || cfg.Height < 21 || cfg.Width > zaloQRMaxSide || cfg.Height > zaloQRMaxSide {
		return ZaloQRImage{}, bad
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return ZaloQRImage{}, bad
	}
	dark := func(x, y int) bool {
		r, g, b, a := img.At(x, y).RGBA()
		return a >= 0x8000 && (299*r+587*g+114*b)/1000 < 0x8000
	}
	bb := img.Bounds()
	box := image.Rectangle{Min: bb.Max, Max: bb.Min}
	for y := bb.Min.Y; y < bb.Max.Y; y++ {
		for x := bb.Min.X; x < bb.Max.X; x++ {
			if dark(x, y) {
				box.Min.X, box.Min.Y = min(box.Min.X, x), min(box.Min.Y, y)
				box.Max.X, box.Max.Y = max(box.Max.X, x+1), max(box.Max.Y, y+1)
			}
		}
	}
	if box.Empty() || box.Dx() < 21 || box.Dy() < 21 {
		return ZaloQRImage{}, bad
	}
	side := max(box.Dx(), box.Dy())
	cells, step := 0, 0.0
	if m := finderModule(dark, box); m > 0 { // one cell per module when the finder pattern tells the module size
		if n := int(math.Round(float64(side) / m)); n >= 21 && n <= 177 {
			cells, step = n, float64(side)/float64(n)
		}
	}
	if cells == 0 { // otherwise the pixels, at most zaloQRGrid a side
		s := (side + zaloQRGrid - 1) / zaloQRGrid
		cells, step = (side+s-1)/s, float64(s)
	}
	const quiet = 4
	var p strings.Builder
	for cy := range cells {
		run := 0
		flush := func(end int) {
			if run > 0 {
				fmt.Fprintf(&p, "M%d %dh%dv1h-%dz", end-run+quiet, cy+quiet, run, run)
				run = 0
			}
		}
		for cx := range cells {
			x, y := box.Min.X+int((float64(cx)+0.5)*step), box.Min.Y+int((float64(cy)+0.5)*step)
			if x < box.Max.X && y < box.Max.Y && dark(x, y) {
				run++
			} else {
				flush(cx)
			}
		}
		flush(cells)
	}
	return ZaloQRImage{Size: cells + 2*quiet, Path: p.String()}, nil
}

// finderModule reads the module size from the top-left finder pattern: along the diagonal from the corner of the dark box, a dark
// module, a light one, then three dark ones (a rounded corner is skipped). 0 when the runs are not there.
func finderModule(dark func(x, y int) bool, box image.Rectangle) float64 {
	x, y := box.Min.X, box.Min.Y
	in := func() bool { return x < box.Max.X && y < box.Max.Y }
	for in() && !dark(x, y) {
		x, y = x+1, y+1
	}
	var runs [3]int
	for i := range runs {
		for in() && dark(x, y) == (i%2 == 0) {
			runs[i]++
			x, y = x+1, y+1
		}
		if runs[i] == 0 {
			return 0
		}
	}
	return float64(runs[0]+runs[1]+runs[2]) / 5
}
