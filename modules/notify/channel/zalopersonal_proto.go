package channel

// The wire protocol of the unofficial Zalo web client, as read from zca-js v2.2.0
// (MIT, github.com/RFS-ADRENO/zca-js) and re-implemented here. Nothing in it is
// documented by Zalo. Every answer is untrusted: sizes are capped, decoding fails
// closed, and nothing from an answer is printed except as a short cleaned reason.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" //nolint:gosec // the protocol's request signature is MD5; it is not a security control here
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// zaloAPIType and zaloAPIVersion are the web client identity zca-js sends as
// type/client_version/zpw_type/zpw_ver. Zalo may stop accepting an old version.
const (
	zaloAPIType      = 30
	zaloAPIVersion   = 685
	zaloMaxCipher    = 2 * maxResponseBody // base64 text of an encrypted answer
	zaloMaxSession   = 32 << 10
	zaloMaxCookieLen = 4096
)

// zaloLoginKey encrypts the zcid (the web client's constant, not a secret).
const zaloLoginKey = "3FC4F0D2AB50057BCE0D90D9187A22B1"

var (
	zaloCookieNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	zaloDomainRE     = regexp.MustCompile(`^\.?[A-Za-z0-9.-]{1,100}$`)
	zaloIMEIRE       = regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)
	zaloLangRE       = regexp.MustCompile(`^[a-z]{2}$`)
)

var errZaloDecrypt = errors.New("the answer could not be decrypted")

func badAnswer(reason string) error {
	return &ProviderError{Channel: ZaloPersonal, Reason: reason}
}

type zaloCookie struct{ name, value, domain string }

// zaloSession is the parsed Session secret.
type zaloSession struct {
	imei, userAgent, language string
	cookies                   []zaloCookie
}

func zaloCookieValueOK(v string) bool {
	if v == "" || len(v) > zaloMaxCookieLen {
		return false
	}
	for _, r := range v {
		if r <= ' ' || r > '~' || r == ';' || r == ',' {
			return false
		}
	}
	return true
}

// parseZaloSession reads the session as a logged-in Zalo web client has it, the
// shape zca-js and the n8n Zalo node use: JSON with "imei", "userAgent",
// optional "language" (default "vi") and "cookie", which is an array of
// {name, value, domain?}, an object {url, cookies: [...]}, or a header string
// "a=b; c=d". Cookies for other domains are kept but are never sent to a Zalo
// host. Anything else is refused.
func parseZaloSession(raw string) (zaloSession, error) {
	var s zaloSession
	if len(raw) > zaloMaxSession {
		return s, errors.New("session too large")
	}
	var in struct {
		IMEI      string          `json:"imei"`
		UserAgent string          `json:"userAgent"`
		Language  string          `json:"language"`
		Cookie    json.RawMessage `json:"cookie"`
	}
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return s, errors.New("session is not valid JSON")
	}
	s.imei, s.userAgent, s.language = in.IMEI, in.UserAgent, in.Language
	if s.language == "" {
		s.language = "vi"
	}
	switch {
	case !zaloIMEIRE.MatchString(s.imei):
		return s, errors.New("bad imei")
	case !zaloLangRE.MatchString(s.language):
		return s, errors.New("bad language")
	case s.userAgent == "" || len(s.userAgent) > 512 || strings.ContainsFunc(s.userAgent, func(r rune) bool { return r < ' ' || r > '~' }):
		return s, errors.New("bad user agent")
	}
	list, ok := zaloCookieList(in.Cookie, 0)
	if !ok {
		return s, errors.New("bad cookie")
	}
	if len(list) == 0 || len(list) > zaloMaxCookies {
		return s, errors.New("bad cookie count")
	}
	for _, c := range list {
		d := strings.ToLower(c.Domain)
		if !zaloCookieNameRE.MatchString(c.Name) || !zaloCookieValueOK(c.Value) || (d != "" && !zaloDomainRE.MatchString(d)) {
			return s, errors.New("bad cookie")
		}
		s.cookies = append(s.cookies, zaloCookie{c.Name, c.Value, strings.TrimPrefix(d, ".")})
	}
	return s, nil
}

type zaloCookieItem struct{ Name, Value, Domain string }

// zaloCookieList reads the "cookie" member in any of its accepted shapes. A
// string may itself hold JSON (the n8n node keeps the array as text) once.
func zaloCookieList(raw json.RawMessage, depth int) ([]zaloCookieItem, bool) {
	var list []zaloCookieItem
	var wrapped struct{ Cookies []zaloCookieItem }
	var str string
	switch {
	case json.Unmarshal(raw, &list) == nil:
		return list, true
	case json.Unmarshal(raw, &wrapped) == nil && wrapped.Cookies != nil:
		return wrapped.Cookies, true
	case json.Unmarshal(raw, &str) == nil:
		if t := strings.TrimSpace(str); depth == 0 && t != "" && (t[0] == '[' || t[0] == '{') {
			return zaloCookieList(json.RawMessage(t), 1)
		}
		for _, p := range strings.Split(str, ";") {
			if n, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok {
				list = append(list, zaloCookieItem{Name: n, Value: v})
			}
		}
		return list, true
	}
	return nil, false
}

// zaloHostOK reports whether h (a host name without port) is a Zalo host. The
// session cookies and the signed message only ever go to such a host.
func zaloHostOK(h string) bool {
	h = strings.ToLower(h)
	return h == "zalo.me" || strings.HasSuffix(h, ".zalo.me")
}

// zaloServiceBase checks a service URL taken from an answer before any cookie is
// sent to it: https, a Zalo host, no credentials, port 443 or none, no path.
func zaloServiceBase(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || !zaloHostOK(u.Hostname()) ||
		(u.Port() != "" && u.Port() != "443") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", badAnswer("the answer named a service address that is not a Zalo host")
	}
	return "https://" + u.Host, nil
}

// ---- crypto: AES-CBC, zero IV, PKCS#7 (the web client's scheme) ----

func zaloEncrypt(key, plain []byte) (string, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	buf := append(append(make([]byte, 0, len(plain)+pad), plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	cipher.NewCBCEncrypter(blk, make([]byte, aes.BlockSize)).CryptBlocks(buf, buf) //nolint:gosec // the protocol fixes a zero IV; we must speak it as it is
	return base64.StdEncoding.EncodeToString(buf), nil
}

// zaloDecrypt reverses zaloEncrypt on text as it comes off the wire: URI
// escaped (decodeURIComponent; "+" stays "+"), base64 with or without padding.
// It checks the length and the padding strictly.
func zaloDecrypt(key []byte, enc string) ([]byte, error) {
	if len(enc) == 0 || len(enc) > zaloMaxCipher {
		return nil, errZaloDecrypt
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, errZaloDecrypt
	}
	t, err := url.PathUnescape(enc)
	if err != nil {
		return nil, errZaloDecrypt
	}
	raw, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(t); err != nil {
			return nil, errZaloDecrypt
		}
	}
	if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return nil, errZaloDecrypt
	}
	cipher.NewCBCDecrypter(blk, make([]byte, aes.BlockSize)).CryptBlocks(raw, raw)
	pad := int(raw[len(raw)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(raw) {
		return nil, errZaloDecrypt
	}
	for _, b := range raw[len(raw)-pad:] {
		if int(b) != pad {
			return nil, errZaloDecrypt
		}
	}
	return raw[:len(raw)-pad], nil
}

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// ---- answers ----

type zaloEnvelope struct {
	ErrorCode    *int            `json:"error_code"`
	ErrorMessage string          `json:"error_message"`
	Data         json.RawMessage `json:"data"`
}

func (e zaloEnvelope) check(hide []secrets.Value) error {
	switch {
	case e.ErrorCode == nil:
		return badAnswer("the answer did not confirm success")
	case *e.ErrorCode != 0:
		return &ProviderError{Channel: ZaloPersonal, Code: *e.ErrorCode, Reason: reasonFrom([]byte(e.ErrorMessage), hide...)}
	}
	return nil
}

// openZaloAnswer opens a Zalo answer: the outer JSON {error_code, error_message,
// data} must say success, data is a string encrypted with key, and what it
// decrypts to is again {error_code, error_message, data}. It returns the inner
// data. Any other shape is an error. hide is scrubbed from the provider's text.
func openZaloAnswer(body, key []byte, hide ...secrets.Value) (json.RawMessage, error) {
	var outer zaloEnvelope
	if json.Unmarshal(body, &outer) != nil {
		return nil, badAnswer("the answer was not understood")
	}
	if err := outer.check(hide); err != nil {
		return nil, err
	}
	var enc string
	if json.Unmarshal(outer.Data, &enc) != nil {
		return nil, badAnswer("the answer carried no encrypted data")
	}
	plain, err := zaloDecrypt(key, enc)
	if err != nil {
		return nil, badAnswer(err.Error())
	}
	var inner zaloEnvelope
	if json.Unmarshal(plain, &inner) != nil {
		return nil, badAnswer("the answer was not understood")
	}
	if err := inner.check(hide); err != nil {
		return nil, err
	}
	return inner.Data, nil
}

// parseZaloLoginInfo takes the sign-in answer: the session key zpw_enk (base64
// of a 16, 24 or 32 byte AES key) and the base URL of the service that carries
// the message: chat for a person, group for a group.
func parseZaloLoginInfo(data json.RawMessage, group bool) (key []byte, base string, err error) {
	var info struct {
		Enk string `json:"zpw_enk"`
		Map struct {
			Chat  []string `json:"chat"`
			Group []string `json:"group"`
		} `json:"zpw_service_map_v3"`
	}
	if json.Unmarshal(data, &info) != nil {
		return nil, "", badAnswer("the sign-in answer was not understood")
	}
	key, err = base64.StdEncoding.DecodeString(info.Enk)
	if err != nil || (len(key) != 16 && len(key) != 24 && len(key) != 32) {
		return nil, "", badAnswer("the sign-in answer had no usable session key")
	}
	svc := info.Map.Chat
	if group {
		svc = info.Map.Group
	}
	if len(svc) == 0 {
		return nil, "", badAnswer("the sign-in answer named no service for this message")
	}
	if base, err = zaloServiceBase(svc[0]); err != nil {
		return nil, "", err
	}
	return key, base, nil
}

// confirmZaloSend requires a success answer that carries the id of the message.
func confirmZaloSend(body, key []byte, hide ...secrets.Value) error {
	data, err := openZaloAnswer(body, key, hide...)
	if err != nil {
		return err
	}
	var out struct {
		MsgID json.RawMessage `json:"msgId"`
	}
	if json.Unmarshal(data, &out) != nil || len(out.MsgID) == 0 || string(out.MsgID) == "null" {
		return badAnswer("the answer did not confirm delivery")
	}
	return nil
}

// ---- requests ----

func zaloVersionQuery() url.Values {
	return url.Values{"nretry": {"0"}, "zpw_ver": {strconv.Itoa(zaloAPIVersion)}, "zpw_type": {strconv.Itoa(zaloAPIType)}}
}

// zaloSignKey is the request signature: MD5 of "zsecure" + type + the values of
// the parameters in key order.
func zaloSignKey(kind string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("zsecure" + kind)
	for _, k := range keys {
		b.WriteString(params[k])
	}
	sum := md5.Sum([]byte(b.String())) //nolint:gosec // see import
	return hex.EncodeToString(sum[:])
}

// zaloLoginKeyFor derives the key that encrypts the sign-in request and answer
// from the zcid and the random zcid_ext: even characters of the upper-case MD5 of
// zcid_ext (first 8), even characters of zcid (first 12) and the last 12 odd
// characters of zcid, reversed. All characters are ASCII hex.
func zaloLoginKeyFor(zcid, ext string) string {
	m := md5.Sum([]byte(ext)) //nolint:gosec // see import
	n := strings.ToUpper(hex.EncodeToString(m[:]))
	split := func(s string) (even, odd []byte) {
		for i := 0; i < len(s); i++ {
			if i%2 == 0 {
				even = append(even, s[i])
			} else {
				odd = append(odd, s[i])
			}
		}
		return
	}
	ne, _ := split(n)
	ze, zo := split(zcid)
	for i, j := 0, len(zo)-1; i < j; i, j = i+1, j-1 {
		zo[i], zo[j] = zo[j], zo[i]
	}
	return string(ne[:8]) + string(ze[:12]) + string(zo[:12])
}

// zaloLoginQuery builds the query of the sign-in request and returns the key the
// answer is encrypted with. ext is the random zcid_ext (6 to 12 hex characters).
func zaloLoginQuery(imei, language string, now time.Time, ext string) (url.Values, string, error) {
	ms := now.UnixMilli()
	zcid, err := zaloEncryptHex([]byte(zaloLoginKey), fmt.Sprintf("%d,%s,%d", zaloAPIType, imei, ms))
	if err != nil {
		return nil, "", err
	}
	enk := zaloLoginKeyFor(zcid, ext)
	plain, err := json.Marshal(struct {
		ComputerName string `json:"computer_name"`
		IMEI         string `json:"imei"`
		Language     string `json:"language"`
		TS           int64  `json:"ts"`
	}{"Web", imei, language, ms})
	if err != nil {
		return nil, "", err
	}
	enc, err := zaloEncrypt([]byte(enk), plain)
	if err != nil {
		return nil, "", err
	}
	p := map[string]string{
		"zcid": zcid, "zcid_ext": ext, "enc_ver": "v2", "params": enc,
		"type": strconv.Itoa(zaloAPIType), "client_version": strconv.Itoa(zaloAPIVersion),
	}
	q := zaloVersionQuery()
	for k, v := range p {
		q.Set(k, v)
	}
	q.Set("signkey", zaloSignKey("getlogininfo", p))
	return q, enk, nil
}

func zaloEncryptHex(key []byte, msg string) (string, error) {
	b64, err := zaloEncrypt(key, []byte(msg))
	if err != nil {
		return "", err
	}
	raw, _ := base64.StdEncoding.DecodeString(b64)
	return strings.ToUpper(hex.EncodeToString(raw)), nil
}

func zaloServerInfoQuery(imei string) url.Values {
	p := map[string]string{"imei": imei, "type": strconv.Itoa(zaloAPIType), "client_version": strconv.Itoa(zaloAPIVersion), "computer_name": "Web"}
	q := url.Values{}
	for k, v := range p {
		q.Set(k, v)
	}
	q.Set("signkey", zaloSignKey("getserverinfo", p))
	return q
}

// zaloRandHex returns the random zcid_ext: 6 to 12 hex characters.
func zaloRandHex() string {
	var b [7]byte
	_, _ = rand.Read(b[:]) // crypto/rand does not fail on supported platforms; a zero buffer would still be a valid ext
	return hex.EncodeToString(b[1:])[:6+int(b[0])%7]
}

// zaloMessageParams is the plaintext of the send request for one text message.
func zaloMessageParams(imei, to, text string, group bool, now time.Time) []byte {
	p := map[string]any{"message": text, "clientId": now.UnixMilli(), "ttl": 0}
	if group {
		p["grid"], p["visibility"] = to, 0
	} else {
		p["toid"], p["imei"] = to, imei
	}
	out, _ := json.Marshal(p) // a map of strings and numbers always marshals
	return out
}
