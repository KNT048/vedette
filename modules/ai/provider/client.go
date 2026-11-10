package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	defaultTimeout = 60 * time.Second
	defaultMaxBody = 4 << 20 // response cap: a model answer is far below this

)

var modelRE = regexp.MustCompile(`^[\w.:/-]{1,80}$`)

// Config describes one connection to a provider. The model and key come from the AI profile; nothing is
// defaulted here except the public base URL of the three native APIs (see DefaultBaseURL).
type Config struct {
	Style   APIStyle
	BaseURL string // no user info, no query; "http" only makes sense for servers inside the network (checked by the ai package)
	Model   string
	APIKey  Secret
	// CompatMode sends max_tokens instead of max_completion_tokens (Ollama, vLLM, gateways). OpenAI style only.
	CompatMode bool
	// InternalOnly marks a profile with location=internal: the connection may only reach private addresses
	// (loopback, RFC 1918, link-local, unique-local, CGNAT), checked on the resolved address at dial time, and
	// the environment proxy is not used. This is what makes "internal" more than a label (INV-3).
	InternalOnly bool
	// AnthropicVersion overrides the anthropic-version header. Empty = DefaultAnthropicVersion.
	AnthropicVersion string
	// Timeout bounds one call. Zero = 60 s. The caller's context can only make it shorter.
	Timeout time.Duration
	// MaxResponseBytes caps the body read from the provider. Zero = 4 MiB.
	MaxResponseBytes int64
}

// DefaultAnthropicVersion is the anthropic-version header value sent unless Config.AnthropicVersion says otherwise.
const DefaultAnthropicVersion = "2026-10-21"

// DefaultBaseURL returns the public endpoint of a native API, or "" for kinds that always need a base URL.
func DefaultBaseURL(kind string) string {
	switch kind {
	case "anthropic":
		return "https://api.anthropic.com"
	case "openai":
		return "https://api.openai.com/v1"
	case "gemini":
		return "https://generativelanguage.googleapis.com"
	}
	return ""
}

// StyleForKind maps a profile kind to its wire format. "custom" needs the style chosen by the user.
func StyleForKind(kind string, custom APIStyle) (APIStyle, error) {
	switch kind {
	case "anthropic":
		return StyleAnthropic, nil
	case "openai", "openai-compatible":
		return StyleOpenAI, nil
	case "gemini":
		return StyleGemini, nil
	case "custom":
		switch custom {
		case StyleAnthropic, StyleOpenAI, StyleGemini:
			return custom, nil
		}
		return "", errors.New("provider: a custom profile must say which API style the server speaks (openai, anthropic or gemini)")
	}
	return "", fmt.Errorf("provider: unknown provider kind %q", kind)
}

// New builds a Provider. It validates the configuration; it makes no network call.
func New(c Config) (Provider, error) {
	base, err := ParseBaseURL(c.BaseURL)
	if err != nil {
		return nil, err
	}
	if !modelRE.MatchString(c.Model) {
		return nil, errors.New("provider: the model name may only contain letters, digits, dots, dashes, colons and slashes (80 characters at most)")
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = defaultMaxBody
	}
	if c.AnthropicVersion == "" {
		c.AnthropicVersion = DefaultAnthropicVersion
	}
	h := &httpClient{
		base: base, key: c.APIKey, timeout: c.Timeout, maxBody: c.MaxResponseBytes,
		// Never follow redirects: a custom header such as x-api-key would travel to the new host.
		c: &http.Client{Transport: newTransport(c.InternalOnly, base), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	switch c.Style {
	case StyleAnthropic:
		return &anthropic{h: h, model: c.Model, version: c.AnthropicVersion}, nil
	case StyleOpenAI:
		return &openAI{h: h, model: c.Model, compat: c.CompatMode}, nil
	case StyleGemini:
		m := strings.TrimPrefix(c.Model, "models/")
		if strings.Contains(m, "/") || m == "" {
			return nil, errors.New("provider: a Gemini model name must not contain a slash")
		}
		return &gemini{h: h, model: m}, nil
	}
	return nil, fmt.Errorf("provider: unknown API style %q", c.Style)
}

// ParseBaseURL checks a base URL: http or https, a host, no user info, no query, no fragment. It returns it
// without a trailing slash.
func ParseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("provider: the server address is not valid; enter it in full, for example https://api.anthropic.com")
	}
	if u.User != nil {
		return nil, errors.New("provider: the server address must not contain a user name or password; enter the API key in its own field")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("provider: the server address must not contain a query or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

type httpClient struct {
	base    *url.URL
	key     Secret
	timeout time.Duration
	maxBody int64
	c       *http.Client
}

// post sends a JSON body to base+path and returns the (size-capped) body of a 2xx answer.
// Every other outcome is an error whose message never contains the key or the URL.
func (h *httpClient) post(ctx context.Context, path string, headers map[string]string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("ai provider: encode request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	u := *h.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, newErr(ErrRequest, 0, "request could not be built", h.key)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.c.Do(req)
	if err != nil {
		return nil, h.transportErr(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, h.maxBody+1))
	if err != nil {
		return nil, h.transportErr(ctx, err)
	}
	if int64(len(data)) > h.maxBody {
		return nil, newErr(ErrTooLarge, resp.StatusCode, fmt.Sprintf("more than %d bytes", h.maxBody), h.key)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return data, nil
	}
	return nil, statusErr(resp.StatusCode, data, h.key)
}

func (h *httpClient) transportErr(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err() // the caller gave up; not a provider failure
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return newErr(ErrTimeout, 0, "", h.key)
	}
	if errors.Is(err, errForbiddenDestination) {
		return newErr(ErrNetwork, 0, "the server is at an address no profile may use (a metadata service, link-local, multicast or unspecified address); check the address", h.key)
	}
	if errors.Is(err, errPrivateForCloud) {
		return newErr(ErrNetwork, 0, "this profile is marked as cloud, but the server is at a private address; use its public address, or mark the profile as running inside your network", h.key)
	}
	if errors.Is(err, errPublicDestination) {
		return newErr(ErrNetwork, 0, "this profile is marked internal, but the server is at a public address; check the address or change where the profile runs", h.key)
	}
	// The text of a dial error names the address (and a url.Error the whole URL), so none of it is kept.
	return newErr(ErrNetwork, 0, "connection failed", h.key)
}

func statusErr(status int, body []byte, key Secret) *Error {
	kind := ErrRequest
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		kind = ErrAuth
	case status == http.StatusTooManyRequests:
		kind = ErrRateLimited
	case status == http.StatusRequestTimeout || status == http.StatusGatewayTimeout:
		kind = ErrTimeout
	case status >= 500:
		kind = ErrServer
	}
	return newErr(kind, status, errorText(body), key)
}

// errorText pulls a message out of the common error shapes ({"error":{"message":..}}, {"error":"..."}),
// falling back to the start of the raw body.
func errorText(body []byte) string {
	var e struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && len(e.Error) > 0 {
		var s string
		if json.Unmarshal(e.Error, &s) == nil {
			return s
		}
		var o struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(e.Error, &o) == nil && o.Message != "" {
			return o.Message
		}
	}
	return string(body)
}

func checkRequest(r Request) error {
	for _, m := range r.Messages {
		if len(m.Raw) > 0 && (!json.Valid(m.Raw) || bytes.TrimSpace(m.Raw)[0] != '[') {
			return errors.New("provider: the raw content of a message must be a JSON array")
		}
	}
	if r.MaxTokens <= 0 {
		return errors.New("provider: max tokens must be positive")
	}
	if len(r.Messages) == 0 {
		return errors.New("provider: a request needs at least one message")
	}
	for _, t := range r.Tools {
		if t.Name == "" || (len(t.InputSchema) > 0 && !json.Valid(t.InputSchema)) {
			return errors.New("provider: a tool needs a name and a valid JSON schema")
		}
	}
	if r.Schema != nil && !json.Valid(r.Schema.JSON) {
		return errors.New("provider: the output schema is not valid JSON")
	}
	return nil
}

func schemaOrEmpty(s json.RawMessage) json.RawMessage {
	if len(s) == 0 {
		return json.RawMessage(`{"type":"object","properties":{}}`)
	}
	return s
}

// object checks that raw is a JSON object (tool arguments) and normalises empty input to {}.
func object(raw json.RawMessage) (json.RawMessage, bool) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || string(t) == "null" {
		return json.RawMessage(`{}`), true
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(t, &m) != nil {
		return nil, false
	}
	return t, true
}

func badResponse(msg string) error { return &Error{Kind: ErrBadResponse, Message: msg} }

var (
	errPublicDestination    = errors.New("destination is not an internal address")
	errForbiddenDestination = errors.New("destination is an address no profile may use")
	errPrivateForCloud      = errors.New("destination is a private address, but the profile is cloud")
)

var (
	cgnat       = netip.MustParsePrefix("100.64.0.0/10")
	v4Broadcast = netip.MustParseAddr("255.255.255.255")
	ec2v6Meta   = netip.MustParseAddr("fd00:ec2::254") // the AWS metadata service over IPv6; it sits inside the unique-local range
)

// cloudMayDialPrivate lets the tests of this package dial httptest servers on loopback for profiles that are not internal. It is
// unexported and set only from test code, so no configuration can switch the rule off.
var cloudMayDialPrivate = false

// Forbidden reports whether ip is an address no profile may reach, whatever it is marked as: the unspecified address, multicast,
// the limited broadcast, link-local (169.254.0.0/16, fe80::/10, which holds the 169.254.169.254 metadata service) and the IPv6
// metadata address fd00:ec2::254. IPv4-mapped IPv6 is treated as the IPv4 address.
func Forbidden(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	return ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip == v4Broadcast || ip == ec2v6Meta || carriesIPv4(ip)
}

// IsInternalAddr reports whether ip is a private address a profile inside the network may use: loopback (a local Ollama), RFC 1918,
// unique-local (fc00::/7) or carrier-grade NAT (100.64.0.0/10). Forbidden addresses are never internal. IPv4-mapped IPv6 is treated
// as the IPv4 address.
func IsInternalAddr(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	return !Forbidden(ip) && (ip.IsLoopback() || ip.IsPrivate() || cgnat.Contains(ip))
}

func resolved(address string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	return ip, err == nil
}

// internalOnlyControl is a net.Dialer.Control: it runs on the resolved address just before connect, so a public destination is
// refused whatever the name was (DNS rebinding included) and without sending a packet. Forbidden addresses are refused too.
func internalOnlyControl(_, address string, _ syscall.RawConn) error {
	ip, ok := resolved(address)
	switch {
	case !ok:
		return errPublicDestination
	case Forbidden(ip):
		return errForbiddenDestination
	case !IsInternalAddr(ip):
		return errPublicDestination
	}
	return nil
}

// cloudOnlyControl is the Control of a cloud profile that is not behind a proxy: only public addresses. A name that resolves to
// loopback or a private range is refused at connect time, as the label "cloud" says the data goes to a provider.
func cloudOnlyControl(_, address string, _ syscall.RawConn) error {
	ip, ok := resolved(address)
	switch {
	case !ok:
		return errPrivateForCloud
	case Forbidden(ip):
		return errForbiddenDestination
	case IsInternalAddr(ip):
		return errPrivateForCloud
	}
	return nil
}

// forbiddenOnlyControl refuses only the addresses nobody may use. It is the Control of a cloud profile behind a proxy: the dial
// goes to the proxy, which may well be on a private address, so the destination is the proxy's to check.
func forbiddenOnlyControl(_, address string, _ syscall.RawConn) error {
	if ip, ok := resolved(address); !ok || Forbidden(ip) {
		return errForbiddenDestination
	}
	return nil
}

func cloudControlFor(proxied bool) func(network, address string, c syscall.RawConn) error {
	if proxied || cloudMayDialPrivate {
		return forbiddenOnlyControl
	}
	return cloudOnlyControl
}

// newTransport returns the HTTP transport of one provider. An internal profile gets no proxy and a dialer that refuses public
// addresses; a cloud profile keeps the environment proxy and a dialer that refuses private ones (unless a proxy is in the way).
// Both refuse the Forbidden addresses.
func newTransport(internal bool, base *url.URL) *http.Transport {
	if !internal {
		t := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // the default transport is an *http.Transport
		proxied := false
		if base != nil {
			if u, err := http.ProxyFromEnvironment(&http.Request{URL: base}); err == nil && u != nil {
				proxied = true
			}
		}
		t.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: cloudControlFor(proxied)}).DialContext
		return t
	}
	d := &net.Dialer{Timeout: 10 * time.Second, Control: internalOnlyControl}
	return &http.Transport{
		Proxy: nil, DialContext: d.DialContext, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
	}
}

// embeddedV4 are the IPv6 forms that carry an IPv4 address: NAT64 (64:ff9b::/96 and the local-use 64:ff9b:1::/48), 6to4, the
// deprecated IPv4-compatible form, and Teredo. Writing 127.0.0.1 or 169.254.169.254 inside one of them must not get past the
// address policy, so no profile may use them (D-94 says the same for connections). IPv4-mapped addresses are unwrapped to the
// IPv4 address before any check, so they are judged as that address.
var embeddedV4 = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("::ffff:0:0:0/96"), netip.MustParsePrefix("2001::/32"),
}

func carriesIPv4(ip netip.Addr) bool {
	if !ip.Is6() || ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	for _, p := range embeddedV4 {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
