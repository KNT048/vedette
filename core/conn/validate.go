package conn

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn/internal/transport"
	"github.com/knt048/vedette/core/secrets"
)

// The checks of a connection before it is saved. They answer exactly like the mock API of the GUI
// (web/src/features/core/connectionsMock.ts): the same codes, fields and messages (D-93, D-94).

// Kinds of connection (D-58). mcp-stdio is in the contract but never saved (D-94 (3)).
const (
	KindHTTP       = "http"
	KindSSH        = "ssh"
	KindRESTCONF   = "netconf-restconf"
	KindAutomation = "automation"
	KindMCP        = "mcp-http"
	kindMCPStdio   = "mcp-stdio"
)

// Sign-in types.
const (
	AuthNone  = "none"
	AuthToken = "token"
	AuthBasic = "basic"
	AuthKey   = "ssh-key"
)

// kindAuth is which sign-in each kind can use (web/src/lib/connections.ts KIND_AUTH).
var kindAuth = map[string][]string{
	KindHTTP: {AuthNone, AuthToken, AuthBasic}, KindSSH: {AuthKey, AuthBasic}, KindRESTCONF: {AuthBasic, AuthToken},
	KindAutomation: {AuthToken, AuthBasic}, KindMCP: {AuthNone, AuthToken, AuthBasic},
}

// MaxTargetLen is the longest address (characters), the limit of the column.
const MaxTargetLen = 2048

// MaxConnections is how many connections a box holds.
const MaxConnections = 20

var (
	userRE          = regexp.MustCompile(`^[^\s\p{Z}:\p{Cc}\p{Cf}]{1,64}$`)
	sshTargetRE     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}(:\d{1,5})?$`)
	hostNameRE      = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$`)
	numericHost     = regexp.MustCompile(`(?i)^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*$`)
	typedHostRE     = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*://(?:[^/@?#]*@)?(\[[^\]]*\]|[^/:?#]*)`)
	sshPortSufRE    = regexp.MustCompile(`:\d{1,5}$`)
	encodedSlashDot = regexp.MustCompile(`(?i)%(2f|5c|2e)`)
)

func bad(code, message, field string) *apierr.Error {
	return apierr.New(400, code, message).With("field", field)
}

// tidy trims a text and folds every run of white space into one space.
func tidy(s string) string { return strings.Join(strings.Fields(s), " ") }

// checked is an input that passed every check, with what the store needs to know about the change.
type checked struct {
	name, kind, target, authType string
	username                     *string
	header                       *string       // header name of a token sign-in, nil = Authorization: Bearer
	secret                       secrets.Value // a new secret to store; unset = none given
	keyFP                        *string       // fingerprint of the new SSH key
	assetID                      *string
	allow                        []string
	enabled, clearPin            bool
	tools                        []ToolInput
	retarget                     bool // another kind or target: the old test result no longer counts
	moved                        bool // another kind or server (host and port): the pin and the saved secret belong to the old one
}

// checkEnv is what a check needs from the rest of the box. The callbacks answer from the database; a nil one skips its check.
type checkEnv struct {
	box          []netip.Prefix
	nameTaken    func(name string) bool
	assetUnknown func(id string) bool
}

// check validates in against the rules of the contract. existing is the saved connection on an edit. The order of the
// checks is the order of the mock. The caller adds the checks that need the database (duplicate name, number of
// connections, asset).
func check(in Input, existing *Connection, env checkEnv) (*checked, *apierr.Error) {
	boxAddrs := env.box
	name := tidy(in.Name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 40 {
		return nil, bad("invalid_name", `Give the connection a name of 1 to 40 characters, for example "Office firewall API".`, "name")
	}
	if env.nameTaken != nil && env.nameTaken(name) {
		return nil, bad("duplicate_name", "Another connection already has this name. Pick a different one.", "name")
	}
	if _, ok := kindAuth[in.Kind]; !ok {
		if in.Kind == kindMCPStdio {
			return nil, bad("kind_unsupported", `An MCP server that Vedette starts as a command is not supported. Use an MCP server that has a web address (kind "MCP server (URL)").`, "kind")
		}
		return nil, bad("invalid_kind", "Pick a kind: HTTP API, SSH / CLI, NETCONF / RESTCONF, automation platform or MCP server.", "kind")
	}
	ssh := in.Kind == KindSSH
	target := strings.TrimSpace(in.Target)
	if e := checkTarget(target, ssh, boxAddrs); e != nil {
		return nil, e
	}
	auth := in.AuthType
	if auth == "" {
		auth = AuthNone
	}
	if auth != AuthNone && auth != AuthToken && auth != AuthBasic && auth != AuthKey {
		return nil, bad("invalid_auth", "Pick how the box signs in: none, token, user and password, or SSH key.", "auth_type")
	}
	if !contains(kindAuth[in.Kind], auth) {
		who := "This kind of connection"
		if ssh {
			who = "An SSH server"
		}
		return nil, bad("invalid_auth", who+" cannot sign in that way. Pick one of the options the form offers.", "auth_type")
	}
	var username *string
	if ssh || auth == AuthBasic {
		u := tidy(deref(in.Username))
		if u == "" {
			return nil, bad("username_required", "Enter the user name the box signs in with.", "username")
		}
		if !userRE.MatchString(u) {
			return nil, bad("invalid", "The user name is 1 to 64 characters, with no spaces, colons or control characters.", "username")
		}
		username = &u
	}
	var header *string
	if h := strings.TrimSpace(deref(in.AuthHeader)); h != "" {
		if auth != AuthToken {
			return nil, bad("invalid", "A header name belongs to a token sign-in only.", "auth_header")
		}
		if !transport.ValidAuthHeader(h) {
			return nil, bad("invalid_auth_header", "The header name is not valid. Use letters, digits and hyphens, for example X-API-Key; Host, Content-Length, Transfer-Encoding and Connection cannot carry a token.", "auth_header")
		}
		header = &h
	}
	secret := in.Secret
	if secret.IsSet() && utf8.RuneCountInString(secret.Reveal()) < 8 {
		return nil, bad("invalid_secret", "The secret is too short. Copy the whole token, password or key again.", "secret")
	}
	var keyFP *string
	if secret.IsSet() && auth == AuthKey {
		fp, e := checkKey(secret.Reveal())
		if e != nil {
			return nil, e
		}
		keyFP = &fp
	}
	if auth == AuthNone {
		secret, keyFP = secrets.Value{}, nil // a connection with no sign-in holds no secret
	}
	sameKind := existing != nil && existing.Kind == in.Kind
	moved := sameKind && HostPort(existing.Kind, existing.Target) != HostPort(in.Kind, target)
	hadSecret := existing != nil && existing.hasSecret()
	keep := sameKind && !moved && hadSecret && existing.Auth.Type == auth
	if auth != AuthNone && !secret.IsSet() && !keep {
		if moved && hadSecret && existing.Auth.Type == auth {
			return nil, bad("secret_required", "Enter the secret again: the address changed, and a saved secret is only sent to the address it was saved for.", "secret")
		}
		return nil, bad("secret_required", "Enter the secret. It stays on this box and is encrypted; only the last 4 characters are shown afterwards.", "secret")
	}
	allow, e := checkAllow(in.Allow, target, ssh)
	if e != nil {
		return nil, e
	}
	if asset := deref(in.AssetID); asset != "" && env.assetUnknown != nil && env.assetUnknown(asset) {
		return nil, bad("unknown_asset", "The device you linked is not in the inventory.", "asset_id")
	}
	if in.Kind != KindMCP {
		for _, t := range in.Tools {
			if t.Access != nil {
				return nil, bad("invalid_tool_access", "Only tools of an MCP server can be marked read or write; the built-in tools of this kind are fixed.", "tools")
			}
		}
	}
	var asset *string
	if in.AssetID != nil && *in.AssetID != "" {
		asset = in.AssetID
	}
	return &checked{
		name: name, kind: in.Kind, target: target, authType: auth, username: username, header: header, secret: secret, keyFP: keyFP, assetID: asset,
		allow: allow, enabled: in.Enabled, clearPin: in.ClearPin, tools: in.Tools,
		retarget: existing != nil && (existing.Kind != in.Kind || existing.Target != target), moved: existing != nil && (!sameKind || moved),
	}, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// checkTarget applies the form of the address (HTTPS URL, or host[:port] for SSH) and the address policy of D-94 to the
// host as typed and to the host after the URL parser normalised it.
func checkTarget(target string, ssh bool, box []netip.Prefix) *apierr.Error {
	const notValid = "The address is not valid. Enter it in full, for example https://192.168.10.1."
	if utf8.RuneCountInString(target) > MaxTargetLen {
		return bad("invalid_target", "The address is too long: at most 2048 characters.", "target")
	}
	var host string
	if ssh {
		if !sshTargetRE.MatchString(target) {
			return bad("invalid_target", "Enter the SSH server as host or host:port, for example 192.168.10.30:22.", "target")
		}
		if m := sshPortSufRE.FindString(target); m != "" {
			if p, _ := strconv.Atoi(m[1:]); p < 1 || p > 65535 {
				return bad("invalid_target", "Enter the SSH server as host or host:port, for example 192.168.10.30:22.", "target")
			}
		}
		host = typedHost(target, true)
		if trimmed := strings.TrimRight(host, "."); !hostNameRE.MatchString(trimmed) {
			return bad("invalid_target", "Enter the SSH server as host or host:port, for example 192.168.10.30:22.", "target")
		}
	} else {
		u, err := url.Parse(target)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" {
			if err == nil && u.Scheme != "" && u.Scheme != "https" {
				return bad("invalid_target", "The address must start with https://. Vedette sends sign-in details and changes only over HTTPS.", "target")
			}
			return bad("invalid_target", notValid, "target")
		}
		if u.Scheme != "https" {
			return bad("invalid_target", "The address must start with https://. Vedette sends sign-in details and changes only over HTTPS.", "target")
		}
		if u.User != nil {
			return bad("invalid_target", "The address must not contain a user name or password. Enter the secret in its own field.", "target")
		}
		if p := u.Port(); p != "" {
			if n, _ := strconv.Atoi(p); n < 1 || n > 65535 {
				return bad("invalid_target", notValid, "target")
			}
		}
		if strings.ContainsAny(target, "?#") {
			return bad("invalid_target", "The address must not include ? or #.", "target")
		}
		host = typedHost(target, false)
		if why := refusedHost(host, box); why != "" {
			return refusal(why)
		}
		norm := strings.ToLower(u.Hostname())
		if !strings.Contains(norm, ":") && !numericHost.MatchString(norm) && !hostNameRE.MatchString(norm) {
			return bad("invalid_target", notValid, "target")
		}
		host = norm
	}
	if why := refusedHost(host, box); why != "" {
		return refusal(why)
	}
	return nil
}

func refusal(why string) *apierr.Error {
	if why == embeddedWhy {
		return bad("invalid_target", embeddedWhy, "target")
	}
	return bad("invalid_target", "Vedette never connects to "+why+". Enter the address of the device or service itself.", "target")
}

// typedHost is the host exactly as the administrator wrote it, before any normalisation.
func typedHost(target string, ssh bool) string {
	if ssh {
		return sshPortSufRE.ReplaceAllString(target, "")
	}
	if m := typedHostRE.FindStringSubmatch(target); m != nil {
		return m[1]
	}
	return ""
}

// refusedHost says in plain words why the host may never be used, or "" when it may (D-94: loopback, link-local including
// the cloud metadata address, multicast, unspecified, localhost, numeric names written in a non-standard way, the box
// itself). A private range is fine, and so is a public name: the administrator declared it (privacy flow 12). The same
// rules are applied again to the resolved address when a connection is dialled (slice 13b-5).
func refusedHost(raw string, box []netip.Prefix) string {
	h := strings.TrimRight(strings.ToLower(strings.TrimSpace(raw)), ".")
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return "a loopback address"
	}
	if strings.Contains(h, ":") {
		a, err := netip.ParseAddr(h)
		if err != nil {
			return "an address that is not valid"
		}
		a = a.WithZone("")
		if a.Is4In6() || (!a.IsLoopback() && !a.IsUnspecified() && inPrefixes(embeddedV4, a)) {
			return embeddedWhy
		}
		return refusedAddr(a, box)
	}
	if numericHost.MatchString(h) {
		a, err := netip.ParseAddr(h)
		if err != nil || !a.Is4() {
			return "a numeric host name written in a non-standard way (use the usual dotted form, like 192.168.10.1)"
		}
		return refusedAddr(a, box)
	}
	return ""
}

// embeddedWhy is the reason for an IPv6 address that carries an IPv4 address; it is the whole sentence of the message.
const embeddedWhy = "Vedette does not connect to IPv6 addresses that carry an IPv4 address; use the IPv4 address."

// embeddedV4 are the IPv6 forms that carry an IPv4 address: IPv4-mapped (checked with Is4In6), NAT64, 6to4, IPv4-compatible,
// IPv4-translated and Teredo. Writing 127.0.0.1 or 169.254.169.254 in one of them must not get past the address policy.
var embeddedV4 = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0:0/96"), netip.MustParsePrefix("2001::/32"),
}

func inPrefixes(l []netip.Prefix, a netip.Addr) bool {
	for _, p := range l {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// RefusedAddr says why a resolved address may never be a connection's target, or "" when it may: the policy applied to an IP
// (loopback, unspecified including all of 0.0.0.0/8, link-local, multicast, IPv6 forms that carry an IPv4 address, and the
// box itself with its whole subnets). The save-time check and the dial-time check (slice 13b-5) both use it.
func RefusedAddr(a netip.Addr, box []netip.Prefix) string {
	a = a.WithZone("")
	if a.Is4In6() || (a.Is6() && !a.IsLoopback() && !a.IsUnspecified() && inPrefixes(embeddedV4, a)) {
		return embeddedWhy
	}
	return refusedAddr(a, box)
}

func refusedAddr(a netip.Addr, box []netip.Prefix) string {
	switch {
	case a.IsLoopback():
		return "a loopback address"
	case a.IsUnspecified() || (a.Is4() && a.As4()[0] == 0):
		return "an unspecified address"
	case a.IsLinkLocalUnicast():
		if a.Is4() {
			return "a link-local address (the cloud metadata service lives there)"
		}
		return "a link-local address"
	case a.IsMulticast() || a.IsLinkLocalMulticast():
		return "a multicast address"
	}
	for _, b := range box {
		if b.Contains(a) || b.Contains(a.Unmap()) {
			return "the box itself"
		}
	}
	return ""
}

// HostPort is the identity of the server a connection talks to: host and port after normalisation (a path, a trailing slash
// or the letter case do not count). Its pin and its saved secret belong to it.
func HostPort(kind, target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if kind == KindSSH {
		host, port := t, "22"
		if m := sshPortSufRE.FindString(t); m != "" {
			host, port = strings.TrimSuffix(t, m), m[1:]
		}
		return host + ":" + port
	}
	u, err := url.Parse(t)
	if err != nil || u.Host == "" {
		return t
	}
	return strings.TrimSuffix(u.Host, ":443")
}

// checkAllow normalises the allow-list and applies its rules.
func checkAllow(in []string, target string, ssh bool) ([]string, *apierr.Error) {
	seen := map[string]bool{}
	allow := []string{}
	for _, a := range in {
		a = strings.TrimSpace(a)
		if a != "" && !seen[a] {
			seen[a] = true
			allow = append(allow, a)
		}
	}
	if len(allow) == 0 {
		return nil, bad("allow_required", "Add at least one entry to the allow-list. Only hosts, addresses or commands on this list may be used.", "allow")
	}
	for _, a := range allow {
		if utf8.RuneCountInString(a) > 200 || strings.ContainsFunc(a, unicode.IsControl) {
			return nil, bad("invalid_allow", "The allow-list holds up to 30 entries of 200 characters each, one per line.", "allow")
		}
	}
	if len(allow) > 30 {
		return nil, bad("invalid_allow", "The allow-list holds up to 30 entries of 200 characters each, one per line.", "allow")
	}
	if ssh {
		return allow, nil
	}
	for _, a := range allow {
		if strings.ContainsFunc(a, unicode.IsSpace) {
			return nil, bad("invalid_allow", "A host or address in the allow-list cannot contain spaces.", "allow")
		}
	}
	for _, a := range allow {
		if !under(a, target) {
			t := strings.TrimRight(target, "/")
			return nil, bad("invalid_allow", fmt.Sprintf("Each allow-list entry must be an address under %s, for example %s/api/.", t, t), "allow")
		}
	}
	return allow, nil
}

// under reports whether the allow-list entry is an address under the target: the same scheme, host and port, and a path
// at or below the target's. Dot segments are resolved first, so an entry cannot climb out of the target.
func under(entry, target string) bool {
	if strings.Contains(entry, `\`) || encodedSlashDot.MatchString(entry) {
		return false // a backslash or an encoded slash, backslash or dot may be read as a path separator or a dot segment further on
	}
	e, err1 := url.Parse(entry)
	b, err2 := url.Parse(target)
	if err1 != nil || err2 != nil {
		return false
	}
	if e.Scheme != b.Scheme || !strings.EqualFold(e.Hostname(), b.Hostname()) || effectivePort(e) != effectivePort(b) {
		return false
	}
	bp := strings.TrimRight(cleanPath(b.Path), "/")
	ep := cleanPath(e.Path)
	return ep == bp || ep == bp+"/" || strings.HasPrefix(ep, bp+"/")
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

const passphraseMsg = "This private key is protected by a passphrase, which Vedette cannot type. Save a copy without one and paste that."

// checkKey parses an SSH private key and returns the SHA256 fingerprint of its public half. A key protected by a
// passphrase cannot be used: Vedette has nobody to type the passphrase. Weak keys (DSA, RSA under 2048 bits) are refused.
func checkKey(pem string) (string, *apierr.Error) {
	if strings.Contains(pem, "Proc-Type: 4,ENCRYPTED") || strings.Contains(pem, "BEGIN ENCRYPTED PRIVATE KEY") {
		return "", bad("invalid_secret", passphraseMsg, "secret")
	}
	signer, err := ssh.ParsePrivateKey([]byte(pem))
	if err != nil {
		var pm *ssh.PassphraseMissingError
		if errors.As(err, &pm) {
			return "", bad("invalid_secret", passphraseMsg, "secret")
		}
		return "", bad("invalid_secret", "This private key could not be read. Paste the whole key, including the BEGIN and END lines.", "secret")
	}
	pub := signer.PublicKey()
	weak := pub.Type() == "ssh-dss" // DSA: only ever 1024 bits
	if ck, ok := pub.(ssh.CryptoPublicKey); ok {
		if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok && rk.N.BitLen() < 2048 {
			weak = true
		}
	}
	if weak {
		return "", bad("invalid_secret", "This key type is not accepted. Use an Ed25519, ECDSA or RSA key of at least 2048 bits.", "secret")
	}
	return ssh.FingerprintSHA256(pub), nil
}
