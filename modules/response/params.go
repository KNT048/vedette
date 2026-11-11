package response

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Typed parameters and escaping (INV-14a, INV-14b, docs/specs/action-templates.md section 1.2).
//
// Trigger data (a source address, a device name, a log text) is controlled by the attacker. A value enters a
// template only through a typed placeholder: it is checked by type first (CheckValue, which also returns the
// canonical spelling) and escaped for the place it lands in second (Fill). A value that fails the first layer never
// reaches the second. This file is the only place that builds the text of a command or an API call.

// ParamType is the type of a placeholder.
type ParamType string

// The placeholder types of a template.
const (
	PIP        ParamType = "ip"
	PCIDR      ParamType = "cidr"
	PDomain    ParamType = "domain"
	PPort      ParamType = "port"
	PMAC       ParamType = "mac"
	PVLAN      ParamType = "vlan"
	PInterface ParamType = "interface"
	PID        ParamType = "id"
	PName      ParamType = "name"
	PText      ParamType = "text"
)

// ParamTypes lists the types in the order the API shows them.
var ParamTypes = []ParamType{PIP, PCIDR, PDomain, PPort, PMAC, PVLAN, PInterface, PID, PName, PText}

// RuntimeValues are read from the device or derived when an action runs (action-templates 1.1 precheck, 1.4 ttl).
// A rule never supplies them: they are not parameters, and a request shows them as <name>.
var RuntimeValues = []string{"seq", "previous_vlan", "found_id", "expiry_s", "timeout", "rules_before"}

// Widest network a cidr value may name when no other limit is set: /16 for IPv4, /48 for IPv6.
const (
	minCIDRBitsV4 = 16
	minCIDRBitsV6 = 48
)

var (
	domainRE    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	macRE       = regexp.MustCompile(`^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$`)
	interfaceRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/.:-]{0,31}$`)
	nameRE      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
	// textRE: letters, numbers, space and . , : @ # / _ - only. No quotes, no shell characters, no newline.
	textRE        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.,:@#/-]{0,79}$`)
	digitsRE      = regexp.MustCompile(`^[0-9]{1,10}$`)
	placeholderRE = regexp.MustCompile(`\{([a-z_]+)\}`)
)

// ParamLabel says in plain words what a type expects.
var ParamLabel = map[ParamType]string{
	PIP: "an IP address", PCIDR: "an address range", PDomain: "a domain", PPort: "a port number", PMAC: "a MAC address",
	PVLAN: "a VLAN number", PInterface: "a port or interface name", PID: "a whole number (for example a policy number)",
	PName: "a name of letters, numbers, . _ and - (up to 64)", PText: "a short plain-text value",
}

func validType(p ParamType) bool {
	for _, t := range ParamTypes {
		if t == p {
			return true
		}
	}
	return false
}

func isRuntime(k string) bool {
	for _, r := range RuntimeValues {
		if r == k {
			return true
		}
	}
	return false
}

// CheckValue is the type check (layer 1). It returns the canonical spelling of v, which is what every later step
// uses, and false when v is not a value of the type. The type check never looks at the never-touch list: that is the
// planner's job, because the list changes while the check does not.
func CheckValue(t ParamType, v string) (string, bool) {
	switch t {
	case PIP:
		a, err := netip.ParseAddr(v)
		if err != nil || a.Zone() != "" {
			return "", false
		}
		a = a.Unmap()
		if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || reservedV4(a) {
			return "", false
		}
		return a.String(), true
	case PCIDR:
		p, err := netip.ParsePrefix(v)
		if err != nil || p.Addr().Zone() != "" {
			return "", false
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), unmapBits(p)).Masked()
		a := p.Addr()
		if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || reservedV4(a) {
			return "", false
		}
		if (a.Is4() && p.Bits() < minCIDRBitsV4) || (a.Is6() && p.Bits() < minCIDRBitsV6) {
			return "", false
		}
		return p.String(), true
	case PDomain:
		d := strings.ToLower(v)
		if len(d) > 253 || !domainRE.MatchString(d) {
			return "", false
		}
		return d, true
	case PPort:
		n, ok := intIn(v, 1, 65535)
		return strconv.Itoa(n), ok
	case PMAC:
		m := strings.ToLower(v)
		if !macRE.MatchString(m) {
			return "", false
		}
		return strings.ReplaceAll(m, "-", ":"), true
	case PVLAN:
		n, ok := intIn(v, 1, 4094)
		return strconv.Itoa(n), ok
	case PInterface:
		return v, interfaceRE.MatchString(v) && cleanSegments(v)
	case PID:
		n, ok := intIn(v, 1, 2147483647)
		return strconv.Itoa(n), ok
	case PName:
		return v, nameRE.MatchString(v)
	case PText:
		return v, textRE.MatchString(v)
	}
	return "", false
}

// reservedV4 reports an IPv4 address that is never a target: 0.0.0.0/8 ("this network") and 240.0.0.0/4 (reserved, which
// holds the broadcast address 255.255.255.255).
func reservedV4(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	return b[0] == 0 || b[0] >= 240
}

// cleanSegments is false when an interface value has an empty segment or a "." or ".." segment: the value lands in an API
// path (1%2F..%2Fadmin), and a server that decodes %2F before routing would walk up it.
func cleanSegments(v string) bool {
	if strings.Contains(v, "..") {
		return false
	}
	for seg := range strings.SplitSeq(v, "/") {
		if seg == "" || seg == "." {
			return false
		}
	}
	return true
}

// unmapBits is the prefix length of p after the address is unmapped (::ffff:a.b.c.d/N counts as IPv4 /N-96).
func unmapBits(p netip.Prefix) int {
	if p.Addr().Is4In6() {
		return max(p.Bits()-96, 0)
	}
	return p.Bits()
}

func intIn(v string, lo, hi int) (int, bool) {
	if !digitsRE.MatchString(v) {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, false
	}
	return n, true
}

// Values maps a placeholder type to a checked, canonical value.
type Values map[ParamType]string

// CheckValues checks every parameter a template uses. It returns the canonical values, or the plain-words reason
// the first one failed. Nothing is filled before this returns nil.
func CheckValues(params []ParamType, raw map[ParamType]string) (Values, string) {
	out := Values{}
	for _, p := range params {
		v := raw[p]
		if v == "" {
			return nil, "This action needs " + ParamLabel[p] + ", which this trigger does not provide."
		}
		c, ok := CheckValue(p, v)
		if !ok {
			return nil, "The " + string(p) + " value is not valid (it must be " + ParamLabel[p] + "). Nothing was changed."
		}
		out[p] = c
	}
	return out, ""
}

// Transport is the place a value lands in.
type Transport string

// The four transports.
const (
	TCLI    Transport = "cli"
	TJSON   Transport = "json"
	TURL    Transport = "url"
	THeader Transport = "header"
)

// escapeFor is layer 2. Values are already checked by type.
func escapeFor(t Transport, v string) string {
	switch t {
	case TJSON:
		b, _ := json.Marshal(v) // a string never fails to marshal
		return string(b[1 : len(b)-1])
	case TURL:
		return url.PathEscape(v)
	case THeader:
		return strings.NewReplacer("\r", "", "\n", "").Replace(v)
	}
	return v
}

// shellChars may never appear in a command, even in the fixed text of a template (INV-14b, SYS-1).
const shellChars = ";|&$`<>()\\!~^"

// HasShellChar reports whether s contains a character of the never-allowed set.
func HasShellChar(s string) bool { return strings.ContainsAny(s, shellChars) }

// Fill puts checked values into the placeholders of text. A placeholder that is a runtime value shows as <name>.
// It returns an error, never a partial text, when a placeholder has no checked value (callers run CheckValues first),
// and for the cli transport when the result still holds a shell character.
func Fill(text string, vals Values, t Transport) (string, error) {
	var bad string
	out := placeholderRE.ReplaceAllStringFunc(text, func(m string) string {
		k := m[1 : len(m)-1]
		if isRuntime(k) {
			return "<" + k + ">"
		}
		v, ok := vals[ParamType(k)]
		if !ok || !validType(ParamType(k)) {
			bad = k
			return ""
		}
		// A value is canonical because CheckValues made it so; check again so a caller that skipped the first layer
		// cannot reach the second.
		if c, ok := CheckValue(ParamType(k), v); !ok || c != v {
			bad = k
			return ""
		}
		return escapeFor(t, v)
	})
	if bad != "" {
		return "", fmt.Errorf("response: unchecked placeholder %q", bad)
	}
	if t == TCLI {
		chk := out
		for _, r := range RuntimeValues {
			chk = strings.ReplaceAll(chk, "<"+r+">", "") // the display form of a value read at run time
		}
		if HasShellChar(chk) {
			return "", fmt.Errorf("response: a command holds a shell character")
		}
	}
	return out, nil
}

// Tpl is a template of one step of an action: a command, or an API call with a path, a JSON body and headers. Expect (D-95) only
// means something on the read-back (verify): after the action its output must contain the text, after the undo it must not.
type Tpl struct {
	CLI     string `json:"cli"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Body    string `json:"body"`
	Headers string `json:"headers"`
	Expect  string `json:"expect"`
}

// Empty reports whether the template has nothing to run.
// Headers count: a step that holds only headers is not empty, so it is validated (and refused) like any other.
func (t Tpl) Empty() bool {
	return strings.TrimSpace(t.CLI) == "" && t.Method == "" && t.Path == "" && strings.TrimSpace(t.Body) == "" && strings.TrimSpace(t.Headers) == ""
}

// templateParams lists the typed placeholders the texts use, in the API order.
func templateParams(texts ...string) []ParamType {
	found := map[ParamType]bool{}
	for _, t := range texts {
		for _, m := range placeholderRE.FindAllStringSubmatch(t, -1) {
			if validType(ParamType(m[1])) {
				found[ParamType(m[1])] = true
			}
		}
	}
	out := []ParamType{}
	for _, p := range ParamTypes {
		if found[p] {
			out = append(out, p)
		}
	}
	return out
}

func tplParams(ts ...Tpl) []ParamType {
	var texts []string
	for _, t := range ts {
		texts = append(texts, t.CLI, t.Path, t.Body, t.Headers, t.Expect)
	}
	return templateParams(texts...)
}

var (
	safeTextRE   = regexp.MustCompile(`^[A-Za-z0-9 _.,:/"'{}=\n\t@#%+*?\[\]-]*$`)
	headerLineRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,40}: [A-Za-z0-9 _.,:/@#=+{}*-]{0,200}$`)
	apiPathRE    = regexp.MustCompile(`^/[A-Za-z0-9/_.{}-]*$`)
	expectRE     = regexp.MustCompile(`^[A-Za-z0-9 _.,:/"'{}=@#%+*?\[\]-]*$`) // one line of plain text, placeholders allowed
	refuseRE     = regexp.MustCompile(`^[\x20-\x7e]{1,80}$`)                  // a refusal text: printable ASCII, no control character
)

// Limits of the check before and the read-back text (D-95).
const (
	maxExpect     = 200
	maxRefuse     = 8
	maxRefuseText = 80
)

// forbiddenHeader reports whether a template may not set the header: the connection sets the credentials and the address
// (Authorization, Cookie, Host, Proxy-*), and hop-by-hop and forwarding headers belong to the connection too (D-94). Headers that
// make a server act as another method (X-HTTP-Method-Override...) or as another client or path (X-Real-IP, X-Original-URL...) are
// refused as well (review of 13b-2).
func forbiddenHeader(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "authorization", "cookie", "host", "connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "forwarded", "via", "x-forwarded",
		"x-http-method-override", "x-http-method", "x-method-override", "x-real-ip", "x-original-url", "x-rewrite-url":
		return true
	}
	return strings.HasPrefix(n, "proxy-") || strings.HasPrefix(n, "x-forwarded-")
}

// credentialWords are the parts of a header name that mark a credential (D-174), matched on the name without hyphens, in lower case.
var credentialWords = []string{"key", "token", "secret", "auth", "pass", "session"}

// credentialHeader reports whether a header name carries a credential (D-174): its name, without hyphens, contains key, token, secret,
// auth, pass or session (X-API-Key, X-ApiKey, Api-Key, X-Auth-Token, X-Password, X-Session, Proxy-Authorization, Cookie...). A template
// may not hold a literal value for one: the connection's sign-in (a token with a header name) sends it, and the request, its log and the
// backup never hold it. Its value in a template is exactly one placeholder.
func credentialHeader(name string) bool {
	n := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "-", "")
	if n == "cookie" {
		return true
	}
	return slices.ContainsFunc(credentialWords, func(w string) bool { return strings.Contains(n, w) })
}

var onePlaceholderRE = regexp.MustCompile(`^\{[a-z_]+\}$`)

// ValidateTpl checks a template when it is saved (and again when it is loaded): only characters that cannot reach a
// shell, only typed placeholders or runtime values, a path that cannot leave the connection, a body that is JSON.
// It returns "" when the template is acceptable, otherwise a one-line reason in plain words.
func ValidateTpl(t Tpl, what string) string {
	if strings.TrimSpace(t.CLI) == "" && (t.Method == "" || t.Path == "") {
		return what + ": give a command or an API call."
	}
	if len(t.CLI) > 2000 || len(t.Body) > 2000 || len(t.Path) > 300 || len(t.Headers) > 600 || len(t.Expect) > maxExpect {
		return what + ": too long."
	}
	for _, f := range []struct{ name, v string }{{"command", t.CLI}, {"API path", t.Path}, {"API body", t.Body}, {"headers", t.Headers}} {
		if !safeTextRE.MatchString(f.v) {
			return what + ": the " + f.name + " contains a character that is not allowed (shell characters such as ; | & $ ` < > ( ) \\ are refused)."
		}
		for _, m := range placeholderRE.FindAllStringSubmatch(f.v, -1) {
			switch {
			case m[1] == "text":
				return what + ": {text} is only for message actions. In a command or API call use a typed placeholder such as {ip}, {domain}, {name} or {id}."
			case !validType(ParamType(m[1])) && !isRuntime(m[1]):
				return what + ": unknown placeholder {" + m[1] + "}. Use {ip}, {cidr}, {domain}, {port}, {mac}, {vlan}, {interface}, {id} or {name}."
			}
		}
	}
	if t.Method != "" && !validMethod(t.Method) {
		return what + ": choose the API method."
	}
	if t.Headers != "" {
		for l := range strings.SplitSeq(t.Headers, "\n") {
			if !headerLineRE.MatchString(l) {
				return what + `: each header must look like "Name: value".`
			}
			if name, _, _ := strings.Cut(l, ":"); forbiddenHeader(name) {
				return what + ": the header " + name + " is set by the connection and cannot be part of a template."
			}
			if name, val, _ := strings.Cut(l, ":"); credentialHeader(name) && !onePlaceholderRE.MatchString(strings.TrimSpace(val)) {
				return what + ": the header " + name + " looks like a credential. Do not put it in a template: give the connection a token with a header name (Settings, Connections) and it is sent from there."
			}
		}
	}
	if t.Expect != "" {
		if !expectRE.MatchString(t.Expect) {
			return what + ": the text to look for contains a character that is not allowed."
		}
		for _, m := range placeholderRE.FindAllStringSubmatch(t.Expect, -1) {
			switch {
			case m[1] == "text":
				return what + ": {text} is only for message actions."
			case !validType(ParamType(m[1])) && !isRuntime(m[1]):
				return what + ": unknown placeholder {" + m[1] + "} in the text to look for."
			}
		}
	}
	if t.Method != "" && t.Path == "" {
		return what + ": an API call needs a path."
	}
	if t.Path != "" && t.Method == "" {
		return what + ": choose the API method."
	}
	if t.Path != "" && (!apiPathRE.MatchString(t.Path) || strings.HasPrefix(t.Path, "//") || strings.Contains(t.Path, "..")) {
		return what + ": the API path must start with a single / and cannot contain .. or a query."
	}
	if t.Body != "" && !json.Valid([]byte(placeholderRE.ReplaceAllString(t.Body, "0"))) {
		return what + ": the API body must be valid JSON."
	}
	return ""
}

// precheckProblem checks the check before with its refusal texts and its required text as a group (D-95): a read-only template (a
// command, or a GET without a body), at least one refusal text or a required text, no read-back text, at most 8 refusal texts of up
// to 80 plain characters, a required text of up to 80 plain characters. "" when acceptable.
func precheckProblem(t Tpl, refuse []string, expect string) string {
	const what = "Check before"
	if t.Empty() && len(refuse) == 0 && expect == "" {
		return ""
	}
	switch {
	case t.Empty():
		return what + ": give the read-only command or API call, or remove the texts that make it refuse."
	case len(refuse) == 0 && expect == "":
		return what + ": add at least one text that makes it refuse, or a text the output must contain."
	case len(refuse) > maxRefuse:
		return what + ": up to 8 texts that make it refuse."
	case t.Expect != "":
		return what + ": the text to look for belongs to the read-back, not here."
	case (t.Method != "" && t.Method != "GET") || strings.TrimSpace(t.Body) != "":
		return what + ": an API call can only be a GET without a body. It must not change anything."
	}
	for _, r := range refuse {
		if !refuseRE.MatchString(r) || strings.TrimSpace(r) == "" {
			return what + ": each text that makes it refuse is 1 to 80 plain characters."
		}
	}
	if expect != "" && (!refuseRE.MatchString(expect) || strings.TrimSpace(expect) == "") {
		return what + ": the text the output must contain is 1 to 80 plain characters."
	}
	return ValidateTpl(t, what)
}

// portLikeParams are the placeholders that can name a port: {interface} always; in a customer's action also {port}, {id} and {name}
// when they sit in a command or an API path, because the type system has no "this is a port" type for them ({port} is a TCP or UDP
// number, {id} a whole number and {name} a free name, and "interface GigabitEthernet1/0/{port}" or "interface {name}" names a port
// all the same).
var portLikeParams = []ParamType{PInterface, PPort, PID, PName}

func usesPortLike(run, rollback, verify, pre Tpl, custom bool) bool {
	if slices.Contains(tplParams(run, rollback, verify, pre), PInterface) {
		return true
	}
	if !custom {
		return false
	}
	var texts []string
	for _, t := range []Tpl{run, rollback} {
		texts = append(texts, t.CLI, t.Path)
	}
	for _, p := range templateParams(texts...) {
		if slices.Contains(portLikeParams, p) {
			return true
		}
	}
	return false
}

// needsPrecheck reports whether the templates can name a port without the check before and a refusal text that D-95 (3) requires, so
// a trunk or uplink port is never touched. custom: the action is a customer's (see portLikeParams).
func needsPrecheck(run, rollback, verify, pre Tpl, refuse []string, custom bool) bool {
	return usesPortLike(run, rollback, verify, pre, custom) && (pre.Empty() || len(refuse) == 0)
}

func validMethod(m string) bool {
	switch m {
	case "GET", "PUT", "PATCH", "POST", "DELETE":
		return true
	}
	return false
}

// oneLine makes s a single short line.
func oneLine(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
	if limit > 0 {
		if r := []rune(s); len(r) > limit {
			s = string(r[:limit])
		}
	}
	return s
}
