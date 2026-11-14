package pack

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// D-528: no template of the pack changes state on the target or makes anyone contact a third party, whatever its set. The builder
// (scripts/scanpack) decides it from the parsed template with ChangeInRequest, ThirdPartyURL and its destination rule, and it also
// requires NoChangeText of the whole file; the worker runs NoChangeText on every template file of every job before nuclei starts, so
// the image's pack is checked on both sides with the same text rule. Upstream tags are not reliable enough to be the only rule
// (review FULL-4b r1 H1, H3: write and password-reset templates were in the KEV set).

// NeverTags are tags that mark a template that writes, uploads, takes over an account or reads third-party sources (D-528).
// "instrusive" is nuclei-templates' own misspelling of intrusive, on several templates.
var NeverTags = []string{"intrusive", "instrusive", "file-upload", "file-write", "upload", "account-takeover", "osint"}

// methodsOK are the only request methods a template of the pack may send: reading, and POST. PUT, DELETE, PATCH and the WebDAV
// writes never.
var methodsOK = []string{"GET", "HEAD", "POST", "OPTIONS", "PROPFIND", "TRACE"}

// MethodOK says whether a template may send method (upper case).
func MethodOK(method string) bool { return slices.Contains(methodsOK, method) }

// textMarks are texts that, anywhere in a template file, mean a write, an override of the method, a request to another host than
// the job's, or an upload (lower case). They are rare enough in matchers that the whole file is read: the worker has no YAML parser.
var textMarks = []string{"into outfile", "into dumpfile", "xp_cmdshell", "file_put_contents", "x-http-method-override", "x-http-method:",
	"x-method-override", "_method=put", "_method=delete", "_method=patch", "gopher://", "dict://"}

// atHostRE is a raw request's @Host: annotation, which sends it to another host or port than the job's.
var atHostRE = regexp.MustCompile(`(?im)^\s*@host\s*:`)

// NoChangeText is the text rule of D-528 over a whole template file: no write method in a raw request line or a method: key, no
// @Host: annotation, none of textMarks, and no multipart part that carries a file.
func NoChangeText(body []byte) error {
	low := strings.ToLower(string(body))
	for _, m := range textMarks {
		if strings.Contains(low, m) {
			return fmt.Errorf("it holds %q", m)
		}
	}
	if atHostRE.Match(body) {
		return errors.New("a request to another host (@Host)")
	}
	if strings.Contains(low, "multipart/form-data") && strings.Contains(low, "filename=") {
		return errors.New("a file upload")
	}
	for _, l := range strings.Split(string(body), "\n") {
		if m := rawLineRE.FindStringSubmatch(l); m != nil && !MethodOK(m[1]) {
			return fmt.Errorf("a %s request", m[1])
		}
		if m := methodRE.FindStringSubmatch(l); m != nil && m[1] != "" && !MethodOK(strings.ToUpper(m[1])) {
			return fmt.Errorf("method %q", m[1])
		}
	}
	return nil
}

// changeREs are request parts that change state (matched on the lower-cased, twice percent-decoded part with + read as a space):
// password change and reset, and account creation, when the part is sent with POST (a GET shows the form, it changes nothing); SQL
// that writes and a shell writing a file, whatever the method.
var changeREs = []struct {
	why    string
	onPost bool
	re     *regexp.Regexp
}{
	{"a password change or reset", true, regexp.MustCompile(`change[-_]?pass|changepw|reset[-_]?pass|resetpw|forgot[-_]?pass|set[-_]?password|update[-_]?pass|new[-_]?passw|password[-_]?reset|password[-_]?change|request[-_]?reset`)},
	{"an account creation", true, regexp.MustCompile(`signup|sign-up|[/=?&_]register([/?.&=\s]|$)`)},
	{"an account creation", false, regexp.MustCompile(`create\w{0,12}(users?|admin\w*)\b|add[-_]?users?\b|user[-_]?add\b|create[-_]?account\b`)},
	{"a reset of the application", false, regexp.MustCompile(`do_reset|factory[-_]?reset|reset[-_]?(wordpress|database|config|settings)`)},
	{"an SQL write", false, regexp.MustCompile(`insert\s+into|update\s+[\w.\x60"\[\]]+\s+set\s|delete\s+from|drop\s+(table|database|user)|create\s+user|alter\s+user|grant\s+all`)},
	// a shell redirection after a command word (">" right after ")", a quote or "]" is HTML of an XSS payload, not a shell)
	{"a file write", false, regexp.MustCompile(`\bfwrite\s*\(|fopen\s*\([^)]{0,80},\s*['"][wa]|[;|&$(\x60]\s*[a-z]+[^<>\n]{0,80}[^)"'\]\s<]\s*>>?\s*[/.~][\w/.-]|\btouch\s+[/.~]`)},
}

// ChangeInRequest is the reason a request part (a path, a raw request, a body, a header or payload value) changes state, or "". post
// says the part is sent with POST.
func ChangeInRequest(part string, post bool) string {
	d := strings.ReplaceAll(strings.ToLower(percentDecode(percentDecode(part))), "+", " ")
	for _, c := range changeREs {
		if (post || !c.onPost) && c.re.MatchString(d) {
			return c.why
		}
	}
	return ""
}

var (
	absURLRE = regexp.MustCompile(`(?i)(https?|ftp)://([^/\s"'<>?#\\&]+)`)
	b64TokRE = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	// xmlNameRE are XML namespace declarations and schema locations: names in a request body that nobody fetches.
	xmlNameRE = regexp.MustCompile(`(?i)(xmlns(:[\w.-]+)?|schemalocation)\s*=\s*(\\?["'])[^"'\\]*(\\?["'])`)
	// schemaHosts name XML namespaces, SOAP actions and schemas: identifiers in a request body that nobody fetches.
	schemaHosts = []string{"www.w3.org", "w3.org", "schemas.xmlsoap.org", "schemas.microsoft.com", "schemas.dmtf.org", "www.opengis.net",
		"docs.oasis-open.org", "tempuri.org", "schemas.openxmlformats.org", "purl.org", "xmlns.com", "java.sun.com", "xml.apache.org",
		"ns.adobe.com", "schemas.android.com", "www.springframework.org"}
)

// notThirdParty says whether a URL host (lower case, without port) is not a party on the Internet: a template expression (the job's
// address), a name with no dot (it does not resolve publicly), a reserved name (RFC 2606, RFC 6761), a schema identifier, or a
// loopback, private, shared or link-local address of the target's own network.
func notThirdParty(h string) bool {
	if strings.HasPrefix(h, "{{") || !strings.Contains(h, ".") && !strings.Contains(h, ":") || slices.Contains(schemaHosts, h) {
		return true
	}
	for _, d := range []string{"example.com", "example.net", "example.org", ".example", ".test", ".invalid", ".localhost", ".local"} {
		if h == d || strings.HasSuffix(h, "."+strings.TrimPrefix(d, ".")) {
			return true
		}
	}
	a, err := netip.ParseAddr(strings.Trim(h, "[]"))
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() || netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// ThirdPartyHost says whether a host (a name or address, with or without a port, IPv6 in brackets) is a party on the Internet other
// than the job's address (notThirdParty).
func ThirdPartyHost(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	if strings.HasPrefix(h, "[") {
		h, _, _ = strings.Cut(h, "]")
		h = strings.TrimPrefix(h, "[")
	} else if j := strings.LastIndexByte(h, ':'); j > 0 && strings.Count(h, ":") == 1 {
		h = h[:j]
	}
	return !notThirdParty(h)
}

// userinfoHost is the part of a URL's userinfo a lenient parser could read as the host: the user name without bytes outside
// printable ASCII, when it holds a dot or such a byte; "" otherwise (a plain user name such as "admin").
func userinfoHost(userinfo string) string {
	user, _, _ := strings.Cut(userinfo, ":")
	odd := false
	clean := strings.Map(func(r rune) rune {
		if r < 0x21 || r > 0x7e {
			odd = true
			return -1
		}
		return r
	}, user)
	if !odd && !strings.Contains(clean, ".") || clean == "" {
		return ""
	}
	return clean
}

// PercentDecode decodes %XX escapes twice (a request part as a server would read it after a second decoding).
func PercentDecode(s string) string { return percentDecode(percentDecode(s)) }

// ThirdPartyURL is the first absolute URL in a request part whose host is a party on the Internet other than the job's address
// (notThirdParty), also inside a base64 token, or "".
func ThirdPartyURL(part string) string {
	check := func(s string) string {
		s = xmlNameRE.ReplaceAllString(s, "")
		for _, m := range absURLRE.FindAllStringSubmatch(s, -1) {
			host := strings.ToLower(m[2])
			if i := strings.LastIndexByte(host, '@'); i >= 0 {
				// review kev r1 H-2: a parser may take the userinfo for the host (http://oast.me%EF%BF%BD@localhost), so a
				// userinfo that holds a dot name or a byte outside printable ASCII is checked as a host too
				if u := userinfoHost(host[:i]); u != "" && ThirdPartyHost(u) {
					return m[0]
				}
				host = host[i+1:]
			}
			if ThirdPartyHost(host) {
				return m[0]
			}
		}
		return ""
	}
	d := percentDecode(percentDecode(part))
	if u := check(d); u != "" {
		return u
	}
	for _, tok := range b64TokRE.FindAllString(d, -1) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(tok); err == nil {
				if u := check(string(b)); u != "" {
					return "base64 " + u
				}
			}
		}
	}
	return ""
}
