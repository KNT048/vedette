// Package pack reads the index of the safe nuclei template pack (D-125 (4)): the list of templates the signed scan
// image carries, built at release time with the pack. Core reads it to choose templates (one per CVE a device is
// suspected of), to write the request line of the probe log before anything is sent (INV-7), and to refuse a template
// that is not in the safe set (INV-4); the worker reads the same index to check each template file's SHA-256 before
// nuclei starts. The index is the project's own format, so it is decoded strictly (internal/jsonstrict) and every
// entry is checked again here, behind the release builder's own checks. Since D-527 each entry names its sets: the KEV set of
// every job that is not full, and the deep and disruptive sets of a full job (exposure, testing terms accepted).
package pack

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/internal/jsonstrict"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

// Limits of an index. The pack of D-527 (KEV plus the deep and disruptive sets of nuclei-templates 10.5.1) is measured in
// docs/decisions/D-527.md; these keep about twice its size.
const (
	MaxSize      = 12 << 20 // bytes
	MaxTemplates = 20000
	maxTags      = 32
	maxRequest   = 200
	maxName      = 120
)

// SafeTags are the tags a template of the KEV set must carry one of: the KEV sets (CISA KEV, VulnCheck KEV) (INV-4).
var SafeTags = []string{"kev", "vkev"}

// The sets of the pack (D-527). SetKEV is the set of every job that is not full, as before: the LAN scan and the read-only own_ip
// checks. A full job (testing terms accepted, nucleiargv.DepthFull) runs SetDeep, and SetDisruptive only with the extra tick. A
// template belongs to one or two: kev alone, kev with deep or disruptive (a KEV template allowed at full depth), deep, disruptive.
const (
	SetKEV        = "kev"
	SetDeep       = "deep"
	SetDisruptive = "disruptive"
)

// severities are nuclei's info.severity values.
var severities = []string{"info", "low", "medium", "high", "critical", "unknown"}

// Template is one entry of the index.
type Template struct {
	ID      string   `json:"id"`            // nuclei template id, the -id value
	CVE     string   `json:"cve,omitempty"` // the CVE it confirms; always set in the KEV set, optional in the others
	Path    string   `json:"path"`          // relative to nucleiargv.TemplatesDir
	SHA256  string   `json:"sha256"`        // of the template file
	Tags    []string `json:"tags"`          //
	Request string   `json:"request"`       // the first request line, for the probe log (contract.ts ProbeEntry.request)
	// OwnIP says the template may run on the box's own public IP (exposure's safe checks, D-520): decided when the pack is built
	// (scripts/scanpack) from the template itself, conservatively: http only, every request GET or HEAD without a body, no
	// credential, no command, no refused tag (OwnIPRefusedTag), and the file passes OwnIPText. Absent = false: a template the
	// builder could not judge is not allowed. The worker checks the file again with OwnIPText before an own_ip job runs.
	OwnIP bool `json:"own_ip,omitempty"`
	// Sets are the sets the template belongs to (D-527): SetKEV, SetDeep, SetDisruptive (see there). The worker runs a template only
	// in a job its sets allow (RunsAt).
	Sets []string `json:"sets"`
	// Name and Severity are info.name (printable ASCII) and info.severity, from the template: what a deep result without a CVE
	// shows (an exposed .git, an admin panel). Always set outside the KEV set.
	Name     string `json:"name,omitempty"`
	Severity string `json:"severity,omitempty"`
	// Generic marks a deep http template of the exposure, misconfiguration, panel and miscellaneous categories that names no
	// product (no vendor or product in its metadata, none of its tags a product of the technologies templates): a full job runs it
	// on every web port, whatever the technologies found (D-527).
	Generic bool `json:"generic,omitempty"`
}

// InKEV says whether the template is in the KEV set.
func (t Template) InKEV() bool { return slices.Contains(t.Sets, SetKEV) }

// FullSet is the set the template runs in at full depth: SetDeep, SetDisruptive, or "" when it never runs at full depth.
func (t Template) FullSet() string {
	for _, s := range t.Sets {
		if s == SetDeep || s == SetDisruptive {
			return s
		}
	}
	return ""
}

// RunsAt says whether a job of this depth may run the template (D-527): a job that is not full runs the KEV set only; a full job
// runs the deep set, and the disruptive set only with the extra tick.
func (t Template) RunsAt(full, disruptive bool) bool {
	if !full {
		return t.InKEV()
	}
	s := t.FullSet()
	return s == SetDeep || s == SetDisruptive && disruptive
}

// Tech says whether the template is one of the technologies templates a full job runs first on a web port (D-527).
func (t Template) Tech() bool { return strings.HasPrefix(t.Path, "http/technologies/") }

// genericTags are tags of the technologies templates that name no product: they are never product tags.
var genericTags = []string{"tech", "detect", "waf", "favicon", "http", "https", "panel", "login", "config", "exposure", "version",
	"api", "server", "web", "default", "page", "status", "admin", "discovery", "misconfig", "network", "ssl", "tls", "tcp", "cms",
	"unauth", "service", "file", "files", "debug", "cloud", "cdn", "proxy", "dashboard", "portal", "console", "header", "headers",
	"js", "javascript", "framework", "library", "plugin", "theme", "router", "camera", "iot", "vpn", "firewall", "mail", "email",
	"database", "storage", "monitoring", "devops", "ai", "oss", "vuln", "cve", "kev", "vkev", "edb", "packetstorm", "wpscan"}

// GenericTag says whether a tag names no product (genericTags).
func GenericTag(tag string) bool { return slices.Contains(genericTags, tag) }

// ProductTags is nuclei's automatic scan rule on the technologies templates of tpls (-as, nuclei v3.11.1
// pkg/protocols/common/automaticscan: a matched detection template's tag counts when the template's id contains it): every tag of a
// technologies template of a full set that its id contains, at least 3 letters, but genericTags. These are the products a full job
// can find on a web port: the builder keeps a template that names one out of the generic ones, and core turns what a port shows into
// these tags (cmd/vedette exposuretemplates.go).
func ProductTags(tpls []Template) map[string]bool {
	out := map[string]bool{}
	for _, t := range tpls {
		if !t.Tech() || t.FullSet() == "" {
			continue
		}
		for _, tag := range t.Tags {
			if len(tag) >= 3 && strings.Contains(t.ID, tag) && !slices.Contains(genericTags, tag) {
				out[tag] = true
			}
		}
	}
	return out
}

// Index is the whole pack.
type Index struct {
	Version   string     `json:"version"`
	SHA256    string     `json:"sha256"` // of the pack as shipped; a job names it so the worker can refuse another pack
	Templates []Template `json:"templates"`

	byCVE  map[string][]int // the KEV set
	allCVE map[string][]int // every set
	byID   map[string]int
}

var (
	idRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`) // a nuclei template id: no comma, no leading dash
	versionRE = regexp.MustCompile(`^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,4}$`)
	cveRE     = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)
	shaRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	tagRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	requestRE = regexp.MustCompile(`^[ -~]{1,200}$`)
)

// Parse decodes and checks an index. Any entry that breaks a rule refuses the whole index: a pack that is not
// exactly what the builder promised is not used at all.
func Parse(raw []byte) (*Index, error) {
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("pack: index of %d bytes is over the %d cap", len(raw), MaxSize)
	}
	var ix Index
	if err := jsonstrict.Decode(raw, &ix); err != nil {
		return nil, fmt.Errorf("pack: reading the index: %w", err)
	}
	if !versionRE.MatchString(ix.Version) || !shaRE.MatchString(ix.SHA256) {
		return nil, errors.New("pack: the index has no valid version or hash")
	}
	if len(ix.Templates) == 0 || len(ix.Templates) > MaxTemplates {
		return nil, fmt.Errorf("pack: an index has 1 to %d templates, got %d", MaxTemplates, len(ix.Templates))
	}
	ix.byCVE, ix.allCVE, ix.byID = map[string][]int{}, map[string][]int{}, map[string]int{}
	for i, t := range ix.Templates {
		if err := t.check(); err != nil {
			return nil, fmt.Errorf("pack: template %d (%.100q): %w", i, t.ID, err)
		}
		if _, dup := ix.byID[t.ID]; dup {
			return nil, fmt.Errorf("pack: template id %q is listed twice", t.ID)
		}
		ix.byID[t.ID] = i
		if t.CVE != "" {
			ix.allCVE[t.CVE] = append(ix.allCVE[t.CVE], i)
		}
		if t.InKEV() {
			ix.byCVE[t.CVE] = append(ix.byCVE[t.CVE], i)
		}
	}
	return &ix, nil
}

// checkSets checks the sets of an entry (D-527): one or two, of the allowed pairs, and what each needs.
func (t Template) checkSets() error {
	switch {
	case len(t.Sets) == 1 && slices.Contains([]string{SetKEV, SetDeep, SetDisruptive}, t.Sets[0]):
	case len(t.Sets) == 2 && t.Sets[0] == SetKEV && (t.Sets[1] == SetDeep || t.Sets[1] == SetDisruptive):
	default:
		return fmt.Errorf("sets %.60q are not kev, deep, disruptive or kev with one of the other two", t.Sets)
	}
	if t.InKEV() && !cveRE.MatchString(t.CVE) {
		return errors.New("cve is not a CVE id")
	}
	if !t.InKEV() && (t.CVE != "" && !cveRE.MatchString(t.CVE) || t.Name == "" || t.Severity == "") {
		return errors.New("a template outside the KEV set needs a name and a severity, and its cve must be a CVE id or empty")
	}
	if len(t.Name) > maxName || t.Name != "" && !requestRE.MatchString(t.Name) {
		return errors.New("name is not one printable line")
	}
	if t.Severity != "" && !slices.Contains(severities, t.Severity) {
		return errors.New("severity is not one of nuclei's")
	}
	if t.Generic && (t.FullSet() != SetDeep || !strings.HasPrefix(t.Path, "http/")) {
		return errors.New("generic is for a deep http template only")
	}
	if t.OwnIP && !t.InKEV() {
		return errors.New("own_ip is for a template of the KEV set only")
	}
	return nil
}

func (t Template) check() error {
	switch {
	case !idRE.MatchString(t.ID):
		return errors.New("id is not a template id")
	case t.checkSets() != nil:
		return t.checkSets()
	case !nucleiargv.ValidTemplatePath(t.Path):
		return errors.New("path is not a relative .yaml path")
	case !RunsUnderProtocols(t.Path):
		return errors.New("path is not under http/, network/ or ssl/: nuclei runs with -pt http,tcp,ssl and would drop it without a line")
	case !shaRE.MatchString(t.SHA256):
		return errors.New("sha256 is not a lower-case SHA-256")
	case len(t.Tags) == 0 || len(t.Tags) > maxTags:
		return fmt.Errorf("a template has 1 to %d tags", maxTags)
	case len(t.Request) > maxRequest || !requestRE.MatchString(t.Request):
		return errors.New("request is not one printable request line")
	}
	safe, disruptive := false, false
	forbidden := nucleiargv.ForbiddenTags() // nuclei is told to exclude the same list (-etags)
	onlyDisruptive := slices.Equal(t.Sets, []string{SetDisruptive})
	for _, tag := range t.Tags {
		if !tagRE.MatchString(tag) {
			return fmt.Errorf("tag %.40q is not valid", tag)
		}
		if slices.Contains(forbidden, tag) && (tag != "dos" || !onlyDisruptive) { // D-527: dos only in the disruptive set
			return fmt.Errorf("tag %q is never allowed", tag)
		}
		if tag == "oast" { // L3: nuclei runs with -ni, so a check that needs an out-of-band answer would always say "not matched"
			return errors.New("needs out-of-band interaction (oast), which nuclei runs without")
		}
		safe = safe || slices.Contains(SafeTags, tag)
		disruptive = disruptive || slices.Contains(nucleiargv.DisruptiveTags(), tag)
	}
	if t.InKEV() && !safe {
		return errors.New("not in the KEV sets (kev, vkev)")
	}
	if disruptive && t.FullSet() == SetDeep {
		return errors.New("a template of the disruptive checks (dos, brute-force, default-login, authenticated) is in the deep set")
	}
	if t.OwnIP && (!strings.HasPrefix(t.Path, "http/") || !strings.HasPrefix(t.Request, "GET ") && !strings.HasPrefix(t.Request, "HEAD ") ||
		slices.ContainsFunc(t.Tags, OwnIPRefusedTag)) {
		return errors.New("marked own_ip, but it is not an http GET/HEAD check or carries a refused tag")
	}
	return nil
}

// ownIPRefusedParts refuse a tag that contains them (conservative: "commerce" or "salesforce" are refused for "rce" too).
var ownIPRefusedParts = []string{"sqli", "injection", "xss", "ssti", "rce", "login", "brute", "upload", "write", "deserializ", "password",
	"passwd", "reset", "cmdi", "jndi", "auth", "credential", "creds", "intrusive", "fuzz", "dos", "ssrf", "crlf"}

// OwnIPRefusedTag says whether a template with this tag may never run on the box's own public IP (D-559 K-6, D-520): a tag of
// nucleiargv.OwnIPForbiddenTags, or one that contains a part of ownIPRefusedParts.
func OwnIPRefusedTag(tag string) bool {
	return slices.Contains(nucleiargv.OwnIPForbiddenTags(), tag) || slices.ContainsFunc(ownIPRefusedParts, func(p string) bool { return strings.Contains(tag, p) })
}

var (
	// rawLineRE is the request line of a raw request: METHOD target HTTP/x.
	rawLineRE = regexp.MustCompile(`^\s*([A-Z]+)\s+\S+\s+HTTP/[0-9.]+\s*$`)
	// methodRE is a method: key of an http block.
	methodRE = regexp.MustCompile(`^\s*-?\s*method:\s*["']?([A-Za-z]*)`)
	// bodyRE is a body: key of an http block.
	bodyRE = regexp.MustCompile(`^\s*-?\s*body:`)
	// credHeaderRE is a header line or a headers key that carries a credential.
	credHeaderRE = regexp.MustCompile(`(?i)^\s*-?\s*["']?(authorization|proxy-authorization|cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token|token)["']?\s*:`)
)

// credMarks are texts of a template that sends a credential, a command, a delay, a change or a request that makes the service
// reach a third party (lower case). Conservative: a description that names one of them refuses the template too.
var credMarks = []string{"{{username", "{{password", "{{user}}", "{{pass", "{{cmd", "{{command", "password=", "passwd=", "pwd=",
	"digest-username", "digest-password", "sleep(", "echo+", "echo%20", "echo ", ";id", "|id", "%7cid", "`id`", "$(", "/bin/sh",
	"/bin/bash", "cmd.exe", "powershell", "whoami", "{{sid", "${jndi", "exec(", "system(", "%60", "--exec", "%24%28", "%3bid", "reset",
	"delete", "remove", "drop ", "oast.", "interact.sh"}

// OwnIPText is the worker's own check of a template file before an own_ip job (D-520), the last fence, without a YAML parser
// (the sensor binary links none): every raw request line is GET or HEAD, every method: key is GET or HEAD, there is no body: key,
// no header that carries a credential and no credential, command or delay variable. It is stricter than it needs to be on
// purpose: the builder marks own_ip only templates that also pass it.
func OwnIPText(body []byte) error {
	low := strings.ToLower(string(body))
	for _, m := range credMarks {
		if strings.Contains(low, m) {
			return fmt.Errorf("it holds %q", m)
		}
	}
	inHeaders := false // the lines after a raw request line, up to the blank line, are its headers
	for _, l := range strings.Split(string(body), "\n") {
		t := strings.TrimSpace(l)
		if m := rawLineRE.FindStringSubmatch(l); m != nil {
			if m[1] != "GET" && m[1] != "HEAD" {
				return fmt.Errorf("a %s request", m[1])
			}
			if err := RequestPayloadOK(strings.Fields(t)[1]); err != nil {
				return err
			}
			inHeaders = true
			continue
		}
		switch {
		case t == "" || strings.HasPrefix(t, "- |") || strings.HasSuffix(t, ":"):
			inHeaders = false
		case inHeaders:
			if _, v, ok := strings.Cut(t, ":"); ok {
				if err := RequestPayloadOK(strings.TrimSpace(v)); err != nil {
					return fmt.Errorf("a header: %w", err)
				}
			}
		case strings.Contains(t, "{{BaseURL}}") || strings.Contains(t, "{{RootURL}}"): // a path entry
			if err := RequestPayloadOK(strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "-")), `"'`)); err != nil {
				return err
			}
		}
		if m := methodRE.FindStringSubmatch(l); m != nil && !strings.EqualFold(m[1], "GET") && !strings.EqualFold(m[1], "HEAD") {
			return fmt.Errorf("method %q", m[1])
		}
		if bodyRE.MatchString(l) {
			return errors.New("a request body")
		}
		if credHeaderRE.MatchString(l) {
			return errors.New("a credential header")
		}
	}
	return nil
}

// nucleiVars are the only {{…}} expressions a request of an own_ip template may hold: nuclei's own address variables.
var nucleiVars = []string{"{{BaseURL}}", "{{RootURL}}", "{{Hostname}}"}

var (
	exprRE   = regexp.MustCompile(`\{\{[^}]*\}\}`)
	sqlRE    = regexp.MustCompile(`\b(union|select)\b`)
	base64RE = regexp.MustCompile(`[A-Za-z0-9+/_-]{8,}={0,2}`)
)

// RequestPayloadOK refuses a request target (path and query) or a header value that carries an injection-shaped payload (D-520,
// review round 2 M1), on the text and on its percent-decoded form: a quote, a "--" comment, a ";" in the query, a CR or LF, a
// script or javascript: (also inside a base64 blob), SQL words (union, select, sleep(, benchmark(), a template expression other
// than nuclei's address variables, ${ or #{. Conservative: false refusals are accepted.
func RequestPayloadOK(s string) error {
	for _, e := range exprRE.FindAllString(s, -1) {
		if !slices.Contains(nucleiVars, e) {
			return fmt.Errorf("the expression %.40q", e)
		}
	}
	if strings.Count(s, "{{") != len(exprRE.FindAllString(s, -1)) {
		return errors.New("an unclosed expression")
	}
	if strings.Contains(s, `\r`) || strings.Contains(s, `\n`) {
		return errors.New("a CR or LF")
	}
	d := strings.ToLower(percentDecode(percentDecode(s)))
	if _, q, ok := strings.Cut(d, "?"); ok && strings.Contains(q, ";") {
		return errors.New("a ; in the query")
	}
	for _, m := range []string{"'", `"`, "`", "--", "\r", "\n", "<script", "javascript:", "sleep(", "benchmark(", "${", "#{"} {
		if strings.Contains(d, m) {
			return fmt.Errorf("%q", m)
		}
	}
	if sqlRE.MatchString(d) {
		return errors.New("an SQL word")
	}
	for _, tok := range base64RE.FindAllString(percentDecode(percentDecode(s)), -1) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(tok); err == nil {
				if l := strings.ToLower(string(b)); strings.Contains(l, "<script") || strings.Contains(l, "javascript:") {
					return errors.New("a script in base64")
				}
			}
		}
	}
	return nil
}

// percentDecode decodes %XX escapes and leaves anything else as it is.
func percentDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool { return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' }

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c >= 'a':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// RunsUnderProtocols says whether a template path sits in a directory of a protocol nuclei runs (-pt http,tcp,ssl in
// nucleiargv): every other protocol is dropped silently and would read as "no match reported", so the pack refuses it
// here and a template of the pack always runs.
func RunsUnderProtocols(path string) bool {
	return strings.HasPrefix(path, "http/") || strings.HasPrefix(path, "network/") || strings.HasPrefix(path, "ssl/")
}

// ForCVE returns the templates of the KEV set that confirm cve, in index order; none when the pack has no template for it
// (the result is then no_template, and nothing is sent: INV-8).
func (ix *Index) ForCVE(cve string) []Template {
	var out []Template
	for _, i := range ix.byCVE[cve] {
		out = append(out, ix.Templates[i])
	}
	return out
}

// FullForCVE returns the templates of any set that confirm cve and that a full job may run (RunsAt), in index order (D-527).
func (ix *Index) FullForCVE(cve string, disruptive bool) []Template {
	var out []Template
	for _, i := range ix.allCVE[cve] {
		if ix.Templates[i].RunsAt(true, disruptive) {
			out = append(out, ix.Templates[i])
		}
	}
	return out
}

// Get returns the template of id.
func (ix *Index) Get(id string) (Template, bool) {
	i, ok := ix.byID[id]
	if !ok {
		return Template{}, false
	}
	return ix.Templates[i], true
}

// Has says whether id is a template of the pack.
func (ix *Index) Has(id string) bool {
	_, ok := ix.byID[id]
	return ok
}

// oastRE is a template's use of an out-of-band server: nuclei's interactsh variables and parts, or a public interactsh or oast host
// the target would be made to reach. The word alone ("Interactsh Server" as a matcher of tech-detect) is not a use.
var oastRE = regexp.MustCompile(`(?i)\{\{\s*(interactsh|oast)|interactsh[-_](url|protocol|request|response|ip)|interactsh\.(com|me|sh)|oast\.(me|fun|live|online|site|pro|sh|com)|interact\.sh|burpcollaborator\.`)

// NeedsOAST says whether a template uses an out-of-band server (a third party: a data flow leaving the box), D-527.
func NeedsOAST(body []byte) bool { return oastRE.Match(body) }

// oobServerRE is a matcher looking for an interactsh server's own page: outside the technologies templates, a template that matches
// it makes the target fetch one (review FULL-4b r1 M3, CVE-2021-22054 hides the URL in base64).
var oobServerRE = regexp.MustCompile(`(?i)interactsh server`)

// FullText is the worker's own check of a template file before a full job (D-527), behind the index's sets and the file's hash and
// NoChangeText (D-528, every job): no out-of-band interaction (interactsh, oast), and outside the technologies templates (tech) no
// match on an interactsh server's page. Like OwnIPText it reads the text without a YAML parser (the sensor binary links none).
func FullText(body []byte, tech bool) error {
	if NeedsOAST(body) || !tech && oobServerRE.Match(body) {
		return errors.New("it needs out-of-band interaction")
	}
	return NoChangeText(body)
}
