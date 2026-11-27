package main

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan/pack"
)

// The deep-scan groups of nuclei's templates and the web paths a target skips, decided in core before a template leaves (the worker
// accepts any subset of the sets its job allows, so leaving templates out needs no change there).
//
// A template of the disruptive set is in one group:
//   - GroupDoS: a check that can exhaust or crash a service, whatever its tags say: the dos tag, or a name that says so (denial of
//     service, Billion Laughs, a crash, a flood, exhaustion). CVE-2019-11253 (Kubernetes YAML parsing, Billion Laughs) carries no dos
//     tag and is one.
//   - GroupLogins: it tries passwords or logs in with known credentials: a default-login folder, or a tag of password guessing,
//     default or hard-coded credentials, or a login with the template's own user name and password (scripts/scanpack puts these in
//     the disruptive set for the same reasons).
//   - GroupChange: every other disruptive template: exploit checks that send more than a harmless read (POST requests, unreviewed
//     exploit requests) and may create or change data.
//
// The deep and KEV sets are no group: they run whatever the settings (a deep template whose name says denial of service is a version
// read; a test holds that against the index).

// dosNameRE is a template name that says the check can exhaust or crash a service.
var dosNameRE = regexp.MustCompile(`(?i)\b(denial[- ]of[- ]service|d?dos|billion[- ]laughs|crash(es|ing)?|flood(ing)?|exhaust(s|ion)?|slowloris|xml bomb|zip bomb|redos|resource consumption|infinite loop|out[- ]of[- ]memory)\b`)

// loginDirs are the default-login folders of the pack; loginTags the tags of a template that tries passwords or logs in with
// credentials of its own.
var (
	loginDirs = []string{"http/default-logins/", "network/default-login/"}
	loginTags = []string{"default-login", "brute-force", "authenticated", "hardcoded-credentials", "default-credentials", "default-credential", "weak-credentials"}
)

// templateGroup is the group of a template of the disruptive set (0 for a template of no disruptive group: the deep and KEV sets).
func templateGroup(tp pack.Template) exposure.Groups {
	if tp.FullSet() != pack.SetDisruptive {
		return 0
	}
	switch {
	case slices.Contains(tp.Tags, "dos") || dosNameRE.MatchString(tp.Name):
		return exposure.GroupDoS
	case slices.ContainsFunc(loginDirs, func(d string) bool { return strings.HasPrefix(tp.Path, d) }) ||
		slices.ContainsFunc(tp.Tags, func(t string) bool { return slices.Contains(loginTags, t) }):
		return exposure.GroupLogins
	}
	return exposure.GroupChange
}

// groupAllows says mode m lets tp run as far as its group goes (RunsAt still decides the set).
func groupAllows(m exposure.ScanMode, tp pack.Template) bool {
	switch templateGroup(tp) {
	case exposure.GroupDoS:
		return m.Disruptive && m.DoS
	case exposure.GroupLogins:
		return m.Disruptive && m.Logins
	case exposure.GroupChange:
		return m.Disruptive && m.Change
	}
	return true
}

// tplFilter is what may leave for one port of a deep scan: the template's set at the mode's depth (RunsAt), its group (groupAllows)
// and the web paths to skip. The planners choose only such templates, so a port's room is never spent on one the send would drop.
// left, when not nil, collects the templates that only the paths kept out, with their verdict (for pathsLine).
type tplFilter struct {
	m     exposure.ScanMode
	paths []string
	left  map[string]tplPathVerdict
}

func (f tplFilter) runs(tp pack.Template) bool {
	if !tp.RunsAt(true, f.m.Disruptive) || !groupAllows(f.m, tp) {
		return false
	}
	v := templatePathOf(tp, f.paths)
	if v != tplPathRuns && f.left != nil {
		f.left[tp.ID] = v
	}
	return v == tplPathRuns
}

// requestRE is a request line as the index keeps it: the method, then the URL as written, to the end of the line (a path entry
// may hold a space).
var requestRE = regexp.MustCompile(`^[A-Z]+ (\S.*)$`)

// pathExprRE are the expressions a request path may hold and still be judged: values nuclei puts in that hold no "/", "\", "%",
// ";" or dot segment of their own (the target's host, port and domain parts, random strings and numbers). Any other expression
// in a path (an extracted value, a helper function, a variable with no value in the pack, the cut end of a long line) may hold
// "../" or an encoded one and reach any path: the request is unknown.
var pathExprRE = regexp.MustCompile(`^(Host|Hostname|Port|FQDN|RDN|DN|TLD|SD|randstr(_[A-Za-z0-9_]+)?|(rand_base|rand_int|rand_text_alpha|rand_text_alphanumeric|rand_text_numeric)\(\s*[0-9]+(\s*,\s*[0-9]+)?\s*\))$`)

// tplPathVerdict says whether a template may run on a target with web paths to skip (URL path prefixes, never patterns): it runs
// only when every request it can send is known and outside every prefix. A request path is held against a prefix as written and
// as the web server resolves it (percent-encoding, "\", ";" parameters, repeated slashes and dot segments), in any letter case
// as the ZAP exclude of the same setting matches, so "/res/../admin/x" or "/Admin/x" is under "/admin". Skipped: a request goes
// under one. Unknown: a request's path is built while the template runs ({{BaseURL}}{{paths}} with no value in the pack, an
// extracted value, a helper function, a raw request to {{Host}}:{{Port}}, pack.RequestUnknown), so it could go under one; it is
// left out too (fail closed). Only the values of pathExprRE leave a path judged. The index lists every request of an http
// template (pack.Template.Requests); an index built before that list has only the first request line, so a template there is
// unknown unless that line is already under a prefix. A template outside http/ sends no web path. nuclei runs with -dr (no
// redirect followed), and the builder marks the one exception, an unsafe raw request with redirects: true, as unknown.
type tplPathVerdict int

const (
	tplPathRuns tplPathVerdict = iota
	tplPathSkipped
	tplPathUnknown
)

func templatePathOf(tp pack.Template, skip []string) tplPathVerdict {
	if len(skip) == 0 || !strings.HasPrefix(tp.Path, "http/") {
		return tplPathRuns
	}
	if len(tp.Requests) == 0 { // an older index: the later requests are not known
		if requestPathOf(tp.Request, skip) == tplPathSkipped {
			return tplPathSkipped
		}
		return tplPathUnknown
	}
	verdict := tplPathRuns
	for _, r := range tp.Requests {
		switch requestPathOf(r, skip) {
		case tplPathSkipped:
			return tplPathSkipped
		case tplPathUnknown:
			verdict = tplPathUnknown
		}
	}
	return verdict
}

// requestPathOf is the verdict of one request line against skip. The path (up to the query) is judged as written and as the web
// server reads it (normPath), and a prefix matches in any letter case, as the ZAP exclude of the same setting does.
func requestPathOf(line string, skip []string) tplPathVerdict {
	m := requestRE.FindStringSubmatch(line)
	if m == nil {
		return tplPathUnknown
	}
	u := m[1]
	for _, base := range []string{"{{BaseURL}}", "{{RootURL}}"} { // the input's scheme, host and port, with no path of its own
		if strings.HasPrefix(u, base) {
			u = strings.TrimPrefix(u, base)
			if u == "" {
				u = "/"
			}
			break
		}
	}
	if !strings.HasPrefix(u, "/") {
		return tplPathUnknown
	}
	parts, exprs, ok := pathParts(u)
	if !ok {
		return tplPathUnknown
	}
	if slices.ContainsFunc(exprs, func(e string) bool { return !pathExprRE.MatchString(e) }) {
		if underAny(parts[0], skip) { // what is known before the first value that could be anything
			return tplPathSkipped
		}
		return tplPathUnknown
	}
	for _, v := range []string{"", "x"} { // every value is one of pathExprRE: the path as sent, each value as "" and as a letter
		if underAny(strings.Join(parts, v), skip) {
			return tplPathSkipped
		}
	}
	for k := range exprs { // the text before a value: when a prefix starts with it, the value may run into the prefix
		before := strings.Join(parts[:k+1], "x")
		for _, p := range skip {
			for _, pf := range pathForms(p, false) {
				for _, bf := range pathForms(before, true) {
					if strings.HasPrefix(pf, bf) {
						return tplPathUnknown
					}
				}
			}
		}
	}
	return tplPathRuns
}

// pathParts splits the path of u (up to the first "?" outside an expression) into its literal parts and the expressions between
// them (len(parts) == len(exprs)+1); ok false when an expression is not closed.
func pathParts(u string) (parts, exprs []string, ok bool) {
	var b strings.Builder
	for i := 0; i < len(u); {
		switch {
		case strings.HasPrefix(u[i:], "{{"):
			j := strings.Index(u[i+2:], "}}")
			if j < 0 {
				return nil, nil, false
			}
			parts, exprs = append(parts, b.String()), append(exprs, strings.TrimSpace(u[i+2:i+2+j]))
			b.Reset()
			i += j + 4
		case u[i] == '?':
			return append(parts, b.String()), exprs, true
		default:
			b.WriteByte(u[i])
			i++
		}
	}
	return append(parts, b.String()), exprs, true
}

// underAny says whether the path p goes under one of skip, as written or as the server reads it, in any letter case.
func underAny(p string, skip []string) bool {
	for _, s := range skip {
		for _, sf := range pathForms(s, false) {
			for _, pf := range pathForms(p, true) {
				if strings.HasPrefix(pf, sf) {
					return true
				}
			}
		}
	}
	return false
}

// pathForms are p as written and as normPath reads it, in lower case.
func pathForms(p string, params bool) [2]string {
	return [2]string{strings.ToLower(p), strings.ToLower(normPath(p, params))}
}

// normPath is the path p as a web server resolves it: percent-encoding decoded (up to three times, for double encoding; a "%"
// that starts no escape is kept), "\" read as "/", tabs and newlines dropped, with params each segment's path parameters (";…",
// as Tomcat reads "..;") dropped, then repeated slashes and dot segments resolved. A trailing "/" is kept.
func normPath(p string, params bool) string {
	for range 3 {
		d := unescapeLoose(p)
		if d == p {
			break
		}
		p = d
	}
	p = strings.NewReplacer(`\`, "/", "\t", "", "\n", "", "\r", "").Replace(p) // a URL parser drops tabs and newlines (".%09." is "..")
	if params {
		segs := strings.Split(p, "/")
		for i, g := range segs {
			if j := strings.IndexByte(g, ';'); j >= 0 {
				segs[i] = g[:j]
			}
		}
		p = strings.Join(segs, "/")
	}
	dir := strings.HasSuffix(p, "/") || strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..")
	p = path.Clean("/" + p)
	if dir && p != "/" {
		p += "/"
	}
	return p
}

// unescapeLoose decodes every %XX of s and keeps any other "%".
func unescapeLoose(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			h, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b.WriteByte(byte(h))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// pathsLine is the line of the templates left out of port for the web paths to skip, by verdict; "" when there is none. Every one
// of them is left out: none is sent.
func pathsLine(left map[string]tplPathVerdict, port int, skip []string) string {
	skipped, unknown := 0, 0
	for _, v := range left {
		switch v {
		case tplPathSkipped:
			skipped++
		case tplPathUnknown:
			unknown++
		}
	}
	if skipped+unknown == 0 {
		return ""
	}
	why := "each sends a request under one of them"
	switch {
	case skipped == 0:
		why = "each sends a request whose path is only built while it runs, so it could be under one"
	case unknown > 0:
		why = fmt.Sprintf("%d %s a request under one of them, %d %s a request whose path is only built while it runs, so it could be under one",
			skipped, plural(skipped, "sends", "send"), unknown, plural(unknown, "sends", "send"))
	}
	return fmt.Sprintf("nuclei left out %s on port %d for this target's web paths to skip (%s): %s.", count(skipped+unknown, "template", "templates"), port, strings.Join(skip, ", "), why)
}

// groupsOffLine is the line of the disruptive groups this target's settings turned off for nuclei, "" when none.
func groupsOffLine(m exposure.ScanMode) string {
	off := (m.Off & (exposure.GroupDoS | exposure.GroupLogins | exposure.GroupChange)).Names()
	if len(off) == 0 {
		return ""
	}
	return "nuclei's disruptive templates of " + strings.Join(off, ", ") + ": " + exposure.NotBySettings
}
