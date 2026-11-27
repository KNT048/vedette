package main

import (
	"fmt"
	"regexp"
	"slices"
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

// requestRE is a request line as the index keeps it: the method, then the URL as written.
var requestRE = regexp.MustCompile(`^[A-Z]+ (\S*)`)

// tplPathVerdict says whether a template may run on a target with web paths to skip (URL path prefixes, matched as written): it
// runs only when every request it can send is known and outside every prefix. Skipped: a request goes under one. Unknown: a
// request's path is built while the template runs ({{BaseURL}}{{paths}} with no value in the pack, {{randstr}}, a raw request
// to {{Host}}:{{Port}}, pack.RequestUnknown), so it could go under one; it is left out too (fail closed). The index lists every
// request of an http template (pack.Template.Requests); an index built before that list has only the first request line, so
// a template there is unknown unless that line is already under a prefix. A template outside http/ sends no web path. nuclei
// runs with -dr (no redirect followed), and the builder marks the one exception, an unsafe raw request with redirects: true,
// as unknown.
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

// requestPathOf is the verdict of one request line against skip.
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
	literal, variable := u, false
	if i := strings.Index(u, "{{"); i >= 0 {
		literal, variable = u[:i], true
	}
	unknown := false
	for _, p := range skip {
		switch {
		case strings.HasPrefix(literal, p):
			return tplPathSkipped
		case variable && strings.HasPrefix(p, literal): // the variable part may run into the prefix
			unknown = true
		}
	}
	if unknown {
		return tplPathUnknown
	}
	return tplPathRuns
}

// Lines of the templates the web paths to skip kept out of a port: every one is left out, none is sent.
const (
	notPathSkipped = "nuclei left out %d templates on port %d for this target's web paths to skip (%s): each sends a request under one of them."
	notPathMixed   = "nuclei left out %d templates on port %d for this target's web paths to skip (%s): %d send a request under one of them, %d a request whose path is only built while they run, so it could be under one."
	notPathUnknown = "nuclei left out %d templates on port %d for this target's web paths to skip (%s): each sends a request whose path is only built while it runs, so it could be under one."
)

// pathsLine is the line of the templates left out of port for the web paths to skip, by verdict; "" when there is none.
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
	paths := strings.Join(skip, ", ")
	switch {
	case skipped+unknown == 0:
		return ""
	case unknown == 0:
		return fmt.Sprintf(notPathSkipped, skipped, port, paths)
	case skipped == 0:
		return fmt.Sprintf(notPathUnknown, unknown, port, paths)
	}
	return fmt.Sprintf(notPathMixed, skipped+unknown, port, paths, skipped, unknown)
}

// groupsOffLine is the line of the disruptive groups this target's settings turned off for nuclei, "" when none.
func groupsOffLine(m exposure.ScanMode) string {
	off := (m.Off & (exposure.GroupDoS | exposure.GroupLogins | exposure.GroupChange)).Names()
	if len(off) == 0 {
		return ""
	}
	return "nuclei's disruptive templates of " + strings.Join(off, ", ") + ": " + exposure.NotBySettings
}
