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
type tplFilter struct {
	m     exposure.ScanMode
	paths []string
}

func (f tplFilter) runs(tp pack.Template) bool {
	return tp.RunsAt(true, f.m.Disruptive) && groupAllows(f.m, tp) && templatePathOf(tp, f.paths) != tplPathSkipped
}

// requestRE is the first request line of a template as the index keeps it: the method, then the URL as written.
var requestRE = regexp.MustCompile(`^[A-Z]+ (\S*)`)

// tplPathVerdict says whether tp's first request goes under one of skip (a URL path prefix): skipped (it does), judged (it does not),
// or unknown when the path is built while the template runs ({{BaseURL}}{{paths}}, {{path}}, a raw request to {{Host}}:{{Port}}),
// so it cannot be told. A template outside http/ sends no web path. Only the first request is in the index: a template's later
// requests are not seen (best effort, as the settings page says).
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
	m := requestRE.FindStringSubmatch(tp.Request)
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

// notPathUnknown is the line of the templates whose path could not be told against the web paths to skip: they ran.
const notPathUnknown = "nuclei could not filter %d templates by path on port %d: their first request's path is built while they run, so they ran although this target has web paths to skip (%s)."

// pathsLine is notPathUnknown for port, "" when n is 0.
func pathsLine(n, port int, skip []string) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(notPathUnknown, n, port, strings.Join(skip, ", "))
}

// groupsOffLine is the line of the disruptive groups this target's settings turned off for nuclei, "" when none.
func groupsOffLine(m exposure.ScanMode) string {
	off := (m.Off & (exposure.GroupDoS | exposure.GroupLogins | exposure.GroupChange)).Names()
	if len(off) == 0 {
		return ""
	}
	return "nuclei's disruptive templates of " + strings.Join(off, ", ") + ": " + exposure.NotBySettings
}
