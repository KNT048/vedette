package main

import (
	"crypto/sha256"
	_ "embed" // reviewed.tsv
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/knt048/vedette/modules/scan/pack"
)

// D-528 step 2 (lead decision after review kev r1 H-0 and FULL-4b r2 H1, 2026-11-14): word and destination rules cannot tell what a
// request does to a product, so the sets that run without the extra tick are an allowlist, as Nessus's "safe checks" default is. A
// template is in them only if (a) it is a read-only GET (readOnlyGET) whose id and name name no state change (stateName), or (b) a
// person read it and listed it in reviewed.tsv with the SHA-256 of the file they read. Everything else waits in the review queue
// (docs/research/kev-review-queue.md). The D-528 step-1 rule (changeReason: denylist, tags, NoChangeText, destination, third party)
// still applies to both.

// reviewedTSV is the reviewed allowlist: one template a line, "id<TAB>sha256<TAB>why it changes nothing", # for comments.
//
//go:embed reviewed.tsv
var reviewedTSV string

type reviewedEntry struct{ sha, why string }

// reviewed is reviewedTSV parsed; a malformed line stops the builder (parseReviewed).
var reviewed = func() map[string]reviewedEntry {
	m, err := parseReviewed(reviewedTSV)
	if err != nil {
		panic(err) // a developer tool: the committed file is held to its format by TestReviewedListFormat
	}
	return m
}()

func parseReviewed(text string) (map[string]reviewedEntry, error) {
	out := map[string]reviewedEntry{}
	for n, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) != 3 || !idRE.MatchString(f[0]) || !shaRE.MatchString(f[1]) || len(strings.TrimSpace(f[2])) < 20 {
			return nil, fmt.Errorf("scanpack: reviewed.tsv line %d is not id<TAB>sha256<TAB>reason (20 characters at least)", n+1)
		}
		if _, dup := out[f[0]]; dup {
			return nil, fmt.Errorf("scanpack: reviewed.tsv lists %s twice", f[0])
		}
		out[f[0]] = reviewedEntry{f[1], f[2]}
	}
	return out, nil
}

// reviewedState says what the allowlist says of a template: listed with this file's hash, listed with another hash (the file
// changed since a person read it: the build stops until they read it again), or not listed.
func reviewedState(id, sha string) (listed, stale bool) {
	e, ok := reviewed[id]
	return ok && e.sha == sha, ok && e.sha != sha
}

// stateNameRE is a template name or id that says the check changes the target (lower case, ids with - read as spaces): a creation,
// a user or admin added, a takeover, a purge, a write or overwrite, a reset, a restore, an install, an upload, a deletion, an enable,
// a publish, a registration of something, a backdoor or webshell, persistence, a privilege escalation, a settings or options change,
// a stored script. "Enabled", "Installation" and "Registration" are not in it: they name a page or a state a GET reads ("Debug Mode
// Enabled", "Installation Page", "Open Registration").
var stateNameRE = regexp.MustCompile(`\b(creat(e|es|ing|ion)|adds? (a |an )?(new )?(user|admin|administrator|account)s?|takeover|take over|purge|writ(e|es|ing)|overwrit(e|es|ing)|reset|restor(e|es|ing|ation)|install|installs|upload|uploads|delet(e|es|ing|ion)|enable|enables|publish|register|registers|backdoor|webshell|web shell|persisten(t|ce)|privilege escalation|(option|options|setting|settings|config|configuration) (update|change|modification|overwrite|injection)|stored (xss|cross[- ]site scripting))\b`)

// stateName says whether the id or name of a template names a state change.
func stateName(id, name string) bool {
	// "Out-of-Bounds Write" is a memory flaw class, not a change the check makes
	n := strings.NewReplacer("out-of-bounds write", "", "out of bounds write", "").Replace(strings.ToLower(name))
	return stateNameRE.MatchString(strings.ToLower(strings.ReplaceAll(id, "-", " "))) || stateNameRE.MatchString(n)
}

// getVerbRE is a request target that asks the target to do something, read on a GET too: an action word as a path segment or a
// parameter name or value prefix (restoreAdmin.php, ?action=set_map_properties, operation=write, cmd=writeuploaddir, /submit?).
var getVerbRE = regexp.MustCompile(`(?i)([/?&=_.-]|^)(delete|remove|purge|restore|reset|write|enable|disable|create|submit|save|import|truncate|reboot|restart|shutdown|activate|register|signup)|[?&](action|act|cmd|op|operation|do|task|func|function|mode)=(set|save|update|del|remove|add|create|write|reset|restore|enable|disable|install|upload|import|submit|apply|change|edit)`)

// credHeaderNames are request headers that carry a credential: a GET that sends one tries to log in.
var credHeaderNames = []string{"authorization", "proxy-authorization", "cookie", "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token", "token"}

// readOnlyGET is rule (a): every request of the template is an http GET or HEAD with no body, none sends a credential (a header of
// credHeaderNames, a variable named like one, a user name or password expression), every request target and header value passes
// the own_ip payload screen (pack.RequestPayloadOK: no quote, SQL words, script, command separator in the query, template expression
// other than the job's address) and names no action (getVerbRE). The block keys are those of own_ip (ownIPKeys): anything else
// (payloads, body, a newer feature) is not judged. Such a check may still confirm a flaw by reading: a path traversal that reads a
// file, a page that should not answer.
func readOnlyGET(rel string, doc map[string]any) (bool, string) {
	if !strings.HasPrefix(rel, "http/") || doc["tcp"] != nil || doc["ssl"] != nil {
		return false, "not http"
	}
	if vars, ok := doc["variables"].(map[string]any); ok {
		for k := range vars {
			if credName.MatchString(k) {
				return false, "a credential variable"
			}
		}
	} else if doc["variables"] != nil {
		return false, "variables"
	}
	bl := blocks(doc, "http")
	if len(bl) == 0 {
		return false, "no request"
	}
	target := func(s string) string {
		if err := pack.RequestPayloadOK(s); err != nil {
			return "payload: " + err.Error()
		}
		if getVerbRE.MatchString(pack.PercentDecode(s)) {
			return "an action in " + clip(s)
		}
		return ""
	}
	for _, m := range bl {
		for k := range m {
			if !slices.Contains(ownIPKeys, k) {
				return false, "key " + k
			}
		}
		if h, has := m["headers"]; has {
			hm, ok := h.(map[string]any)
			if !ok {
				return false, "headers"
			}
			for k, v := range hm {
				vs, _ := v.(string)
				if slices.Contains(credHeaderNames, strings.ToLower(k)) || pack.RequestPayloadOK(vs) != nil {
					return false, "header " + k
				}
			}
		}
		raws, hasRaw := m["raw"].([]any)
		paths, hasPath := m["path"].([]any)
		switch {
		case hasRaw == hasPath:
			return false, "raw and path"
		case hasPath:
			if meth, has := m["method"]; has {
				ms, _ := meth.(string)
				if !strings.EqualFold(ms, "GET") && !strings.EqualFold(ms, "HEAD") {
					return false, "method " + ms
				}
			}
			for _, p := range paths {
				ps, _ := p.(string)
				if why := target(ps); why != "" {
					return false, why
				}
			}
		default:
			if _, has := m["method"]; has {
				return false, "method key on raw"
			}
			for _, r := range raws {
				rs, _ := r.(string)
				if why := rawReadOnly(rs, target); why != "" {
					return false, why
				}
			}
		}
	}
	return true, ""
}

// rawReadOnly is readOnlyGET of one raw request: GET or HEAD, no credential header, every header value through the payload screen,
// the target through target, and nothing after the blank line that ends the headers.
func rawReadOnly(r string, target func(string) string) string {
	lines := strings.Split(strings.ReplaceAll(r, "\r\n", "\n"), "\n")
	i := 0
	for i < len(lines) && (strings.TrimSpace(lines[i]) == "" || strings.HasPrefix(strings.TrimSpace(lines[i]), "@")) {
		i++
	}
	if i == len(lines) {
		return "no request line"
	}
	f := strings.Fields(lines[i])
	if len(f) < 2 || f[0] != "GET" && f[0] != "HEAD" {
		return "method " + clip(lines[i])
	}
	if why := target(f[1]); why != "" {
		return why
	}
	for i++; i < len(lines) && strings.TrimSpace(lines[i]) != ""; i++ {
		name, value, ok := strings.Cut(lines[i], ":")
		if !ok || slices.Contains(credHeaderNames, strings.ToLower(strings.TrimSpace(name))) || pack.RequestPayloadOK(strings.TrimSpace(value)) != nil {
			return "header " + clip(lines[i])
		}
	}
	for ; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "" {
			return "a body"
		}
	}
	return ""
}

// reviewRow is one template of the review queue: a KEV template that passed every other rule and waits for a person to read it.
type reviewRow struct {
	id, cve, product, method, why, path, sha string
}

// queueRow describes a template for the review queue (rel and body are those qualify judged).
func queueRow(rel string, body []byte, reason string) reviewRow {
	var doc map[string]any
	_ = yaml.Unmarshal(body, &doc)
	info, _ := doc["info"].(map[string]any)
	id, _ := doc["id"].(string)
	name, _ := info["name"].(string)
	r := reviewRow{id: id, cve: cveOf(info), path: rel, why: reason}
	sum := sha256.Sum256(body)
	r.sha = hex.EncodeToString(sum[:])
	md, _ := info["metadata"].(map[string]any)
	if p, ok := md["product"].(string); ok && p != "" {
		r.product = p
		if v, ok := md["vendor"].(string); ok && v != "" {
			r.product = v + " " + p
		}
	} else {
		r.product, _, _ = strings.Cut(name, " - ")
	}
	var methods []string
	add := func(m string) {
		if m = strings.ToUpper(m); m != "" && !slices.Contains(methods, m) {
			methods = append(methods, m)
		}
	}
	for _, b := range blocks(doc, "http") {
		if m, ok := b["method"].(string); ok {
			add(m)
		}
		for _, raw := range strs(b["raw"]) {
			if f := strings.Fields(firstRequestLine(raw)); len(f) > 0 {
				add(f[0])
			}
		}
		if _, ok := b["path"]; ok && b["method"] == nil {
			add("GET")
		}
	}
	if doc["tcp"] != nil {
		add("tcp")
	}
	if doc["ssl"] != nil {
		add("ssl")
	}
	r.method = strings.Join(methods, ", ")
	if reason == "not reviewed" {
		if _, d := readOnlyGET(rel, doc); d != "" {
			r.why = d
		}
	} else {
		r.why = "the name says a change: " + name
	}
	return r
}

func firstRequestLine(raw string) string {
	for _, l := range strings.Split(raw, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "@") {
			return l
		}
	}
	return ""
}

// writeQueue writes the review queue: every KEV template left out by rule (a), one table row each, sorted by id, with the sha256 a
// reviewer copies into reviewed.tsv after reading the file.
func writeQueue(path, version string, rows []reviewRow) error {
	sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	cell := func(s string) string {
		s = strings.Join(strings.Fields(s), " ")
		return strings.NewReplacer("|", "\\|", "`", "'").Replace(s)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# KEV templates waiting for a reviewer (pack %s, D-528 step 2)\n\n", version)
	b.WriteString("Written by `make scan-pack` (scripts/scanpack); do not edit by hand. These KEV templates passed every other rule of the pack but are not read-only GETs (or their name says a change), so the LAN scan and the own-IP checks do not run them until a person reads the file and adds `id<TAB>sha256<TAB>reason` to `scripts/scanpack/reviewed.tsv`. Read the requests, not the name: a check is reviewed only if it changes nothing on the target (no account, password, setting, file, record or mail) and reaches no other host. Work in batches by product.\n\n")
	fmt.Fprintf(&b, "%d templates.\n\n| id | CVE | product | method | why it waits | path | sha256 |\n|---|---|---|---|---|---|---|\n", len(rows))
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", cell(r.id), cell(r.cve), cell(r.product), cell(r.method), cell(r.why), cell(r.path), r.sha)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// noTickReason is rule (a) or (b) for one template that passed changeReason: "" when it may run without the tick, "stale review"
// when its allowlist entry names another hash, else "state name" or "not reviewed" with why rule (a) did not hold. ownIP is the
// D-520 decision (ownIPSafe), stricter than readOnlyGET (it also refuses commands, deletes and resets in the text and the refused
// tags) and already shipped as safe on a public IP: such a template is in without the name rule, whose words ("Arbitrary File
// Upload") then name the flaw a version read reports, not what the GET does.
func noTickReason(id, name, rel, sha string, doc map[string]any, ownIP bool) (why, detail string) {
	listed, stale := reviewedState(id, sha)
	switch {
	case stale:
		return "stale review", "reviewed.tsv names another sha256: read the template again"
	case listed, ownIP:
		return "", ""
	case stateName(id, name):
		return "state name", name
	}
	if ok, d := readOnlyGET(rel, doc); !ok {
		return "not reviewed", d
	}
	return "", ""
}
