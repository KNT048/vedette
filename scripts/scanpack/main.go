// Command scanpack builds the safe nuclei template pack that the signed `scan` image carries (D-125 (4), D-146): the templates of
// the KEV sets (tags kev, vkev) that are plain http, tcp or ssl checks for exactly one CVE, copied byte for byte, and the index
// (modules/scan/pack) that core reads to choose them and the worker reads to check them. Run it with `make scan-pack`.
//
// The source is pinned: the GitHub tag archive of projectdiscovery/nuclei-templates (MIT) at the version and SHA-256 of
// deploy/containers/pins.env; a download that does not hash to it is refused before anything is read from it. A template is left
// out, never repaired, when it has any of: no KEV tag, a tag of nucleiargv.ForbiddenTags or oast, a mention of
// interactsh, a top-level key other than id, info, variables, http, tcp, ssl (headless, code, javascript, file, dns, whois,
// websocket, flow, self-contained and everything a later nuclei adds), not exactly one CVE, an id nuclei would take for a flag, or no
// printable request line for the probe log. Next to that KEV set, D-527 adds the deep and disruptive sets that a full job (testing
// terms accepted) runs: see fullSet. Each index entry names its sets. Every set, KEV included, leaves out anything of the
// state-change, destination and third-party rule of D-528 (nochange.go). The product never runs this: it ships the result. Network,
// for a maintainer only: github.com and codeload.github.com, 60 s limit.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/pack"
)

const (
	archiveURL = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v%s.tar.gz"
	maxArchive = 256 << 20
	maxFile    = 1 << 20
	maxEntries = 200000
)

var (
	versionRE = regexp.MustCompile(`^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,4}$`)
	srcVerRE  = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)
	shaRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
	cveRE     = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)
	tagRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	requestRE = regexp.MustCompile(`^[ -~]{1,200}$`)
)

// allowedKeys are the only top-level keys of a template that goes in: a fail-closed list, so a protocol or feature of a newer
// nuclei is left out until someone decides on it.
var allowedKeys = []string{"id", "info", "variables", "http", "tcp", "ssl"}

func main() {
	srcVersion := flag.String("src-version", "", "version of nuclei-templates to build from, e.g. 10.5.1 (deploy/containers/pins.env)")
	srcSHA := flag.String("src-sha256", "", "SHA-256 of that version's tag archive (deploy/containers/pins.env)")
	version := flag.String("version", "", "version of the pack, AAAA.M.N (deploy/containers/pins.env)")
	in := flag.String("in", "", "build from this unpacked local folder instead of downloading (offline rebuilds, tests)")
	out := flag.String("out", "deploy/containers/scan-base/pack", "folder to write: templates/ and index.json; must be empty or new")
	flag.Parse()
	if err := run(*srcVersion, *srcSHA, *version, *in, *out); err != nil {
		fmt.Fprintln(os.Stderr, "scanpack:", err)
		os.Exit(1)
	}
}

func run(srcVersion, srcSHA, version, in, out string) error {
	src := in
	if src == "" {
		if !srcVerRE.MatchString(srcVersion) || !shaRE.MatchString(srcSHA) {
			return errors.New("-src-version and -src-sha256 are needed (or -in)")
		}
		raw, err := download(fmt.Sprintf(archiveURL, srcVersion))
		if err != nil {
			return err
		}
		tmp, err := os.MkdirTemp("", "scanpack-")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		if err := unpack(raw, srcSHA, tmp); err != nil {
			return err
		}
		src = tmp
	}
	rep, err := build(src, out, version)
	if err != nil {
		return err
	}
	fmt.Printf("scanpack: %d templates kept, per set: %v, left out: %v\n", rep.Kept, rep.Sets, rep.Left)
	return nil
}

// download reads the archive over HTTPS from GitHub only (the tag URL redirects to codeload.github.com).
func download(u string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c := &http.Client{CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		if r.URL.Scheme != "https" || (r.URL.Host != "github.com" && r.URL.Host != "codeload.github.com") {
			return fmt.Errorf("redirect to %s refused", (&url.URL{Scheme: r.URL.Scheme, Host: r.URL.Host}).String())
		}
		return nil
	}}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxArchive+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxArchive {
		return nil, errors.New("download: archive over the size cap")
	}
	return raw, nil
}

// unpack checks the archive against its pinned SHA-256 and writes its .yaml files, without the archive's top folder, into dir.
// Anything that is not a plain file or folder (a link, a device) refuses the whole archive: a pack made from a tree with links is
// not one the worker would accept.
func unpack(raw []byte, wantSHA, dir string) error {
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != wantSHA {
		return fmt.Errorf("unpack: the archive hashes to %x, not the pinned %s", h, wantSHA)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("unpack: %w", err)
	}
	tr := tar.NewReader(zr)
	for n := 0; ; n++ {
		hd, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("unpack: %w", err)
		}
		if n > maxEntries {
			return errors.New("unpack: too many entries")
		}
		switch hd.Typeflag {
		case tar.TypeXGlobalHeader, tar.TypeXHeader, tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return fmt.Errorf("unpack: entry %q is not a plain file or folder", hd.Name)
		}
		_, rel, ok := strings.Cut(hd.Name, "/")
		if !ok || rel == "" || path.IsAbs(rel) || path.Clean(rel) != rel || rel == ".." || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") {
			return fmt.Errorf("unpack: path %q leaves the archive's folder", hd.Name)
		}
		if !strings.HasSuffix(rel, ".yaml") && rel != "LICENSE.md" { // the MIT notice travels with the templates
			continue
		}
		if hd.Size > maxFile { // a real template is a few KB; the biggest in the archive (a plugin list) is not a safe check, so it is skipped
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxFile+1))
		if err != nil || len(body) > maxFile {
			return fmt.Errorf("unpack: %q is unreadable or over %d bytes", hd.Name, maxFile)
		}
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(dst, body, 0o600); err != nil {
			return err
		}
	}
}

// Report says what a build did: how many templates went in and, by reason, how many .yaml files were left out.
type Report struct {
	Kept int
	Left map[string]int
	Sets map[string]int // templates per set (a template may be in two), and how many deep ones are generic
}

// build writes out/templates/<path> for every template that qualifies, and out/index.json. out must not hold anything yet.
func build(src, out, version string) (Report, error) {
	rep := Report{Left: map[string]int{}}
	if !versionRE.MatchString(version) {
		return rep, fmt.Errorf("version %q is not AAAA.M.N", version)
	}
	if ents, err := os.ReadDir(out); err == nil && len(ents) > 0 {
		return rep, fmt.Errorf("%s is not empty: a stale file would ship", out)
	}
	type kept struct {
		tpl  pack.Template
		body []byte
	}
	var all []kept
	var queue []reviewRow
	ids := map[string]bool{}
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".yaml") || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		body, err := os.ReadFile(p) //nolint:gosec // a developer tool: p is a regular file under src, which is the operator's argument or our own unpack
		if err != nil {
			return err
		}
		tpl, reason := qualify(rel, body)
		if reason == "" && ids[tpl.ID] {
			reason = "id"
		}
		// D-528 step 2: a KEV template out of the KEV set (left out, or only behind the tick) waits for a person
		// (docs/research/kev-review-queue.md)
		if (reason == "not reviewed" || reason == "state name" || reason == "" && !tpl.InKEV()) && kevCandidate(body) {
			queue = append(queue, queueRow(rel, body, reason))
		}
		if reason != "" {
			rep.Left[reason]++
			return nil
		}
		ids[tpl.ID] = true
		all = append(all, kept{tpl, body})
		return nil
	})
	if err != nil {
		return rep, err
	}
	if err := writeQueue(filepath.Join(out, "review-queue.md"), version, queue); err != nil {
		return rep, err
	}
	if n := rep.Left["stale review"]; n > 0 { // D-528 step 2: a reviewed template changed: a person reads it again before it ships
		return rep, fmt.Errorf("%d templates of reviewed.tsv changed since they were read (their sha256 differs): read them again and update the list", n)
	}
	if len(all) == 0 || len(all) > pack.MaxTemplates {
		return rep, fmt.Errorf("a pack has 1 to %d templates, this one %d", pack.MaxTemplates, len(all))
	}
	sort.Slice(all, func(i, j int) bool { return all[i].tpl.Path < all[j].tpl.Path })
	tpls := make([]pack.Template, len(all))
	for i := range all {
		tpls[i] = all[i].tpl
	}
	products := pack.ProductTags(tpls)
	label := sha256.New()
	_, _ = fmt.Fprintf(label, "%s\n", version) // a hash.Hash never fails to write
	ix := pack.Index{Version: version}
	rep.Sets = map[string]int{}
	for i := range all {
		k := &all[i]
		if k.tpl.Generic && slices.ContainsFunc(k.tpl.Tags, func(t string) bool { return products[t] }) {
			k.tpl.Generic = false // a tag names a product a technologies template detects: it runs when that product is found
		}
		mark := "" // the own_ip mark is part of what the label covers (review round 2 L2), and the sets (D-527)
		if k.tpl.OwnIP {
			mark = "\town_ip"
		}
		_, _ = fmt.Fprintf(label, "%s\t%s%s\t%s\n", k.tpl.Path, k.tpl.SHA256, mark, strings.Join(k.tpl.Sets, ","))
		for _, s := range k.tpl.Sets {
			rep.Sets[s]++
		}
		if k.tpl.Generic {
			rep.Sets["generic"]++
		}
		ix.Templates = append(ix.Templates, k.tpl)
		dst := filepath.Join(out, "templates", filepath.FromSlash(k.tpl.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return rep, err
		}
		if err := os.WriteFile(dst, k.body, 0o600); err != nil { // the Containerfile makes the tree world-readable (chmod -R a+rX)
			return rep, err
		}
	}
	if lic, err := os.ReadFile(filepath.Join(src, "LICENSE.md")); err == nil { //nolint:gosec // a developer tool: src is the operator's argument or our own unpack
		if err := os.WriteFile(filepath.Join(out, "LICENSE-nuclei-templates.md"), lic, 0o600); err != nil {
			return rep, err
		}
	}
	ix.SHA256 = hex.EncodeToString(label.Sum(nil))
	raw, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		return rep, err
	}
	raw = append(raw, '\n')
	if _, err := pack.Parse(raw); err != nil { // what core and the worker will read must be what they accept
		return rep, fmt.Errorf("the index does not pass the reader of core and the worker: %w", err)
	}
	if err := os.WriteFile(filepath.Join(out, "index.json"), raw, 0o600); err != nil {
		return rep, err
	}
	rep.Kept = len(all)
	return rep, nil
}

// qualify decides one file: the index entry with its sets, or the reason it is left out. A template is in the KEV set by the
// rule of D-125/D-520 (kevReason), and in the deep or disruptive set by the rule of D-527 (fullSet); the reason of a template in
// neither is the full rule's when the template sits in a folder of a full set, else the KEV rule's.
func qualify(rel string, body []byte) (pack.Template, string) {
	var zero pack.Template
	if !nucleiargv.ValidTemplatePath(rel) {
		return zero, "path"
	}
	if !pack.RunsUnderProtocols(rel) { // the folder rule of pack.Parse: a template there would fail the whole build
		return zero, "folder"
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil || doc == nil {
		return zero, "yaml"
	}
	for k := range doc {
		if !slices.Contains(allowedKeys, k) {
			return zero, "protocol"
		}
	}
	id, _ := doc["id"].(string)
	if !idRE.MatchString(id) {
		return zero, "id"
	}
	info, _ := doc["info"].(map[string]any)
	tags := tagsOf(info)
	if len(tags) == 0 { // a template is chosen and fenced by its tags: one without is not judged
		return zero, "tags"
	}
	cve := cveOf(info)
	req := requestOf(doc)
	if !requestRE.MatchString(req) {
		return zero, "request"
	}
	kr := kevReason(doc, body, tags, cve)
	fs, fr := fullSet(rel, doc, body, tags)
	if kr != "" && fs == "" {
		if fr != "dir" {
			return zero, fr
		}
		return zero, kr
	}
	if why, _ := changeReason(id, doc, body, tags); why != "" { // D-528, every set: no state change, no other destination, no third party
		return zero, why
	}
	// D-528 step 2: without the tick (the KEV set, the deep set) only a read-only GET or a reviewed template; a template whose
	// name says a change is in no set; any other goes behind the tick (disruptive) when it is of a full set, and waits for a reader
	sum := sha256.Sum256(body)
	ownIP := kr == "" && ownIPSafe(rel, doc, tags, body)
	switch why, _ := noTickReason(id, nameOf(info), rel, hex.EncodeToString(sum[:]), doc, ownIP); why {
	case "":
	case "not reviewed":
		kr = why
		if fs == pack.SetDeep {
			fs = pack.SetDisruptive
		}
		if fs == "" {
			return zero, why
		}
	default: // "state name": never at any depth; "stale review": the build stops
		return zero, why
	}
	var sets []string
	if kr == "" {
		sets = append(sets, pack.SetKEV)
	}
	if fs != "" {
		sets = append(sets, fs)
	}
	if kr != "" { // outside the KEV set the cve may be empty or the first of several
		cve = firstCVE(info)
	}
	t := pack.Template{ID: id, CVE: cve, Path: rel, SHA256: hex.EncodeToString(sum[:]), Tags: tags, Request: req, Sets: sets, OwnIP: ownIP}
	if fs != "" {
		t.Name, t.Severity = nameOf(info), severityOf(info)
		t.Generic = fs == pack.SetDeep && genericDir(rel) && !namesProduct(info)
	}
	return t, ""
}

// kevReason is the KEV rule of D-125 (unchanged by D-527): the KEV tags, no forbidden or oast tag, no interactsh, no fuzzing,
// payloads or race, and exactly one CVE. "" when the template is in the KEV set.
func kevReason(doc map[string]any, body []byte, tags []string, cve string) string {
	switch {
	case hasUnsafeHTTP(doc):
		return "http feature"
	case strings.Contains(strings.ToLower(string(body)), "interactsh"):
		return "interactsh"
	case slices.ContainsFunc(tags, func(t string) bool { return slices.Contains(append(nucleiargv.ForbiddenTags(), "oast"), t) }):
		return "forbidden tag"
	case !slices.ContainsFunc(pack.SafeTags, func(s string) bool { return slices.Contains(tags, s) }):
		return "tags"
	case cve == "":
		return "cve"
	}
	return ""
}

// The folders of the full sets (D-527). deepDirs are the categories a deep external scan uses: nuclei's cves, vulnerabilities,
// exposures, misconfiguration, exposed-panels and technologies, plus cnvd (product vulnerabilities by their Chinese id, like cves),
// iot (the vulnerabilities of routers, cameras and NAS, what a home or office public IP shows), miscellaneous (directory listing,
// TRACE, security.txt: hardening notes) and on the network side cves, vulnerabilities, exposures, misconfig, detection (the service
// fingerprints), enumeration and backdoor, and every ssl template but the C2 fingerprints (protocol, cipher and certificate checks).
// Left out: osint, token-spray and credential-stuffing (they send to third-party sites or try credentials), takeovers (a DNS name,
// never an IP), fuzzing, honeypot, c2, jarm and global-matchers (threat intelligence and passive matchers, not the customer's
// exposure). disruptiveDirs are the default-login folders: they try passwords.
var (
	deepDirs = []string{"http/cves/", "http/cnvd/", "http/vulnerabilities/", "http/exposures/", "http/misconfiguration/", "http/exposed-panels/",
		"http/technologies/", "http/miscellaneous/", "http/iot/", "network/cves/", "network/vulnerabilities/", "network/exposures/",
		"network/misconfig/", "network/detection/", "network/enumeration/", "network/backdoor/", "ssl/"}
	notDeepDirs    = []string{"ssl/c2/"}
	disruptiveDirs = []string{"http/default-logins/", "network/default-login/"}
	// genericDirs are the categories whose templates a full job runs on every web port when they name no product.
	genericDirs = []string{"http/exposures/", "http/misconfiguration/", "http/exposed-panels/", "http/miscellaneous/"}
)

func under(rel string, dirs []string) bool {
	return slices.ContainsFunc(dirs, func(d string) bool { return strings.HasPrefix(rel, d) })
}

func genericDir(rel string) bool { return under(rel, genericDirs) }

// fullKeys are the keys of an http block that turn a check into fuzzing, parallel or pipelined traffic: never at any depth.
var fullKeys = []string{"fuzzing", "race", "race_count", "pipeline", "threads"}

// maxPayloadValues bounds the requests a payload list may make: the product of the lengths of a block's inline lists.
const maxPayloadValues = 64

var (
	// credKeyRE is a payload name that holds user names or passwords: the template tries to log in with them (review FULL-4b r1 M2).
	credKeyRE = regexp.MustCompile(`(?i)pass|pwd|user|login|cred`)
	// credTags mark a template that logs in with known credentials.
	credTags = []string{"hardcoded-credentials", "default-credentials", "default-credential", "weak-credentials"}
)

// fullSet is the D-527 rule: the set of a template at full depth (SetDeep or SetDisruptive) with "", or "" with the reason it is
// left out. Always out: a folder of no full set ("dir"), the tags intrusive, fuzz and oast and any use of an out-of-band server (a
// third party), a file pack.FullText refuses (the worker's own check), fuzzing, race, pipeline and thread keys, a payload read from a
// file (it is not in the pack) or a list of more than maxPayloadValues requests, and a request method pack.MethodOK refuses; the
// D-528 rule (changeReason) applies after. Disruptive: a default-login folder, a tag of nucleiargv.DisruptiveTags (dos, brute-force,
// default-login, authenticated) or credTags, or payloads named like user names or passwords (credKeyRE).
func fullSet(rel string, doc map[string]any, body []byte, tags []string) (string, string) {
	disruptive := under(rel, disruptiveDirs)
	if !disruptive && (!under(rel, deepDirs) || under(rel, notDeepDirs)) {
		return "", "dir"
	}
	if slices.ContainsFunc(tags, func(t string) bool { return t == "intrusive" || t == "fuzz" || t == "oast" }) {
		return "", "forbidden tag"
	}
	if pack.NeedsOAST(body) { // a matcher that only names interactsh (tech-detect) is no use of it
		return "", "interactsh"
	}
	if pack.FullText(body, strings.HasPrefix(rel, "http/technologies/")) != nil { // the worker's own check must pass (D-527, D-528)
		return "", "full text"
	}
	creds := slices.ContainsFunc(tags, func(t string) bool { return slices.Contains(credTags, t) })
	for _, key := range []string{"http", "tcp", "ssl"} {
		blocks, _ := doc[key].([]any)
		for _, b := range blocks {
			m, ok := b.(map[string]any)
			if !ok {
				return "", "yaml"
			}
			if slices.ContainsFunc(fullKeys, func(k string) bool { _, has := m[k]; return has }) {
				return "", "http feature"
			}
			if meth, has := m["method"]; has {
				ms, _ := meth.(string)
				if !pack.MethodOK(strings.ToUpper(ms)) {
					return "", "method"
				}
			}
			raws, _ := m["raw"].([]any)
			for _, r := range raws {
				rs, _ := r.(string)
				if f := strings.Fields(firstLine(rs)); len(f) == 0 || !pack.MethodOK(f[0]) {
					return "", "method"
				}
			}
			if p, has := m["payloads"]; has {
				if !payloadsInline(p) {
					return "", "payloads"
				}
				for k := range p.(map[string]any) { // review FULL-4b r1 M2: a list of user names or passwords is a login attempt
					creds = creds || credKeyRE.MatchString(k)
				}
			}
		}
	}
	if disruptive || creds || slices.ContainsFunc(tags, func(t string) bool { return slices.Contains(nucleiargv.DisruptiveTags(), t) }) {
		return pack.SetDisruptive, ""
	}
	return pack.SetDeep, ""
}

// firstLine is the request line of a raw request: its first line that is not blank or an @ annotation.
func firstLine(raw string) string {
	for _, l := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "@") {
			return l
		}
	}
	return ""
}

// payloadsInline says whether every payload of a block is an inline list (a string names a file, which is not in the pack) and
// together they make at most maxPayloadValues requests.
func payloadsInline(p any) bool {
	m, ok := p.(map[string]any)
	if !ok {
		return false
	}
	n := 1
	for _, v := range m {
		l, ok := v.([]any)
		if !ok || len(l) == 0 {
			return false
		}
		n *= len(l)
		if n > maxPayloadValues {
			return false
		}
	}
	return true
}

// nameOf is info.name as one printable ASCII line: other runes become "?", cut at 120 bytes.
func nameOf(info map[string]any) string {
	s, _ := info["name"].(string)
	b := []byte(strings.TrimSpace(s))
	for i, c := range b {
		if c < ' ' || c > '~' {
			b[i] = '?'
		}
	}
	if len(b) > 120 {
		b = b[:120]
	}
	if len(b) == 0 {
		return "unnamed"
	}
	return string(b)
}

// severityOf is info.severity when it is one of nuclei's, else "unknown".
func severityOf(info map[string]any) string {
	s, _ := info["severity"].(string)
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "info", "low", "medium", "high", "critical":
		return s
	}
	return "unknown"
}

// namesProduct says whether the template's metadata names a vendor or a product.
func namesProduct(info map[string]any) bool {
	md, _ := info["metadata"].(map[string]any)
	return md["vendor"] != nil || md["product"] != nil
}

// firstCVE is the first CVE id of info.classification.cve-id, "" when there is none: a deep entry keeps it so a job of that CVE
// finds it (pack.FullForCVE).
func firstCVE(info map[string]any) string {
	cls, _ := info["classification"].(map[string]any)
	var ids []string
	switch v := cls["cve-id"].(type) {
	case string:
		ids = strings.Split(v, ",")
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				ids = append(ids, s)
			}
		}
	}
	for _, id := range ids {
		if id = strings.ToUpper(strings.TrimSpace(id)); cveRE.MatchString(id) {
			return id
		}
	}
	return ""
}

// ownIPKeys are the keys of an http block an own_ip template may have: the request (raw, or path with method and headers) and
// how its answer is read. Anything else (body, payloads, digest credentials, unsafe raw sockets, a newer feature) is not judged
// and so not allowed.
var ownIPKeys = []string{"raw", "path", "method", "headers", "matchers", "matchers-condition", "extractors", "stop-at-first-match",
	"redirects", "host-redirects", "max-redirects", "cookie-reuse", "req-condition", "max-size", "read-all", "disable-path-automerge",
	"skip-variables-check", "iterate-all", "id", "name"}

// credName is a header or variable name that carries a credential.
var credName = regexp.MustCompile(`(?i)auth|cookie|token|key|session|secret|pass|user|login|cred`)

// ownIPSafe is the D-520 decision for one template that qualified: may it run on the box's own public IP? Conservative (the lead's
// rule): only http checks under http/, every request GET or HEAD with no body (raw requests read line by line, path requests by
// their method key), no header or variable that carries a credential, no injection-shaped payload in a request target or header
// value (pack.RequestPayloadOK), no refused tag (pack.OwnIPRefusedTag), and the file passes the worker's own text check
// (pack.OwnIPText), so the worker never refuses what the builder allowed.
func ownIPSafe(rel string, doc map[string]any, tags []string, body []byte) bool {
	if !strings.HasPrefix(rel, "http/") || doc["tcp"] != nil || doc["ssl"] != nil || slices.ContainsFunc(tags, pack.OwnIPRefusedTag) || pack.OwnIPText(body) != nil {
		return false
	}
	if vars, ok := doc["variables"].(map[string]any); ok {
		for k := range vars {
			if credName.MatchString(k) {
				return false
			}
		}
	} else if doc["variables"] != nil {
		return false
	}
	blocks, _ := doc["http"].([]any)
	if len(blocks) == 0 {
		return false
	}
	for _, b := range blocks {
		m, ok := b.(map[string]any)
		if !ok {
			return false
		}
		for k := range m {
			if !slices.Contains(ownIPKeys, k) {
				return false
			}
		}
		if h, has := m["headers"]; has {
			hm, ok := h.(map[string]any)
			if !ok {
				return false
			}
			for k, v := range hm {
				vs, _ := v.(string)
				if credName.MatchString(k) || pack.RequestPayloadOK(vs) != nil {
					return false
				}
			}
		}
		raws, hasRaw := m["raw"].([]any)
		paths, hasPath := m["path"].([]any)
		switch {
		case hasRaw == hasPath: // exactly one way of making requests
			return false
		case hasPath:
			for _, p := range paths {
				ps, ok := p.(string)
				if !ok || pack.RequestPayloadOK(ps) != nil { // review round 2 M1: no injection-shaped payload in a GET
					return false
				}
			}
			if meth, has := m["method"]; has {
				ms, _ := meth.(string)
				if !strings.EqualFold(ms, "GET") && !strings.EqualFold(ms, "HEAD") {
					return false
				}
			}
		default:
			if _, has := m["method"]; has {
				return false
			}
			for _, r := range raws {
				rs, ok := r.(string)
				if !ok || !rawGetOnly(rs) {
					return false
				}
			}
		}
	}
	return true
}

// rawGetOnly reads one raw request: its request line (after any @ annotations) is GET or HEAD, no header carries a credential,
// and nothing follows the blank line that ends the headers.
func rawGetOnly(r string) bool {
	lines := strings.Split(strings.ReplaceAll(r, "\r\n", "\n"), "\n")
	i := 0
	for i < len(lines) && (strings.TrimSpace(lines[i]) == "" || strings.HasPrefix(strings.TrimSpace(lines[i]), "@")) {
		i++
	}
	if i == len(lines) {
		return false
	}
	f := strings.Fields(lines[i])
	if len(f) < 2 || f[0] != "GET" && f[0] != "HEAD" || pack.RequestPayloadOK(f[1]) != nil {
		return false
	}
	for i++; i < len(lines) && strings.TrimSpace(lines[i]) != ""; i++ {
		name, value, ok := strings.Cut(lines[i], ":")
		if !ok || credName.MatchString(name) || pack.RequestPayloadOK(strings.TrimSpace(value)) != nil {
			return false
		}
	}
	for ; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "" {
			return false // a body
		}
	}
	return true
}

// unsafeHTTPKeys are the keys of an http block that turn one check into many requests or into attack traffic: fuzzing, payload
// lists with an attack mode, and race conditions (parallel requests). A pack check sends what its request line says, once.
var unsafeHTTPKeys = []string{"fuzzing", "payloads", "attack", "race", "race_count", "pipeline", "threads"}

func hasUnsafeHTTP(doc map[string]any) bool {
	blocks, _ := doc["http"].([]any)
	for _, b := range blocks {
		m, _ := b.(map[string]any)
		for _, k := range unsafeHTTPKeys {
			if _, has := m[k]; has {
				return true
			}
		}
	}
	return false
}

// tagsOf reads info.tags (a comma list or a YAML list), lower-cased; a tag the index would refuse is dropped, which cannot hide a
// forbidden tag because all of those are valid tags.
func tagsOf(info map[string]any) []string {
	var raw []string
	switch v := info["tags"].(type) {
	case string:
		raw = strings.Split(v, ",")
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				raw = append(raw, s)
			}
		}
	}
	var out []string
	for _, t := range raw {
		t = strings.ToLower(strings.TrimSpace(t))
		if tagRE.MatchString(t) && !slices.Contains(out, t) && len(out) < 32 {
			out = append(out, t)
		}
	}
	return out
}

// cveOf is the one CVE the template confirms; "" when there is none or more than one.
func cveOf(info map[string]any) string {
	cls, _ := info["classification"].(map[string]any)
	var ids []string
	switch v := cls["cve-id"].(type) {
	case string:
		ids = strings.Split(v, ",")
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				ids = append(ids, s)
			}
		}
	}
	if len(ids) != 1 {
		return ""
	}
	id := strings.ToUpper(strings.TrimSpace(ids[0]))
	if !cveRE.MatchString(id) {
		return ""
	}
	return id
}

// requestOf is the first request line of the template for the probe log (what is sent, shown before it is sent). The first block
// that exists decides: http (the first line of a raw request, else the method and first path), tcp (the address and the first
// bytes of the first input), ssl (the address).
func requestOf(doc map[string]any) string {
	first := func(key string) map[string]any {
		l, _ := doc[key].([]any)
		if len(l) == 0 {
			return nil
		}
		m, _ := l[0].(map[string]any)
		return m
	}
	var line string
	switch {
	case first("http") != nil:
		h := first("http")
		if raw, _ := h["raw"].([]any); len(raw) > 0 {
			s, _ := raw[0].(string)
			for _, l := range strings.Split(s, "\n") {
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "@") {
					line = l
					break
				}
			}
		} else if paths, _ := h["path"].([]any); len(paths) > 0 {
			method, _ := h["method"].(string)
			if method == "" {
				method = "GET"
			}
			p, _ := paths[0].(string)
			line = method + " " + p
		}
	case first("tcp") != nil:
		t := first("tcp")
		host := "{{Hostname}}"
		if hs, _ := t["host"].([]any); len(hs) > 0 {
			host, _ = hs[0].(string)
		}
		line = fmt.Sprintf("TCP %s:%v", host, t["port"])
		if in, _ := t["inputs"].([]any); len(in) > 0 {
			if m, _ := in[0].(map[string]any); m != nil {
				if d, _ := m["data"].(string); d != "" {
					line += " " + strings.TrimSpace(strings.SplitN(d, "\n", 2)[0])
				}
			}
		}
	case first("ssl") != nil:
		addr, _ := first("ssl")["address"].(string)
		line = "SSL " + addr
	}
	if len(line) > 200 {
		line = line[:200]
	}
	return line
}
