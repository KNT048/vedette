package exposure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	zapdata "github.com/knt048/vedette/content/zap"
	"github.com/knt048/vedette/core/store"
)

// Vedette's ZAP rule list and the versions ZAP reads (D-565, CONTRACT INV-24). content/zap/vedette-baseline.conf is the one list:
// the host hands it to ZAP with -c, and exposure applies it itself when it reads a report (so it holds before -c is wired, and on
// snapshots stored before it): an IGNORE rule's alert is dropped, a FAIL rule's alert is "Fix this" (shown first), any other alert is
// "Hardening" with ZAP's own risk, except that an unlisted rule ZAP rates high or medium is "Fix this". Three rules carry a version: 10003 (a JavaScript library and the CVEs Retire.js lists for it),
// 10036 (the Server header) and 10037 (X-Powered-By). Those versions are compared with today's exploited CVEs when a snapshot is read.

// WebSoftware is a product and version ZAP read on a page (WebFindingRow.Software). All of it came from the scanned server, so it is
// kept only when it passes the strict patterns below.
type WebSoftware struct {
	Product string   `json:"product"` // "jquery", "Apache", "PHP"
	Version string   `json:"version"` // "3.4.1", "2.4.49", "1.1.1d"
	CVEs    []string `json:"cves"`    // 10003: the CVEs Retire.js lists for that version; [] for a header
	Distro  string   `json:"distro"`  // a header that names its distribution ("Apache/2.4.41 (Ubuntu)"); "" when none
}

// The web finding groups (WebFindingRow.Group).
const (
	webGroupFix       = "fix"       // a FAIL rule of the list, or an unlisted rule ZAP rates high or medium
	webGroupHardening = "hardening" // a WARN rule, or an unlisted rule ZAP rates low or info
)

const (
	ruleJSLibrary    = "10003"
	ruleServerHeader = "10036"
	rulePoweredBy    = "10037"

	maxWebSoftware  = 4   // products kept per alert
	maxWebCVEs      = 32  // CVEs kept per JavaScript library
	maxZapInstances = 100 // instances of one alert read for versions
	maxZapEvidence  = 2000
)

var (
	zapRules  = mustZapRules(zapdata.Baseline)
	headerCPE = mustHeaderCPE(zapdata.HeaderCPE)

	softwareRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,59}$`)
	versionRE   = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]{0,31}$`)
	cveInTextRE = regexp.MustCompile(`\bCVE-(?:19|20)[0-9]{2}-[0-9]{4,7}\b`)
	// Retire.js's sentence in ZAP's otherinfo (retire add-on, retire.rule.otherinfo): "The identified library {0}, version {1} is vulnerable."
	retireRE = regexp.MustCompile(`The identified library ([A-Za-z0-9][A-Za-z0-9._-]{0,59}), version ([0-9][0-9A-Za-z.+-]{0,31}) is vulnerable`)
	// One product/version token of a Server or X-Powered-By header ("Apache/2.4.49", "PHP/7.4.3", "OpenSSL/1.1.1d"), with the package
	// suffix a distribution build adds ("PHP/7.4.3-4ubuntu2.24", "PHP/8.2.7-1~deb12u1"): the upstream version is compared, and the
	// distribution it names marks the match as maybe backported.
	headerTokenRE = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_-]{0,39})/([0-9]{1,4}(?:\.[0-9]{1,6}){0,3}[a-z]?)(?:-([0-9A-Za-z.+~]{1,40}))?$`)
	// The distribution a package suffix names: Ubuntu's "ubuntu", Debian's "deb" (and "+deb", "~deb"), Red Hat's "el8".
	suffixDistro = []struct {
		re     *regexp.Regexp
		distro string
	}{{regexp.MustCompile(`ubuntu`), "Ubuntu"}, {regexp.MustCompile(`deb[0-9]`), "Debian"}, {regexp.MustCompile(`(^|[.+~_])el[0-9]`), "Red Hat"}}
)

// mustZapRules reads the embedded list; a broken file (content/zap TestBaseline_IsZAPConfig fails on it) applies no rule.
func mustZapRules(data []byte) map[string]string {
	rules, err := zapdata.Parse(data)
	out := map[string]string{}
	if err != nil {
		return out
	}
	for id, st := range rules {
		out[strconv.Itoa(id)] = st
	}
	return out
}

func mustHeaderCPE(data []byte) map[string]string {
	out := map[string]string{}
	if json.Unmarshal(data, &out) != nil {
		return map[string]string{}
	}
	delete(out, "_about")
	return out
}

// webGroup is the group of an alert of rule pluginID with ZAP's risk, and keep is false for an IGNORE rule. A rule the list does not
// name (a rule the list missed, or one a newer ZAP added) is "fix" when ZAP rates it high or medium: never "hardening" with a High
// chip on it (review r1 M2).
func webGroup(pluginID, risk string) (group string, keep bool) {
	switch zapRules[pluginID] {
	case zapdata.Ignore:
		return "", false
	case zapdata.Fail:
		return webGroupFix, true
	case zapdata.Warn:
		return webGroupHardening, true
	}
	if risk == "high" || risk == "medium" {
		return webGroupFix, true
	}
	return webGroupHardening, true
}

// sortWebGroups puts "Fix this" first, then the highest risk first inside each group (stable otherwise).
func sortWebGroups(rows []WebFindingRow) {
	slices.SortStableFunc(rows, func(a, b WebFindingRow) int {
		if a.Group != b.Group {
			if a.Group == webGroupFix {
				return -1
			}
			if b.Group == webGroupFix {
				return 1
			}
		}
		return slices.Index(zapRisks, b.Risk) - slices.Index(zapRisks, a.Risk)
	})
}

// parseZAPWithRules is ParseZAPReport with the rule list applied (D-565): IGNORE alerts dropped, each row's group set, the versions of
// 10003, 10036 and 10037 read, "Fix this" first. A report ParseZAPReport refuses is refused the same way.
func parseZAPWithRules(raw []byte, page string) ([]WebFindingRow, error) {
	rows, err := ParseZAPReport(raw, page)
	if err != nil {
		return nil, err
	}
	soft := zapSoftware(raw, page, len(rows))
	out := []WebFindingRow{}
	for i, r := range rows {
		g, keep := webGroup(r.PluginID, r.Risk)
		if !keep {
			continue
		}
		r.Group, r.Software = g, []WebSoftware{}
		if soft != nil {
			r.Software = soft[i]
		}
		out = append(out, r)
	}
	sortWebGroups(out)
	return out, nil
}

// zapExtras is the part of a ZAP report that carries versions; ParseZAPReport has already checked the rest.
type zapExtras struct {
	Site []struct {
		Name   string `json:"@name"`
		Alerts []struct {
			PluginID   zapNum `json:"pluginid"`
			Confidence zapNum `json:"confidence"`
			OtherInfo  string `json:"otherinfo"`
			Reference  string `json:"reference"`
			Evidence   string `json:"evidence"`
			Instances  []struct {
				OtherInfo string `json:"otherinfo"`
				Evidence  string `json:"evidence"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

// zapSoftware returns the software of each row ParseZAPReport made from raw, in the same order (it walks the same alerts of the same
// site and skips the same false positives), or nil when that does not line up: then no version is read, nothing else changes.
func zapSoftware(raw []byte, page string, n int) [][]WebSoftware {
	var rep zapExtras
	want, ok := pageKey(page)
	if !ok || json.Unmarshal(raw, &rep) != nil {
		return nil
	}
	out := [][]WebSoftware{}
	for _, site := range rep.Site {
		if k, ok := pageKey(site.Name); !ok || k != want {
			continue
		}
		for _, a := range site.Alerts {
			if a.Confidence == 0 {
				continue
			}
			var sw []WebSoftware
			id := strconv.Itoa(int(a.PluginID))
			switch id {
			case ruleJSLibrary:
				texts := []string{a.OtherInfo}
				for i, in := range a.Instances {
					if i < maxZapInstances {
						texts = append(texts, in.OtherInfo)
					}
				}
				sw = retireSoftware(texts, a.Reference)
			case ruleServerHeader, rulePoweredBy:
				texts := []string{a.Evidence}
				for i, in := range a.Instances {
					if i < maxZapInstances {
						texts = append(texts, in.Evidence)
					}
				}
				sw = headerSoftware(texts)
			}
			out = append(out, cleanSoftware(id, sw))
		}
	}
	if len(out) != n {
		return nil
	}
	return out
}

// retireSoftware reads Retire.js's library, version and CVEs from the otherinfo texts of a 10003 alert (one per instance: the alert
// groups every script that matched). The CVEs of the reference text count only when the alert names one library.
func retireSoftware(texts []string, reference string) []WebSoftware {
	var out []WebSoftware
	for _, t := range texts {
		if len(t) > maxZapEvidence*4 {
			continue
		}
		m := retireRE.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		out = addSoftware(out, WebSoftware{Product: m[1], Version: m[2], CVEs: cveInTextRE.FindAllString(t, maxWebCVEs)})
	}
	if len(out) == 1 && len(reference) <= maxZapEvidence*4 {
		out[0].CVEs = append(out[0].CVEs, cveInTextRE.FindAllString(reference, maxWebCVEs)...)
	}
	return out
}

// headerSoftware reads the product/version tokens of the evidence of a 10036 or 10037 alert ("Apache/2.4.49 (Unix) OpenSSL/1.1.1d",
// "X-Powered-By: PHP/7.4.3"), with the distribution the header names, if any.
func headerSoftware(texts []string) []WebSoftware {
	var out []WebSoftware
	for _, t := range texts {
		if t == "" || len(t) > maxZapEvidence {
			continue
		}
		distro := ""
		for _, d := range distros {
			if strings.Contains(strings.ToLower(t), strings.ToLower(d)) {
				distro = d
				break
			}
		}
		for _, tok := range strings.FieldsFunc(t, func(r rune) bool { return strings.ContainsRune(" \t();,:[]\"'", r) }) {
			m := headerTokenRE.FindStringSubmatch(tok)
			if m == nil {
				continue
			}
			d := distro
			if m[3] != "" { // a distribution build: compared by its upstream version only when the suffix names the distribution
				d = ""
				for _, x := range suffixDistro {
					if x.re.MatchString(strings.ToLower(m[3])) {
						d = x.distro
						break
					}
				}
				if d == "" {
					continue
				}
			}
			out = addSoftware(out, WebSoftware{Product: m[1], Version: m[2], CVEs: []string{}, Distro: d})
		}
	}
	return out
}

// addSoftware adds w, or merges its CVEs into the entry of the same product and version.
func addSoftware(l []WebSoftware, w WebSoftware) []WebSoftware {
	for i, x := range l {
		if strings.EqualFold(x.Product, w.Product) && x.Version == w.Version {
			l[i].CVEs = append(l[i].CVEs, w.CVEs...)
			return l
		}
	}
	return append(l, w)
}

// cleanSoftware is the one check a WebSoftware passes, when it is read from a report and again when a snapshot is read: only the three
// rules carry software, at most maxWebSoftware, each product and version strict, CVEs well-formed, unique and sorted, a distribution
// only one of distros. It never returns nil.
func cleanSoftware(pluginID string, in []WebSoftware) []WebSoftware {
	out := []WebSoftware{}
	if pluginID != ruleJSLibrary && pluginID != ruleServerHeader && pluginID != rulePoweredBy {
		return out
	}
	for _, w := range in {
		if len(out) == maxWebSoftware {
			break
		}
		if !softwareRE.MatchString(w.Product) || !versionRE.MatchString(w.Version) || (w.Distro != "" && !slices.Contains(distros, w.Distro)) {
			continue
		}
		cves := []string{}
		if pluginID == ruleJSLibrary {
			for _, c := range w.CVEs {
				if cveRE.MatchString(c) && !slices.Contains(cves, c) && len(cves) < maxWebCVEs {
					cves = append(cves, c)
				}
			}
			slices.Sort(cves)
		}
		out = append(out, WebSoftware{Product: w.Product, Version: w.Version, CVEs: cves, Distro: w.Distro})
	}
	return out
}

// webOnRead applies today's rule list to the web findings of a snapshot as it is read, also one stored before the list existed:
// IGNORE alerts dropped (dropped counts them), group set, software checked again, "Fix this" first.
func webOnRead(rows []WebFindingRow) (out []WebFindingRow, dropped int) {
	out = []WebFindingRow{}
	for _, r := range rows {
		g, keep := webGroup(r.PluginID, r.Risk)
		if !keep {
			dropped++
			continue
		}
		r.Group, r.Software = g, cleanSoftware(r.PluginID, r.Software)
		out = append(out, r)
	}
	sortWebGroups(out)
	return out, dropped
}

// The lines of the version comparison of the web scan (INV-24, D-565).
const (
	notWebVersionsMatcher = "Versions ZAP read on the web pages were not compared with exploited vulnerabilities: the comparison is not set up on this box yet."
	notWebVersionsFail    = "Versions ZAP read on the web pages could not be compared with the list of exploited vulnerabilities. Try again later."
)

// withWebVersions applies the rule list to the snapshot's web findings and compares the versions ZAP read with today's exploited CVEs
// (D-565), when the snapshot is read, like withVulns. A CVE Retire.js names for a JavaScript library that CISA lists is a VulnRow with
// basis "js_library"; a product and version of a Server or X-Powered-By header go through the Matcher like a service nmap identified,
// unless nmap already read a version of that product on that port. A row never replaces one already there for the same address, port
// and CVE. A failed comparison is a "Not checked" line, never "no exploited CVE".
func (s *Service) withWebVersions(ctx context.Context, snap *Snapshot) {
	var dropped int
	snap.WebFindings, dropped = webOnRead(snap.WebFindings)
	if dropped > 0 { // a snapshot stored before the list: its "web" line counted alerts that are no longer shown (review r1 L6)
		snap.Checks = slices.Clone(snap.Checks)
		for i, c := range snap.Checks {
			if c.Kind == "web" {
				snap.Checks[i].Text = clipText(c.Text+fmt.Sprintf(" %d of them hidden: Vedette's rule list treats them as noise.", dropped), maxLineText)
				break
			}
		}
	}
	type hit struct {
		host   string
		port   int
		header string // "Server" or "X-Powered-By"; "" for a JavaScript library
		w      WebSoftware
	}
	var js, hdr []hit
	for _, r := range snap.WebFindings {
		host, port, ok := siteHostPort(r.Site)
		if !ok {
			continue
		}
		for _, w := range r.Software {
			switch r.PluginID {
			case ruleJSLibrary:
				if len(w.CVEs) > 0 {
					js = append(js, hit{host: host, port: port, w: w})
				}
			case ruleServerHeader, rulePoweredBy:
				base := headerCPE[strings.ToLower(w.Product)]
				if base == "" || nmapRead(snap.Services, host, port, base) {
					continue
				}
				h := map[string]string{ruleServerHeader: "Server", rulePoweredBy: "X-Powered-By"}[r.PluginID]
				hdr = append(hdr, hit{host: host, port: port, header: h, w: w})
			}
		}
	}
	if len(js)+len(hdr) == 0 {
		return
	}
	if s.cfg.Matcher == nil {
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "cve", Text: notWebVersionsMatcher})
		return
	}
	have := map[string]bool{}
	for _, v := range snap.Vulns {
		have[fmt.Sprintf("%s:%d:%s", v.IP, v.Port, v.CVE)] = true
	}
	add := func(v VulnRow) bool {
		k := fmt.Sprintf("%s:%d:%s", v.IP, v.Port, v.CVE)
		if have[k] {
			return false
		}
		have[k] = true
		snap.Vulns = append(snap.Vulns, v)
		return true
	}
	matched, failed := 0, "" // failed: the "Not checked" line of a comparison that did not run
	if len(js) > 0 {
		var listed map[string]KEVEntry // ExploitedLookup (greenbone.go): the CVEs Retire.js names that today's list carries (D-565)
		var err error
		look, ok := s.cfg.Matcher.(ExploitedLookup)
		if ok {
			var ids []string
			for _, h := range js {
				ids = append(ids, h.w.CVEs...)
			}
			slices.Sort(ids)
			listed, err = look.Exploited(ctx, slices.Compact(ids))
		}
		switch {
		case !ok:
			failed = notWebVersionsMatcher
		case err != nil:
			failed = s.webVersionsFailed(ctx, snap, err)
		}
		for _, h := range js {
			for _, c := range h.w.CVEs {
				v, ok := listed[c]
				if !ok {
					continue
				}
				if add(VulnRow{IP: h.host, Port: h.port, CVE: c, Name: clipText(v.Name, maxWebName), Basis: "js_library", DateAdded: v.DateAdded, Ransomware: v.Ransomware,
					Summary: jsSummary(h.port, h.w.Product, h.w.Version, c)}) {
					matched++
				}
			}
		}
	}
	for _, h := range hdr {
		row := ServiceRow{IP: h.host, Port: h.port, Name: "http", Product: h.w.Product, Version: h.w.Version, CPE: "cpe:/" + headerCPE[strings.ToLower(h.w.Product)] + ":" + h.w.Version, Extra: h.w.Distro}
		m, err := s.cfg.Matcher.Match(ctx, []ServiceRow{row})
		if err != nil {
			failed = s.webVersionsFailed(ctx, snap, err)
			break
		}
		var mine []VulnRow
		for _, v := range m.Vulns {
			v.Summary = strings.TrimSpace(v.Summary + " The version was seen in the " + h.header + " header by ZAP.")
			mine = append(mine, v)
		}
		markBackports(mine, []ServiceRow{row})
		for _, v := range mine {
			if add(v) {
				matched++
			}
		}
	}
	if failed != "" {
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "cve", Text: failed})
		return
	}
	snap.Checks = append(snap.Checks, CheckRow{Kind: "cve", At: store.FormatTS(s.clock()), Text: fmt.Sprintf(
		"Versions ZAP read on the web pages compared with today's CISA list of exploited vulnerabilities (%d from JavaScript libraries, %d from Server or X-Powered-By headers): %s.",
		len(js), len(hdr), plural(matched, "exploited CVE")+" matched")})
}

// jsSummary is the sentence of a js_library row (the mock's jsVulns in web/src/features/exposure/data.ts says the same). A library
// version is weaker evidence than a server version in range: it does not show the site calls the affected function, and the risk is
// to the visitors' browsers, not the server (review r1 M3).
func jsSummary(port int, product, version, cve string) string {
	return fmt.Sprintf("A page on port %d loads the JavaScript library %s %s (seen by ZAP). Retire.js lists %s for that version and CISA lists it as exploited. "+
		"A library version alone does not show that the site uses the affected function; the risk is to visitors' browsers, not the server. Update the library.", port, product, version, cve)
}

// webVersionsFailed is the "Not checked" line of a comparison that did not run: the reason of an *Unavailable as is (the Feeds module
// is off: trying again does not help), otherwise the error is logged and the line says to try again.
func (s *Service) webVersionsFailed(ctx context.Context, snap *Snapshot, err error) string {
	var un *Unavailable
	if errors.As(err, &un) {
		return "Versions ZAP read on the web pages were not compared with exploited vulnerabilities: " + clipText(un.Reason, 200)
	}
	s.cfg.Log.ErrorContext(ctx, "exposure: comparing the versions ZAP read with exploited vulnerabilities failed", "snapshot", snap.ID, "error", err)
	return notWebVersionsFail
}

// nmapRead says nmap -sV already read a version of the same product (the CPE's product part, so an alias vendor counts) on host:port.
func nmapRead(services []ServiceRow, host string, port int, base string) bool {
	product := base[strings.LastIndexByte(base, ':')+1:]
	for _, sv := range services {
		f := strings.Split(strings.TrimPrefix(strings.ToLower(sv.CPE), "cpe:/"), ":")
		if sv.IP == host && sv.Port == port && sv.Version != "" && len(f) >= 3 && f[2] == product {
			return true
		}
	}
	return false
}

// siteHostPort is the host and effective port of a scanned page (WebFindingRow.Site).
func siteHostPort(site string) (string, int, bool) {
	k, ok := pageKey(site)
	if !ok {
		return "", 0, false
	}
	u, err := url.Parse(k)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return u.Hostname(), port, true
}
