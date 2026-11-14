package exposure

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Safe checks for exploited vulnerabilities on the services identified on the box's own public IP (S-EXP-2, CONTRACT INV-23, D-561,
// plan exposure-real-vulns §5 slice b). After service identification and the comparison with the CISA list, the CVEs that matched a
// service are handed to a TemplateScanner (nuclei with the safe template set, in the scan container, owned by another module) for
// that port only. A template that matches turns the row's basis into "confirmed by template"; nothing else ever does.

// Limits and wording of the template step.
const (
	// TemplatesPerJob is the most CVE ids (so the most templates) one job carries; the scanner runs at most this many for it.
	TemplatesPerJob = 32
	// TemplateRPS is the request rate a job asks for; the scanner never goes above it (D-125/D-126 safe set).
	TemplateRPS = 5
	// ScopeOwnIP is the only scope a job has: the box's own verified public IP, the address and port of the job and nothing else.
	ScopeOwnIP = "own_ip"
	// TemplatesTimeout bounds the step, like ServicesTimeout.
	TemplatesTimeout = 5 * time.Minute

	maxTemplateJobs = 64
	maxTemplateRows = 128 // per service: TemplatesPerJob x 4 jobs; matched results are kept first
	maxTemplatesLn  = 6   // template ids named in the "what was checked" line

	// NotSetUpTemplates is the line of every scan of an IP while no TemplateScanner is wired.
	NotSetUpTemplates = "Not checked: safe exploited-vulnerability templates are not set up on this box yet."
	notTemplatesDom   = "Safe templates for exploited vulnerabilities: they run on the box's own verified public IP only, for the services identified there."
	notTemplatesNoSvc = "Safe templates for exploited vulnerabilities did not run: no services were identified."
	notTemplatesNoCmp = "Safe templates for exploited vulnerabilities did not run: the identified services could not be compared with the list of exploited vulnerabilities."
	notTemplatesGate  = "Safe templates for exploited vulnerabilities did not run: this IP can no longer be scanned (it was removed, paused, no longer verified or needs the scan confirmed again), so nothing was sent."
	notTemplatesNoLog = "Safe templates for exploited vulnerabilities did not run: the probe log could not be written, and nothing is sent without it."
	notTemplatesFail  = "Safe templates for exploited vulnerabilities failed, so no service was confirmed by them. The box log has the error."
	notTemplatesSlow  = "Safe templates for exploited vulnerabilities did not finish within 5 minutes, so the ones that had not finished are not reported."
)

// The outcomes of one template on one service.
const (
	OutcomeMatched = "matched"
	OutcomeNoMatch = "no_match"
	OutcomeError   = "error"
)

type (
	// TemplateJob is what the scanner is asked to check on one open port of the box's own IP: the exploited CVEs the comparison
	// matched there. The scanner runs the safe template of each of those CVEs that has one (at most TemplatesPerJob) and nothing
	// else: no template is chosen by tag, severity or banner words (D-561). Scheme is "http", "https" or "" (a service that is not web: the scanner decides or skips). Host
	// is the IP itself: never a name. Scope is always ScopeOwnIP and RPS at most TemplateRPS.
	TemplateJob struct {
		Port   int      `json:"port"`
		Scheme string   `json:"scheme"`
		Host   string   `json:"host"`
		CVEs   []string `json:"cves"`
		Scope  string   `json:"scope"`
		RPS    int      `json:"rps"`
	}
	// TemplateResult is what one template did on one port. CVE is the CVE the template is for (always one the job asked about).
	// It came from the scan container, so it is untrusted: sanitizeTemplateResults limits it.
	TemplateResult struct {
		Port     int
		Template string
		CVE      string
		Outcome  string // OutcomeMatched, OutcomeNoMatch or OutcomeError
	}
	// TemplateScan is the answer of one ScanTemplates: a result per template that ran. A CVE the scanner has no safe template
	// for has no result, which is not an error.
	TemplateScan struct {
		Results []TemplateResult
		// Sent are the ids of the templates the scanner logged and sent (one id per template, whatever its outcome).
		Sent []string
	}
	// TemplateRow is a TemplateResult as a service row keeps it.
	TemplateRow struct {
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		CVE      string `json:"cve"`
		Template string `json:"template"`
		Outcome  string `json:"outcome"`
	}
	// TemplateProbe is one request-to-be of the template step, for the probe log (LEGAL §3: target, time, template id).
	TemplateProbe struct {
		ID       string
		IP       string
		Label    string
		Template string
		Request  string
	}
)

// TemplateScanner runs safe nuclei templates for exploited CVEs on the box's own verified public IP (S-EXP-2). The scan calls it
// after service identification, only for an IP target that passed the gate of that run (INV-1, INV-13, the commitment sentence of
// D-559 K-4/K-5), only for the ports of jobs, and only after every probe is in the probe log. ip is that target. The implementation
// keeps its own fences (scope own_ip, the worker checks again that ip is the box's own egress, at most TemplateRPS requests a
// second, no template that sends a credential or changes anything, D-125/D-126, D-559 K-6). A step that could not run for a reason
// the page may show returns *Unavailable.
//
// Obligations of the implementation (D-561, LEGAL §3): (1) it re-runs the gate exactly as the service scanner does (ScannableIP with
// the actor ScanTarget.User) right before sending; (2) it resolves each CVE of a job to its template id in the verified index and
// writes a probe-log row with that template id, the target and the time BEFORE it sends the template, and returns the ids it sent
// in TemplateScan.Sent (exposure keeps them in the "what was checked" list); exposure's own pre-call rows name the CVEs planned,
// not templates sent; (3) it fills TemplateResult.CVE.
type TemplateScanner interface {
	ScanTemplates(ctx context.Context, t ScanTarget, ip netip.Addr, jobs []TemplateJob) (TemplateScan, error)
}

// ProbeLog keeps the probe log of the scan module (scan INV-7, 90 days). RecordTemplateProbes must have written the rows when it
// returns without an error; the step sends nothing when it fails.
type ProbeLog interface {
	RecordTemplateProbes(ctx context.Context, probes []TemplateProbe) error
}

var (
	cveID      = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)
	templateID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

// runTemplates is the template step of a scan of an IP, after service identification (INV-23). Only a stop of the run ends the scan
// here; every other outcome is a line of what was checked or not checked, and the rest of the result is kept.
func (s *Service) runTemplates(ctx context.Context, st ScanTarget, ip netip.Addr, c Content) (Content, error) {
	if s.cfg.Templates == nil {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "templates", Text: NotSetUpTemplates})
		return c, nil
	}
	if len(c.Services) == 0 {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "templates", Text: notTemplatesNoSvc})
		return c, nil
	}
	if s.cfg.Matcher == nil {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "templates", Text: notTemplatesNoCmp})
		return c, nil
	}
	m, err := s.cfg.Matcher.Match(ctx, c.Services)
	if err != nil {
		if ctx.Err() != nil {
			return c, err
		}
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "templates", Text: notTemplatesNoCmp})
		return c, nil
	}
	jobs, skipped := buildJobs(ip, c.Services, m.Vulns)
	if skipped > 0 {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "templates", Text: fmt.Sprintf("Safe templates for exploited vulnerabilities: %s were not run, over the limit of %d jobs a scan.", plural(skipped, "exploited CVE"), maxTemplateJobs)})
	}
	if len(jobs) == 0 {
		c.Checks = append(c.Checks, CheckRow{Kind: "templates", At: store.FormatTS(s.clock()),
			Text: "Safe templates for exploited vulnerabilities: none needed, no identified service matched an exploited CVE."})
		return c, nil
	}
	// M1: the gate of the run is minutes old (the runner and nmap came first): the target must still be verified, committed to the
	// sentence in force, not paused and still the box's own IP right before anything is logged or sent.
	if _, reason, gerr := s.gate(ctx, st.User, st.ID); gerr != nil || reason != "" {
		if ctx.Err() != nil {
			return c, ctx.Err()
		}
		if gerr != nil {
			s.cfg.Log.ErrorContext(ctx, "exposure: the gate before the template step failed", "target", st.Value, "error", gerr)
		} else {
			s.cfg.Log.InfoContext(ctx, "exposure: the template step was refused by the gate", "target", st.Value, "reason", string(reason))
		}
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "templates", Text: notTemplatesGate})
		return c, nil
	}
	if s.cfg.Probes == nil {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "templates", Text: notTemplatesNoLog})
		return c, nil
	}
	if err := s.cfg.Probes.RecordTemplateProbes(ctx, probesOf(ip, jobs)); err != nil { // LEGAL §3: logged before anything is sent
		if ctx.Err() != nil {
			return c, err
		}
		s.cfg.Log.ErrorContext(ctx, "exposure: writing the probe log of the template step failed", "target", st.Value, "error", err)
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "templates", Text: notTemplatesNoLog})
		return c, nil
	}
	tctx, cancel := context.WithTimeout(ctx, TemplatesTimeout)
	defer cancel()
	res, err := s.cfg.Templates.ScanTemplates(tctx, st, ip, jobs)
	var un *Unavailable
	switch {
	case err == nil:
		rows, notKept := sanitizeTemplateResults(res.Results, jobs)
		c.Templates = templateRows(c.Services, ip, rows)
		c.Checks = append(c.Checks, CheckRow{Kind: "templates", At: store.FormatTS(s.clock()), Text: templatesLine(jobs, rows, sentIDs(res.Sent), notKept)})
	case ctx.Err() != nil:
		return c, err
	case errors.As(err, &un):
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "templates", Text: "Safe templates for exploited vulnerabilities did not run: " + clipText(un.Reason, 200)})
	case tctx.Err() != nil:
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "templates", Text: notTemplatesSlow})
	default:
		s.cfg.Log.ErrorContext(ctx, "exposure: the safe templates failed", "target", st.Value, "error", err)
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "templates", Text: notTemplatesFail})
	}
	return c, nil
}

// buildJobs makes the jobs of a scan: one or more per port that has an exploited CVE, none for any other port, each with at most
// TemplatesPerJob CVEs. Ports come from the freshly identified services, never from a port an earlier scan saw (INV-22: kept rows are
// not probed).
func buildJobs(ip netip.Addr, services []ServiceRow, vulns []VulnRow) (jobs []TemplateJob, skipped int) {
	byPort := map[int][]string{}
	for _, v := range vulns {
		if v.IP == ip.String() && cveID.MatchString(v.CVE) {
			byPort[v.Port] = append(byPort[v.Port], v.CVE)
		}
	}
	ports := make([]int, 0, len(byPort))
	for p := range byPort {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	for _, p := range ports {
		var svc ServiceRow
		for _, x := range services {
			if x.IP == ip.String() && x.Port == p {
				svc = x
			}
		}
		if svc.Port == 0 { // a match on a port that was not identified: nothing to probe
			continue
		}
		cves := dedupe(byPort[p])
		sort.Strings(cves)
		for i := 0; i < len(cves); i += TemplatesPerJob {
			chunk := cves[i:min(i+TemplatesPerJob, len(cves))]
			if len(jobs) >= maxTemplateJobs {
				skipped += len(chunk)
				continue
			}
			jobs = append(jobs, TemplateJob{Port: p, Scheme: schemeOf(svc), Host: ip.String(), CVEs: chunk, Scope: ScopeOwnIP, RPS: TemplateRPS})
		}
	}
	return jobs, skipped
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// schemeOf says how to speak to a web service. nmap's XML keeps TLS in a separate tunnel="ssl" attribute that the sensor-active parser
// does not pass on (deferred: .ai/deferred/feat-exposure-kev-templates-mlee.md), so a TLS service arrives named just "http". Until it does:
// a name with "https" ("https", "https-alt") or the "ssl/http" nmap prints is https, and so is a web service on a well-known TLS port
// (443, 8443, 9443); any other web service is http, and a name that is not web is "".
func schemeOf(r ServiceRow) string {
	n := strings.ToLower(r.Name)
	switch {
	case strings.Contains(n, "https") || strings.HasPrefix(n, "ssl/http"):
		return "https"
	case strings.HasPrefix(n, "http"):
		if r.Port == 443 || r.Port == 8443 || r.Port == 9443 {
			return "https"
		}
		return "http"
	}
	return ""
}

// probesOf is the probe log of the step: one row per CVE to be checked (the CVE id names the template: nuclei names the template of a CVE
// after it), written before the scanner is called.
func probesOf(ip netip.Addr, jobs []TemplateJob) []TemplateProbe {
	var out []TemplateProbe
	add := func(port int, name string) {
		out = append(out, TemplateProbe{ID: store.NewID("tp"), IP: ip.String(), Label: fmt.Sprintf("%s:%d", ip, port), Template: "exposure: template " + name,
			Request: fmt.Sprintf("planned: asked the scanner to check %s with its safe template, if it has one, on %s:%d (own IP, at most %d requests a second)", name, ip, port, TemplateRPS)})
	}
	for _, j := range jobs {
		for _, c := range j.CVEs {
			add(j.Port, c)
		}
	}
	return out
}

// sanitizeTemplateResults keeps the results that belong to a job (its port, and its CVE when it names one), with ids and outcomes of
// the right shape, at most maxTemplateRows per port; others are dropped (the answer came from the scan container: untrusted).
func sanitizeTemplateResults(in []TemplateResult, jobs []TemplateJob) (out []TemplateResult, notKept int) {
	cves := map[int]map[string]bool{}
	for _, j := range jobs {
		if cves[j.Port] == nil {
			cves[j.Port] = map[string]bool{}
		}
		for _, c := range j.CVEs {
			cves[j.Port][c] = true
		}
	}
	n := map[int]int{}
	seen := map[string]bool{}
	in = matchedFirst(in, func(r TemplateResult) string { return r.Outcome })
	for _, r := range in {
		ok := cves[r.Port] != nil && templateID.MatchString(r.Template) && n[r.Port] < maxTemplateRows &&
			cves[r.Port][r.CVE] && cveID.MatchString(r.CVE) &&
			(r.Outcome == OutcomeMatched || r.Outcome == OutcomeNoMatch || r.Outcome == OutcomeError)
		key := fmt.Sprintf("%d|%s", r.Port, r.Template)
		if cves[r.Port][r.CVE] && cveID.MatchString(r.CVE) && templateID.MatchString(r.Template) && n[r.Port] >= maxTemplateRows && !seen[key] {
			notKept++ // well-formed, but over the per-service limit
		}
		if !ok || seen[key] {
			continue
		}
		seen[key] = true
		n[r.Port]++
		out = append(out, r)
	}
	return out, notKept
}

// templateRows turns the results into the rows a snapshot keeps, for the services identified on ip.
func templateRows(services []ServiceRow, ip netip.Addr, rs []TemplateResult) []TemplateRow {
	have := map[int]bool{}
	for _, x := range services {
		have[x.Port] = x.IP == ip.String()
	}
	out := []TemplateRow{}
	for _, r := range rs {
		if have[r.Port] {
			out = append(out, TemplateRow{IP: ip.String(), Port: r.Port, CVE: r.CVE, Template: r.Template, Outcome: r.Outcome})
		}
	}
	return out
}

// templatesLine is the "what was checked" line: how many templates were sent on how many ports, with their outcomes and the ids the
// scanner says it sent (INV-19, INV-23).
func templatesLine(jobs []TemplateJob, rs []TemplateResult, sent []string, notKept int) string {
	ports := map[int]bool{}
	asked := 0
	for _, j := range jobs {
		ports[j.Port] = true
		asked += len(j.CVEs)
	}
	var matched, none, failed int
	names := sent
	for _, r := range rs {
		switch r.Outcome {
		case OutcomeMatched:
			matched++
		case OutcomeNoMatch:
			none++
		default:
			failed++
		}
		if len(sent) == 0 {
			names = append(names, r.Template)
		}
	}
	head := fmt.Sprintf("Safe templates for exploited vulnerabilities (nuclei, at most %d requests a second, own IP only)", TemplateRPS)
	if len(rs) == 0 && len(names) == 0 {
		return fmt.Sprintf("%s: the scanner reported no result for the %s asked about on %s.", head, plural(asked, "exploited CVE"), plural(len(ports), "port"))
	}
	text := fmt.Sprintf("%s: %s sent on %s, %d matched, %d no match, %d error", head, plural(max(len(names), len(rs)), "template"), plural(len(ports), "port"), matched, none, failed)
	if missing := asked - len(rs) - notKept; missing > 0 {
		text += fmt.Sprintf("; no result for %s of %d asked about", plural(missing, "CVE"), asked)
	}
	if notKept > 0 {
		text += fmt.Sprintf("; %d not kept, over the limit of %d a service", notKept, maxTemplateRows)
	}
	if len(names) > maxTemplatesLn {
		names = append(names[:maxTemplatesLn:maxTemplatesLn], fmt.Sprintf("%d more", len(names)-maxTemplatesLn))
	}
	return clipText(text+". "+strings.Join(names, ", ")+".", maxLineText) // sanitizeChecks drops a longer line
}

// sanitizeTemplates limits the template rows of a snapshot: only the services it has, ids and outcomes of the right shape, at most
// maxTemplateRows per service.
func sanitizeTemplates(in []TemplateRow, services []ServiceRow) []TemplateRow {
	have := map[netip.AddrPort]bool{}
	for _, x := range services {
		if ip, err := netip.ParseAddr(x.IP); err == nil {
			have[netip.AddrPortFrom(ip, uint16(x.Port))] = true //nolint:gosec // sanitizeServices kept ports 1..65535
		}
	}
	out := []TemplateRow{}
	n := map[netip.AddrPort]int{}
	in = matchedFirst(in, func(r TemplateRow) string { return r.Outcome })
	for _, r := range in {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || r.Port < 1 || r.Port > 65535 {
			continue
		}
		k := netip.AddrPortFrom(ip, uint16(r.Port))
		if have[k] && n[k] < maxTemplateRows && templateID.MatchString(r.Template) && cveID.MatchString(r.CVE) &&
			(r.Outcome == OutcomeMatched || r.Outcome == OutcomeNoMatch || r.Outcome == OutcomeError) {
			n[k]++
			out = append(out, TemplateRow{IP: ip.String(), Port: r.Port, CVE: r.CVE, Template: r.Template, Outcome: r.Outcome})
		}
	}
	return out
}

// markTemplates applies the stored template results to the CVE rows computed on read (INV-23). A match makes the basis "template":
// the strongest evidence, and the one a distribution's backport does not weaken. A template that did not match is one check, never
// "not vulnerable"; a template that failed neither confirms nor rules out.
func markTemplates(vulns []VulnRow, rows []TemplateRow) {
	by := map[string]TemplateRow{}
	for _, t := range rows {
		if t.CVE == "" {
			continue
		}
		k := fmt.Sprintf("%s:%d:%s", t.IP, t.Port, t.CVE)
		if old, ok := by[k]; !ok || old.Outcome != OutcomeMatched && t.Outcome == OutcomeMatched {
			by[k] = t
		}
	}
	for i, v := range vulns {
		t, ok := by[fmt.Sprintf("%s:%d:%s", v.IP, v.Port, v.CVE)]
		if !ok {
			continue
		}
		vulns[i].Template, vulns[i].TemplateResult = t.Template, t.Outcome
		switch t.Outcome {
		case OutcomeMatched:
			vulns[i].Basis = "template"
			vulns[i].Summary = strings.TrimSpace("Confirmed by template " + t.Template + ": the safe check got the answer of an affected service. " + v.Summary)
		case OutcomeNoMatch:
			vulns[i].Summary = strings.TrimSpace(v.Summary + " No match reported by the safe template " + t.Template + ": that is one check, not proof that this service is not affected.")
		default:
			vulns[i].Summary = strings.TrimSpace(v.Summary + " The safe template " + t.Template + " could not finish, so it neither confirmed nor ruled this out.")
		}
	}
}

// matchedFirst orders results so that a cap never drops a match in favour of a no-match or an error (the rest keep their order).
func matchedFirst[T any](in []T, outcome func(T) string) []T {
	out := make([]T, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return outcome(out[i]) == OutcomeMatched && outcome(out[j]) != OutcomeMatched })
	return out
}

// sentIDs keeps the template ids the scanner says it sent: well-formed, no repeats, at most 4 jobs' worth per call.
func sentIDs(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, id := range in {
		if templateID.MatchString(id) && !seen[id] && len(out) < TemplatesPerJob*maxTemplateJobs {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
