package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/pack"
)

// The deep scan of a target whose testing terms were accepted (exposure ScanMode.Full). Every identified port
// of the box's own public IP gets nuclei's own automatic scan (nuclei -as, docs.projectdiscovery.io/tools/nuclei/running "-as,
// -automatic-scan: automatic web scan using wappalyzer technology detection to tags mapping"; nuclei v3.11.1
// pkg/protocols/common/automaticscan runs the detection templates first and then the templates tagged with what they found), with
// the pack's templates only:
//   - a web port (scheme http or https): the pack's technologies templates first; what they matched (their tags that their id
//     contains, and the matcher name, as -as reads them) plus the product and service words of nmap's -sV and its CPE, kept when they
//     are product tags of the pack (pack.ProductTags), are the tags; then the deep templates with one of those tags, the generic
//     exposure, misconfiguration, panel and miscellaneous templates that name no product, the KEV templates of the port's exploited
//     CVEs, and on https the TLS checks (ssl/). At most exposure.FullTemplatesPerPort templates a port, in that order of priority.
//   - any other port: the KEV templates of its exploited CVEs, the network templates with a tag of the -sV service name or product,
//     and the TLS checks when nmap saw TLS.
//
// The disruptive set runs only while the mode is Disruptive. Before each run leaves core (at most nucleiargv.MaxFullTemplates
// templates, the full shape of nucleiargv at nucleiargv.FullRate): exposure's ModeNow (the terms are read again, fail closed: no
// longer Full = nothing deep is sent and a line says so; the tick taken back = no disruptive template), then the gate, then a probe
// row per template (LEGAL §3), then the job. The worker checks the depth, the sets in its own index, each file and the own-IP fence
// again.

const (
	// templatesNotFull is the reason when the terms were withdrawn (or are of an older version) during the scan.
	templatesNotFull = "the testing terms of this target are no longer accepted, so no deep template was sent."
	// fullCapped is the line of a web port whose selection was cut at exposure.FullTemplatesPerPort.
	fullCapped = "Deep templates on port %d: %d of the templates chosen for what runs there were not sent, over the limit of %d a port."
	// fullSlow and fullFailed are the lines of the runs that were not reported after earlier ones were kept.
	fullSlow   = "Deep templates did not finish in the time of the step, so the ports that had not finished are not reported (%s)."
	fullFailed = "Deep templates on port %d and after did not run: %s"
)

// fullPort is what a full scan knows of one port: the address to send to, the exploited CVEs matched there and what nmap read.
type fullPort struct {
	port                  int
	target                nucleiargv.Target
	cves                  []string
	service, product, cpe string
}

// fullPorts merges exposure's jobs of depth full by port (a port with more than 32 CVEs has several), in their order; a port the
// target's settings skip gets none.
func fullPorts(ip netip.Addr, jobs []exposure.TemplateJob, skip []int) []fullPort {
	var out []fullPort
	for _, j := range jobs {
		if j.Scope != exposure.ScopeOwnIP || j.Host != ip.String() || j.Depth != exposure.DepthFull || slices.Contains(skip, j.Port) {
			continue
		}
		i := slices.IndexFunc(out, func(p fullPort) bool { return p.port == j.Port })
		if i < 0 {
			out = append(out, fullPort{port: j.Port, target: nucleiargv.Target{Host: ip.String(), Port: j.Port, Scheme: j.Scheme}, service: j.Service, product: j.Product, cpe: j.CPE})
			i = len(out) - 1
		}
		out[i].cves = append(out[i].cves, j.CVEs...)
	}
	return out
}

// errNotFull stops a full scan whose terms are no longer accepted.
var errNotFull = &exposure.Unavailable{Reason: templatesNotFull}

func (a exposureTemplateScan) scanFull(ctx context.Context, t exposure.ScanTarget, ip netip.Addr, ix *pack.Index, jobs []exposure.TemplateJob) (exposure.TemplateScan, error) {
	var out exposure.TemplateScan
	products := pack.ProductTags(ix.Templates)
	ports := fullPorts(ip, jobs, t.SkipPorts)
	if l := groupsOffLine(t.Mode); l != "" && len(ports) > 0 && t.Domain == nil && !t.Typed { // where the disruptive checks could run at all
		out.NotChecked = append(out.NotChecked, l)
	}
	bounds := make([]int64, len(ports))
	meter := &fullMeter{}
	for i, p := range ports {
		bounds[i] = portBound(ix, products, p, tplFilter{m: t.Mode, paths: t.SkipPaths})
		meter.plan += bounds[i]
	}
	meter.s = progress.NewSeries(ctx, progress.PhaseVulns, meter.plan)
	for i, p := range ports {
		err := a.fullPortScan(ctx, t, ip, ix, products, p, &out, meter, bounds[i])
		if err == nil {
			continue
		}
		var un *exposure.Unavailable
		switch {
		case len(out.Sent) == 0 && errors.Is(err, errNotFull) && ctx.Err() == nil && t.Domain == nil: // review r1 L3: withdrawn before anything deep went out
			return a.baselineInstead(ctx, t, ip, ix, jobs)
		case len(out.Sent) == 0 || errors.Is(ctx.Err(), context.Canceled): // nothing sent yet, or the scan was stopped: exposure says why
			return exposure.TemplateScan{}, err
		case ctx.Err() != nil: // the step's bound ran out: keep what earlier runs found
			var left []string
			for _, q := range ports[i:] {
				left = append(left, fmt.Sprintf("port %d", q.port))
			}
			out.NotChecked = append(out.NotChecked, fmt.Sprintf(fullSlow, namesOf(left)))
		case errors.As(err, &un):
			out.NotChecked = append(out.NotChecked, fmt.Sprintf(fullFailed, p.port, un.Reason))
		default:
			a.log.ErrorContext(ctx, "exposure: a run of the deep templates failed, the ones before it are kept", "ip", ip.String(), "port", p.port, "error", err)
			out.NotChecked = append(out.NotChecked, fmt.Sprintf(fullFailed, p.port, templatesFailed))
		}
		return out, nil // the ports after it are not sent (the page says so)
	}
	return out, nil
}

// baselineInstead is the scan of a target whose terms were withdrawn before the first deep run: the read-only KEV checks of a target
// without terms, as the next scan would run them, with a line saying no deep template was sent. The ModeNow of the next runs
// is not needed: the baseline is what every verified target gets, and scanBaseline still runs the gate before each run.
func (a exposureTemplateScan) baselineInstead(ctx context.Context, t exposure.ScanTarget, ip netip.Addr, ix *pack.Index, jobs []exposure.TemplateJob) (exposure.TemplateScan, error) {
	var base []exposure.TemplateJob
	for _, j := range jobs {
		if j.Depth == exposure.DepthFull && len(j.CVEs) > 0 {
			j.Depth, j.RPS, j.Service, j.Product, j.CPE = "", min(j.RPS, exposure.TemplateRPS), "", "", "" // #850 review M1: a lower shared speed stays lower
			base = append(base, j)
		}
	}
	out, err := a.scanBaseline(ctx, t, ip, ix, base)
	if err != nil {
		return out, err
	}
	out.NotChecked = append([]string{"Deep templates did not run: " + templatesNotFull + " The safe checks for exploited vulnerabilities ran instead."}, out.NotChecked...)
	return out, nil
}

// fullMeter is the count of a deep scan's templates over all its ports (#830 FAIL 2: the page showed each 200-template run's own
// count, 85 % → 39 % → 82 %). It starts from an upper bound of each port (portBound) and is made exact as each port's templates are
// chosen and sent, so the total only shrinks and the bar of the step only moves forward.
type fullMeter struct {
	s    *progress.Series
	plan int64
}

// reckon replaces was, the checks planned for a port, with now; it returns now.
func (m *fullMeter) reckon(was, now int64) int64 {
	m.plan += now - was
	m.s.Plan(m.plan)
	return now
}

// portBound is what fullPortScan can send to a port with the mode the scan started with (a later ModeNow is never more): a web port's
// technologies templates and its plan with every tag they could find (reachableTags), up to exposure.FullTemplatesPerPort in all;
// another port's plan as it is.
func portBound(ix *pack.Index, products map[string]bool, p fullPort, f tplFilter) int64 {
	if p.target.Scheme == "" {
		return int64(len(otherPlan(ix, p, f)))
	}
	tech := 0
	for _, tp := range ix.Templates {
		if tp.Tech() && f.runs(tp) {
			tech++
		}
	}
	plan, _ := webPlan(ix, p, reachableTags(ix, products, p), f, exposure.FullTemplatesPerPort-tech)
	return int64(tech + len(plan))
}

// reachableTags are the product tags foundTags can give a web port whatever its technologies templates match (review r1 #2): every
// product tag a technologies template carries, and the words of nmap's product, service name and CPE. A matcher name whose words are
// no tag of any technologies template can still add a tag; the bound is then low, and the step's bar waits (it never goes back).
func reachableTags(ix *pack.Index, products map[string]bool, p fullPort) []string {
	found := map[string][]string{}
	for _, tp := range ix.Templates {
		if tp.Tech() {
			found[tp.ID] = nil
		}
	}
	tags := foundTags(ix, products, found, p) // tags in the id, and nmap's words
	for _, tp := range ix.Templates {
		if tp.Tech() {
			for _, tag := range tp.Tags {
				if products[tag] && !slices.Contains(tags, tag) {
					tags = append(tags, tag)
				}
			}
		}
	}
	return tags
}

// fullPortScan runs the deep templates of one port, appending to out what was sent and found. meter counts its checks, bound
// being what it planned for this port (#830).
func (a exposureTemplateScan) fullPortScan(ctx context.Context, t exposure.ScanTarget, ip netip.Addr, ix *pack.Index, products map[string]bool, p fullPort, out *exposure.TemplateScan, meter *fullMeter, bound int64) error {
	sent := map[string]bool{}
	var silent []string // review r1 M1: handed to nuclei, no line printed: not run
	handed := 0
	unknown := map[string]bool{}                                      // templates whose path could not be told against the web paths to skip (they ran)
	run := func(tmpls []pack.Template) (map[string][]string, error) { // template id -> matcher names of its matching lines
		found := map[string][]string{}
		for c := range slices.Chunk(tmpls, nucleiargv.MaxFullTemplates) {
			m, err := a.modeNow(ctx, t)
			if err != nil {
				return nil, err
			}
			c = slices.DeleteFunc(slices.Clone(c), func(tp pack.Template) bool {
				return sent[tp.ID] || !tp.RunsAt(true, m.Disruptive) || !groupAllows(m, tp) || templatePathOf(tp, t.SkipPaths) == tplPathSkipped
			})
			for _, tp := range c {
				if templatePathOf(tp, t.SkipPaths) == tplPathUnknown {
					unknown[tp.ID] = true
				}
			}
			if len(c) == 0 {
				continue
			}
			jctx, end := meter.s.Job(ctx)
			res, o, quiet, err := a.send(jctx, t.User, ip, ix, templateRun{port: p.port, target: p.target, tmpls: c, full: true, disruptive: m.Disruptive, gentle: t.Gentle, domain: t.Domain})
			end(int64(len(c)))
			if err != nil {
				return nil, err
			}
			out.Results = append(out.Results, res...)
			silent, handed = append(silent, quiet...), handed+len(c)
			for _, tp := range c {
				sent[tp.ID] = true
				out.Sent = append(out.Sent, tp.ID)
			}
			for _, l := range o.Results {
				if l.Matched {
					found[l.Template] = append(found[l.Template], l.MatcherName)
				}
			}
		}
		return found, nil
	}
	// what the mode allows is read again before each run (run); this first read only picks the candidates
	m, err := a.modeNow(ctx, t)
	if err != nil {
		return err
	}
	var plan []pack.Template
	f := tplFilter{m: m, paths: t.SkipPaths} // the room of the port goes only to templates that may leave
	if p.target.Scheme == "" {
		plan = otherPlan(ix, p, f)
	} else {
		tech := filterTemplates(ix, func(tp pack.Template) bool { return tp.Tech() && f.runs(tp) })
		found, err := run(tech)
		if err != nil {
			return err
		}
		tags := foundTags(ix, products, found, p)
		var capped int
		plan, capped = webPlan(ix, p, tags, f, exposure.FullTemplatesPerPort-len(tech))
		if capped > 0 {
			out.NotChecked = append(out.NotChecked, fmt.Sprintf(fullCapped, p.port, capped, exposure.FullTemplatesPerPort))
		}
	}
	bound = meter.reckon(bound, int64(handed+len(plan))) // the port's templates are chosen: its count is exact from here
	_, err = run(plan)
	if err == nil {
		meter.reckon(bound, int64(handed)) // what was sent, the ones the mode no longer allowed left out
	}
	if len(silent) > 0 {
		out.NotChecked = append(out.NotChecked, fmt.Sprintf(notRunFull, p.port, len(silent), handed))
	}
	if l := pathsLine(len(unknown), p.port, t.SkipPaths); l != "" {
		out.NotChecked = append(out.NotChecked, l)
	}
	return err
}

// modeNow is exposure's ModeNow, fail closed: an error stops the scan, and a target that is not Full any more is errNotFull.
func (a exposureTemplateScan) modeNow(ctx context.Context, t exposure.ScanTarget) (exposure.ScanMode, error) {
	if a.mode == nil {
		return exposure.ScanMode{}, errNotFull
	}
	m, err := a.mode(ctx, t.User, t.ID)
	switch {
	case ctx.Err() != nil:
		return exposure.ScanMode{}, ctx.Err()
	case err != nil:
		return exposure.ScanMode{}, fmt.Errorf("vedette: reading the testing terms of target %s: %w", t.ID, err)
	case !m.Full:
		return exposure.ScanMode{}, errNotFull
	}
	return m.And(t.Mode), nil // never more than the run started with, group by group
}

func filterTemplates(ix *pack.Index, keep func(pack.Template) bool) []pack.Template {
	var out []pack.Template
	for _, tp := range ix.Templates {
		if keep(tp) {
			out = append(out, tp)
		}
	}
	return out
}

var wordRE = regexp.MustCompile(`[a-z0-9][a-z0-9-]*`)

// words are the lower-case words of a text ("Apache httpd" -> apache, httpd; "http_server" -> http-server, http, server).
func words(s string) []string {
	s = strings.ToLower(s)
	out := wordRE.FindAllString(strings.ReplaceAll(s, "_", "-"), -1)
	return append(out, wordRE.FindAllString(strings.ReplaceAll(s, "_", " "), -1)...)
}

// foundTags are the product tags of a web port (nuclei -as): of each technologies template that matched, its tags that its id
// contains and the words of its matcher names, plus the words of nmap's product, service name and CPE vendor and product; each kept
// only when it is a product tag of the pack.
func foundTags(ix *pack.Index, products map[string]bool, found map[string][]string, p fullPort) []string {
	var cand []string
	for id, names := range found {
		if tp, ok := ix.Get(id); ok {
			for _, tag := range tp.Tags {
				if strings.Contains(tp.ID, tag) {
					cand = append(cand, tag)
				}
			}
		}
		for _, n := range names {
			n, _, _ = strings.Cut(n, ":") // -as: "name:version" is the name
			cand = append(cand, words(n)...)
			cand = append(cand, strings.Join(strings.Fields(strings.ToLower(n)), "-"))
		}
	}
	cand = append(cand, words(p.product)...)
	cand = append(cand, words(p.service)...)
	if f := strings.Split(p.cpe, ":"); len(f) >= 4 {
		cand = append(cand, words(f[2]+" "+f[3])...)
	}
	var out []string
	for _, c := range cand {
		if products[c] && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}

// webCandidate says whether webPlan may choose tp for the web port p: not a technologies template (those run first), allowed by the
// mode and the target's settings (f), not a network template, and a TLS check only on https.
func webCandidate(tp pack.Template, p fullPort, f tplFilter) bool {
	return !tp.Tech() && f.runs(tp) && !strings.HasPrefix(tp.Path, "network/") && (!strings.HasPrefix(tp.Path, "ssl/") || p.target.Scheme == "https")
}

// webPlan is the second step of a web port: the KEV templates of its CVEs, the deep templates with a found tag, the generic ones,
// then on https the TLS checks; no technologies template (they ran first), none twice, at most room. capped is how many were left out.
func webPlan(ix *pack.Index, p fullPort, tags []string, f tplFilter, room int) (plan []pack.Template, capped int) {
	seen := map[string]bool{}
	add := func(tp pack.Template) {
		if seen[tp.ID] || !webCandidate(tp, p, f) {
			return
		}
		seen[tp.ID] = true
		if len(plan) >= room {
			capped++
			return
		}
		plan = append(plan, tp)
	}
	for _, c := range p.cves {
		for _, tp := range ix.FullForCVE(c, f.m.Disruptive) {
			add(tp)
		}
	}
	tagSet := make(map[string]bool, len(tags))
	for _, t := range tags {
		tagSet[t] = true
	}
	for _, tp := range ix.Templates {
		if slices.ContainsFunc(tp.Tags, func(t string) bool { return tagSet[t] }) {
			add(tp)
		}
	}
	for _, tp := range ix.Templates {
		if tp.Generic {
			add(tp)
		}
	}
	if p.target.Scheme == "https" {
		for _, tp := range ix.Templates {
			if strings.HasPrefix(tp.Path, "ssl/") {
				add(tp)
			}
		}
	}
	return plan, capped
}

// otherPlan is the plan of a port that is not web: the KEV templates of its CVEs and the network templates with a tag of the -sV
// service name or product (a word of at least 3 letters that names something, pack.GenericTag), and the TLS checks when nmap saw
// TLS ("ssl/…"). At most exposure.FullTemplatesPerPort.
func otherPlan(ix *pack.Index, p fullPort, f tplFilter) []pack.Template {
	var keys []string
	for _, w := range append(words(p.service), words(p.product)...) {
		if len(w) >= 3 && !pack.GenericTag(w) && !slices.Contains(keys, w) {
			keys = append(keys, w)
		}
	}
	tls := strings.HasPrefix(strings.ToLower(p.service), "ssl/")
	seen := map[string]bool{}
	var plan []pack.Template
	add := func(tp pack.Template) {
		if !seen[tp.ID] && f.runs(tp) && !strings.HasPrefix(tp.Path, "http/") && len(plan) < exposure.FullTemplatesPerPort {
			seen[tp.ID] = true
			plan = append(plan, tp)
		}
	}
	for _, c := range p.cves {
		for _, tp := range ix.FullForCVE(c, f.m.Disruptive) {
			add(tp)
		}
	}
	for _, tp := range ix.Templates {
		switch {
		case strings.HasPrefix(tp.Path, "network/") && slices.ContainsFunc(tp.Tags, func(t string) bool { return slices.Contains(keys, t) }):
			add(tp)
		case tls && strings.HasPrefix(tp.Path, "ssl/"):
			add(tp)
		}
	}
	return plan
}
