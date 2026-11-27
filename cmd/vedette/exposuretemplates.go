package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/content/nucleipack"
	"github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/pack"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// exposureTemplateScan is exposure's TemplateScanner (S-EXP-2, exposure INV-23): the safe nuclei templates of the
// exploited CVEs matched on a port of the box's own verified public IP, run by the scan container's worker through sensor-active's
// Dispatcher with scope own_ip. exposureService sets it as cfg.Templates; the commitment sentence of NoticeVersion 2026-11-14 (K-4)
// names "safe checks for known exploited vulnerabilities", and PRIVACY flow 9 says what is sent.
//
// Two fences before a packet leaves, both fail closed: (1) core: right before each run, exposure's gate with the person who
// pressed Scan now as the actor (OwnIPProof: verified, committed, inside its proof's 90 days; a sighting renews it); (2) the
// worker: nucleiargv's own_ip grammar (one public IPv4, the job's port, 5 requests a second), the own_ip mark of each template in
// its own index and its own read of each template file (pack.OwnIPText), and the address as the box's own: the job carries the time
// of the sighting core's yes rests on, which the worker takes while it holds (90 days), else its own check, with the three public
// IP services, that the box goes out through that address. No argv goes over the wire.
//
// Templates come only from the verified pack core plans with (content/nucleipack, the index of the image; the worker refuses a job
// planned for another pack): the template of each CVE of a job (pack.ForCVE; in the KEV pack its id is the CVE id), none chosen by
// tag, and only one the pack marks own_ip (pack.Template.OwnIP: http GET or HEAD only, no body, no credential, no command).
// A CVE whose template is not marked gets a "not run on a public IP" line. Each template is a row of the probe log, with its real
// id, before its run is handed out (LEGAL §3), and is completed with its outcome after.
type exposureTemplateScan struct {
	on     func() bool                 // sensor-active is on: it runs the scan container
	pack   func() (*pack.Index, error) // the pack core plans with
	run    func(ctx context.Context, r sensoractive.NucleiRequest) (nucleiout.Outcome, error)
	gate   ownIPGate
	probes func(ctx context.Context, ps []scan.ExternalProbe) error // the scan module's probe log
	log    *slog.Logger
	// mode is exposure's ModeNow: the scan mode of the target right before each full run leaves core.
	mode func(ctx context.Context, actor, id string) (exposure.ScanMode, error)
}

// templatesHostErrors is -mhe of a run: nuclei stops on the address after 3 errors in a row (the scan module's default).
const templatesHostErrors = 3

// The reasons exposure shows after "Safe templates for exploited vulnerabilities did not run: ".
const (
	templatesOff     = "the Active discovery module is off, so the scan container does not run them. An admin can turn it on in Settings, Modules."
	templatesNoWork  = "the scan container is not available (it has not reported, or it has no nuclei or template pack). Settings, Sensors says why."
	templatesBusy    = "the scan container's nuclei was busy with a vulnerability scan of the network. Scan again later."
	templatesOld     = "the scan container is older than the rest of Vedette and cannot run them on a public IP. Update the box, then scan again."
	templatesRefused = "the scan container refused the job; it may be older than the rest of Vedette. Update the box, then scan again."
	templatesPack    = "the scan container holds another template pack than this version of Vedette. Update the box, then scan again."
	templatesBadPack = "the scan container's template pack failed its integrity check, so nothing was sent. Settings, Sensors says why."
	templatesNoCheck = "the scan container could not reach the public IP services to check that %s is still this box's address, so nothing was sent. Check that the box can reach checkip.amazonaws.com, icanhazip.com and ifconfig.me over HTTPS."
	templatesNotOwn  = "this box no longer reaches the Internet through %s, so nothing was sent."
	templatesNoLog   = "the probe log could not be written, and nothing is sent without it."
	templatesFailed  = "they failed. The box log has the error."

	// notReadOnly is the line of the CVEs of a port whose template may not run on a public IP.
	notReadOnly = "Safe templates for exploited vulnerabilities: %s on port %d: not run on a public IP: this check is not a read-only request."
	// runSlow and runFailed are the lines of the runs that were not reported after earlier ones were kept (review M2, L2).
	runSlow   = "Safe templates for exploited vulnerabilities did not finish within 5 minutes, so the ones that had not finished are not reported (%s)."
	runFailed = "Safe templates for exploited vulnerabilities on port %d did not run: %s"
	// notRunKEV and notRunFull are the lines of templates a finished run printed nothing for (review r1 M1): nuclei did not run them;
	// their probe-log rows have the result not_run (kf-scan item 5).
	notRunKEV  = "Safe templates for exploited vulnerabilities on port %d: nuclei printed no result for %d of %d, so they did not run (%s)."
	notRunFull = "Deep templates on port %d: nuclei printed no result for %d of %d templates sent to it, so they did not run."
)

// templateRun is one nuclei job: at most nucleiargv.MaxTemplates templates on one port, or nucleiargv.MaxFullTemplates for a full
// run (depth full, the disruptive set too when disruptive).
type templateRun struct {
	port       int
	target     nucleiargv.Target
	tmpls      []pack.Template
	full       bool
	disruptive bool
	gentle     bool                  // a full run at the gentle speed of the target's settings (nucleiargv.GentleFullRate)
	domain     *exposure.DomainScope // A full run on an address of a verified domain's name (domain_ip); nil otherwise
}

func (a exposureTemplateScan) ScanTemplates(ctx context.Context, t exposure.ScanTarget, ip netip.Addr, jobs []exposure.TemplateJob) (exposure.TemplateScan, error) {
	if a.on != nil && !a.on() {
		return exposure.TemplateScan{}, &exposure.Unavailable{Reason: templatesOff}
	}
	if a.run == nil {
		return exposure.TemplateScan{}, &exposure.Unavailable{Reason: templatesNoWork}
	}
	if t.Typed && t.Domain == nil {
		return exposure.TemplateScan{}, &exposure.Unavailable{Reason: orText(t.TypedWhy, webTypedNoScope)}
	}
	ix, err := a.pack()
	if err != nil {
		return exposure.TemplateScan{}, err
	}
	if t.Domain != nil && !t.Mode.Full { // An address that is not the box's gets the deep templates only, as a domain_ip job
		return exposure.TemplateScan{}, errNotFull
	}
	if t.Mode.Full { // The deep scan of a target whose testing terms were accepted
		return a.scanFull(ctx, t, ip, ix, jobs)
	}
	return a.scanBaseline(ctx, t, ip, ix, jobs)
}

// scanBaseline runs the read-only KEV templates of the jobs, the scan of a target without accepted testing terms.
func (a exposureTemplateScan) scanBaseline(ctx context.Context, t exposure.ScanTarget, ip netip.Addr, ix *pack.Index, jobs []exposure.TemplateJob) (exposure.TemplateScan, error) {
	runs, notes := templateRuns(ix, ip, jobs, t)
	out := exposure.TemplateScan{NotChecked: notes}
	var checks int64
	for _, r := range runs {
		checks += int64(len(r.tmpls))
	}
	series := progress.NewSeries(ctx, progress.PhaseVulns, checks) // #830 FAIL 2: one count over the runs, not each run's own
	for i, r := range runs {
		jctx, end := series.Job(ctx)
		res, silent, err := a.runOne(jctx, t.User, ip, ix, r)
		end(int64(len(r.tmpls)))
		if err == nil {
			out.Results = append(out.Results, res...)
			for _, tp := range r.tmpls { // handed to nuclei and logged; the ones it did not run are counted below
				out.Sent = append(out.Sent, tp.ID)
			}
			if len(silent) > 0 {
				out.NotChecked = append(out.NotChecked, fmt.Sprintf(notRunKEV, r.port, len(silent), len(r.tmpls), namesOf(silent)))
			}
			continue
		}
		var un *exposure.Unavailable
		switch {
		case i == 0 || errors.Is(ctx.Err(), context.Canceled): // nothing kept yet, or the scan was stopped: exposure says why
			return exposure.TemplateScan{}, err
		case ctx.Err() != nil: // exposure's 5 minutes ran out: keep what earlier runs found, as the probe log does (review M2)
			out.NotChecked = append(out.NotChecked, fmt.Sprintf(runSlow, cveList(runs[i:])))
		case errors.As(err, &un):
			out.NotChecked = append(out.NotChecked, fmt.Sprintf(runFailed, r.port, un.Reason))
		default:
			a.log.ErrorContext(ctx, "exposure: a run of the safe templates failed, the ones before it are kept", "ip", ip.String(), "port", r.port, "error", err)
			out.NotChecked = append(out.NotChecked, fmt.Sprintf(runFailed, r.port, templatesFailed))
		}
		return out, nil // the runs after it are not sent (review L2: the page says so)
	}
	return out, nil
}

// cveList names the CVEs of runs, at most six and a count of the rest.
func cveList(runs []templateRun) string {
	var ids []string
	for _, r := range runs {
		for _, tp := range r.tmpls {
			ids = append(ids, tp.CVE)
		}
	}
	return namesOf(ids)
}

func namesOf(ids []string) string {
	if len(ids) > 6 {
		return strings.Join(ids[:6], ", ") + fmt.Sprintf(" and %d more", len(ids)-6)
	}
	return strings.Join(ids, ", ")
}

// templateRuns turns exposure's jobs into nuclei runs: for each job of ip (scope own_ip), the pack's templates of its CVEs that the
// pack marks own_ip, at most nucleiargv.MaxTemplates a run. A CVE the pack has no template for is left out (no result, not an
// error); a CVE whose templates are all unmarked gets a notReadOnly line; a job for another address or scope is left out (exposure
// never makes one).
func templateRuns(ix *pack.Index, ip netip.Addr, jobs []exposure.TemplateJob, t exposure.ScanTarget) (runs []templateRun, notes []string) {
	for _, j := range jobs {
		if j.Scope != exposure.ScopeOwnIP || j.Host != ip.String() || j.Depth != "" || t.Skips(j.Port) { // a full job is scanFull's, in a Full scan only
			continue
		}
		var tmpls []pack.Template
		var refused []string
		left := map[string]tplPathVerdict{}
		for _, cve := range j.CVEs {
			all := ix.ForCVE(cve)
			ok := 0
			for _, tp := range all {
				pv := templatePathOf(tp, t.SkipPaths)
				if tp.OwnIP && pv != tplPathRuns { // a request under a web path the target skips, or one that could be: left out, not refused
					left[tp.ID], ok = pv, ok+1
					continue
				}
				if tp.OwnIP && !slices.ContainsFunc(tmpls, func(x pack.Template) bool { return x.ID == tp.ID }) {
					tmpls, ok = append(tmpls, tp), ok+1
				}
			}
			if len(all) > 0 && ok == 0 {
				refused = append(refused, cve)
			}
		}
		if len(refused) > 0 {
			notes = append(notes, fmt.Sprintf(notReadOnly, namesOf(refused), j.Port))
		}
		if l := pathsLine(left, j.Port, t.SkipPaths); l != "" {
			notes = append(notes, l)
		}
		target := nucleiargv.Target{Host: ip.String(), Port: j.Port, Scheme: j.Scheme}
		for c := range slices.Chunk(tmpls, nucleiargv.MaxTemplates) {
			runs = append(runs, templateRun{port: j.Port, target: target, tmpls: c})
		}
	}
	return runs, notes
}

// runOne is one run, in this order: the gate (obligation 1), the probe rows with the real template ids (obligation 2, LEGAL §3),
// the job, the results with their CVE (obligation 3), the probe rows completed.
func (a exposureTemplateScan) runOne(ctx context.Context, actor string, ip netip.Addr, ix *pack.Index, r templateRun) ([]exposure.TemplateResult, []string, error) {
	res, _, silent, err := a.send(ctx, actor, ip, ix, r)
	return res, silent, err
}

// send is runOne with the parsed lines of the run too (a full run reads the matcher names of the technologies templates).
// silent are the templates nuclei printed nothing for (not run, review r1 M1).
func (a exposureTemplateScan) send(ctx context.Context, actor string, ip netip.Addr, ix *pack.Index, r templateRun) (res []exposure.TemplateResult, got nucleiout.Outcome, silent []string, err error) {
	ok := true
	var proven time.Time // the sighting the gate's yes rests on: the worker takes the address as the box's own on it
	if r.domain == nil { // A domain_ip run is not the box's own IP; exposure's deepGate checked it, and the worker's fence does
		proven, ok, err = a.gate(ctx, actor, ip)
	}
	switch {
	case ctx.Err() != nil:
		return nil, nucleiout.Outcome{}, nil, ctx.Err()
	case err != nil:
		return nil, nucleiout.Outcome{}, nil, fmt.Errorf("vedette: checking that %s may still be scanned: %w", ip, err)
	case !ok:
		return nil, nucleiout.Outcome{}, nil, &exposure.Unavailable{Reason: fmt.Sprintf(templatesNotOwn, ip)}
	case r.domain != nil && !r.full:
		return nil, nucleiout.Outcome{}, nil, errNotFull
	}
	rate, depth, what := nucleiargv.OwnIPRate, "", "own IP"
	if r.full { // FULL-4
		rate, depth, what = nucleiargv.FullRate, nucleiargv.DepthFull, "own IP, deep scan, testing terms accepted"
		if r.gentle {
			rate = nucleiargv.GentleFullRate
		}
		if r.domain != nil {
			// review r1 L4: short, so the template's own request (the probe itself) is not what scan_probe.request's 300 cut off
			what = "domain_ip " + r.domain.Domain + " via " + finalName(r.domain) + ", deep scan, testing terms accepted"
		}
		if r.disruptive {
			what += ", disruptive checks"
		}
	}
	request := func(tp pack.Template) string {
		return fmt.Sprintf("nuclei %s to %s (%s, at most %d requests a second): %s", tp.ID, r.target.Input(), what, rate, tp.Request)
	}
	if r.domain != nil { // review r2 L-5: the template's request is kept whole; only the domain part shrinks to fit the row
		request = func(tp pack.Template) string {
			line := func(d, f string) string {
				return fmt.Sprintf("nuclei %s to %s (domain_ip %s via %s%s, at most %d requests a second): %s", tp.ID, r.target.Input(), d, f,
					strings.TrimPrefix(what, "domain_ip "+r.domain.Domain+" via "+finalName(r.domain)), rate, tp.Request)
			}
			d, f := r.domain.Domain, finalName(r.domain)
			over := utf8.RuneCountInString(line(d, f)) - probeRequestMax
			if over <= 0 {
				return line(d, f)
			}
			keep := max(len(d)+len(f)-over-2, 2)
			return line(keepEnd(d, keep/2), keepEnd(f, keep-keep/2))
		}
	}
	scope, dom := nucleiargv.ScopeOwnIP, (*sensorlink.DomainScope)(nil)
	if r.domain != nil {
		sc := scopeOf(r.domain)
		scope, dom = sensorlink.ScopeDomainIP, &sc
	}
	rows := make([]scan.ExternalProbe, len(r.tmpls))
	ids := make([]string, len(r.tmpls))
	for i, tp := range r.tmpls {
		ids[i] = tp.ID
		rows[i] = scan.ExternalProbe{ID: store.NewID("tp"), IP: ip.String(), Label: fmt.Sprintf("%s:%d", ip, r.port), Template: tp.ID,
			Request: request(tp), RunID: exposure.RunIDOf(ctx)}
	}
	if err := a.probes(ctx, rows); err != nil {
		if ctx.Err() != nil {
			return nil, nucleiout.Outcome{}, nil, ctx.Err()
		}
		a.log.ErrorContext(ctx, "exposure: writing the probe log of the safe templates failed", "ip", ip.String(), "error", err)
		return nil, nucleiout.Outcome{}, nil, &exposure.Unavailable{Reason: templatesNoLog}
	}
	got, err = a.run(ctx, sensoractive.NucleiRequest{PackVersion: ix.Version, PackSHA256: ix.SHA256, Templates: ids,
		Targets: []nucleiargv.Target{r.target}, Rate: rate, MaxHostErrors: templatesHostErrors, Scope: scope,
		Depth: depth, Disruptive: r.full && r.disruptive, Domain: dom, ProvenAt: proven})
	if err != nil && ctx.Err() == nil && refusedBeforeSending(err) { // kf-scan item 5: nothing was sent; the rows say refused
		for i := range rows {
			rows[i].Result = scan.ProbeRefused
		}
		if perr := a.probes(context.WithoutCancel(ctx), rows); perr != nil {
			a.log.WarnContext(ctx, "exposure: completing the probe log of the safe templates failed", "ip", ip.String(), "error", perr)
		}
	}
	if un, ok := domainErr(err, r.domain, ip.String()); ok && ctx.Err() == nil {
		return nil, nucleiout.Outcome{}, nil, un
	}
	if err != nil {
		return nil, nucleiout.Outcome{}, nil, templatesErr(ctx, ip, err)
	}
	res = outcomes(r, got)
	if sk := got.Skipped; sk.Lines > 0 { // lines that cannot be a result of the job were skipped, the run is kept
		a.log.WarnContext(ctx, "exposure: nuclei printed lines that cannot be a result of the job; skipped, the run is kept", "ip", ip.String(), "port", r.port,
			"lines", sk.Lines, "matched", sk.Matched, "template", sk.Template, "host", sk.Host, "skipped_port", sk.Port)
		for i := range rows {
			if slices.Contains(sk.MatchedTemplates, rows[i].Template) { // review r2 M3: first, so the cut never drops it
				rows[i].Request = nucleiout.AppendNote(rows[i].Request, " ["+nucleiout.InconclusiveNote+"]", probeRequestMax)
			}
			if slices.Contains(sk.Templates, rows[i].Template) { // after the request, cut to the row (review r1 L7)
				rows[i].Request = nucleiout.AppendNote(rows[i].Request, sk.Note(), probeRequestMax)
			}
		}
	}
	// With -ms nuclei prints a line for every template it executes (a failure line when nothing matched), so a
	// template of a finished run with no line and no unreachable target (outcomes gives it no result) was not run: dropped at load or
	// not parsed. Its probe row has the result not_run (scan migration 0007, kf-scan item 5), and the caller adds a "Not checked"
	// line (it stays in Sent: it was logged and handed to nuclei). "No match reported" is only a template nuclei says it ran.
	for i := range rows {
		rows[i].Result = ""
		ran := false
		for _, x := range res {
			if x.Template == rows[i].Template {
				ran = true
				rows[i].Result = map[string]string{exposure.OutcomeMatched: "matched", exposure.OutcomeNoMatch: "not_matched"}[x.Outcome]
			}
		}
		if !ran {
			silent = append(silent, rows[i].Template)
			rows[i].Result = scan.ProbeNotRun
			if got.Skipped.MoreTemplates > 0 { // review r2 L5: it may be one of the templates past the cap Skipped names
				rows[i].Request = nucleiout.AppendNote(rows[i].Request, nucleiout.OverCapNote, probeRequestMax)
			}
		}
	}
	if len(silent) > 0 {
		a.log.WarnContext(ctx, "exposure: nuclei printed nothing for templates of a finished run, so they did not run", "ip", ip.String(), "port", r.port, "not_run", len(silent), "of", len(rows), "full", r.full)
	}
	if err := a.probes(context.WithoutCancel(ctx), rows); err != nil { // the rows stay "sent, no answer": the results still count
		a.log.WarnContext(ctx, "exposure: completing the probe log of the safe templates failed", "ip", ip.String(), "error", err)
	}
	return res, got, silent, nil
}

// refusedBeforeSending says the job never reached the target: the scan worker refused it (its own-IP fence, the domain fence before
// nuclei started, an invalid job), or no worker that runs domain_ip jobs was there. A domain fence that stopped nuclei mid-run is
// not one: requests went out.
func refusedBeforeSending(err error) bool {
	var dr *sensoractive.DomainRefusedError
	if errors.As(err, &dr) {
		return !dr.MidRun
	}
	return errors.Is(err, sensoractive.ErrWorkerRefused) || errors.Is(err, sensoractive.ErrDomainUnsupported)
}

// outcomes reads a run's parsed lines (nucleiout already kept only the job's templates and target, fail closed) into one result per
// template: matched when a line matched, error when a line carries an error or the address stopped answering before the template
// printed a line, no_match when it printed lines and none matched. A template without a line and an address that kept answering
// has no result (nuclei did not run it): exposure says "no result" for its CVE.
func outcomes(r templateRun, o nucleiout.Outcome) []exposure.TemplateResult {
	unreachable := slices.ContainsFunc(o.HostErrors, func(h nucleiout.HostError) bool { return h.Unreachable }) ||
		len(nucleiout.GaveUp(o.Results, o.Skipped)) > 0 // nuclei gave the address up itself (a refused or reset connection counts there)
	var out []exposure.TemplateResult
	for _, tp := range r.tmpls {
		seen, matched, failed, elsewhere := false, false, false, false
		for _, l := range o.Results {
			if l.Template == tp.ID {
				seen, matched, failed = true, matched || l.Matched, failed || l.Error != ""
			}
		}
		outcome := exposure.OutcomeNoMatch
		switch {
		case matched:
			outcome = exposure.OutcomeMatched
		case failed || !seen && unreachable:
			outcome = exposure.OutcomeError
		case slices.Contains(o.Skipped.MatchedTemplates, tp.ID):
			// review r2 M3: a line said matched but could not be tied to this address: inconclusive, never "no match reported",
			// never a finding; the probe row says to check by hand
			outcome = exposure.OutcomeError
		case !seen && slices.Contains(o.Skipped.Templates, tp.ID):
			// review r1 M7: nuclei ran it (it printed lines), but every line named another address or none readable: "no match
			// reported", with the note on its probe row, never "not run"; those lines may carry an error (a host found unresponsive),
			// so it does not say the template found nothing on this port
			elsewhere = true
		case !seen:
			continue
		}
		res := exposure.TemplateResult{Port: r.port, Template: tp.ID, CVE: tp.CVE, Outcome: outcome, Elsewhere: elsewhere}
		if r.full { // A deep result shows the template's name and severity, from the pack index
			res.Name, res.Severity = tp.Name, tp.Severity
		}
		out = append(out, res)
	}
	return out
}

// templatesErr maps what the Dispatcher said to what exposure shows. A stop by ctx (exposure's 5-minute bound included) stays a
// context error; everything not listed is a failure exposure logs and shows without its text.
func templatesErr(ctx context.Context, ip netip.Addr, err error) error {
	reason := ""
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case errors.Is(err, sensoractive.ErrOwnIPUnsupported), errors.Is(err, sensoractive.ErrNucleiFullUnsupported): // A worker without full gets no full job
		reason = templatesOld
	case errors.Is(err, sensoractive.ErrNucleiBusy):
		reason = templatesBusy
	case errors.Is(err, sensoractive.ErrEgressUnverified): // before ErrWorkerRefused, which wraps it
		reason = fmt.Sprintf(templatesNoCheck, ip)
	case errors.Is(err, sensoractive.ErrNotOwnIP):
		reason = fmt.Sprintf(templatesNotOwn, ip)
	case errors.Is(err, sensoractive.ErrPackMismatch):
		reason = templatesPack
	case errors.Is(err, sensoractive.ErrPackInvalid):
		reason = templatesBadPack
	case errors.Is(err, sensoractive.ErrScannerUnavailable):
		reason = templatesNoWork
	case errors.Is(err, sensoractive.ErrWorkerRefused):
		reason = templatesRefused
	default:
		return err
	}
	return &exposure.Unavailable{Reason: reason}
}

// exposureTemplatesFor builds the scanner for exposureService.
func exposureTemplatesFor(d deps, gate ownIPGate,
	mode func(ctx context.Context, actor, id string) (exposure.ScanMode, error)) exposureTemplateScan {
	a := exposureTemplateScan{
		on:   func() bool { return d.Reg == nil || d.Reg.Enabled("sensor-active") },
		pack: nucleipack.Index,
		gate: gate,
		mode: mode,
		probes: func(ctx context.Context, ps []scan.ExternalProbe) error {
			return scanService(d).RecordExternalProbes(ctx, ps)
		},
		log: d.Log,
	}
	if a.log == nil {
		a.log = slog.New(slog.DiscardHandler)
	}
	if d.SensorDispatcher != nil {
		a.run = d.SensorDispatcher.RunNuclei
	}
	return a
}
