package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/knt048/vedette/content/nucleipack"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/pack"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// exposureTemplateScan is exposure's TemplateScanner (S-EXP-2, exposure INV-23, D-561, D-520): the safe nuclei templates of the
// exploited CVEs matched on a port of the box's own verified public IP, run by the scan container's worker through sensor-active's
// Dispatcher with scope own_ip. exposureService sets it as cfg.Templates; the commitment sentence of NoticeVersion 2026-11-14 (D-559,
// K-4) names "safe checks for known exploited vulnerabilities", and PRIVACY flow 9 says what is sent.
//
// Two fences before a packet leaves, both fail closed: (1) core: right before each run, exposure's ScannableIP with the person who
// pressed Scan now as the actor (verified, committed, the box's own IP seen within 5 minutes, else a fresh full check); (2) the
// worker: nucleiargv's own_ip grammar (one public IPv4, the job's port, 5 requests a second), the own_ip mark of each template in
// its own index and its own read of each template file (pack.OwnIPText), and its own check, with the three public IP services,
// that the box goes out through that address. No argv goes over the wire.
//
// Templates come only from the verified pack core plans with (content/nucleipack, the index of the image; the worker refuses a job
// planned for another pack): the template of each CVE of a job (pack.ForCVE; in the KEV pack its id is the CVE id), none chosen by
// tag, and only one the pack marks own_ip (pack.Template.OwnIP: http GET or HEAD only, no body, no credential, no command, D-520).
// A CVE whose template is not marked gets a "not run on a public IP" line. Each template is a row of the probe log, with its real
// id, before its run is handed out (LEGAL §3), and is completed with its outcome after.
type exposureTemplateScan struct {
	on     func() bool                 // sensor-active is on: it runs the scan container
	pack   func() (*pack.Index, error) // the pack core plans with
	run    func(ctx context.Context, r sensoractive.NucleiRequest) (nucleiout.Outcome, error)
	gate   func(ctx context.Context, actor string, ip netip.Addr) (bool, error)
	probes func(ctx context.Context, ps []scan.ExternalProbe) error // the scan module's probe log
	log    *slog.Logger
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

	// notReadOnly is the line of the CVEs of a port whose template may not run on a public IP (D-520).
	notReadOnly = "Safe templates for exploited vulnerabilities: %s on port %d: not run on a public IP: this check is not a read-only request."
	// runSlow and runFailed are the lines of the runs that were not reported after earlier ones were kept (review M2, L2).
	runSlow   = "Safe templates for exploited vulnerabilities did not finish within 5 minutes, so the ones that had not finished are not reported (%s)."
	runFailed = "Safe templates for exploited vulnerabilities on port %d did not run: %s"
)

// templateRun is one nuclei job: at most nucleiargv.MaxTemplates templates on one port.
type templateRun struct {
	port   int
	target nucleiargv.Target
	tmpls  []pack.Template
}

func (a exposureTemplateScan) ScanTemplates(ctx context.Context, t exposure.ScanTarget, ip netip.Addr, jobs []exposure.TemplateJob) (exposure.TemplateScan, error) {
	if a.on != nil && !a.on() {
		return exposure.TemplateScan{}, &exposure.Unavailable{Reason: templatesOff}
	}
	if a.run == nil {
		return exposure.TemplateScan{}, &exposure.Unavailable{Reason: templatesNoWork}
	}
	ix, err := a.pack()
	if err != nil {
		return exposure.TemplateScan{}, err
	}
	runs, notes := templateRuns(ix, ip, jobs)
	out := exposure.TemplateScan{NotChecked: notes}
	for i, r := range runs {
		res, err := a.runOne(ctx, t.User, ip, ix, r)
		if err == nil {
			out.Results = append(out.Results, res...)
			for _, tp := range r.tmpls {
				out.Sent = append(out.Sent, tp.ID)
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
func templateRuns(ix *pack.Index, ip netip.Addr, jobs []exposure.TemplateJob) (runs []templateRun, notes []string) {
	for _, j := range jobs {
		if j.Scope != exposure.ScopeOwnIP || j.Host != ip.String() {
			continue
		}
		var tmpls []pack.Template
		var refused []string
		for _, cve := range j.CVEs {
			all := ix.ForCVE(cve)
			ok := 0
			for _, tp := range all {
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
		target := nucleiargv.Target{Host: ip.String(), Port: j.Port, Scheme: j.Scheme}
		for c := range slices.Chunk(tmpls, nucleiargv.MaxTemplates) {
			runs = append(runs, templateRun{port: j.Port, target: target, tmpls: c})
		}
	}
	return runs, notes
}

// runOne is one run, in this order: the gate (obligation 1), the probe rows with the real template ids (obligation 2, LEGAL §3),
// the job, the results with their CVE (obligation 3), the probe rows completed.
func (a exposureTemplateScan) runOne(ctx context.Context, actor string, ip netip.Addr, ix *pack.Index, r templateRun) ([]exposure.TemplateResult, error) {
	ok, err := a.gate(ctx, actor, ip)
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		return nil, fmt.Errorf("vedette: checking that %s may still be scanned: %w", ip, err)
	case !ok:
		return nil, &exposure.Unavailable{Reason: fmt.Sprintf(templatesNotOwn, ip)}
	}
	rows := make([]scan.ExternalProbe, len(r.tmpls))
	ids := make([]string, len(r.tmpls))
	for i, tp := range r.tmpls {
		ids[i] = tp.ID
		rows[i] = scan.ExternalProbe{ID: store.NewID("tp"), IP: ip.String(), Label: fmt.Sprintf("%s:%d", ip, r.port), Template: tp.ID,
			Request: fmt.Sprintf("nuclei %s to %s (own IP, at most %d requests a second): %s", tp.ID, r.target.Input(), nucleiargv.OwnIPRate, tp.Request)}
	}
	if err := a.probes(ctx, rows); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		a.log.ErrorContext(ctx, "exposure: writing the probe log of the safe templates failed", "ip", ip.String(), "error", err)
		return nil, &exposure.Unavailable{Reason: templatesNoLog}
	}
	got, err := a.run(ctx, sensoractive.NucleiRequest{PackVersion: ix.Version, PackSHA256: ix.SHA256, Templates: ids,
		Targets: []nucleiargv.Target{r.target}, Rate: nucleiargv.OwnIPRate, MaxHostErrors: templatesHostErrors, Scope: nucleiargv.ScopeOwnIP})
	if err != nil {
		return nil, templatesErr(ctx, ip, err)
	}
	res := outcomes(r, got)
	for i := range rows {
		rows[i].Result = ""
		for _, x := range res {
			if x.Template == rows[i].Template {
				rows[i].Result = map[string]string{exposure.OutcomeMatched: "matched", exposure.OutcomeNoMatch: "not_matched"}[x.Outcome]
			}
		}
	}
	if err := a.probes(context.WithoutCancel(ctx), rows); err != nil { // the rows stay "sent, no answer": the results still count
		a.log.WarnContext(ctx, "exposure: completing the probe log of the safe templates failed", "ip", ip.String(), "error", err)
	}
	return res, nil
}

// outcomes reads a run's parsed lines (nucleiout already kept only the job's templates and target, fail closed) into one result per
// template: matched when a line matched, error when a line carries an error or the address stopped answering before the template
// printed a line, no_match when it printed lines and none matched. A template without a line and an address that kept answering
// has no result (nuclei did not run it): exposure says "no result" for its CVE.
func outcomes(r templateRun, o nucleiout.Outcome) []exposure.TemplateResult {
	unreachable := slices.ContainsFunc(o.HostErrors, func(h nucleiout.HostError) bool { return h.Unreachable })
	var out []exposure.TemplateResult
	for _, tp := range r.tmpls {
		seen, matched, failed := false, false, false
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
		case !seen:
			continue
		}
		out = append(out, exposure.TemplateResult{Port: r.port, Template: tp.ID, CVE: tp.CVE, Outcome: outcome})
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
	case errors.Is(err, sensoractive.ErrOwnIPUnsupported):
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
func exposureTemplatesFor(d deps, gate func(ctx context.Context, actor string, ip netip.Addr) (bool, error)) exposureTemplateScan {
	a := exposureTemplateScan{
		on:   func() bool { return d.Reg == nil || d.Reg.Enabled("sensor-active") },
		pack: nucleipack.Index,
		gate: gate,
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
