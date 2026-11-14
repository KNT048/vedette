package sensoractive

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
)

// Nuclei as a second kind of job (D-125, sensor-protocol.md section 6.4 and 6.5, protocol 2). The scan module is the only
// caller: it has decided the scope, the consent, the window and the templates and has written the probe rows (scan INV-1..7)
// before it calls RunNuclei. The Dispatcher hands the job to the worker in the scan container through the nuclei slot, and
// parses what comes back here, in core, fail closed (nucleiout): the worker is a process that talked to devices an attacker
// may control, and may itself be compromised (SYS-6).

// Errors of the nuclei path. ErrScannerUnavailable (and what wraps it) is "keep the targets, try again later, tell the user
// the scanner is down" (503 scanner_unavailable, D-125 (5)); the others fail the run.
var (
	ErrScannerUnavailable    = errors.New("sensoractive: the vulnerability scanner is not available")
	ErrScanWorkerUnavailable = fmt.Errorf("%w: worker_unavailable", ErrScannerUnavailable)
	ErrNucleiMissing         = fmt.Errorf("%w: nuclei_missing", ErrScannerUnavailable)
	// ErrPackMismatch: the template pack in the scan image is not the one the request was planned against. Nothing was sent, and
	// asking again with the same request cannot succeed: it is not ErrScannerUnavailable (core's pack and the image's pack come
	// from different releases; an update or a new plan fixes it).
	ErrPackMismatch = errors.New("sensoractive: pack_mismatch")
	// ErrPackInvalid: the worker found the image's template pack damaged (a file whose hash is not the index's, a link or a
	// special file in the tree): an integrity signal, never retried, logged at ERROR; not ErrScannerUnavailable.
	ErrPackInvalid     = errors.New("sensoractive: pack_invalid: the template pack in the scan image failed its integrity check")
	ErrOutputTruncated = errors.New("sensoractive: nuclei printed more than the limit; its output is discarded")
	// ErrOwnIPUnsupported: the worker's latest heartbeat does not say own_ip (an older worker, while an update runs): an own_ip
	// job is never sent to it (D-520). Nothing was sent.
	ErrOwnIPUnsupported = errors.New("sensoractive: the scan container's worker is older and runs no own-IP nuclei job")
	// ErrNucleiBusy: an own_ip job found the nuclei slot holding another job (a Scan now of the LAN may run up to an hour), and
	// exposure's 5-minute step does not queue behind it (D-520). Nothing was sent.
	ErrNucleiBusy  = errors.New("sensoractive: the scan container's nuclei is busy with another scan")
	errJSONLTooBig = errors.New("nuclei output is larger than the limit")
)

// NucleiRequest is one nuclei run (D-125 (1), D-136 (4) and (6)): template ids from the pack index, never paths; targets that
// are canonical private IPv4 literals with a port, or for Scope nucleiargv.ScopeOwnIP exactly one public one, the box's own IP
// (D-520: the caller has checked that, and the worker checks it again). The grammar is nucleiargv's; Dispatcher.RunNuclei checks
// it again before the job leaves, and the worker checks it a third time.
type NucleiRequest struct {
	PackVersion, PackSHA256 string
	Templates               []string // template ids, 1..nucleiargv.MaxTemplates
	Targets                 []nucleiargv.Target
	Rate                    int    // requests per second, 1..nucleiargv.MaxRate (own_ip: nucleiargv.OwnIPRate)
	MaxHostErrors           int    // nucleiargv.MinHostErrors..MaxHostErrors
	Scope                   string // "" (LAN) or nucleiargv.ScopeOwnIP
}

// Scanner is the seam the scan module calls (the smallest one: scan's own Engine asks only Ready, and the run is what S5 adds).
// *Dispatcher implements it. A nil Scanner in scan means the scanner is unavailable and nothing is ever sent.
type Scanner interface {
	// Ready returns nil when a job can be sent now: the worker has a fresh heartbeat and says nuclei runs and its image holds a
	// template pack; otherwise it says why (NucleiHealth).
	Ready(ctx context.Context) error
	// RunNuclei sends the job and returns one Result per line nuclei printed, after the output was parsed fail closed: one line
	// that is not what the job asked for makes the whole run an error. It also returns the host errors the worker counted
	// (targets that stopped answering, INV-6), each checked against the request: a target the job did not name, or an
	// Unreachable that does not follow from the count and the job's MaxHostErrors, makes the run an error too. ctx carries
	// the deadline (at most one hour reaches the worker) and cancelling it stops the run: the worker kills nuclei within seconds.
	RunNuclei(ctx context.Context, r NucleiRequest) (nucleiout.Outcome, error)
}

var _ Scanner = (*Dispatcher)(nil)

var (
	templateIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`) // the template id of the pack index
	packVersion  = regexp.MustCompile(`^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,4}$`)
	packSHA      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Ready implements Scanner (and scan.Engine). The error says which of the reasons it is: ErrScanWorkerUnavailable,
// ErrNucleiMissing, or ErrScannerUnavailable alone (an overrun not yet stopped, no pack); all of them wrap ErrScannerUnavailable.
func (d *Dispatcher) Ready(context.Context) error {
	msg, base := d.nucleiProblem(false)
	if msg == "" {
		return nil
	}
	return fmt.Errorf("%w: %s", base, msg)
}

// check is the grammar of a nuclei job as core applies it before dispatch: the one of nucleiargv (Build refuses every target,
// rate and count outside it) with each template id stood in for by a path of its own, since core knows ids and the worker's
// index knows paths.
func (r NucleiRequest) check() error {
	if !packVersion.MatchString(r.PackVersion) || !packSHA.MatchString(r.PackSHA256) {
		return errors.New("the pack has no valid version or hash")
	}
	paths := make([]string, len(r.Templates))
	for i, id := range r.Templates {
		if !templateIDRE.MatchString(id) || slices.Contains(r.Templates[:i], id) {
			return fmt.Errorf("template id %q is not valid or is repeated", id)
		}
		paths[i] = "t" + strconv.Itoa(i) + ".yaml"
	}
	if r.Scope == nucleiargv.ScopeLAN { // the wire says LAN by leaving the scope out: a worker of protocol 5 reads the job it knows
		return errors.New(`the LAN scope is "" in a request`)
	}
	if _, err := nucleiargv.Build(nucleiargv.Job{Templates: paths, Targets: r.Targets, Rate: r.Rate, MaxHostErrors: r.MaxHostErrors, Scope: r.Scope}); err != nil {
		return err
	}
	return nil
}

// checkPack compares the pack the request needs with the pack of the worker's latest heartbeat, before anything is sent.
func (d *Dispatcher) checkPack(r NucleiRequest) error {
	d.mu.Lock()
	have := d.nuclei.Pack
	d.mu.Unlock()
	if have.Version != r.PackVersion || have.SHA256 != r.PackSHA256 {
		return fmt.Errorf("%w: the scan image has template pack %s (%.12s), the request needs %s (%.12s)", ErrPackMismatch, have.Version, have.SHA256, r.PackVersion, r.PackSHA256)
	}
	return nil
}

// RunNuclei implements Scanner.
func (d *Dispatcher) RunNuclei(ctx context.Context, r NucleiRequest) (nucleiout.Outcome, error) {
	if err := r.check(); err != nil {
		return nucleiout.Outcome{}, fmt.Errorf("sensoractive: %w", err)
	}
	if err := d.Ready(ctx); err != nil {
		return nucleiout.Outcome{}, err
	}
	if err := d.checkPack(r); err != nil {
		return nucleiout.Outcome{}, err
	}
	if r.Scope == nucleiargv.ScopeOwnIP { // D-520: only a worker that said own_ip, and never queued behind a scan of the LAN
		d.mu.Lock()
		ok := d.nuclei.OwnIP
		busy := d.nucSlot.pending != nil || d.nucSlot.running != nil && !d.nucSlot.running.finished
		d.mu.Unlock()
		switch {
		case !ok:
			return nucleiout.Outcome{}, ErrOwnIPUnsupported
		case busy:
			return nucleiout.Outcome{}, ErrNucleiBusy
		}
	}
	if err := ctx.Err(); err != nil {
		return nucleiout.Outcome{}, err
	}
	spec := sensorlink.Job{ID: randomHex(), Kind: sensorlink.KindNuclei, Nuclei: &sensorlink.NucleiJob{
		Pack:          sensorlink.JobPack{Version: r.PackVersion, SHA256: r.PackSHA256},
		Templates:     slices.Clone(r.Templates),
		Targets:       make([]sensorlink.NucleiTarget, len(r.Targets)),
		Rate:          r.Rate,
		MaxHostErrors: r.MaxHostErrors,
		Scope:         r.Scope,
	}}
	hostPort := make([]string, len(r.Targets))
	for i, t := range r.Targets {
		spec.Nuclei.Targets[i] = sensorlink.NucleiTarget{Host: t.Host, Port: t.Port, Scheme: t.Scheme}
		hostPort[i] = t.Host + ":" + strconv.Itoa(t.Port)
	}
	j := &djob{spec: spec}
	if err := d.await(ctx, d.nucSlot, j); err != nil {
		if errors.Is(err, ErrWorkerUnavailable) {
			return nucleiout.Outcome{}, ErrScanWorkerUnavailable
		}
		return nucleiout.Outcome{}, err
	}
	out, err := d.nucleiOutcome(j)
	if err != nil {
		return nucleiout.Outcome{}, err
	}
	res, err := nucleiout.Parse(out, r.Templates, hostPort)
	if err != nil {
		d.log.WarnContext(ctx, "sensor_active_nuclei_output_rejected", "error", err) // the text is built from nuclei's bytes: the log gets the parser's own words only
		return nucleiout.Outcome{}, fmt.Errorf("%w: %w", ErrResultRejected, err)
	}
	he, err := hostErrorsOf(j.res.HostErrors, hostPort, r.MaxHostErrors)
	if err != nil {
		d.log.WarnContext(ctx, "sensor_active_nuclei_host_errors_rejected", "error", err)
		return nucleiout.Outcome{}, fmt.Errorf("%w: %w", ErrResultRejected, err)
	}
	return nucleiout.Outcome{Results: res, HostErrors: he}, nil
}

// hostErrorsOf checks the worker's host errors against the request (the wire shape was checked by sensorlink): every target
// is one the job named, and Unreachable is exactly "Errors reached the job's MaxHostErrors". Fail closed: a worker that
// says otherwise is not believed.
func hostErrorsOf(in []sensorlink.HostError, targets []string, maxHostErrors int) ([]nucleiout.HostError, error) {
	out := make([]nucleiout.HostError, 0, len(in))
	for _, h := range in {
		if !slices.Contains(targets, h.Target) {
			return nil, errors.New("host_errors names a target the job did not")
		}
		if h.Unreachable != (h.Errors >= maxHostErrors) {
			return nil, errors.New("host_errors: unreachable does not follow from the count")
		}
		out = append(out, nucleiout.HostError{Target: h.Target, Errors: h.Errors, Unreachable: h.Unreachable})
	}
	return out, nil
}

// nucleiOutcome turns a finished nuclei job into its stdout. Like nmap's, only the exit code, the truncation and the
// bytes count; the status and the reason of the worker explain a failure and never excuse one.
func (d *Dispatcher) nucleiOutcome(j *djob) ([]byte, error) {
	if j.err != nil {
		return nil, j.err
	}
	res := j.res
	switch {
	case res.Status == "refused" && res.Reason == "pack_mismatch":
		d.log.Error("sensor_active_worker_refused_job", "reason", res.Reason) // the image's pack is not the pack core planned with
		return nil, ErrPackMismatch
	case res.Status == "refused" && res.Reason == "not_own_ip": // the worker's own-IP fence of an own_ip job (D-520), as for nmap's external shape
		d.log.Warn("sensor_active_worker_refused_own_ip_job", "reason", res.Reason)
		return nil, fmt.Errorf("%w (%s): %w", ErrWorkerRefused, res.Reason, ErrNotOwnIP)
	case res.Status == "refused" && res.Reason == "egress_unverified":
		d.log.Warn("sensor_active_worker_refused_own_ip_job", "reason", res.Reason)
		return nil, fmt.Errorf("%w (%s): %w", ErrWorkerRefused, res.Reason, ErrEgressUnverified)
	case res.Status == "refused" && res.Reason == "pack_invalid":
		d.mu.Lock()
		d.packInvalid, d.packInvalidSHA = true, d.nuclei.Pack.SHA256 // until the image holds another pack
		ver := d.nuclei.Pack.Version
		d.mu.Unlock()
		d.log.Error("sensor_active_template_pack_failed_its_integrity_check", "pack", ver) // tampering or a damaged image
		return nil, ErrPackInvalid
	case res.Status == "refused":
		d.log.Error("sensor_active_worker_refused_job", "reason", res.Reason)
		return nil, fmt.Errorf("%w (%s)", ErrWorkerRefused, res.Reason)
	case res.XML() != nil || res.XMLB64 != "" || len(res.SNMP) > 0:
		return nil, fmt.Errorf("%w: nmap or snmp output on a nuclei job", ErrResultRejected)
	case res.Reason == "nuclei_missing":
		d.mu.Lock()
		d.nuclei.Present = false // until the next heartbeat says otherwise
		d.mu.Unlock()
		return nil, ErrNucleiMissing
	case res.ExitCode > 0:
		return nil, &exec.ExitError{Name: "nuclei", ExitCode: res.ExitCode}
	case res.ExitCode < 0 || res.Status != "done":
		return nil, fmt.Errorf("sensoractive: the worker reported %s (%s), exit %d", res.Status, res.Reason, res.ExitCode)
	case res.Truncated:
		return nil, ErrOutputTruncated
	}
	return res.JSONL(), nil
}
