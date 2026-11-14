package sensoractive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// The remote Prober (D-113, sensor-protocol.md section 6.4 and 6.5). The Dispatcher keeps one job in memory: the
// service has already checked the scope, the window and the settings and written the probe row (INV-1..3, INV-9);
// the worker in the scan container fetches the job by long poll, re-checks it, runs nmap and posts the result. Core
// never trusts what the worker says about itself beyond "it ran": the exit code, the size and the XML are checked
// here and by parseNmapXML.
const (
	// heartbeatTimeout is how long without a heartbeat before the worker counts as gone (sensor-protocol.md 6.3).
	heartbeatTimeout = 90 * time.Second
	// pickupTimeout is how long a job may wait for the worker to fetch it.
	pickupTimeout = 60 * time.Second
	// cancelGrace is how long after its context ended a probe waits for the worker to confirm the stop; then it counts
	// as stopped (the next job still waits until the worker says it runs nothing).
	cancelGrace = 30 * time.Second
	// maxJobSeconds is the longest job the protocol carries (2 hours).
	maxJobSeconds = 7200
	// maxNucleiSeconds is the longest nuclei job (D-125 (1)).
	maxNucleiSeconds = 3600
	dispatchTick     = time.Second
)

// Errors of the remote Prober. ErrWorkerUnavailable and ErrNmapMissing wrap ErrUnavailable (INV-6): the queue keeps
// the device and tries again later. ErrWorkerLost, ErrWorkerRefused and ErrResultRejected fail the probe.
var (
	ErrWorkerUnavailable = fmt.Errorf("%w: worker_unavailable", ErrUnavailable)
	ErrNmapMissing       = fmt.Errorf("%w: nmap_missing", ErrUnavailable)
	ErrWorkerLost        = errors.New("sensoractive: worker_lost")
	ErrWorkerRefused     = errors.New("sensoractive: the worker refused the job")
	ErrResultRejected    = errors.New("sensoractive: the worker's result was rejected")
)

// DispatcherOptions configures a Dispatcher. Both fields are for tests.
type DispatcherOptions struct {
	// Now is the clock of the heartbeat, pickup and grace timeouts. nil means time.Now.
	Now func() time.Time
	// Tick is how often a waiting probe looks at those timeouts. 0 means one second.
	Tick time.Duration
	Log  *slog.Logger
	// ContainerOnly is the install kind (modreg.Registry.ContainerOnly, D-381): the health texts then give the advice that fits a
	// customer who runs the compose files, not the appliance's "rebuilt" (D-168 (4)).
	ContainerOnly bool
}

// Dispatcher is the Prober that hands a job to the worker, and the sensorlink.Backend of the active role: the
// listener of core serves Jobs, JobRunning, JobResult and ActiveHeartbeat to it. Create it with NewDispatcher. It has three
// slots, nmap, nuclei (D-125 (3)) and snmp (D-512): one job of each kind may run at once, so a "Scan now" or an SNMP Test does
// not wait for a two-hour sweep. The rules of a slot (lease, pickup, grace, cancel) are those of SP-3 for all.
type Dispatcher struct {
	now       func() time.Time
	tick      time.Duration
	log       *slog.Logger
	instance  string
	container bool // DispatcherOptions.ContainerOnly

	mu       sync.Mutex
	wake     chan struct{} // closed and replaced whenever something a long poll looks at changes
	nmapSlot *slot
	nucSlot  *slot
	snmpSlot *slot           // D-512: the SNMP reads, beside nmap and nuclei
	orphans  map[string]bool // ids the worker reported that core does not know, already answered with a cancel
	beatAt   time.Time
	haveBeat bool
	nmap     sensorlink.HeartbeatNmap
	nuclei   sensorlink.HeartbeatNuclei
	snmp     bool // the worker's heartbeat says it runs snmp jobs (protocol 5)
	domainIP bool // the worker's heartbeat says it runs domain_ip jobs: it holds the fence key (D-591)

	packInvalid    bool   // the worker found the image's pack damaged (pack_invalid): not trusted until the image holds another pack
	packInvalidSHA string // the pack hash the heartbeat reported when it happened
}

// slot is the state of one kind of job. At most one job of the kind is handed to the worker at a time.
type slot struct {
	kind       string
	maxSeconds int
	pending    *djob  // waiting for the worker to fetch it
	running    *djob  // fetched and not finished (it may be abandoned: its probe stopped, the worker not yet)
	lastDone   string // the job that finished last
	doneSent   bool   // a poll that still named it has been answered at once
	byResult   bool   // lastDone ended with a result from the worker (not lost, not rejected)
	overrun    string // the id of a job that ran past its limit and was given up; until a poll no longer names it
}

func (d *Dispatcher) slots() [numSlots]*slot {
	return [numSlots]*slot{d.nmapSlot, d.nucSlot, d.snmpSlot}
}

// numSlots is the kinds of job the worker runs at once (sensorlink.MaxRunning).
const numSlots = sensorlink.MaxRunning

type djob struct {
	spec      sensorlink.Job
	deadline  time.Time // of the probe's context, zero when it has none
	done      chan struct{}
	finished  bool
	res       *sensorlink.JobResult
	err       error
	exclusive bool // an own_ip nuclei job (D-520): refused with ErrNucleiBusy instead of waiting for a busy slot
	cancelled bool // the probe stopped after the worker had the job: cancel it
	cancelOut bool // a poll reply has carried the cancel

	ctxDone     <-chan struct{} // of the probe's context: a pending job whose probe is over is dropped
	ctxErr      func() error
	deliveredAt time.Time // when the worker fetched it
	lastPoll    time.Time // the latest poll that named it as running: the proof the worker is alive and has it
}

// NewDispatcher returns a Dispatcher with a fresh instance nonce, the one the worker's lease is tied to.
func NewDispatcher(o DispatcherOptions) *Dispatcher {
	d := &Dispatcher{now: o.Now, tick: o.Tick, log: o.Log, container: o.ContainerOnly, wake: make(chan struct{}), orphans: map[string]bool{},
		nmapSlot: &slot{kind: sensorlink.KindNmap, maxSeconds: maxJobSeconds}, nucSlot: &slot{kind: sensorlink.KindNuclei, maxSeconds: maxNucleiSeconds},
		snmpSlot: &slot{kind: sensorlink.KindSNMP, maxSeconds: sensorlink.MaxSNMPSeconds}}
	if d.now == nil {
		d.now = time.Now
	}
	if d.tick <= 0 {
		d.tick = dispatchTick
	}
	if d.log == nil {
		d.log = slog.New(slog.DiscardHandler)
	}
	d.instance = randomHex()
	return d
}

func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24)
	return hex.EncodeToString(b)
}

// signal wakes every long poll. The caller holds mu.
func (d *Dispatcher) signal() {
	close(d.wake)
	d.wake = make(chan struct{})
}

// fresh reports whether the worker's last heartbeat is recent. The caller holds mu.
func (d *Dispatcher) fresh(now time.Time) bool {
	return d.haveBeat && now.Sub(d.beatAt) <= heartbeatTimeout
}

// expireLocked gives up the running job of a slot whose worker has stopped answering for it: no poll naming it for 90 seconds,
// or no result within its timeout plus the 30 seconds of grace (a stuck nmap is not left to block the box for ever). The job is
// lost; the next poll that still names it gets a cancel (pollLocked). The caller holds mu.
func (d *Dispatcher) expireLocked(now time.Time) {
	for _, s := range d.slots() {
		j := s.running
		if j == nil || j.finished {
			continue
		}
		switch {
		case now.Sub(j.lastPoll) > heartbeatTimeout:
		case now.Sub(j.deliveredAt) > time.Duration(j.spec.TimeoutS)*time.Second+cancelGrace:
			s.overrun = j.spec.ID
		default:
			continue
		}
		s.running = nil
		d.finishLocked(s, j, nil, ErrWorkerLost)
	}
}

// NmapHealth is "" when the worker can run nmap, otherwise what the status page says (INV-6): no heartbeat for 90 s,
// or the heartbeat says nmap is missing.
func (d *Dispatcher) NmapHealth() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.expireLocked(now)
	switch {
	case !d.haveBeat:
		return "the scan worker has not reported since core started; active discovery runs once it does (the scan container, on a container-only install from compose.sensors.yaml)"
	case !d.fresh(now):
		return "the scan worker has not reported for 90 seconds; active discovery cannot run until it does"
	case d.nmapSlot.overrun != "":
		return "the scan worker ran a job past its time limit; core has told it to stop, and active discovery waits until it has"
	case len(d.orphans) > 0:
		return orphanMessage("active discovery")
	case !d.nmap.Present:
		return d.nmapMissing()
	}
	return ""
}

// nmapMissing is the health text for a scan worker without nmap. The appliance builds its scan image from the OS packages;
// the project's image for a container-only install has no nmap by design (it is not shipped, D-168 (4)), so "rebuild" would
// be wrong advice there.
func (d *Dispatcher) nmapMissing() string {
	if d.container {
		return "nmap is not installed in the scan container; the Vedette scan image does not include nmap, so active discovery is off on a container-only install"
	}
	return "nmap is not installed in the scan container; active discovery cannot run until the scan image is rebuilt"
}

// imageFix is the end of a "cannot run until ..." text for a damaged or incomplete scan image.
func (d *Dispatcher) imageFix() string {
	if d.container {
		return "you pull the scan image of this release again (docker compose --env-file vedette.env pull, then up -d; podman compose on Podman)"
	}
	return "the scan image is rebuilt"
}

// orphanMessage is what both health messages say while the worker names a job core does not know (one it gave up, or one of a
// core that restarted): it has been told to stop it, and no job of either kind goes out until it has.
func orphanMessage(what string) string {
	return "the scan worker is still running a job that core does not know; core has told it to stop, and " + what + " waits until it has"
}

// NucleiHealth is "" when the worker can run nuclei with a template pack, otherwise what the status page says (D-125 (5)):
// no heartbeat for 90 s, nuclei missing, or no pack in the image.
func (d *Dispatcher) NucleiHealth() string {
	msg, _ := d.nucleiProblem(true)
	return msg
}

// nucleiProblem is NucleiHealth with the error that goes with the message (nil base when there is no problem).
func (d *Dispatcher) nucleiProblem(forHealth bool) (msg string, base error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.expireLocked(now)
	switch {
	case !d.haveBeat:
		return "the scan worker has not reported since core started; vulnerability scanning runs once it does (the scan container, on a container-only install from compose.sensors.yaml)", ErrScanWorkerUnavailable
	case !d.fresh(now):
		return "the scan worker has not reported for 90 seconds; vulnerability scanning cannot run until it does", ErrScanWorkerUnavailable
	case d.nucSlot.overrun != "":
		return "the scan worker ran a nuclei job past its time limit; core has told it to stop, and vulnerability scanning waits until it has", ErrScannerUnavailable
	case forHealth && len(d.orphans) > 0: // a status message only: a request still queues and waits for the worker to be free
		return orphanMessage("vulnerability scanning"), ErrScannerUnavailable
	case d.packInvalid && d.nuclei.Pack.SHA256 == d.packInvalidSHA:
		return "ERROR: the template pack in the scan image failed its integrity check (a changed file, or a link or special file in it); vulnerability scanning is off until the scan image is replaced", ErrPackInvalid
	case !d.nuclei.Present:
		return "nuclei is not installed in the scan container; vulnerability scanning cannot run until " + d.imageFix(), ErrNucleiMissing
	case d.nuclei.Pack.SHA256 == "":
		return "the scan image has no usable template pack; vulnerability scanning cannot run until " + d.imageFix(), ErrScannerUnavailable
	}
	return "", nil
}

func (d *Dispatcher) usable() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case !d.fresh(d.now()):
		return ErrWorkerUnavailable
	case !d.nmap.Present:
		return ErrNmapMissing
	}
	return nil
}

// Probe implements Prober. argv is what nmapargv.Build made; the job on the wire carries its shape, rate and targets
// and no argv (D-111 (3)). It returns when the result is in, when the worker is gone, or when ctx ended and the worker
// had 30 seconds to confirm the stop.
func (d *Dispatcher) Probe(ctx context.Context, argv []string) (Output, error) {
	return d.probe(ctx, argv, nil)
}

// ProbeDomain implements DomainProber: Probe of a full shape with one target as a domain_ip job (D-591), sent only to a worker whose
// heartbeat says domain_ip (else ErrDomainUnsupported, nothing sent); the worker checks the domain fence itself before nmap.
func (d *Dispatcher) ProbeDomain(ctx context.Context, argv []string, scope sensorlink.DomainScope) (Output, error) {
	return d.probe(ctx, argv, &scope)
}

func (d *Dispatcher) probe(ctx context.Context, argv []string, scope *sensorlink.DomainScope) (Output, error) {
	kind, rate, targets, err := nmapargv.Parse(argv)
	if err != nil {
		return Output{}, fmt.Errorf("sensoractive: %w", err)
	}
	if err := d.usable(); err != nil {
		return Output{}, err
	}
	if kind.IsFull() { // D-526: only a worker whose heartbeat says it runs the full shapes gets one (pollLocked again at hand-over)
		d.mu.Lock()
		ok := d.nmap.Full
		d.mu.Unlock()
		if !ok {
			return Output{}, ErrFullUnsupported
		}
	}
	if scope != nil {
		if !kind.IsFull() || len(targets) != 1 {
			return Output{}, fmt.Errorf("sensoractive: a domain_ip job is a full shape on one address, not %s on %d", kind.Name(), len(targets))
		}
		d.mu.Lock()
		ok := d.domainIP
		d.mu.Unlock()
		if !ok {
			return Output{}, ErrDomainUnsupported
		}
	}
	if err := ctx.Err(); err != nil {
		return Output{}, err
	}
	j := &djob{spec: sensorlink.Job{ID: randomHex(), Kind: sensorlink.KindNmap, Shape: kind.Name(), Rate: rate, Targets: make([]string, len(targets))}}
	if scope != nil {
		j.spec.Scope, j.spec.Domain = sensorlink.ScopeDomainIP, scope
	}
	for i, t := range targets {
		j.spec.Targets[i] = t.String()
	}
	if err := d.await(ctx, d.nmapSlot, j); err != nil {
		return Output{}, err
	}
	return d.outcome(j)
}

// await hands j to the worker through slot s and waits until it is finished (nil: look at j with outcome), the worker is gone,
// or ctx ended and the worker had 30 seconds to confirm the stop.
func (d *Dispatcher) await(ctx context.Context, s *slot, j *djob) error {
	j.done = make(chan struct{})
	j.deadline, _ = ctx.Deadline()
	j.ctxDone, j.ctxErr = ctx.Done(), ctx.Err

	d.mu.Lock()
	if j.exclusive && (s.pending != nil || s.running != nil && !s.running.finished) { // under the same lock as the hand-over (#review L4)
		d.mu.Unlock()
		return ErrNucleiBusy
	}
	if s.pending != nil {
		d.mu.Unlock()
		return errors.New("sensoractive: a probe is already waiting for the worker") // the service runs one at a time
	}
	s.pending = j
	submitted := d.now()
	d.signal()
	d.mu.Unlock()

	tk := time.NewTicker(d.tick)
	defer tk.Stop()
	ctxDone := ctx.Done()
	var abandonAt time.Time
	for {
		select {
		case <-j.done:
			if abandonAt.IsZero() {
				return nil
			}
			return ctx.Err()
		case <-ctxDone:
			ctxDone = nil
			d.mu.Lock()
			switch {
			case s.pending == j: // the worker never had it: drop it
				s.pending = nil
				d.mu.Unlock()
				return ctx.Err()
			case j.finished:
				d.mu.Unlock()
				return ctx.Err()
			}
			j.cancelled = true // the worker has it (or is just fetching it): the next poll reply carries the cancel
			d.signal()         // and the long poll that is open now is woken to carry it: Stop lands within seconds (D-125 (3))
			d.mu.Unlock()
			abandonAt = d.now().Add(cancelGrace)
		case <-tk.C:
			now := d.now()
			d.mu.Lock()
			err := d.lookLocked(s, j, now, submitted, abandonAt)
			d.mu.Unlock()
			if err != nil {
				if !abandonAt.IsZero() {
					return ctx.Err()
				}
				return err
			}
		}
	}
}

// lookLocked checks the timeouts of a waiting probe and returns the reason it must end now, or nil.
func (d *Dispatcher) lookLocked(s *slot, j *djob, now, submitted, abandonAt time.Time) error {
	d.expireLocked(now) // a job given up here finishes with ErrWorkerLost, which the probe loop returns next
	switch {
	case j.finished:
		return nil
	case s.pending == j && (now.Sub(submitted) >= pickupTimeout || !d.fresh(now)):
		s.pending = nil
		return ErrWorkerUnavailable
	case s.running == j && !abandonAt.IsZero() && !now.Before(abandonAt):
		return ErrStopped // the stop was not confirmed in time; the job stays in running until the worker says it is gone
	}
	return nil
}

// finishLocked records the end of j once and wakes its probe and the long poll.
func (d *Dispatcher) finishLocked(s *slot, j *djob, res *sensorlink.JobResult, err error) {
	if j.finished {
		return
	}
	j.finished, j.res, j.err = true, res, err
	s.lastDone, s.doneSent, s.byResult = j.spec.ID, false, res != nil
	close(j.done)
	d.signal()
}

// outcome turns a finished nmap job into what Prober returns. Only the exit code, the truncation and the XML count; the
// status and the reason of the worker are used to explain a failure, never to excuse one (D-113 (5)).
func (d *Dispatcher) outcome(j *djob) (Output, error) {
	if j.err != nil {
		return Output{}, j.err
	}
	res := j.res
	switch {
	case res.Status == "refused" && res.Reason == "not_own_ip":
		// The worker's own-IP fence (D-514): it sees the box leave the Internet through another address than the external job's.
		d.log.Warn("sensor_active_worker_refused_external_job", "reason", res.Reason)
		return Output{}, fmt.Errorf("%w (%s): %w", ErrWorkerRefused, res.Reason, ErrNotOwnIP)
	case res.Status == "refused" && res.Reason == "egress_unverified":
		// The fence could not ask the public IP services (no route, DNS, TLS, no agreement): nothing is known, so nothing is sent.
		d.log.Warn("sensor_active_worker_refused_external_job", "reason", res.Reason)
		return Output{}, fmt.Errorf("%w (%s): %w", ErrWorkerRefused, res.Reason, ErrEgressUnverified)
	case res.Status == "stopped" && res.Reason == "not_own_ip":
		// The re-check of a running full job (D-526, review r1 H1): nmap ran and was killed, its output discarded.
		d.log.Warn("sensor_active_worker_stopped_external_job", "reason", res.Reason)
		return Output{}, fmt.Errorf("%w (%s): %w", ErrStoppedMidRun, res.Reason, ErrNotOwnIP)
	case res.Status == "stopped" && res.Reason == "egress_unverified":
		d.log.Warn("sensor_active_worker_stopped_external_job", "reason", res.Reason)
		return Output{}, fmt.Errorf("%w (%s): %w", ErrStoppedMidRun, res.Reason, ErrEgressUnverified)
	case j.spec.Domain != nil && domainReason(res):
		return Output{}, d.domainRefused(res)
	case res.Status == "refused":
		d.log.Error("sensor_active_worker_refused_job", "reason", res.Reason) // core and worker disagree on the grammar, or the worker is not what it should be
		return Output{}, fmt.Errorf("%w (%s)", ErrWorkerRefused, res.Reason)
	case res.JSONL() != nil || res.JSONLB64 != "" || len(res.HostErrors) > 0 || len(res.SNMP) > 0:
		return Output{}, fmt.Errorf("%w: nuclei or snmp output on an nmap job", ErrResultRejected)
	case res.Reason == "nmap_missing":
		d.mu.Lock()
		d.nmap.Present = false // until the next heartbeat says otherwise
		d.mu.Unlock()
		return Output{}, ErrNmapMissing
	case res.ExitCode > 0:
		return Output{}, &exec.ExitError{Name: "nmap", ExitCode: res.ExitCode}
	case res.ExitCode < 0 || res.Status != "done":
		return Output{}, fmt.Errorf("sensoractive: the worker reported %s (%s), exit %d", res.Status, res.Reason, res.ExitCode)
	}
	return Output{XML: res.XML(), Truncated: res.Truncated}, nil
}

// ---- sensorlink.Backend, active role ----

// Jobs implements sensorlink.Backend: one long poll of the worker. running holds the jobs the worker says it runs.
func (d *Dispatcher) Jobs(ctx context.Context, wait time.Duration, running []string) (sensorlink.JobsReply, error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		d.mu.Lock()
		rep, ready := d.pollLocked(running)
		wake := d.wake
		d.mu.Unlock()
		if ready {
			return rep, nil
		}
		select {
		case <-wake:
		case <-timer.C:
			return rep, nil
		case <-ctx.Done():
			return rep, nil
		}
	}
}

// pollLocked decides what a poll gets. ready says to answer now rather than keep holding it.
func (d *Dispatcher) pollLocked(running []string) (rep sensorlink.JobsReply, ready bool) {
	now := d.now()
	rep = sensorlink.JobsReply{Instance: d.instance, Jobs: []sensorlink.Job{}, Cancel: []string{}}
	d.expireLocked(now)
	slots := d.slots()
	for _, s := range slots {
		if j := s.running; j != nil && !j.finished && !slices.Contains(running, j.spec.ID) {
			// The worker runs nothing of this kind, or something else, and has not answered: it restarted, or its reply was
			// lost (D-113 (4)).
			s.running = nil
			d.finishLocked(s, j, nil, ErrWorkerLost)
		}
	}
	answerNow := false
	var blocked [numSlots]bool // a slot whose kind the worker is not free for: it still names a job core cannot place in another slot
	for _, id := range running {
		var owner *slot
		justDone := false
		for _, s := range slots {
			switch {
			case s.running != nil && s.running.spec.ID == id:
				owner = s
			case s.lastDone == id && s.byResult:
				owner, justDone = s, true
			}
		}
		switch {
		case owner == nil:
			// The worker runs a job core does not hold: one it gave up (lost, over its limit), or one of a core that restarted.
			// Nothing is listening for its result and the scope, the window and the settings were checked for a job that is
			// gone: tell the worker to stop it, at once the first time (INV-3). It cannot be placed in a slot, so it holds all.
			rep.Cancel = append(rep.Cancel, id)
			if !d.orphans[id] {
				d.orphans[id], ready = true, true
			}
			blocked = [numSlots]bool{true, true, true}
		case justDone:
			// The poll still names the job that has just finished: answer now, once, so the worker polls again with a free
			// hand and the next job does not wait for a long poll to run out.
			blocked[slices.Index(slots[:], owner)] = true
			if !owner.doneSent {
				owner.doneSent, answerNow = true, true // the rest of the ids of this poll are still handled below
			}
		default:
			j := owner.running
			j.lastPoll = now // this poll names it: the worker is alive and has it
			if j.cancelled {
				rep.Cancel = append(rep.Cancel, id)
				if !j.cancelOut {
					j.cancelOut, ready = true, true
				}
			}
		}
	}
	for id := range d.orphans {
		if !slices.Contains(running, id) {
			delete(d.orphans, id)
		}
	}
	for _, s := range slots {
		if s.overrun != "" && !slices.Contains(running, s.overrun) {
			s.overrun = "" // the worker is free of it
		}
	}
	if answerNow {
		return rep, true
	}
	for i, s := range slots {
		if j := s.pending; j != nil {
			select {
			case <-j.ctxDone: // its probe is over: nobody wants the job
				s.pending = nil
				d.finishLocked(s, j, nil, j.ctxErr())
			default:
			}
		}
		if s.pending == nil || s.running != nil || blocked[i] {
			continue
		}
		if s == d.snmpSlot && !d.snmp {
			continue // the latest heartbeat says this worker runs no snmp job (protocol 4, or a downgrade since RunSNMP checked): wait
		}
		if n := s.pending.spec.Nuclei; n != nil && n.Scope != "" && !d.nuclei.OwnIP {
			continue // the latest heartbeat says this worker runs no own_ip job (older than D-520, or a downgrade since RunNuclei checked): wait
		}
		if n := s.pending.spec.Nuclei; n != nil && n.Depth != "" && !d.nuclei.Full {
			continue // FULL-4 (D-527): the same for a job of depth full and nuclei.full
		}
		if (s.pending.spec.Domain != nil || s.pending.spec.Nuclei != nil && s.pending.spec.Nuclei.Domain != nil) && !d.domainIP {
			continue // D-591: the latest heartbeat says this worker holds no fence key (or a downgrade since the job was asked): wait
		}
		if k, _ := nmapargv.KindOf(s.pending.spec.Shape); s == d.nmapSlot && k.IsFull() && !d.nmap.Full {
			continue // the latest heartbeat says this worker runs no full shape (older than D-526, or a downgrade since Probe checked): wait
		}
		j := s.pending
		secs := s.maxSeconds
		if !j.deadline.IsZero() {
			secs = min(secs, int(math.Ceil(time.Until(j.deadline).Seconds())))
		}
		if secs < 1 {
			continue // its probe is about to stop; await drops it
		}
		j.spec.TimeoutS = secs
		j.deliveredAt, j.lastPoll = now, now
		s.pending, s.running = nil, j
		rep.Jobs = append(rep.Jobs, j.spec)
		ready = true
	}
	return rep, ready
}

// runningSlot returns the slot whose running job is id, or nil.
func (d *Dispatcher) runningSlot(id string) *slot {
	for _, s := range d.slots() {
		if s.running != nil && s.running.spec.ID == id && !s.running.finished {
			return s
		}
	}
	return nil
}

// JobRunning implements sensorlink.Backend: id is a job handed to the worker and not finished.
func (d *Dispatcher) JobRunning(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.runningSlot(id) != nil
}

// JobResult implements sensorlink.Backend. A result of any job but a running one is unknown, which is also what a
// second copy of a result gets.
func (d *Dispatcher) JobResult(_ context.Context, id string, res *sensorlink.JobResult) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.runningSlot(id)
	if s == nil {
		return sensorlink.NewError(sensorlink.CodeUnknownJob)
	}
	j := s.running
	s.running = nil
	d.finishLocked(s, j, res, nil)
	return nil
}

// JobResultRejected implements sensorlink.ResultRejector: the server refused the body of the result (413 or 400). The
// worker does not send it again, so the probe fails now.
func (d *Dispatcher) JobResultRejected(id string, e *sensorlink.Error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.runningSlot(id)
	if s == nil {
		return
	}
	j := s.running
	s.running = nil
	err := fmt.Errorf("%w: %s", ErrResultRejected, e.Code)
	if e.Code == sensorlink.CodePayloadTooLarge {
		big := errXMLTooBig
		if s.kind == sensorlink.KindNuclei {
			big = errJSONLTooBig
		}
		err = fmt.Errorf("%w: %w", big, err)
	}
	d.finishLocked(s, j, nil, err)
}

// ActiveHeartbeat implements sensorlink.Backend and feeds Health.
func (d *Dispatcher) ActiveHeartbeat(_ context.Context, hb *sensorlink.ActiveHeartbeat) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.beatAt, d.haveBeat, d.nmap, d.nuclei, d.snmp, d.domainIP = d.now(), true, hb.Nmap, hb.Nuclei, hb.SNMP, hb.DomainIP
	return d.instance, nil
}

// ---- the domain fence (D-591) ----

var (
	// ErrDomainUnsupported is returned when the worker's latest heartbeat does not say domain_ip (it holds no fence key: a remote sensor, a container-only
	// install, or an older worker). A domain_ip job is never sent to it. Nothing was sent.
	ErrDomainUnsupported = errors.New("sensoractive: the scan container's worker runs no domain_ip job (it has no fence key, or it is older)")
	// ErrDomainRefused is the refusal of the worker's own domain fence (DomainRefusedError says why), also when it stopped a job while
	// it ran (then the error is ErrStoppedMidRun too).
	ErrDomainRefused = errors.New("sensoractive: the scan container's domain fence refused the job")
)

// DomainRefusedError is ErrDomainRefused with the fence's reason (core/domainfence.Reasons). MidRun: the re-check during a deep nmap
// stopped it and its output was discarded.
type DomainRefusedError struct {
	Reason string
	MidRun bool
}

func (e *DomainRefusedError) Error() string {
	if e.MidRun {
		return "sensoractive: the scan container's domain fence stopped the job while it ran (" + e.Reason + ")"
	}
	return "sensoractive: the scan container's domain fence refused the job (" + e.Reason + ")"
}

// Is makes it ErrDomainRefused, and ErrStoppedMidRun when it ended a running job.
func (e *DomainRefusedError) Is(target error) bool {
	return target == ErrDomainRefused || e.MidRun && target == ErrStoppedMidRun
}

// domainReason says whether res is a refusal or a stop by the worker's domain fence.
func domainReason(res *sensorlink.JobResult) bool {
	return (res.Status == "refused" || res.Status == "stopped") && slices.Contains(domainfence.Reasons, res.Reason) && res.Reason != domainfence.InvalidJob
}

func (d *Dispatcher) domainRefused(res *sensorlink.JobResult) error {
	d.log.Warn("sensor_active_worker_refused_domain_job", "status", res.Status, "reason", res.Reason)
	return &DomainRefusedError{Reason: res.Reason, MidRun: res.Status == "stopped"}
}
