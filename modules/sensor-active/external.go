package sensoractive

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/scan/commonports"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// Service identification on the box's own verified public IP, for exposure (exposure INV-19): nmap in the scan container, in two
// runs of the external shape (nmapargv.External): port discovery over nmap's own most common TCP ports, then -sV over the fixed list
// (the surface scan's ports and the reviewed admin ports) and the open ports the discovery found outside it. The consent is exposure's
// (a verified, committed, current IP target), not the LAN scope's: the LAN settings, window and scope do not apply, and nothing
// is written to the inventory. What holds: one nmap at a time on the box (runMu), the own-IP fence right before the job is handed
// out (and again in the worker), the probe row before the job (INV-9, LEGAL §3), the XML limits (INV-7) and a tighter port bound.
// A target whose testing terms are accepted gets the deep scan instead (sensor-active INV-19): nmapargv.ExternalFull, every TCP
// port with nmap's reviewed scripts, sent only after core's DeepGate said the terms still allow it; when the run allows the
// disruptive checks, nmapargv.ExternalDisruptive is its last step (ScanDisruptive): the disruptive scripts on the open ports the full
// run found, sent only after DeepGate said the terms still allow them.

// KindExternal is the kind of the scan events of a service scan for exposure.
const KindExternal = "external"

// Errors of ScanExternal. No packet went to ip with ErrBusy (another nmap run kept the slot), ErrNoTime (too little of the caller's
// time was left for the run, #723 review L5), ErrNotOwnIP (the fence in core or in the worker saw the box leave through another
// address) or ErrEgressUnverified (the worker could not reach the public IP services to check). ErrHostTimedOut: nmap ran and
// gave up on the host at its --host-timeout, so it printed no port table and nothing can be said of the services.
// ErrAnswersEverywhere: nmap saw more than commonports.MaxBelievableOpen ports open, the shape of a router or firewall that
// answers for every port: its rows describe that device, not services, so they are discarded. Only the full shapes return it: the
// External shape still reads the fixed list with -sV and keeps the ports that named a service (External.AnswersEverywhere).
var (
	ErrBusy              = errors.New("sensoractive: the scan container's nmap is busy with another scan")
	ErrNoTime            = errors.New("sensoractive: too little time was left for service identification")
	ErrNotOwnIP          = errors.New("sensoractive: the address is not the box's own public IP now")
	ErrEgressUnverified  = errors.New("sensoractive: the public IP services could not be reached to check the address")
	ErrHostTimedOut      = errors.New("sensoractive: nmap gave up on the address before it finished")
	ErrAnswersEverywhere = errors.New("sensoractive: the address answers on almost every port")
	// ErrNotDeep: a full shape was asked, and right before the job is handed out the target's testing terms no longer
	// allow a deep scan (withdrawn, or of an older version), or the fence cannot tell (no DeepGate). Nothing was sent: the run was
	// asked as deep, so it never falls back to the External shape by itself.
	ErrNotDeep = errors.New("sensoractive: the target's testing terms no longer allow a deep scan")
	// ErrFullUnsupported: the worker's latest heartbeat does not say it runs the full shapes (an older worker, while an
	// update runs). Nothing was sent.
	ErrFullUnsupported = errors.New("sensoractive: the scan container's worker is older and runs no deep nmap scan")
	// ErrPortsUnsupported: the worker is older and takes no port list, so the -sV follow-up of the weekly scan of every
	// port is not sent (its open ports are recorded without versions).
	ErrPortsUnsupported = errors.New("sensoractive: the scan container's worker is older and runs no port_versions job")
	// ErrStoppedMidRun (review r1 H1, r2 LOW-5): the worker's re-check during a full run found the address no longer the box's own
	// (also ErrNotOwnIP) or could not check it (also ErrEgressUnverified), killed nmap and discarded its output. Unlike a refusal
	// at the start, nmap had already probed the address.
	ErrStoppedMidRun = errors.New("sensoractive: the scan worker stopped the deep scan while it ran and discarded its output")
	// ErrNotDisruptive: the disruptive scripts were asked (ScanDisruptive), and right before the job is handed out the target's
	// testing terms no longer allow the disruptive checks. Nothing was sent.
	ErrNotDisruptive = errors.New("sensoractive: the target's testing terms no longer allow the disruptive checks")
)

// OwnEgress says whether ip is the box's own verified public egress now: exposure's gate (verified, committed, seen by the
// public-IP check within the last 5 minutes, else a fresh full check; exposure INV-13). cmd/vedette implements it.
type OwnEgress interface {
	OwnEgress(ctx context.Context, ip netip.Addr) (bool, error)
}

// OwnProver is an OwnEgress that also says what its yes rests on: provenAt is the latest sighting of ip as the box's egress, from
// which ip stays proven the box's own for egressip.ProofValid (exposure's box_egress proof; zero when the yes rests on no sighting).
// sensor-active asks it instead of OwnEgress and sends provenAt with the job (sensorlink Job.ProvenAt, through ProvenProber) to a
// worker whose heartbeat says own_proof: the worker then runs the job on an address the box does not go out through right now (a
// second line) while the proof holds, instead of needing its own sighting right before nmap.
type OwnProver interface {
	OwnProof(ctx context.Context, ip netip.Addr) (provenAt time.Time, ok bool, err error)
}

// ProvenProber is implemented by a Prober that can send an external job with the ownership proof of its target (*Dispatcher).
// A Prober without it sends the job without the proof, and the worker's own sighting decides.
type ProvenProber interface {
	ProbeProven(ctx context.Context, argv []string, provenAt time.Time) (Output, error)
}

// DeepGate is the second half of core's fence of a full run, asked right after OwnEgress, right before the job is
// handed out: which external shape the target's testing terms allow now, given the one asked. A full run is sent only through an
// OwnEgress that implements it (fail closed). An answer that is not a full shape is ErrNotDeep; ExternalFull for an asked
// ExternalDisruptive (the disruptive tick taken back, or a scan the box runs by itself) is ErrNotDisruptive: nothing is sent; the
// run never gets more than it asked for.
type DeepGate interface {
	ShapeNow(ctx context.Context, asked nmapargv.Kind) (nmapargv.Kind, error)
}

// ExternalService is what -sV read on one open TCP port. The strings come from the network: printable, at most 200 runes
// (text, INV-7); CPE is the first application CPE ("cpe:/a:…") nmap printed, "" when none. exposure limits them further.
// Method is how nmap named the service (M2-7): "probed" (a probe's answer matched), "table" (only the usual service of the port
// number, nothing confirmed), "" when nmap did not say; Conf nmap's confidence 1..10 (0 when absent; a table name is 3).
type ExternalService struct {
	Port    int
	Name    string
	Product string
	Version string
	CPE     string
	Extra   string
	Method  string
	Conf    int
}

// ExternalScript is one NSE script result of a full run: Port is the open TCP port it ran on, 0 for a host script
// (<hostscript>, such as smb-vuln-ms17-010); ID nmap's script name; Output its text, printable runes and line breaks only, at
// most 2000 runes (scriptText), or "Output not stored: it can hold credentials." for a script nmapargv.StoresOutput names
// (review r1 M4); Findings the vulns library's findings, read only from the structured output (review r1 M1, L3). Everything
// came from the network: exposure limits it again before it is stored.
type ExternalScript struct {
	Port     int
	ID       string
	Output   string
	Findings []ScriptFinding
}

// ScriptFinding is one finding of the vulns library: State "vulnerable" (VULNERABLE, also "(Exploitable)" or "(DoS)"), "likely"
// (LIKELY VULNERABLE) or "not_vulnerable"; Title the script's name for it (printable, at most 120 runes); CVEs its CVE ids
// (unique, at most 20).
type ScriptFinding struct {
	State string
	Title string
	CVEs  []string
}

// External is the result of ScanExternal: the open ports with what -sV read, how many TCP ports were probed, which ones, and
// the script results of a full run (nil for the External shape). Probed are the TCP ports the run probed, ascending: for the External
// shape the ports nmap's discovery says it probed (its <scaninfo>, nmap's own top ports) and those of the finished -sV batches; nil for a full
// shape, which probed every port 1..65535. Ports is their count (65535 for a full shape). DiscoveryCut: the External shape's
// discovery hit its host timeout or its output was not usable, so only the fixed list's -sV batches were read.
// AnswersEverywhere: the address answers on almost every port (a router or SYN proxy), so the -sV batches read the fixed list only
// and Services keeps only the ports where -sV named a real service.
//
// Unfinished are the ports of the -sV batches that hit their host timeout, printed nothing usable or were not started for want
// of time, ascending: they are not in Probed (a scan that did not read them never calls them closed), and the next scan of the
// address reads them first (rotation from this run's probe rows).
type External struct {
	Services          []ExternalService
	Ports             int
	Probed            []int
	Scripts           []ExternalScript
	DiscoveryCut      bool
	AnswersEverywhere bool
	Unfinished        []int
	// Refused: nmap got a closed reply (a TCP reset) on at least one port (the full run, or the External shape's discovery), so the
	// address answered this run even if no port was open. Ports that gave no reply (filtered) are not an answer.
	Refused bool
}

// externalRun bounds an external run whose context has no deadline (exposure gives it ServicesTimeout there, 8 minutes); fullRun
// that of a full run (exposure gives it FullServicesTimeout, the host timeout plus 10 minutes).
const (
	externalRun   = 8 * time.Minute
	fullRun       = nmapargv.FullHostTimeout + 10*time.Minute
	disruptiveRun = nmapargv.DisruptiveHostTimeout + 10*time.Minute
)

// externalStep is what one nmap job of an external shape needs on top of nmap's own --host-timeout once it has the nmap slot and
// core's fence said yes (#723 review L5): the worker's fence (at most 5 rounds of 5 s) and the pickup and the result (15 s).
// externalNeed is the least time an External run needs: the discovery, the batches' inner margin, and one -sV batch with core's
// own-IP check before it at nmapargv.BatchMinTimeout (each later batch's host timeout comes from what is left: batchTimeout). With less left of the caller's
// deadline the run is skipped (ErrNoTime) rather than cut by it halfway; the wait for the slot is shortened to leave it, plus
// coreFenceTime for core's own check. fullNeed is the same with the full shapes' host timeout.
const (
	coreFenceTime = 30 * time.Second
	externalStep  = 25*time.Second + 15*time.Second
	externalNeed  = externalStep + nmapargv.ExternalDiscoveryTimeout + innerMargin + batchNeed
	fullNeed      = externalStep + nmapargv.FullHostTimeout
	// batchNeed is the least time left before the inner deadline in which an -sV batch is still tried: core's own-IP check, the
	// job's overhead and the shortest host timeout.
	batchNeed = coreFenceTime + externalStep + nmapargv.BatchMinTimeout
)

// batchTimeout is the host timeout of the next -sV batch when left is what remains of the run after core's own-IP check: what is
// left once the batch's job overhead (externalStep) is set aside, in whole seconds, at most nmapargv.BatchMaxTimeout. Below
// nmapargv.BatchMinTimeout the batch is not started (false): its ports wait for the next scan, which reads them first.
func batchTimeout(left time.Duration) (time.Duration, bool) {
	h := min(left-externalStep, nmapargv.BatchMaxTimeout).Truncate(time.Second)
	return h, h >= nmapargv.BatchMinTimeout
}

// boundsOf is the time a run of kind needs and its bound without a deadline.
func boundsOf(kind nmapargv.Kind) (need, run time.Duration) {
	if kind == nmapargv.ExternalDisruptive {
		return externalStep + nmapargv.DisruptiveHostTimeout, disruptiveRun
	}
	if kind.IsFull() {
		return fullNeed, fullRun
	}
	return externalNeed, externalRun
}

// left is how long ctx has before its deadline (def when it has none).
func left(ctx context.Context, def time.Duration) time.Duration {
	if d, ok := ctx.Deadline(); ok {
		return time.Until(d)
	}
	return def
}

// ScanExternal identifies the services on the open TCP ports of ip, the box's own verified public IP, for exposure, with
// the shape kind: External, or one of the full shapes of a target whose testing terms are accepted.
// Order: wait for the nmap slot at most busyWait, and never so long that less than the run's need plus coreFenceTime would be left
// (else ErrBusy, or ErrNoTime when no wait at all fits); a Stop that came during the wait ends it (ErrStopped); the worker must be
// there (ErrUnavailable); a job row; then, right before the job is handed out, own says whether ip is still the box's own egress
// (else ErrNotOwnIP, nothing sent) and, for a full shape, own's DeepGate which shape the terms allow now (else ErrNotDeep); less
// than the need left → ErrNoTime; the probe row; then the job. A nil own refuses (fail closed). The stop of the module (Stop) or
// of ctx ends it with ErrStopped.
func (s *Service) ScanExternal(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, own OwnEgress) (External, error) {
	if kind == nmapargv.ExternalDisruptive {
		return External{}, errors.New("sensoractive: the disruptive scripts run on the open ports of a full run (ScanDisruptive)")
	}
	return s.scanExternal(ctx, ip, kind, nil, own, nil)
}

// ScanDisruptive is the last step of a deep scan of ip, the box's own verified public IP, whose run allows the disruptive checks:
// nmapargv.ExternalDisruptive on ports, the open TCP ports the scan's full run found (1..commonports.MaxBelievableOpen). The same
// fences as ScanExternal of a full shape: own's own-IP check and its DeepGate right before the job is handed out (the terms must
// still allow the disruptive checks, else ErrNotDisruptive and nothing is sent), the probe row, the worker's own fence. Its result
// holds the script results and the services -sV read on those ports (Probed: ports).
func (s *Service) ScanDisruptive(ctx context.Context, ip netip.Addr, ports []int, own OwnEgress) (External, error) {
	return s.scanExternal(ctx, ip, nmapargv.ExternalDisruptive, ports, own, nil)
}

// DomainIP is a domain_ip run of ScanDomainIP: the fence fields the worker checks and the CNAME chain core saw for the name
// (for the probe log row; "" when core did not look it up).
type DomainIP struct {
	Scope sensorlink.DomainScope
	Chain string
}

// DomainProber is implemented by a Prober that can send a domain_ip nmap job (*Dispatcher). A Prober without it never runs one.
type DomainProber interface {
	ProbeDomain(ctx context.Context, argv []string, scope sensorlink.DomainScope) (Output, error)
}

// ScanDomainIP is ScanExternal of a full shape on a public address that is not the box's own egress, reached because a name under a
// verified domain resolves to it: a domain_ip job. Core's half of the fence is exposure's
// deepGate (just before the step) and gate's DeepGate (the terms, right before the job leaves, like a full run of the box's own IP);
// own-egress is not asked, the worker's domain fence is: its key, the TXT record, the name's address now, again every 3 minutes while
// nmap runs. The probe row names the domain, the name and its CNAME chain. A worker that does not say domain_ip gets nothing
// (ErrDomainUnsupported); a refusal of the worker's fence is a *DomainRefusedError.
func (s *Service) ScanDomainIP(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, d DomainIP, gate DeepGate) (External, error) {
	if !kind.IsFull() {
		return External{}, fmt.Errorf("sensoractive: a domain_ip run is a full shape, not %s", kind.Name())
	}
	if gate == nil {
		return External{}, ErrNotDeep
	}
	if kind == nmapargv.ExternalDisruptive {
		return External{}, fmt.Errorf("sensoractive: a domain_ip run is %s, never the disruptive scripts", nmapargv.ExternalFull.Name())
	}
	return s.scanExternal(ctx, ip, kind, nil, domainGate{gate}, &d)
}

// domainGate is the OwnEgress of a domain_ip run: never asked (probeExternal skips it), its DeepGate is the caller's.
type domainGate struct{ DeepGate }

func (domainGate) OwnEgress(context.Context, netip.Addr) (bool, error) { return false, nil }

func (s *Service) scanExternal(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, ports []int, own OwnEgress, dom *DomainIP) (External, error) {
	if !kind.IsExternal() {
		return External{}, fmt.Errorf("sensoractive: %s is not an external shape", kind.Name())
	}
	targets := []netip.Addr{ip}
	if _, err := nmapargv.BuildFor(kind, nmapargv.ExternalRateOf(kind), ports, targets); err != nil {
		return External{}, fmt.Errorf("sensoractive: %w", err)
	}
	if own == nil {
		return External{}, ErrNotOwnIP
	}
	need, budget := boundsOf(kind)
	wait := min(busyWait, left(ctx, budget)-need-coreFenceTime)
	if wait < 0 {
		return External{}, ErrNoTime
	}
	if s.off.Load() { // the module is off: nothing is queued
		return External{}, ErrStopped
	}
	got := make(chan External, 1) // the work hands its result over: the caller may stop waiting before the work ends
	title := "Service scan of " + ip.String() + " for External exposure"
	if kind == nmapargv.ExternalDisruptive {
		title = "Disruptive nmap scripts on " + ip.String() + " for External exposure"
	}
	err := s.doWork(ctx, run.Spec{Kind: RunService, Title: title, Trigger: run.Event,
		TriggerNote: "an exposure scan", Subject: &run.Subject{Kind: "address", ID: ip.String(), Label: ip.String()}},
		func(ctx context.Context) error {
			res, err := s.serviceScan(ctx, ip, kind, ports, own, dom)
			got <- res
			return err
		}, func(ctx context.Context, err error) run.Result {
			switch {
			case err == nil:
				return run.Result{}
			case errors.Is(err, ErrStopped) && ctx.Err() != nil:
				return run.Result{Status: run.Partial, Error: "stopped"}
			}
			return run.Result{Status: run.Failed, Error: err.Error()}
		}, wait, "The scanner stayed busy, so this service scan did not start")
	switch {
	case errors.Is(err, errNotStarted):
		return External{}, ErrBusy
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return External{}, ErrStopped
	}
	select {
	case res := <-got:
		return res, err
	default:
		return External{}, err
	}
}

// serviceScan is the work of a service_scan run: nmap on the public address, under the run lock.
func (s *Service) serviceScan(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, ports []int, own OwnEgress, dom *DomainIP) (External, error) {
	stops := s.stops.Load()
	s.lockRun(ctx)
	defer s.runMu.Unlock()
	if s.stops.Load() != stops || ctx.Err() != nil { // the module was turned off while the run waited for the slot (#723 review L4)
		return External{}, ErrStopped
	}
	targets := []netip.Addr{ip}
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.setCur(&running{cancel: cancel, targets: targets, rate: nmapargv.ExternalRateOf(kind), kind: kind, external: true, runID: runIDOf(ctx)})
	defer s.setCur(nil)
	if err := s.available(jctx); err != nil {
		return External{}, err
	}
	id, err := s.startJob(ctx, KindExternal, "exposure", 1)
	if err != nil {
		return External{}, err
	}
	res, err := s.probeExternal(jctx, id, ip, kind, ports, own, dom)
	switch {
	case err == nil:
		s.finishJob(ctx, id, StatusDone, 1, 0, "")
	case errors.Is(err, ErrStopped):
		s.finishJob(ctx, id, StatusStopped, 0, 0, "stopped: the scan was stopped or the module was turned off")
	default:
		s.finishJob(ctx, id, StatusFailed, 0, 0, err.Error())
	}
	return res, err
}

func (s *Service) probeExternal(ctx context.Context, jobID string, ip netip.Addr, kind nmapargv.Kind, ports []int, own OwnEgress, dom *DomainIP) (External, error) {
	var note probeNote
	var proof time.Time
	if dom == nil {
		var err error // exposure's gate result is minutes old by now (exposure INV-13, INV-19)
		if proof, err = s.ownNow(ctx, ip, own, false); err != nil {
			return External{}, err
		}
	} else {
		if _, ok := s.prober.(DomainProber); !ok {
			return External{}, ErrDomainUnsupported
		}
		note = probeNote{d: dom}
	}
	if kind.IsFull() {
		var err error
		if kind, err = s.deepNow(ctx, ip, kind, own); err != nil {
			return External{}, err
		}
	}
	need, run := boundsOf(kind)
	if left(ctx, run) < need {
		return External{}, ErrNoTime
	}
	if kind == nmapargv.External {
		return s.probeDefault(ctx, jobID, ip, own, proof)
	}
	var ext External
	err := s.externalJob(ctx, jobID, ip, kind, batchSpec{ports: ports}, note, dom, proof, run, func(hosts []host) (string, error) {
		var err error
		if ext, err = externalOf(hosts, ip, kind, ports); err != nil {
			return "", err
		}
		return fmt.Sprintf("ok: %d open ports, %d script results", len(ext.Services), len(ext.Scripts)), nil
	})
	if err != nil {
		return External{}, err
	}
	return ext, nil
}

// probeDefault is the External shape on the box's own public IP, under the one job row and the one nmap slot, each nmap job with
// its probe row (INV-9) and core's own-IP fence right before it: the discovery (SYN only, nmap's own top ports), then -sV in
// batches (nmapargv.ExternalBatches: the surface scan's list, the reviewed admin ports, then the open ports found outside both).
// nmap's --host-timeout drops every result of a host it gives up on, so each batch is its own job with its own host timeout
// (batchTimeout, from the time left before the batches' inner deadline): a batch that times out, prints nothing usable or runs past
// its own bound loses only its own ports, and a batch that no longer gets nmapargv.BatchMinTimeout is not started (its probe row
// says so). Those ports are Unfinished, not Probed. The order is a queue kept in the probe log (lastRun, planBatches): the next scan
// of the address reads the batches not started first, then those that failed, then the rest. The fixed list always gets its -sV
// batches, whatever the discovery said:
//   - discovery ok, at most commonports.MaxBelievableOpen open: every batch, Probed is the discovery's ports and the finished
//     batches' (an open port that got no -sV is still listed, named by its port number, and is Unfinished);
//   - more open than that (a router or SYN proxy answering for every port): the fixed list's batches only, and only the ports where
//     -sV named a real service are kept (AnswersEverywhere);
//   - the discovery hit its host timeout or its output was not usable (nmap failed, a wrong <scaninfo>): the fixed list's batches,
//     Probed is their finished ports only (DiscoveryCut).
//
// A refusal of either fence or a stop ends the run as before: nothing more is sent and nothing is kept. A worker lost in the
// middle keeps the finished batches. A run in which no batch finished says why: ErrHostTimedOut, the batch's error, or ErrNoTime
// when none started.
func (s *Service) probeDefault(ctx context.Context, jobID string, ip netip.Addr, own OwnEgress, proof time.Time) (External, error) {
	if _, ok := ctx.Deadline(); !ok { // the step's bound when the caller gave none (exposure gives ServicesTimeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, externalRun)
		defer cancel()
	}
	last := s.lastRun(ctx, ip) // read before this run writes its own rows
	var scanned, open []int
	var found []portInfo // the discovery's open ports, as nmap's port table named them
	everywhere, refused := false, false
	err := s.externalJob(ctx, jobID, ip, nmapargv.External, batchSpec{}, probeNote{}, nil, proof, externalRun, func(hosts []host) (string, error) {
		var err error
		scanned, open, err = discoveryOf(hosts, ip)
		if errors.Is(err, ErrAnswersEverywhere) {
			everywhere = true
			return fmt.Sprintf("ok: more than %d ports open, the address answers on almost every port; -sV reads the fixed list next", commonports.MaxBelievableOpen), nil
		}
		if err != nil {
			return "", err
		}
		found, refused = slices.Clone(hosts[0].ports), hosts[0].closed > 0
		return fmt.Sprintf("ok: %d of %d ports open", len(open), len(scanned)), nil
	})
	cut := false
	switch {
	case err == nil:
	case discoveryUnusable(err): // nmap ran but said nothing usable about the top ports: the fixed list still gets -sV
		cut = true
	default:
		return External{}, err
	}
	if cut || everywhere {
		scanned, open, found = nil, nil, nil
	}
	batches, err := planBatches(open, scanned, last, everywhere)
	if err != nil { // never reached: discoveryOf and planBatches bound the ports
		return External{}, fmt.Errorf("sensoractive: %w", err)
	}
	// The batches run against an inner deadline a little before the step's, so the last one, cut at its own bound, never takes
	// the finished ones with it.
	deadline, _ := ctx.Deadline()
	inner, cancel := context.WithDeadline(ctx, deadline.Add(-innerMargin))
	defer cancel()
	res, err := runBatches(inner, batches, batchRunner{
		fence: func(ctx context.Context) error {
			var err error
			proof, err = s.fenceAgain(ctx, ip, own) // the batch goes with the proof of this check
			return err
		},
		run: func(ctx context.Context, b []int, h time.Duration, label string) ([]ExternalService, error) {
			var got []ExternalService
			err := s.externalJob(ctx, jobID, ip, nmapargv.External, batchSpec{ports: b, host: h, label: label}, probeNote{}, nil, proof, externalRun, func(hosts []host) (string, error) {
				x, err := versionsOf(hosts, ip, b, false)
				if err != nil {
					return "", err
				}
				got = x.Services
				return fmt.Sprintf("ok: %d open ports", len(got)), nil
			})
			return got, err
		},
		notStarted: func(b []int, label, why string) { s.notStarted(ctx, jobID, ip, b, label, why) },
	})
	if ctx.Err() != nil {
		return External{}, ErrStopped
	}
	if err != nil {
		return External{}, err
	}
	ext := External{Services: res.services}
	// Every open port the discovery saw that got no -sV this run (its batch did not finish) is still open: listed, named by its
	// port number, and Unfinished, never counted as probed.
	unfinished := unionPorts(res.unfinished, unreadOpen(open, res.done))
	for _, p := range found {
		if _, ok := slices.BinarySearch(unfinished, p.number); ok {
			ext.Services = append(ext.Services, ExternalService{Port: p.number, Name: p.name, Method: "table", Conf: p.conf})
		}
	}
	slices.SortFunc(ext.Services, func(a, b ExternalService) int { return a.Port - b.Port })
	if everywhere || len(ext.Services) > commonports.MaxBelievableOpen {
		ext.Services = slices.DeleteFunc(ext.Services, func(x ExternalService) bool { return !identifiedService(x) })
		ext.AnswersEverywhere = true
	}
	probed := slices.DeleteFunc(slices.Clone(scanned), func(p int) bool { _, ok := slices.BinarySearch(unfinished, p); return ok })
	ext.Probed = unionPorts(probed, res.done)
	ext.Ports = len(ext.Probed)
	ext.DiscoveryCut = cut
	ext.Unfinished = unfinished
	ext.Refused = refused
	return ext, nil
}

// innerMargin is how long before the step's deadline the -sV batches must be done: the room for the last batch's probe row and
// the result to reach the caller.
const innerMargin = 15 * time.Second

// fenceAgain is core's own-IP check right before an -sV batch's job leaves; it returns the proof the batch goes with.
func (s *Service) fenceAgain(ctx context.Context, ip netip.Addr, own OwnEgress) (time.Time, error) {
	return s.ownNow(ctx, ip, own, true)
}

// ownNow is core's half of the own-IP fence right before a job leaves (batch: an -sV batch after the discovery): own's yes (else
// ErrNotOwnIP, logged), and, when own is an OwnProver, the time of the sighting its yes rests on (zero otherwise: the job then goes
// without a proof).
func (s *Service) ownNow(ctx context.Context, ip netip.Addr, own OwnEgress, batch bool) (time.Time, error) {
	var proof time.Time
	var ok bool
	var err error
	if p, isProver := own.(OwnProver); isProver {
		proof, ok, err = p.OwnProof(ctx, ip)
	} else {
		ok, err = own.OwnEgress(ctx, ip)
	}
	switch {
	case ctx.Err() != nil:
		return time.Time{}, ErrStopped
	case err != nil:
		return time.Time{}, fmt.Errorf("sensoractive: checking that %s is the box's own public IP: %w", ip, err)
	case !ok && batch:
		s.log.WarnContext(ctx, "sensoractive: external scan stopped before an -sV batch, the address is not the box's own public IP now; nothing more sent", "ip", ip.String())
		return time.Time{}, ErrNotOwnIP
	case !ok:
		s.log.WarnContext(ctx, "sensoractive: external scan refused, the address is not the box's own public IP now; no packet sent", "ip", ip.String())
		return time.Time{}, ErrNotOwnIP
	}
	return proof, nil
}

// unreadOpen are the ports of open that are not in done, ascending.
func unreadOpen(open, done []int) []int {
	d := slices.Clone(done)
	slices.Sort(d)
	var out []int
	for _, p := range open {
		if _, ok := slices.BinarySearch(d, p); !ok {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// batchRunner is what runBatches does for each batch: core's own-IP check, the batch's job, and the probe row of a batch it does not
// start.
type batchRunner struct {
	fence      func(ctx context.Context) error
	run        func(ctx context.Context, ports []int, host time.Duration, label string) ([]ExternalService, error)
	notStarted func(ports []int, label, why string)
}

// batchResults is what the batches of a run read: the services of the finished batches, their ports, and the ports of the batches
// that did not finish or did not start.
type batchResults struct {
	services         []ExternalService
	done, unfinished []int
}

// The reasons a batch is not started, in its probe row.
const (
	whyNoTime     = "too little time left in this scan"
	whyWorkerLost = "the scan worker was lost during this scan"
)

// runBatches runs the -sV batches in order until ctx's deadline (the inner one): before each, the fence; its host timeout from
// the time left (batchTimeout); its job bound at that timeout plus the job's overhead. A batch whose results are lost (nmap gave up,
// output not usable, cut at its own bound while ctx is alive) is unfinished and the next one runs; a batch that no longer fits, and
// every one after it, is not started; a lost worker ends the loop with the rest not started. The finished batches are kept in each of
// these cases. A stop or a fence refusal returns its error. No batch finished: ErrNoTime when none ran, else the last batch's error.
func runBatches(ctx context.Context, batches [][]int, r batchRunner) (batchResults, error) {
	var res batchResults
	var lost error
	stopRest := func(from int, why string) {
		for j, rest := range batches[from:] {
			r.notStarted(rest, fmt.Sprintf("batch %d of %d", from+j+1, len(batches)), why)
			res.unfinished = append(res.unfinished, rest...)
		}
	}
	for i, b := range batches {
		// Too little left for the own-IP check, the job and a sane batch (or the inner deadline passed): this one and the rest wait
		// for the next scan, and the finished ones are kept.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || left(ctx, externalRun) < batchNeed {
			stopRest(i, whyNoTime)
			break
		}
		if err := r.fence(ctx); err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) { // the check ran into the inner deadline, not a stop of the run
				stopRest(i, whyNoTime)
				break
			}
			return batchResults{}, err
		}
		h, fits := batchTimeout(left(ctx, externalRun))
		if !fits {
			stopRest(i, whyNoTime)
			break
		}
		bctx, cancel := context.WithTimeout(ctx, h+externalStep)
		got, err := r.run(bctx, b, h, fmt.Sprintf("batch %d of %d", i+1, len(batches)))
		// cut at its own bound (or at the inner deadline), not by a stop of the run
		ownBound := err != nil && bctx.Err() != nil && !errors.Is(ctx.Err(), context.Canceled)
		cancel()
		switch {
		case err == nil:
			res.services = append(res.services, got...)
			res.done = append(res.done, b...)
			continue
		case ownBound || batchLost(err): // this batch's results are gone; the finished ones are kept
			res.unfinished = append(res.unfinished, b...)
			if ownBound || errors.Is(err, ErrHostTimedOut) {
				lost = ErrHostTimedOut
			} else if lost == nil {
				lost = err
			}
			continue
		case errors.Is(err, ErrWorkerLost) || errors.Is(err, ErrWorkerUnavailable):
			res.unfinished = append(res.unfinished, b...)
			lost = err
			stopRest(i+1, whyWorkerLost)
		default:
			return batchResults{}, err
		}
		break
	}
	slices.Sort(res.done)
	slices.Sort(res.unfinished)
	res.unfinished = slices.Compact(res.unfinished)
	switch {
	case len(res.done) > 0:
		return res, nil
	case lost == nil:
		return batchResults{}, ErrNoTime
	}
	return batchResults{}, lost
}

// batchState is what the last run's probe row says of an -sV batch, in queue order: not started first, then failed, then done.
type batchState int

const (
	batchNotStarted batchState = iota
	batchFailed
	batchDone
)

// lastBatch is one -sV batch of the last External run on an address, from its probe row: its ports and what became of it.
type lastBatch struct {
	ports []int
	state batchState
}

// planBatches is the ordered -sV batches of a run, a queue rebuilt from the last run (last, in that run's order):
//   - the extras: the open ports the discovery found outside the fixed list first, then the last run's unfinished extras the
//     discovery did not see closed (still open, or not among the ports it probed), at most commonports.MaxBelievableOpen in all;
//     none when the address answers everywhere (the fixed list's batches only);
//   - order: the batches not started last run (in that run's order; a fixed port the last run never wrote a row for counts as not
//     started, after those, and a batch only of ports the last run never planned after that), then the batches that failed last run
//     (in that run's order), then the others in their usual order.
//
// Every batch is read at least once every ceil(n/k) runs when k batches fit a run, and a batch that always fails cannot block the
// others: it queues behind the ones not started.
func planBatches(open, scanned []int, last []lastBatch, everywhere bool) ([][]int, error) {
	var extra []int
	if !everywhere {
		seen := map[int]bool{}
		add := func(p int) {
			if !slices.Contains(nmapargv.ExtraPortNumbers, p) && !seen[p] && len(extra) < commonports.MaxBelievableOpen {
				seen[p] = true
				extra = append(extra, p)
			}
		}
		for _, p := range open {
			add(p)
		}
		for _, l := range last {
			if l.state == batchDone {
				continue
			}
			for _, p := range l.ports {
				if !slices.Contains(scanned, p) || slices.Contains(open, p) { // the discovery did not see it closed
					add(p)
				}
			}
		}
	}
	batches, err := nmapargv.ExternalBatches(extra)
	if err != nil {
		return nil, err
	}
	type rank struct {
		state batchState
		index int
	}
	ranks := map[int]rank{}
	for i, l := range last {
		for _, p := range l.ports {
			if r, ok := ranks[p]; !ok || l.state < r.state || (l.state == r.state && i < r.index) {
				ranks[p] = rank{l.state, i}
			}
		}
	}
	if len(last) > 0 { // a fixed port with no row (the last run stopped before its batch): not started, after the ones that say so
		for _, p := range nmapargv.ExtraPortNumbers {
			if _, ok := ranks[p]; !ok {
				ranks[p] = rank{batchNotStarted, len(last)}
			}
		}
	}
	rankOf := func(b []int) rank {
		best, known := rank{batchDone, 0}, false
		for _, p := range b {
			r, ok := ranks[p]
			known = known || ok
			if ok && r.state != batchDone && (best.state == batchDone || r.state < best.state || (r.state == best.state && r.index < best.index)) {
				best = r
			}
		}
		if !known && len(last) > 0 { // only ports the last run never planned (newly found extras): not started, after the others
			return rank{batchNotStarted, len(last) + 1}
		}
		return best
	}
	slices.SortStableFunc(batches, func(a, b []int) int {
		ra, rb := rankOf(a), rankOf(b)
		if ra.state != rb.state {
			return int(ra.state) - int(rb.state)
		}
		if ra.state == batchDone {
			return 0 // the usual order
		}
		return ra.index - rb.index
	})
	return batches, nil
}

// batchLost says an -sV batch's job ran but its results are lost to this run: nmap gave up on the host at the batch's host timeout,
// exited with an error, printed too much or something not believed. The run goes on with the next batch.
func batchLost(err error) bool {
	var ee *exec.ExitError
	return errors.Is(err, ErrHostTimedOut) || errors.Is(err, errXMLInvalid) || errors.Is(err, errXMLTooBig) || errors.As(err, &ee)
}

// notStarted writes the probe row of an -sV batch that is not started (nothing is sent): the flags it would have had at the
// shortest host timeout and why, so the next scan of the address can queue it first (lastRun).
func (s *Service) notStarted(ctx context.Context, jobID string, ip netip.Addr, ports []int, label, why string) {
	flags, err := nmapargv.BatchFlags(nmapargv.ExternalRate, ports, nmapargv.BatchMinTimeout)
	if err != nil {
		return
	}
	note := probeNote{label: label}
	id, err := s.insertProbeFlags(context.WithoutCancel(ctx), jobID, nmapargv.External, nmapargv.ExternalRate, []netip.Addr{ip}, note, flags)
	if err == nil {
		s.finishProbe(ctx, id, note.with("not started: "+why+"; the next scan starts with these ports"))
	}
}

// lastRun is the -sV batches of the last External run on ip, in its order (its probe rows by id), with what became of each: "ok"
// is done, "not started" is not started, anything else failed. Derived from the probe log (sa_probe) alone; nil when there is no such
// run or the log cannot be read (the run then keeps the usual order).
func (s *Service) lastRun(ctx context.Context, ip netip.Addr) []lastBatch {
	r := s.db.Reader()
	var run sql.NullString
	// the most recent run that wrote -sV rows: a run stopped during or right after its discovery says nothing of the batches, so
	// the queue is taken from the one before it
	if err := r.QueryRowContext(ctx, `SELECT run_id FROM sa_probe WHERE shape = ? AND targets = ? AND run_id IS NOT NULL AND flags LIKE '% -sV %' ORDER BY id DESC LIMIT 1`,
		nmapargv.External.Name(), ip.String()).Scan(&run); err != nil || !run.Valid {
		return nil
	}
	rows, err := r.QueryContext(ctx, `SELECT flags, result FROM sa_probe WHERE run_id = ? AND shape = ? AND targets = ? ORDER BY id`,
		run.String, nmapargv.External.Name(), ip.String())
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []lastBatch
	for rows.Next() {
		var flags, result string
		if rows.Scan(&flags, &result) != nil {
			return nil
		}
		f := strings.Fields(flags)
		i := slices.Index(f, "-p")
		if !slices.Contains(f, "-sV") || i < 0 || i+1 >= len(f) {
			continue
		}
		b := lastBatch{state: batchFailed}
		switch {
		case strings.Contains(result, ": ok: ") || strings.HasPrefix(result, "ok: "):
			b.state = batchDone
		case strings.Contains(result, "not started"):
			b.state = batchNotStarted
		}
		for _, p := range strings.Split(f[i+1], ",") {
			if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 {
				b.ports = append(b.ports, n)
			}
		}
		out = append(out, b)
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

// discoveryUnusable says the discovery's nmap ran and its output says nothing usable about the top ports: it gave up at its host
// timeout, exited with an error, printed too much or something not believed (a wrong <scaninfo>, a port outside it). The -sV batches of
// the fixed list still follow. An older worker's earlier line (errOlderShape) is not one: its -sV job would be refused too.
func discoveryUnusable(err error) bool {
	var ee *exec.ExitError
	return !errors.Is(err, errOlderShape) &&
		(errors.Is(err, ErrHostTimedOut) || errors.Is(err, errXMLInvalid) || errors.Is(err, errXMLTooBig) || errors.As(err, &ee))
}

// batchSpec is an external -sV batch of the External shape: its ports, its host timeout and the label its probe row starts with
// ("batch 2 of 5"). The zero value is any other external job (the discovery, a full run).
type batchSpec struct {
	ports []int
	host  time.Duration
	label string
}

// externalJob runs one nmap job of an external shape (b: an -sV batch of the External shape, zero otherwise) with its probe row,
// bounded by what is left of run: read turns the hosts of its XML into the row's "ok" text, or an error the row names.
func (s *Service) externalJob(ctx context.Context, jobID string, ip netip.Addr, kind nmapargv.Kind, b batchSpec, note probeNote, dom *DomainIP, proof time.Time,
	run time.Duration, read func([]host) (string, error)) error {
	targets := []netip.Addr{ip}
	rate := nmapargv.ExternalRateOf(kind)
	args, err := nmapargv.Build(kind, rate, targets)
	flags, ferr := nmapargv.Flags(kind, rate)
	switch {
	case kind == nmapargv.ExternalDisruptive: // the disruptive scripts on the full run's open ports
		args, err = nmapargv.BuildFor(kind, rate, b.ports, targets)
		flags, ferr = nmapargv.FlagsFor(kind, rate, b.ports)
	case b.ports != nil:
		args, err = nmapargv.BuildBatch(rate, b.ports, b.host, targets)
		flags, ferr = nmapargv.BatchFlags(rate, b.ports, b.host)
	}
	if err = cmp.Or(err, ferr); err != nil {
		return fmt.Errorf("sensoractive: %w", err)
	}
	if b.label != "" {
		note.label = b.label
	}
	probeID, err := s.insertProbeFlags(ctx, jobID, kind, rate, targets, note, flags)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		s.finishProbe(ctx, probeID, note.with(stoppedText))
		return ErrStopped
	}
	rctx, cancel := context.WithTimeout(ctx, min(left(ctx, run), run))
	defer cancel()
	var out Output
	var runErr error
	pp, proven := s.prober.(ProvenProber)
	switch {
	case dom != nil:
		out, runErr = s.prober.(DomainProber).ProbeDomain(rctx, args, dom.Scope) //nolint:forcetypeassert // checked by probeExternal
	case proven && !proof.IsZero(): // the box's own IP with the proof core's fence rested on
		out, runErr = pp.ProbeProven(rctx, args, proof)
	default:
		out, runErr = s.prober.Probe(rctx, args)
	}
	var refused *DomainRefusedError
	if errors.As(runErr, &refused) {
		result := note.with("refused by the scan container's domain fence (" + refused.Reason + "), nothing sent")
		if refused.MidRun {
			result = note.with("stopped by the scan container's domain fence (" + refused.Reason + "), results discarded")
		}
		s.finishProbe(ctx, probeID, result)
		return runErr
	}
	hosts, result, err := runOutcome(ctx, rctx, out, runErr)
	if b.ports != nil && kind == nmapargv.External && errors.Is(ctx.Err(), context.DeadlineExceeded) { // an -sV batch cut at its own bound, not a stop
		result = "failed: the batch ran past its time bound; the next scan starts with these ports"
	}
	if err == nil {
		if result, err = read(hosts); err != nil {
			result = "failed: output not valid, discarded"
			var count *topPortsError
			switch {
			case errors.As(err, &count):
				result = fmt.Sprintf("failed: nmap probed %d ports, not its top %d; output discarded", count.n, nmapargv.ExternalTopPorts)
			case errors.Is(err, errOlderShape):
				result = "failed: the scan worker is older and ran the earlier fixed-list line; output discarded"
			case errors.Is(err, ErrHostTimedOut):
				result = "failed: nmap gave up on the address at its host timeout"
			case errors.Is(err, ErrAnswersEverywhere):
				result = "failed: the address answers on almost every port; the service results were discarded"
			}
		}
	}
	s.finishProbe(ctx, probeID, note.with(result))
	if errors.Is(err, errDeadline) {
		err = ErrStopped
	}
	return err
}

// unionPorts is the ascending union of two port lists.
func unionPorts(a, b []int) []int {
	out := slices.Concat(a, b)
	slices.Sort(out)
	return slices.Compact(out)
}

// externalHost is the one host of an external run's XML: exactly one host, the asked address (-Pn reports it up; none means nmap
// printed nothing usable for it, never "no open port", #723 review L3), not given up on at its host timeout, and its open ports
// TCP, probed (probed) and each once: an answer outside what was asked is not believed in part (INV-7).
func externalHost(hosts []host, ip netip.Addr, probed func(int) bool) (host, error) {
	switch {
	case len(hosts) != 1:
		return host{}, fmt.Errorf("%w: %d hosts for one address", errXMLInvalid, len(hosts))
	case hosts[0].addr != ip:
		return host{}, fmt.Errorf("%w: a host that was not asked about", errXMLInvalid)
	case hosts[0].timedOut:
		return host{}, ErrHostTimedOut
	}
	seen := map[int]bool{}
	for _, p := range hosts[0].ports {
		if p.proto != "tcp" || !probed(p.number) || seen[p.number] {
			return host{}, fmt.Errorf("%w: port %s/%d was not probed", errXMLInvalid, p.proto, p.number)
		}
		seen[p.number] = true
	}
	return hosts[0], nil
}

// topPortsError is a discovery whose <scaninfo> did not list nmapargv.ExternalTopPorts ports (a changed nmap, a broken
// nmap-services): the run is not believed, and the probe row says how many it listed.
type topPortsError struct{ n int }

func (e *topPortsError) Error() string {
	return fmt.Sprintf("%v: the run probed %d ports, not nmap's top %d", errXMLInvalid, e.n, nmapargv.ExternalTopPorts)
}

func (e *topPortsError) Unwrap() error { return errXMLInvalid }

// errOlderShape: the discovery job reached a worker of an earlier release, which ran that release's external line (-sV over exactly
// the fixed surface list) instead of the discovery. Its output is not believed; the caller says the worker may be older.
var errOlderShape = fmt.Errorf("%w: the worker ran the earlier fixed-list line", ErrWorkerRefused)

// discoveryOf reads the External shape's discovery: the TCP ports nmap says it probed (its <scaninfo services>, which must be
// exactly nmapargv.ExternalTopPorts ports, as --top-ports asked: anything else is not the run that was asked for) and the open ones
// among them, ascending. More than commonports.MaxBelievableOpen open is ErrAnswersEverywhere: the -sV batches then read the fixed list alone.
func discoveryOf(hosts []host, ip netip.Addr) (scanned, open []int, err error) {
	if len(hosts) == 1 {
		scanned = expandRanges(hosts[0].scanned, 65535)
	}
	if len(scanned) != nmapargv.ExternalTopPorts && (len(hosts) != 1 || !hosts[0].timedOut) {
		if slices.Equal(scanned, commonports.Numbers()) {
			return nil, nil, errOlderShape
		}
		return nil, nil, &topPortsError{n: len(scanned)}
	}
	h, err := externalHost(hosts, ip, func(p int) bool { _, ok := slices.BinarySearch(scanned, p); return ok })
	if err != nil {
		return nil, nil, err
	}
	for _, p := range h.ports {
		open = append(open, p.number)
	}
	slices.Sort(open)
	if len(open) > commonports.MaxBelievableOpen { // A router or SYN proxy answering for every port
		return nil, nil, ErrAnswersEverywhere
	}
	return scanned, open, nil
}

// expandRanges is the ascending distinct ports of ranges; nil when they hold more than limit ports.
func expandRanges(rs []observe.PortRange, limit int) []int {
	var out []int
	for _, r := range rs {
		if len(out)+r.To-r.From+1 > limit {
			return nil
		}
		for p := r.From; p <= r.To; p++ {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// versionsOf reads the services of one -sV batch of the External shape, which probed exactly ports. With everywhere (the discovery saw
// the address answer on almost every port), or with more than commonports.MaxBelievableOpen open ports here, the address is a router
// or SYN proxy answering for every port: only the ports where -sV named a real service (identifiedService) are kept, and
// AnswersEverywhere says the others were dropped.
func versionsOf(hosts []host, ip netip.Addr, ports []int, everywhere bool) (External, error) {
	h, err := externalHost(hosts, ip, func(p int) bool { _, ok := slices.BinarySearch(ports, p); return ok })
	if err != nil {
		return External{}, err
	}
	ext := External{Services: externalServicesOf(h)}
	if everywhere || len(ext.Services) > commonports.MaxBelievableOpen {
		ext.Services = slices.DeleteFunc(ext.Services, func(x ExternalService) bool { return !identifiedService(x) })
		ext.AnswersEverywhere = true
	}
	return ext, nil
}

// identifiedService says -sV named a real service on the port: a product or a version, or a service name a probe matched that is
// not "tcpwrapped" (the port accepted the connection and closed it, what a SYN proxy does on every port) nor "unknown". A name taken
// only from the port number (method "table") is not one.
func identifiedService(x ExternalService) bool {
	if x.Product != "" || x.Version != "" {
		return true
	}
	name := strings.TrimPrefix(x.Name, "ssl/")
	return name != "" && name != "tcpwrapped" && name != "unknown" && x.Method != "table"
}

// externalServicesOf is what -sV read on each open port of h.
func externalServicesOf(h host) []ExternalService {
	out := []ExternalService{}
	for _, p := range h.ports {
		cpe := ""
		for _, c := range p.cpes {
			if strings.HasPrefix(c, "cpe:/a:") {
				cpe = c
				break
			}
		}
		out = append(out, ExternalService{Port: p.number, Name: p.name, Product: p.product, Version: p.version, CPE: cpe, Extra: p.info, Method: p.method, Conf: p.conf})
	}
	return out
}

// externalOf reads the result of a full run (every TCP port, -p-; the disruptive scripts' run: ports only): the services of its open
// ports (more than commonports.MaxBelievableOpen is ErrAnswersEverywhere) and its script results (of an open port, or of the host).
// The External shape's two runs are read by discoveryOf and versionsOf.
func externalOf(hosts []host, ip netip.Addr, kind nmapargv.Kind, ports []int) (External, error) {
	if !kind.IsFull() {
		return External{}, fmt.Errorf("sensoractive: %s is not a full shape", kind.Name())
	}
	asked := func(p int) bool { return p >= 1 && p <= 65535 }
	if kind == nmapargv.ExternalDisruptive {
		asked = func(p int) bool { return slices.Contains(ports, p) }
	}
	h, err := externalHost(hosts, ip, asked)
	if err != nil {
		return External{}, err
	}
	ext := External{Services: externalServicesOf(h), Ports: 65535, Scripts: []ExternalScript{}, Refused: h.closed > 0}
	if kind == nmapargv.ExternalDisruptive {
		ext.Ports, ext.Probed = len(ports), slices.Clone(ports)
	}
	if len(ext.Services) > commonports.MaxBelievableOpen { // A router or SYN proxy answering for every port
		return External{}, ErrAnswersEverywhere
	}
	seen := map[int]bool{}
	for _, p := range h.ports {
		seen[p.number] = true
	}
	for _, sc := range h.scripts {
		if sc.port != 0 && !seen[sc.port] { // parseNmapXML keeps only scripts of open ports: never reached
			return External{}, fmt.Errorf("%w: a script of port %d, which is not open", errXMLInvalid, sc.port)
		}
		row := ExternalScript{Port: sc.port, ID: sc.id, Output: sc.output}
		for _, f := range sc.findings {
			row.Findings = append(row.Findings, ScriptFinding{State: f.state, Title: f.title, CVEs: slices.Clone(f.cves)})
		}
		ext.Scripts = append(ext.Scripts, row)
	}
	return ext, nil
}

// deepNow is the DeepGate half of core's fence of a full run: the shape the target's terms allow now, never more than
// asked; ErrNotDeep when they no longer allow a deep scan or own has no DeepGate (fail closed). Nothing has been sent yet.
func (s *Service) deepNow(ctx context.Context, ip netip.Addr, asked nmapargv.Kind, own OwnEgress) (nmapargv.Kind, error) {
	g, ok := own.(DeepGate)
	if !ok {
		return 0, ErrNotDeep
	}
	now, err := g.ShapeNow(ctx, asked)
	switch {
	case ctx.Err() != nil:
		return 0, ErrStopped
	case err != nil:
		return 0, fmt.Errorf("sensoractive: checking the testing terms of %s: %w", ip, err)
	case !now.IsFull():
		s.log.WarnContext(ctx, "sensoractive: deep scan refused, the target's testing terms no longer allow it; no packet sent", "ip", ip.String())
		return 0, ErrNotDeep
	case asked == nmapargv.ExternalDisruptive && now == nmapargv.ExternalFull:
		s.log.InfoContext(ctx, "sensoractive: the disruptive checks are no longer allowed for this target; the disruptive scripts were not sent", "ip", ip.String())
		return 0, ErrNotDisruptive
	}
	return asked, nil // never more than asked
}

// maxProbeResult is sa_probe.result's CHECK (length(result) <= 200, migration 0006).
const maxProbeResult = 200

// probeNote is the front of a domain_ip probe row's result: why the address was chosen, with the CNAME chain of
// the name as core saw it. The zero value (no domain) adds nothing.
type probeNote struct {
	d     *DomainIP
	label string // an external -sV batch's "batch 2 of 5", in front of its result
}

// with is the row's result: the note, then result, always within maxProbeResult (review r2 H3: a long name or CDN CNAME must never fail
// the insert or the update). The result is kept whole; the note shrinks first to "domain_ip <domain> -> <final name>: ", then each of
// the two names keeps its end (the registrable part of a name is at its end).
func (n probeNote) with(result string) string {
	if n.label != "" {
		result = n.label + ": " + result
	}
	result = clipRunes(result, maxProbeResult)
	if n.d == nil {
		return result
	}
	d := n.d.Scope
	chain := n.d.Chain
	if chain == "" {
		chain = d.Name
	}
	room := maxProbeResult - utf8.RuneCountInString(result)
	full := "domain_ip " + d.Domain + ", name " + d.Name + " (CNAME chain: " + chain + "): "
	if utf8.RuneCountInString(full) <= room {
		return full + result
	}
	final := chain
	if k := strings.LastIndex(chain, " -> "); k >= 0 {
		final = chain[k+4:]
	}
	const frame = len("domain_ip  -> : ")
	each := max((room-frame)/2, 0)
	return clipRunes("domain_ip "+keepEnd(d.Domain, each)+" -> "+keepEnd(final, each)+": ", max(room, 0)) + result
}

// keepEnd is s, or its last n runes after "…" when it is longer.
func keepEnd(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[len(r)-max(n, 0):])
	}
	return "…" + string(r[len(r)-n+1:])
}
