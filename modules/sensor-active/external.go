package sensoractive

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

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
// A target whose testing terms are accepted gets the deep scan instead (sensor-active INV-19): nmapargv.ExternalFull or
// ExternalDisruptive, every TCP port with nmap's scripts, sent only after core's DeepGate said the terms still allow it.

// KindExternal is the kind of the scan events of a service scan for exposure.
const KindExternal = "external"

// Errors of ScanExternal. No packet went to ip with ErrBusy (another nmap run kept the slot), ErrNoTime (too little of the caller's
// time was left for the run, #723 review L5), ErrNotOwnIP (the fence in core or in the worker saw the box leave through another
// address) or ErrEgressUnverified (the worker could not reach the public IP services to check). ErrHostTimedOut: nmap ran and
// gave up on the host at its --host-timeout, so it printed no port table and nothing can be said of the services.
// ErrAnswersEverywhere: nmap saw more than commonports.MaxBelievableOpen ports open, the shape of a router or firewall that
// answers for every port: its rows describe that device, not services, so they are discarded (the External shape's discovery
// stops there, before any -sV is sent).
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
)

// OwnEgress says whether ip is the box's own verified public egress now: exposure's gate (verified, committed, seen by the
// public-IP check within the last 5 minutes, else a fresh full check; exposure INV-13). cmd/vedette implements it.
type OwnEgress interface {
	OwnEgress(ctx context.Context, ip netip.Addr) (bool, error)
}

// DeepGate is the second half of core's fence of a full run, asked right after OwnEgress, right before the job is
// handed out: which external shape the target's testing terms allow now, given the one asked. A full run is sent only through an
// OwnEgress that implements it (fail closed). An answer that is not a full shape is ErrNotDeep; ExternalFull for an asked
// ExternalDisruptive (the disruptive tick taken back) runs the full shape without the disruptive scripts; the run never gets more
// than it asked for.
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
// shape the ports nmap's discovery says it probed (its <scaninfo>, nmap's own top ports) and those of the -sV run; nil for a full
// shape, which probed every port 1..65535. Ports is their count (65535 for a full shape).
type External struct {
	Services []ExternalService
	Ports    int
	Probed   []int
	Scripts  []ExternalScript
}

// externalRun bounds an external run whose context has no deadline (exposure gives it ServicesTimeout there, 8 minutes); fullRun
// that of a full run (exposure gives it FullServicesTimeout, the host timeout plus 10 minutes).
const (
	externalRun = 8 * time.Minute
	fullRun     = nmapargv.FullHostTimeout + 10*time.Minute
)

// externalStep is what one nmap job of an external shape needs on top of nmap's own --host-timeout once it has the nmap slot and
// core's fence said yes (#723 review L5): the worker's fence (at most 5 rounds of 5 s) and the pickup and the result (15 s).
// externalNeed is the least time an External run needs: its two jobs (the discovery and the -sV run); versionsNeed what the -sV
// run alone needs, checked again before it is sent. With less left of the caller's deadline the run is skipped (ErrNoTime) rather
// than cut by it halfway; the wait for the slot is shortened to leave it, plus coreFenceTime for core's own check. fullNeed is the
// same with the full shapes' host timeout. Worst case of an External run: 2 + 3 minutes of nmap, 6 min 20 s with the steps.
const (
	externalStep  = 25*time.Second + 15*time.Second
	versionsNeed  = externalStep + nmapargv.ExternalVersionsTimeout
	externalNeed  = externalStep + nmapargv.ExternalDiscoveryTimeout + versionsNeed
	fullNeed      = externalStep + nmapargv.FullHostTimeout
	coreFenceTime = 30 * time.Second
)

// boundsOf is the time a run of kind needs and its bound without a deadline.
func boundsOf(kind nmapargv.Kind) (need, run time.Duration) {
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
	return s.scanExternal(ctx, ip, kind, own, nil)
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
	return s.scanExternal(ctx, ip, kind, domainGate{gate}, &d)
}

// domainGate is the OwnEgress of a domain_ip run: never asked (probeExternal skips it), its DeepGate is the caller's.
type domainGate struct{ DeepGate }

func (domainGate) OwnEgress(context.Context, netip.Addr) (bool, error) { return false, nil }

func (s *Service) scanExternal(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, own OwnEgress, dom *DomainIP) (External, error) {
	if !kind.IsExternal() {
		return External{}, fmt.Errorf("sensoractive: %s is not an external shape", kind.Name())
	}
	targets := []netip.Addr{ip}
	if _, err := nmapargv.Build(kind, nmapargv.ExternalRateOf(kind), targets); err != nil {
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
	err := s.doWork(ctx, run.Spec{Kind: RunService, Title: "Service scan of " + ip.String() + " for External exposure", Trigger: run.Event,
		TriggerNote: "an exposure scan", Subject: &run.Subject{Kind: "address", ID: ip.String(), Label: ip.String()}},
		func(ctx context.Context) error {
			res, err := s.serviceScan(ctx, ip, kind, own, dom)
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
func (s *Service) serviceScan(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, own OwnEgress, dom *DomainIP) (External, error) {
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
	res, err := s.probeExternal(jctx, id, ip, kind, own, dom)
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

func (s *Service) probeExternal(ctx context.Context, jobID string, ip netip.Addr, kind nmapargv.Kind, own OwnEgress, dom *DomainIP) (External, error) {
	var note probeNote
	if dom == nil {
		ok, err := own.OwnEgress(ctx, ip) // exposure's gate result is minutes old by now (exposure INV-13, INV-19)
		switch {
		case ctx.Err() != nil:
			return External{}, ErrStopped
		case err != nil:
			return External{}, fmt.Errorf("sensoractive: checking that %s is the box's own public IP: %w", ip, err)
		case !ok:
			s.log.WarnContext(ctx, "sensoractive: external scan refused, the address is not the box's own public IP now; no packet sent", "ip", ip.String())
			return External{}, ErrNotOwnIP
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
		return s.probeDefault(ctx, jobID, ip, own)
	}
	var ext External
	err := s.externalJob(ctx, jobID, ip, kind, nil, note, dom, run, func(hosts []host) (string, error) {
		var err error
		if ext, err = externalOf(hosts, ip, kind); err != nil {
			return "", err
		}
		return fmt.Sprintf("ok: %d open ports, %d script results", len(ext.Services), len(ext.Scripts)), nil
	})
	if err != nil {
		return External{}, err
	}
	return ext, nil
}

// probeDefault is the External shape on the box's own public IP, two nmap jobs under the one job row: the discovery (SYN only,
// nmap's own top ports), then, unless it found more than commonports.MaxBelievableOpen open (ErrAnswersEverywhere, no -sV sent), core's
// own-IP fence again and the -sV run over ExternalVersionPorts of the open ports found. Each job has its probe row (INV-9).
func (s *Service) probeDefault(ctx context.Context, jobID string, ip netip.Addr, own OwnEgress) (External, error) {
	var scanned []int
	var open []int
	err := s.externalJob(ctx, jobID, ip, nmapargv.External, nil, probeNote{}, nil, externalRun, func(hosts []host) (string, error) {
		var err error
		scanned, open, err = discoveryOf(hosts, ip)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("ok: %d of %d ports open", len(open), len(scanned)), nil
	})
	if err != nil {
		return External{}, err
	}
	ports, err := nmapargv.ExternalVersionPorts(open)
	if err != nil { // more open ports than believable: discoveryOf said so already
		return External{}, fmt.Errorf("%w: %w", ErrAnswersEverywhere, err)
	}
	ok, err := own.OwnEgress(ctx, ip) // the discovery took up to its host timeout: ask again before the next job leaves
	switch {
	case ctx.Err() != nil:
		return External{}, ErrStopped
	case err != nil:
		return External{}, fmt.Errorf("sensoractive: checking that %s is the box's own public IP: %w", ip, err)
	case !ok:
		s.log.WarnContext(ctx, "sensoractive: external scan stopped after its port discovery, the address is not the box's own public IP now; no -sV sent", "ip", ip.String())
		return External{}, ErrNotOwnIP
	}
	if left(ctx, externalRun) < versionsNeed {
		return External{}, ErrNoTime
	}
	var ext External
	err = s.externalJob(ctx, jobID, ip, nmapargv.External, ports, probeNote{}, nil, externalRun, func(hosts []host) (string, error) {
		var err error
		if ext, err = versionsOf(hosts, ip, ports); err != nil {
			return "", err
		}
		return fmt.Sprintf("ok: %d open ports", len(ext.Services)), nil
	})
	if err != nil {
		return External{}, err
	}
	ext.Probed = unionPorts(scanned, ports)
	ext.Ports = len(ext.Probed)
	return ext, nil
}

// externalJob runs one nmap job of an external shape (ports: the -sV run of the External shape, nil otherwise) with its probe row,
// bounded by what is left of run: read turns the hosts of its XML into the row's "ok" text, or an error the row names.
func (s *Service) externalJob(ctx context.Context, jobID string, ip netip.Addr, kind nmapargv.Kind, ports []int, note probeNote, dom *DomainIP, run time.Duration,
	read func([]host) (string, error)) error {
	targets := []netip.Addr{ip}
	rate := nmapargv.ExternalRateOf(kind)
	args, err := nmapargv.BuildFor(kind, rate, ports, targets)
	if err != nil {
		return fmt.Errorf("sensoractive: %w", err)
	}
	probeID, err := s.insertProbe(ctx, jobID, kind, rate, targets, note, ports...)
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
	if dom != nil {
		out, runErr = s.prober.(DomainProber).ProbeDomain(rctx, args, dom.Scope) //nolint:forcetypeassert // checked by probeExternal
	} else {
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
	if err == nil {
		if result, err = read(hosts); err != nil {
			result = "failed: output not valid, discarded"
			switch {
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

// discoveryOf reads the External shape's discovery: the TCP ports nmap says it probed (its <scaninfo services>, which must be
// exactly nmapargv.ExternalTopPorts ports, as --top-ports asked: anything else is not the run that was asked for) and the open ones
// among them, ascending. More than commonports.MaxBelievableOpen open is ErrAnswersEverywhere: no -sV run follows.
func discoveryOf(hosts []host, ip netip.Addr) (scanned, open []int, err error) {
	if len(hosts) == 1 {
		scanned = expandRanges(hosts[0].scanned, nmapargv.ExternalTopPorts)
	}
	if len(scanned) != nmapargv.ExternalTopPorts && (len(hosts) != 1 || !hosts[0].timedOut) {
		return nil, nil, fmt.Errorf("%w: the run probed %d ports, not nmap's top %d", errXMLInvalid, len(scanned), nmapargv.ExternalTopPorts)
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

// versionsOf reads the services of the External shape's -sV run, which probed exactly ports.
func versionsOf(hosts []host, ip netip.Addr, ports []int) (External, error) {
	h, err := externalHost(hosts, ip, func(p int) bool { _, ok := slices.BinarySearch(ports, p); return ok })
	if err != nil {
		return External{}, err
	}
	ext := External{Services: externalServicesOf(h)}
	if len(ext.Services) > commonports.MaxBelievableOpen {
		return External{}, ErrAnswersEverywhere
	}
	return ext, nil
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

// externalOf reads the result of a full run (every TCP port, -p-): the services of its open ports (more than
// commonports.MaxBelievableOpen is ErrAnswersEverywhere) and its script results (of an open port, or of the host). The External
// shape's two runs are read by discoveryOf and versionsOf.
func externalOf(hosts []host, ip netip.Addr, kind nmapargv.Kind) (External, error) {
	if !kind.IsFull() {
		return External{}, fmt.Errorf("sensoractive: %s is not a full shape", kind.Name())
	}
	h, err := externalHost(hosts, ip, func(p int) bool { return p >= 1 && p <= 65535 })
	if err != nil {
		return External{}, err
	}
	ext := External{Services: externalServicesOf(h), Ports: 65535, Scripts: []ExternalScript{}}
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
		s.log.InfoContext(ctx, "sensoractive: the disruptive checks were taken out of the target's testing terms; the deep scan runs without them", "ip", ip.String())
		return now, nil
	}
	return asked, nil // never more than asked
}

// maxProbeResult is sa_probe.result's CHECK (length(result) <= 200, migration 0006).
const maxProbeResult = 200

// probeNote is the front of a domain_ip probe row's result: why the address was chosen, with the CNAME chain of
// the name as core saw it. The zero value (no domain) adds nothing.
type probeNote struct{ d *DomainIP }

// with is the row's result: the note, then result, always within maxProbeResult (review r2 H3: a long name or CDN CNAME must never fail
// the insert or the update). The result is kept whole; the note shrinks first to "domain_ip <domain> -> <final name>: ", then each of
// the two names keeps its end (the registrable part of a name is at its end).
func (n probeNote) with(result string) string {
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
