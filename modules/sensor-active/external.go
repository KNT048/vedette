package sensoractive

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/modules/scan/commonports"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// Service identification on the box's own verified public IP, for exposure (D-514, exposure INV-19, plan exposure-real-vulns
// §1.3): nmap -sV in the scan container over the fixed TCP list of the surface scan (nmapargv.External). The consent is exposure's
// (a verified, committed, current IP target), not the LAN scope's: the LAN settings, window and scope do not apply, and nothing
// is written to the inventory. What holds: one nmap at a time on the box (runMu), the own-IP fence right before the job is handed
// out (and again in the worker), the probe row before the job (INV-9, LEGAL §3), the XML limits (INV-7) and a tighter port bound.
// A target whose testing terms are accepted gets the deep scan instead (D-526, sensor-active INV-19): nmapargv.ExternalFull or
// ExternalDisruptive, every TCP port with nmap's scripts, sent only after core's DeepGate said the terms still allow it.

// KindExternal is the sa_job kind of an external run (migration 0005).
const KindExternal = "external"

// Errors of ScanExternal. No packet went to ip with ErrBusy (another nmap run kept the slot), ErrNoTime (too little of the caller's
// time was left for the run, #723 review L5), ErrNotOwnIP (the fence in core or in the worker saw the box leave through another
// address) or ErrEgressUnverified (the worker could not reach the public IP services to check). ErrHostTimedOut: nmap ran and
// gave up on the host at its --host-timeout, so it printed no port table and nothing can be said of the services.
// ErrAnswersEverywhere: nmap saw more than commonports.MaxBelievableOpen ports open, the shape of a router or firewall that
// answers for every port (D-522, N5): its -sV rows describe that device, not services, so they are discarded.
var (
	ErrBusy              = errors.New("sensoractive: the scan container's nmap is busy with another scan")
	ErrNoTime            = errors.New("sensoractive: too little time was left for service identification")
	ErrNotOwnIP          = errors.New("sensoractive: the address is not the box's own public IP now")
	ErrEgressUnverified  = errors.New("sensoractive: the public IP services could not be reached to check the address")
	ErrHostTimedOut      = errors.New("sensoractive: nmap gave up on the address before it finished")
	ErrAnswersEverywhere = errors.New("sensoractive: the address answers on almost every port")
	// ErrNotDeep (D-526): a full shape was asked, and right before the job is handed out the target's testing terms no longer
	// allow a deep scan (withdrawn, or of an older version), or the fence cannot tell (no DeepGate). Nothing was sent: the run was
	// asked as deep, so it never falls back to the External shape by itself.
	ErrNotDeep = errors.New("sensoractive: the target's testing terms no longer allow a deep scan")
	// ErrFullUnsupported (D-526): the worker's latest heartbeat does not say it runs the full shapes (an older worker, while an
	// update runs). Nothing was sent.
	ErrFullUnsupported = errors.New("sensoractive: the scan container's worker is older and runs no deep nmap scan")
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

// DeepGate is the second half of core's fence of a full run (FULL-4, D-526), asked right after OwnEgress, right before the job is
// handed out: which external shape the target's testing terms allow now, given the one asked. A full run is sent only through an
// OwnEgress that implements it (fail closed). An answer that is not a full shape is ErrNotDeep; ExternalFull for an asked
// ExternalDisruptive (the disruptive tick taken back) runs the full shape without the disruptive scripts; the run never gets more
// than it asked for.
type DeepGate interface {
	ShapeNow(ctx context.Context, asked nmapargv.Kind) (nmapargv.Kind, error)
}

// ExternalService is what -sV read on one open TCP port. The strings come from the network: printable, at most 200 runes
// (text, INV-7); CPE is the first application CPE ("cpe:/a:…") nmap printed, "" when none. exposure limits them further.
type ExternalService struct {
	Port    int
	Name    string
	Product string
	Version string
	CPE     string
	Extra   string
}

// ExternalScript is one NSE script result of a full run (D-526): Port is the open TCP port it ran on, 0 for a host script
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

// External is the result of ScanExternal: the open ports with what -sV read, how many TCP ports were probed, and the script
// results of a full run (nil for the External shape).
type External struct {
	Services []ExternalService
	Ports    int
	Scripts  []ExternalScript
}

// externalRun bounds an external run whose context has no deadline (exposure gives it 5 minutes, ServicesTimeout there); fullRun
// that of a full run (exposure gives it FullServicesTimeout, the host timeout plus 10 minutes).
const (
	externalRun = 5 * time.Minute
	fullRun     = nmapargv.FullHostTimeout + 10*time.Minute
)

// externalNeed is the least time an external run needs once it has the nmap slot and core's fence said yes (#723 review L5): the
// worker's fence (at most 5 rounds of 5 s), nmap's --host-timeout of 3 minutes, and the pickup and the result (15 s). With less
// left of the caller's deadline the run is skipped (ErrNoTime) rather than cut by it halfway; the wait for the slot is shortened
// to leave it, plus coreFenceTime for core's own check. fullNeed is the same with the full shapes' host timeout.
const (
	externalNeed  = 25*time.Second + 3*time.Minute + 15*time.Second
	fullNeed      = 25*time.Second + nmapargv.FullHostTimeout + 15*time.Second
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

// externalPorts are the port numbers the external shape names (-p); a port outside them in the XML fails the run (INV-7).
var externalPorts = commonports.Numbers()

// ScanExternal identifies the services on the open TCP ports of ip, the box's own verified public IP, for exposure (D-514), with
// the shape kind: External, or one of the full shapes of a target whose testing terms are accepted (D-526).
// Order: wait for the nmap slot at most busyWait, and never so long that less than the run's need plus coreFenceTime would be left
// (else ErrBusy, or ErrNoTime when no wait at all fits); a Stop that came during the wait ends it (ErrStopped); the worker must be
// there (ErrUnavailable); a job row; then, right before the job is handed out, own says whether ip is still the box's own egress
// (else ErrNotOwnIP, nothing sent) and, for a full shape, own's DeepGate which shape the terms allow now (else ErrNotDeep); less
// than the need left → ErrNoTime; the probe row; then the job. A nil own refuses (fail closed). The stop of the module (Stop) or
// of ctx ends it with ErrStopped.
func (s *Service) ScanExternal(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, own OwnEgress) (External, error) {
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
	need, run := boundsOf(kind)
	wait := min(busyWait, left(ctx, run)-need-coreFenceTime)
	if wait < 0 {
		return External{}, ErrNoTime
	}
	stops := s.stops.Load()
	if !s.lockWithin(ctx, wait) {
		if ctx.Err() != nil {
			return External{}, ErrStopped
		}
		return External{}, ErrBusy
	}
	defer s.runMu.Unlock()
	if s.stops.Load() != stops { // the module was turned off while the run waited for the slot (#723 review L4)
		return External{}, ErrStopped
	}
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.setCur(&running{cancel: cancel, targets: targets, rate: nmapargv.ExternalRateOf(kind), kind: kind, external: true})
	defer s.setCur(nil)
	if err := s.available(jctx); err != nil {
		return External{}, err
	}
	id, err := s.startJob(ctx, KindExternal, "exposure", 1)
	if err != nil {
		return External{}, err
	}
	res, err := s.probeExternal(jctx, id, ip, kind, own)
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

func (s *Service) probeExternal(ctx context.Context, jobID string, ip netip.Addr, kind nmapargv.Kind, own OwnEgress) (External, error) {
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
	if kind.IsFull() {
		if kind, err = s.deepNow(ctx, ip, kind, own); err != nil {
			return External{}, err
		}
	}
	need, run := boundsOf(kind)
	if left(ctx, run) < need {
		return External{}, ErrNoTime
	}
	targets := []netip.Addr{ip}
	rate := nmapargv.ExternalRateOf(kind)
	args, err := nmapargv.Build(kind, rate, targets)
	if err != nil {
		return External{}, fmt.Errorf("sensoractive: %w", err)
	}
	probeID, err := s.insertProbe(ctx, jobID, kind, rate, targets)
	if err != nil {
		return External{}, err
	}
	if ctx.Err() != nil {
		s.finishProbe(ctx, probeID, stoppedText)
		return External{}, ErrStopped
	}
	rctx, cancel := context.WithTimeout(ctx, min(left(ctx, run), run))
	defer cancel()
	out, runErr := s.prober.Probe(rctx, args)
	hosts, result, err := runOutcome(ctx, rctx, out, runErr)
	var ext External
	if err == nil {
		if ext, err = externalOf(hosts, ip, kind); err != nil {
			result = "failed: output not valid, discarded"
			switch {
			case errors.Is(err, ErrHostTimedOut):
				result = "failed: nmap gave up on the address at its host timeout"
			case errors.Is(err, ErrAnswersEverywhere):
				result = "failed: the address answers on almost every port; the service results were discarded"
			}
		} else {
			result = fmt.Sprintf("ok: %d open ports", len(ext.Services))
			if kind.IsFull() {
				result += fmt.Sprintf(", %d script results", len(ext.Scripts))
			}
		}
	}
	s.finishProbe(ctx, probeID, result)
	if errors.Is(err, errDeadline) {
		err = ErrStopped
	}
	if err != nil {
		return External{}, err
	}
	return ext, nil
}

// externalOf reads the services of an external run from every host nmap reported up. Beyond the limits of parseNmapXML (INV-7)
// it fails closed on anything but exactly one host, the asked address (-Pn reports it up; none means nmap printed nothing usable
// for it, never "no open port", #723 review L3), a port that is not TCP or not in the probed list, and a port twice: an answer
// outside what was asked is not believed in part (D-514). More than commonports.MaxBelievableOpen open ports is
// ErrAnswersEverywhere (D-522). A full shape probed every TCP port (-p-, D-526): any port 1..65535 is in the list, and its script
// results (of an open port of the list, or of the host) are kept.
func externalOf(hosts []host, ip netip.Addr, kind nmapargv.Kind) (External, error) {
	probed := func(p int) bool { return slices.Contains(externalPorts, p) }
	ext := External{Services: []ExternalService{}, Ports: len(externalPorts)}
	if kind.IsFull() {
		probed = func(p int) bool { return p >= 1 && p <= 65535 }
		ext.Ports, ext.Scripts = 65535, []ExternalScript{}
	}
	switch {
	case len(hosts) != 1:
		return External{}, fmt.Errorf("%w: %d hosts for one address", errXMLInvalid, len(hosts))
	case hosts[0].addr != ip:
		return External{}, fmt.Errorf("%w: a host that was not asked about", errXMLInvalid)
	case hosts[0].timedOut:
		return External{}, ErrHostTimedOut
	}
	seen := map[int]bool{}
	for _, p := range hosts[0].ports {
		if p.proto != "tcp" || !probed(p.number) || seen[p.number] {
			return External{}, fmt.Errorf("%w: port %s/%d was not probed", errXMLInvalid, p.proto, p.number)
		}
		seen[p.number] = true
		cpe := ""
		for _, c := range p.cpes {
			if strings.HasPrefix(c, "cpe:/a:") {
				cpe = c
				break
			}
		}
		ext.Services = append(ext.Services, ExternalService{Port: p.number, Name: p.name, Product: p.product, Version: p.version, CPE: cpe, Extra: p.info})
	}
	if len(ext.Services) > commonports.MaxBelievableOpen { // D-522 (N5): a router or SYN proxy answering for every port
		return External{}, ErrAnswersEverywhere
	}
	if kind.IsFull() {
		for _, sc := range hosts[0].scripts {
			if sc.port != 0 && !seen[sc.port] { // parseNmapXML keeps only scripts of open ports: never reached
				return External{}, fmt.Errorf("%w: a script of port %d, which is not open", errXMLInvalid, sc.port)
			}
			row := ExternalScript{Port: sc.port, ID: sc.id, Output: sc.output}
			for _, f := range sc.findings {
				row.Findings = append(row.Findings, ScriptFinding{State: f.state, Title: f.title, CVEs: slices.Clone(f.cves)})
			}
			ext.Scripts = append(ext.Scripts, row)
		}
	}
	return ext, nil
}

// deepNow is the DeepGate half of core's fence of a full run (D-526): the shape the target's terms allow now, never more than
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
