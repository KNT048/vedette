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

// KindExternal is the sa_job kind of an external run (migration 0005).
const KindExternal = "external"

// Errors of ScanExternal. No packet went to ip with ErrBusy (another nmap run kept the slot), ErrNoTime (too little of the caller's
// time was left for the run, #723 review L5), ErrNotOwnIP (the fence in core or in the worker saw the box leave through another
// address) or ErrEgressUnverified (the worker could not reach the public IP services to check). ErrHostTimedOut: nmap ran and
// gave up on the host at its --host-timeout, so it printed no port table and nothing can be said of the services.
var (
	ErrBusy             = errors.New("sensoractive: the scan container's nmap is busy with another scan")
	ErrNoTime           = errors.New("sensoractive: too little time was left for service identification")
	ErrNotOwnIP         = errors.New("sensoractive: the address is not the box's own public IP now")
	ErrEgressUnverified = errors.New("sensoractive: the public IP services could not be reached to check the address")
	ErrHostTimedOut     = errors.New("sensoractive: nmap gave up on the address before it finished")
)

// OwnEgress says whether ip is the box's own verified public egress now: exposure's gate (verified, committed, seen by the
// public-IP check within the last 5 minutes, else a fresh full check; exposure INV-13). cmd/vedette implements it.
type OwnEgress interface {
	OwnEgress(ctx context.Context, ip netip.Addr) (bool, error)
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

// External is the result of ScanExternal: the open ports with what -sV read, and how many TCP ports were probed.
type External struct {
	Services []ExternalService
	Ports    int
}

// externalRun bounds an external run whose context has no deadline (exposure gives it 5 minutes, ServicesTimeout there).
const externalRun = 5 * time.Minute

// externalNeed is the least time an external run needs once it has the nmap slot and core's fence said yes (#723 review L5): the
// worker's fence (at most 5 rounds of 5 s), nmap's --host-timeout of 3 minutes, and the pickup and the result (15 s). With less
// left of the caller's deadline the run is skipped (ErrNoTime) rather than cut by it halfway; the wait for the slot is shortened
// to leave it, plus coreFenceTime for core's own check.
const (
	externalNeed  = 25*time.Second + 3*time.Minute + 15*time.Second
	coreFenceTime = 30 * time.Second
)

// left is how long ctx has before its deadline (externalRun when it has none).
func left(ctx context.Context) time.Duration {
	if d, ok := ctx.Deadline(); ok {
		return time.Until(d)
	}
	return externalRun
}

// externalPorts are the port numbers the external shape names (-p); a port outside them in the XML fails the run (INV-7).
var externalPorts = commonports.Numbers()

// ScanExternal identifies the services on the open TCP ports of ip, the box's own verified public IP, for exposure (D-514).
// Order: wait for the nmap slot at most busyWait, and never so long that less than externalNeed plus coreFenceTime would be left
// (else ErrBusy, or ErrNoTime when no wait at all fits); a Stop that came during the wait ends it (ErrStopped); the worker must be
// there (ErrUnavailable); a job row; then, right before the job is handed out, own says whether ip is still the box's own egress
// (else ErrNotOwnIP, nothing sent); less than externalNeed left → ErrNoTime; the probe row; then the job. A nil own refuses (fail
// closed). The stop of the module (Stop) or of ctx ends it with ErrStopped.
func (s *Service) ScanExternal(ctx context.Context, ip netip.Addr, own OwnEgress) (External, error) {
	targets := []netip.Addr{ip}
	args, err := nmapargv.Build(nmapargv.External, nmapargv.ExternalRate, targets)
	if err != nil {
		return External{}, fmt.Errorf("sensoractive: %w", err)
	}
	if own == nil {
		return External{}, ErrNotOwnIP
	}
	wait := min(busyWait, left(ctx)-externalNeed-coreFenceTime)
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
	s.setCur(&running{cancel: cancel, targets: targets, rate: nmapargv.ExternalRate, kind: nmapargv.External, external: true})
	defer s.setCur(nil)
	if err := s.available(jctx); err != nil {
		return External{}, err
	}
	id, err := s.startJob(ctx, KindExternal, "exposure", 1)
	if err != nil {
		return External{}, err
	}
	res, err := s.probeExternal(jctx, id, ip, args, own)
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

func (s *Service) probeExternal(ctx context.Context, jobID string, ip netip.Addr, args []string, own OwnEgress) (External, error) {
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
	if left(ctx) < externalNeed {
		return External{}, ErrNoTime
	}
	targets := []netip.Addr{ip}
	probeID, err := s.insertProbe(ctx, jobID, nmapargv.External, nmapargv.ExternalRate, targets)
	if err != nil {
		return External{}, err
	}
	if ctx.Err() != nil {
		s.finishProbe(ctx, probeID, stoppedText)
		return External{}, ErrStopped
	}
	rctx, cancel := context.WithTimeout(ctx, min(left(ctx), externalRun))
	defer cancel()
	out, runErr := s.prober.Probe(rctx, args)
	hosts, result, err := runOutcome(ctx, rctx, out, runErr)
	var ext External
	if err == nil {
		if ext, err = externalOf(hosts, ip); err != nil {
			result = "failed: output not valid, discarded"
			if errors.Is(err, ErrHostTimedOut) {
				result = "failed: nmap gave up on the address at its host timeout"
			}
		} else {
			result = fmt.Sprintf("ok: %d open ports", len(ext.Services))
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
// outside what was asked is not believed in part (D-514).
func externalOf(hosts []host, ip netip.Addr) (External, error) {
	ext := External{Services: []ExternalService{}, Ports: len(externalPorts)}
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
		if p.proto != "tcp" || !slices.Contains(externalPorts, p.number) || seen[p.number] {
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
	return ext, nil
}
