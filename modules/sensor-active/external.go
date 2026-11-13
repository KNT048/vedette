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

// Errors of ScanExternal. No packet went to ip when one of these is returned before the probe row was written: ErrBusy (another
// nmap run kept the slot for busyWait), ErrNotOwnIP (the fence in core or in the worker said no). ErrHostTimedOut: nmap ran and
// gave up on the host at its --host-timeout, so it printed no port table and nothing can be said of the services.
var (
	ErrBusy         = errors.New("sensoractive: the scan container's nmap is busy with another scan")
	ErrNotOwnIP     = errors.New("sensoractive: the address is not the box's own public IP now")
	ErrHostTimedOut = errors.New("sensoractive: nmap gave up on the address before it finished")
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

// externalPorts are the port numbers the external shape names (-p); a port outside them in the XML fails the run (INV-7).
var externalPorts = commonports.Numbers()

// ScanExternal identifies the services on the open TCP ports of ip, the box's own verified public IP, for exposure (D-514).
// Order: wait at most busyWait for the nmap slot (else ErrBusy); the worker must be there (ErrUnavailable); a job row; then,
// right before the job is handed out, own says whether ip is still the box's own egress (else ErrNotOwnIP, nothing sent); the
// probe row; then the job. A nil own refuses (fail closed). The stop of the module (Stop) or of ctx ends it with ErrStopped.
func (s *Service) ScanExternal(ctx context.Context, ip netip.Addr, own OwnEgress) (External, error) {
	targets := []netip.Addr{ip}
	args, err := nmapargv.Build(nmapargv.External, nmapargv.ExternalRate, targets)
	if err != nil {
		return External{}, fmt.Errorf("sensoractive: %w", err)
	}
	if own == nil {
		return External{}, ErrNotOwnIP
	}
	if !s.lockWithin(ctx, busyWait) {
		if ctx.Err() != nil {
			return External{}, ErrStopped
		}
		return External{}, ErrBusy
	}
	defer s.runMu.Unlock()
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
	targets := []netip.Addr{ip}
	probeID, err := s.insertProbe(ctx, jobID, nmapargv.External, nmapargv.ExternalRate, targets)
	if err != nil {
		return External{}, err
	}
	if ctx.Err() != nil {
		s.finishProbe(ctx, probeID, stoppedText)
		return External{}, ErrStopped
	}
	timeout := externalRun
	if d, ok := ctx.Deadline(); ok {
		timeout = min(time.Until(d), externalRun)
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, runErr := s.prober.Probe(rctx, args)
	hosts, result, err := runOutcome(ctx, rctx, out, runErr, targets)
	var ext External
	if err == nil {
		if ext, err = externalOf(hosts); err != nil {
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

// externalOf reads the services of an external run from the hosts nmap reported for the one address (onlyTargets already dropped
// any other). Beyond the limits of parseNmapXML (INV-7) it fails closed on more than one host, a port that is not TCP or not in
// the probed list, and a port twice: an answer outside what was asked is not believed in part (D-514).
func externalOf(hosts []host) (External, error) {
	ext := External{Services: []ExternalService{}, Ports: len(externalPorts)}
	switch {
	case len(hosts) > 1:
		return External{}, fmt.Errorf("%w: %d hosts for one address", errXMLInvalid, len(hosts))
	case len(hosts) == 0:
		return ext, nil // -Pn reports the host up; none means nmap printed nothing for it
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
