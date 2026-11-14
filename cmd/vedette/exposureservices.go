package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/knt048/vedette/modules/exposure"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// exposureServiceScan is exposure's ServiceScanner over sensor-active's ScanExternal (S-EXP-2, exposure INV-19, D-514): nmap -sV
// in the scan container on the box's own verified public IP. It is BUILT, NOT WIRED: exposureService leaves cfg.Services unset
// until kien words the commitment sentence that names service identification (.ai/deferred/feat-exposure-services-mlee.md,
// plan exposure-real-vulns §3); PRIVACY flow 9 and THIRD_PARTY_NOTICES change in the same commit as the wiring.
//
// The fence (exposure INV-13): right before the job is handed out, sensor-active asks gate, which is exposure's own
// ScannableIP (verified, committed, seen by the public-IP check within 5 minutes, else a fresh full check, with the person who
// pressed Scan now as the actor); the worker checks again by itself before nmap. Every reason the step did not run that the page
// may show is an *exposure.Unavailable; a stop by the caller's context (exposure's 5-minute bound included) stays a context
// error, so exposure says "did not finish within 5 minutes" or drops the run.
type exposureServiceScan struct {
	on   func() bool // sensor-active is switched on
	scan func(ctx context.Context, ip netip.Addr, own sensoractive.OwnEgress) (sensoractive.External, error)
	gate func(ctx context.Context, actor string, ip netip.Addr) (bool, error)
}

// The reasons exposure shows after "Service identification (nmap -sV) did not run: ".
const (
	servicesOff     = "the Active discovery module is off, so the scan container does not run nmap. An admin can turn it on in Settings, Modules."
	servicesBusy    = "the scan container's nmap was busy with another scan. Scan again later."
	servicesNoTime  = "too little of the 5 minutes of this step was left to run nmap -sV. Scan again later."
	servicesNoCheck = "the scan container could not reach the public IP services to check that %s is still this box's address, so its ports were not probed. Check that the box can reach checkip.amazonaws.com, icanhazip.com and ifconfig.me over HTTPS."
	servicesNoWork  = "the scan container is not available (it has not reported, or it has no nmap). Settings, Sensors says why."
	servicesNotOwn  = "this box no longer reaches the Internet through %s, so its ports were not probed."
	servicesOld     = "the scan container refused the job; it may be older than the rest of Vedette. Update the box, then scan again."
	servicesGaveUp  = "nmap gave up on the address after 3 minutes before it finished, so no service versions were read."
	servicesStopped = "the scan was stopped: the Active discovery module was turned off."
)

// ownGate is the core half of the fence as sensor-active asks it: exposure's gate, with the person who started the scan as actor.
type ownGate struct {
	actor string
	gate  func(ctx context.Context, actor string, ip netip.Addr) (bool, error)
}

func (g ownGate) OwnEgress(ctx context.Context, ip netip.Addr) (bool, error) {
	return g.gate(ctx, g.actor, ip)
}

func (a exposureServiceScan) ScanServices(ctx context.Context, t exposure.ScanTarget, ip netip.Addr) (exposure.ServiceScan, error) {
	if a.on != nil && !a.on() {
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesOff}
	}
	ctx, cancel := context.WithTimeout(ctx, exposure.ServicesTimeout) // exposure bounds the step too; this keeps the adapter honest alone
	defer cancel()
	got, err := a.scan(ctx, ip, ownGate{actor: t.User, gate: a.gate})
	switch {
	case err == nil:
	case ctx.Err() != nil: // exposure's bound or the run's stop: exposure tells them apart
		return exposure.ServiceScan{}, ctx.Err()
	case errors.Is(err, sensoractive.ErrStopped):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesStopped}
	case errors.Is(err, sensoractive.ErrNoTime):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesNoTime}
	case errors.Is(err, sensoractive.ErrEgressUnverified): // before ErrWorkerRefused, which wraps it
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: fmt.Sprintf(servicesNoCheck, ip)}
	case errors.Is(err, sensoractive.ErrBusy):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesBusy}
	case errors.Is(err, sensoractive.ErrNotOwnIP):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: fmt.Sprintf(servicesNotOwn, ip)}
	case errors.Is(err, sensoractive.ErrUnavailable):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesNoWork}
	case errors.Is(err, sensoractive.ErrWorkerRefused):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesOld}
	case errors.Is(err, sensoractive.ErrHostTimedOut):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesGaveUp}
	default:
		return exposure.ServiceScan{}, err // logged by exposure, shown as a failure without its text
	}
	out := exposure.ServiceScan{Services: make([]exposure.ServiceRow, 0, len(got.Services)), Ports: got.Ports}
	for _, s := range got.Services {
		out.Services = append(out.Services, exposure.ServiceRow{IP: ip.String(), Port: s.Port, Name: s.Name, Product: s.Product, Version: s.Version, CPE: s.CPE, Extra: s.Extra})
	}
	return out, nil
}

// exposureServicesFor builds the scanner for exposureService. Not called yet: see exposureServiceScan.
func exposureServicesFor(d deps, gate func(ctx context.Context, actor string, ip netip.Addr) (bool, error)) exposureServiceScan {
	return exposureServiceScan{
		on: func() bool { return d.Reg == nil || d.Reg.Enabled("sensor-active") },
		scan: func(ctx context.Context, ip netip.Addr, own sensoractive.OwnEgress) (sensoractive.External, error) {
			svc, err := sensorActiveService(ctx, d) // built once per database; it keeps ctx's values, never its end
			if err != nil {
				return sensoractive.External{}, err
			}
			return svc.ScanExternal(ctx, ip, own)
		},
		gate: gate,
	}
}
