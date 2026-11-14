package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/knt048/vedette/modules/exposure"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// exposureServiceScan is exposure's ServiceScanner over sensor-active's ScanExternal (S-EXP-2, exposure INV-19, D-514): nmap -sV
// in the scan container on the box's own verified public IP. exposureService sets it as cfg.Services; the commitment sentence of
// NoticeVersion 2026-11-14 (D-559, K-4) names service identification, and PRIVACY flow 9 and THIRD_PARTY_NOTICES say what is sent.
// A target whose testing terms are accepted (ScanTarget.Mode.Full, FULL-1) gets the deep scan instead (FULL-4, D-526): every TCP
// port with nmap's default, safe and vuln scripts (nmapargv.ExternalFull), and the dos and brute scripts too with the disruptive
// tick (nmapargv.ExternalDisruptive); its step is bounded by exposure.FullServicesTimeout.
//
// The fence (exposure INV-13): right before the job is handed out, sensor-active asks gate, which is exposure's own
// ScannableIP (verified, committed, seen by the public-IP check within 5 minutes, else a fresh full check, with the person who
// pressed Scan now as the actor), and for a deep scan modeNow, exposure's ModeNow (the terms as stored now: withdrawn or of an
// older version → nothing is sent; the tick taken back → the deep scan without the disruptive scripts); the worker checks the
// address again by itself before nmap. Every reason the step did not run that the page may show is an *exposure.Unavailable; a
// stop by the caller's context (exposure's bound included) stays a context error, so exposure says "did not finish within …" or
// drops the run.
type exposureServiceScan struct {
	on      func() bool // sensor-active is switched on
	scan    func(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, own sensoractive.OwnEgress) (sensoractive.External, error)
	gate    func(ctx context.Context, actor string, ip netip.Addr) (bool, error)
	modeNow func(ctx context.Context, actor, id string) (exposure.ScanMode, error)
}

// The reasons exposure shows after "Service identification (nmap -sV) did not run: ".
const (
	servicesOff     = "the Active discovery module is off, so the scan container does not run nmap. An admin can turn it on in Settings, Modules."
	servicesBusy    = "the scan container's nmap was busy with another scan. Scan again later."
	servicesNoTime  = "too little of the %d minutes of this step was left to run nmap. Scan again later."
	servicesNoCheck = "the scan container could not reach the public IP services to check that %s is still this box's address, so its ports were not probed. Check that the box can reach checkip.amazonaws.com, icanhazip.com and ifconfig.me over HTTPS."
	servicesNoWork  = "the scan container is not available (it has not reported, or it has no nmap). Settings, Sensors says why."
	servicesNotOwn  = "this box no longer reaches the Internet through %s, so its ports were not probed."
	servicesOld     = "the scan container refused the job; it may be older than the rest of Vedette. Update the box, then scan again."
	servicesStopped = "the scan was stopped: the Active discovery module was turned off."
	// D-526: a deep scan whose terms changed before its job left, and a worker too old for the deep shapes.
	servicesNotDeep = "the testing terms of %s are no longer accepted (withdrawn, or new terms to accept), so the deep scan was not sent. An administrator can accept the terms on the target, then scan again."
	servicesOldFull = "the scan container is older than the rest of Vedette and does not run the deep scan of every TCP port. Update the box, then scan again."
)

// ownGate is the core half of the fence as sensor-active asks it: exposure's gate, with the person who started the scan as actor,
// and for a deep scan exposure's ModeNow of the target (sensoractive.DeepGate).
type ownGate struct {
	actor, id string
	gate      func(ctx context.Context, actor string, ip netip.Addr) (bool, error)
	modeNow   func(ctx context.Context, actor, id string) (exposure.ScanMode, error)
}

func (g ownGate) OwnEgress(ctx context.Context, ip netip.Addr) (bool, error) {
	return g.gate(ctx, g.actor, ip)
}

// ShapeNow is the shape the target's terms allow now (D-526). Without modeNow it says External: no deep scan is sent (fail closed).
func (g ownGate) ShapeNow(ctx context.Context, _ nmapargv.Kind) (nmapargv.Kind, error) {
	if g.modeNow == nil {
		return nmapargv.External, nil
	}
	m, err := g.modeNow(ctx, g.actor, g.id)
	if err != nil {
		return 0, err
	}
	return shapeOf(m), nil
}

// shapeOf is the nmap shape of a scan mode (D-526): the K-4 scope keeps External exactly as before FULL-4; accepted terms make it
// the deep scan, and the disruptive tick adds the dos and brute scripts.
func shapeOf(m exposure.ScanMode) nmapargv.Kind {
	switch {
	case !m.Full:
		return nmapargv.External
	case m.Disruptive:
		return nmapargv.ExternalDisruptive
	}
	return nmapargv.ExternalFull
}

func (a exposureServiceScan) ScanServices(ctx context.Context, t exposure.ScanTarget, ip netip.Addr) (exposure.ServiceScan, error) {
	if a.on != nil && !a.on() {
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesOff}
	}
	kind, bound := shapeOf(t.Mode), exposure.ServicesTimeout
	if kind.IsFull() {
		bound = exposure.FullServicesTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, bound) // exposure bounds the step too; this keeps the adapter honest alone
	defer cancel()
	got, err := a.scan(ctx, ip, kind, ownGate{actor: t.User, id: t.ID, gate: a.gate, modeNow: a.modeNow})
	switch {
	case err == nil:
	case ctx.Err() != nil: // exposure's bound or the run's stop: exposure tells them apart
		return exposure.ServiceScan{}, ctx.Err()
	case errors.Is(err, sensoractive.ErrStopped):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesStopped}
	case errors.Is(err, sensoractive.ErrNoTime):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: fmt.Sprintf(servicesNoTime, int(bound/time.Minute))}
	case errors.Is(err, sensoractive.ErrEgressUnverified): // before ErrWorkerRefused, which wraps it
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: fmt.Sprintf(servicesNoCheck, ip)}
	case errors.Is(err, sensoractive.ErrBusy):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesBusy}
	case errors.Is(err, sensoractive.ErrNotOwnIP):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: fmt.Sprintf(servicesNotOwn, ip)}
	case errors.Is(err, sensoractive.ErrNotDeep): // D-526: never the baseline shape instead, the run was asked as deep
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: fmt.Sprintf(servicesNotDeep, ip)}
	case errors.Is(err, sensoractive.ErrFullUnsupported):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesOldFull}
	case errors.Is(err, sensoractive.ErrUnavailable):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesNoWork}
	case errors.Is(err, sensoractive.ErrWorkerRefused):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesOld}
	case errors.Is(err, sensoractive.ErrHostTimedOut): // D-522 (N5): its own line, never "did not run" nor "0 services"
		return exposure.ServiceScan{}, exposure.ErrServicesTimedOut
	case errors.Is(err, sensoractive.ErrAnswersEverywhere): // D-522 (N5): a router or SYN proxy answering for every port
		return exposure.ServiceScan{}, exposure.ErrAnswersEverywhere
	default:
		return exposure.ServiceScan{}, err // logged by exposure, shown as a failure without its text (a failed ModeNow too: fail closed)
	}
	out := exposure.ServiceScan{Services: make([]exposure.ServiceRow, 0, len(got.Services)), Ports: got.Ports}
	for _, s := range got.Services {
		out.Services = append(out.Services, exposure.ServiceRow{IP: ip.String(), Port: s.Port, Name: s.Name, Product: s.Product, Version: s.Version, CPE: s.CPE, Extra: s.Extra})
	}
	for _, s := range got.Scripts { // D-526: only a deep scan has any; exposure sanitizes them before they are stored
		row := exposure.ScriptRow{IP: ip.String(), Port: s.Port, ID: s.ID, Output: s.Output}
		for _, f := range s.Findings {
			row.Findings = append(row.Findings, exposure.ScriptFinding{State: f.State, Title: f.Title, CVEs: f.CVEs})
		}
		out.Scripts = append(out.Scripts, row)
	}
	return out, nil
}

// exposureServicesFor builds the scanner for exposureService.
func exposureServicesFor(d deps, gate func(ctx context.Context, actor string, ip netip.Addr) (bool, error), modeNow func(ctx context.Context, actor, id string) (exposure.ScanMode, error)) exposureServiceScan {
	return exposureServiceScan{
		on: func() bool { return d.Reg == nil || d.Reg.Enabled("sensor-active") },
		scan: func(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, own sensoractive.OwnEgress) (sensoractive.External, error) {
			svc, err := sensorActiveService(ctx, d) // built once per database; it keeps ctx's values, never its end
			if err != nil {
				return sensoractive.External{}, err
			}
			return svc.ScanExternal(ctx, ip, kind, own)
		},
		gate:    gate,
		modeNow: modeNow,
	}
}
