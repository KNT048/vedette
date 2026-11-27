package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/modules/exposure"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// exposureServiceScan is exposure's ServiceScanner over sensor-active's ScanExternal (S-EXP-2, exposure INV-19): nmap in the scan
// container on the box's own verified public IP, port discovery over nmap's 1000 most common TCP ports, then -sV on the open ones
// and the fixed list; the ports it probed reach exposure as ServiceScan.Probed. exposureService sets it as cfg.Services; the commitment sentence of
// NoticeVersion 2026-11-14 (K-4) names service identification, and PRIVACY flow 9 and THIRD_PARTY_NOTICES say what is sent.
// A target whose testing terms are accepted (ScanTarget.Mode.Full) gets the deep scan instead: every TCP
// port with nmap's reviewed default, safe and vuln scripts (nmapargv.ExternalFull); its step is bounded by
// exposure.FullServicesTimeout. When the run allows the disruptive checks, the dos and brute scripts run as the scan's last step
// (ScanDisruptive, nmapargv.ExternalDisruptive) on the open ports the scan found, bounded by exposure.DisruptiveTimeout.
//
// The fence (exposure INV-13): right before the job is handed out, sensor-active asks gate, which is exposure's own
// OwnIPProof (verified, committed, inside its proof's 90 days; a sighting by the public-IP check renews it, with the person who
// pressed Scan now as the actor), and for a deep scan modeNow, exposure's ModeNow (the terms as stored now: withdrawn or of an
// older version → nothing is sent; no disruptive checks allowed now → the deep scan without the disruptive scripts). The job carries
// the time of the sighting the yes rests on (none for an address the box's current one replaced), and the worker takes the address
// as the box's own on that proof while it holds, or on its own sighting right before nmap. Every reason the step did not run that the
// page may show is an *exposure.Unavailable; a
// stop by the caller's context (exposure's bound included) stays a context error, so exposure says "did not finish within …" or
// drops the run.
type exposureServiceScan struct {
	on   func() bool // sensor-active is switched on
	scan func(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, set sensoractive.DeepSettings, own sensoractive.OwnEgress) (sensoractive.External, error)
	// scanDomain is sensor-active's ScanDomainIP: the deep scan of an address a verified domain's name resolves to, as a
	// domain_ip job the worker's own fence checks. nil: such a step is refused (nothing sent).
	scanDomain func(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, set sensoractive.DeepSettings, d sensoractive.DomainIP, gate sensoractive.DeepGate) (sensoractive.External, error)
	// scanOn and scanDomainOn run one of a deep scan's two runs (sensor-active's ScanFullPortsWith and ScanFullOnWith, ScanDomainIPOn):
	// kind nmapargv.ExternalFullPorts without ports, or nmapargv.ExternalFull on the open ports. nil: the deep scan runs in one run
	// (ScanOpenPorts says exposure.ErrPortsFirstUnsupported).
	scanOn       func(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, ports []int, set sensoractive.DeepSettings, own sensoractive.OwnEgress) (sensoractive.External, error)
	scanDomainOn func(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, ports []int, set sensoractive.DeepSettings, d sensoractive.DomainIP, gate sensoractive.DeepGate) (sensoractive.External, error)
	// scanDisruptive is sensor-active's ScanDisruptive: the disruptive scripts on the open ports of the box's own IP. nil: refused.
	scanDisruptive func(ctx context.Context, ip netip.Addr, ports []int, set sensoractive.DeepSettings, own sensoractive.OwnEgress) (sensoractive.External, error)
	gate           ownIPGate
	modeNow        func(ctx context.Context, actor, id string) (exposure.ScanMode, error)
}

// ownIPGate is exposure's OwnIPProof as the executors' adapters ask it, with the person who started the scan as actor: whether ip is
// the box's own verified, committed IP inside its proof's days, and the latest sighting that proof rests on (zero for none).
type ownIPGate func(ctx context.Context, actor string, ip netip.Addr) (provenAt time.Time, ok bool, err error)

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
	// A deep scan whose terms changed before its job left, and a worker too old for the deep shapes.
	servicesNotDeep = "the testing terms of %s are no longer accepted (withdrawn, or new terms to accept), so the deep scan was not sent. An administrator can accept the terms on the target, then scan again."
	servicesOldFull = "the scan container does not run the deep scan of every TCP port: it is older than the rest of Vedette, or its nmap is not the version whose scripts were reviewed. Update the box, then scan again."
	// Review r2 LOW-5: the worker's re-check during a deep scan stopped it; its ports had been probed, the results are discarded.
	servicesNotOwnMid  = "this box stopped reaching the Internet through %s while the deep scan ran, so the deep scan was stopped and its results discarded."
	servicesNoCheckMid = "the scan container could no longer check that %s is still this box's address (the public IP services did not answer), so the deep scan was stopped and its results discarded."
	// servicesOldSettings: the worker does not run a target's deep-scan settings yet; the wider line is never sent instead.
	servicesOldSettings = "the scan container does not apply this target's deep-scan settings (groups turned off, ports to skip, gentle speed): it is older than the rest of Vedette, so nothing was sent. Update the box, then scan again."
	// The disruptive scripts: the terms no longer allow them right before the job, or the step was asked for another address.
	servicesNotDisruptive = "the testing terms of %s no longer allow the disruptive checks (or this scan may not run them), so they were not sent."
	servicesDisruptiveOwn = "the disruptive scripts run only on the box's own public IP."
	// servicesNoPorts: every port the step was given is one the target's settings skip.
	servicesNoPorts = "every open port is one this target's settings skip, so nothing was sent."
)

// ownGate is the core half of the fence as sensor-active asks it: exposure's gate with the proof it rests on (sensoractive.OwnProver),
// with the person who started the scan as actor, and for a deep scan exposure's ModeNow of the target (sensoractive.DeepGate).
type ownGate struct {
	actor, id string
	gate      ownIPGate
	modeNow   func(ctx context.Context, actor, id string) (exposure.ScanMode, error)
}

func (g ownGate) OwnEgress(ctx context.Context, ip netip.Addr) (bool, error) {
	_, ok, err := g.gate(ctx, g.actor, ip)
	return ok, err
}

// OwnProof is OwnEgress with the latest sighting the yes rests on: sensor-active sends it with the job.
func (g ownGate) OwnProof(ctx context.Context, ip netip.Addr) (time.Time, bool, error) {
	return g.gate(ctx, g.actor, ip)
}

// ShapeNow is the shape the target's terms allow now. Without modeNow it says External: no deep scan is sent (fail closed).
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

// GroupsNow is the disruptive groups the target allows now (sensoractive.GroupGate): right before the disruptive scripts leave,
// sensor-active narrows the run's groups to these. Without modeNow none (fail closed).
func (g ownGate) GroupsNow(ctx context.Context) (nmapargv.Groups, error) {
	if g.modeNow == nil {
		return 0, nil
	}
	m, err := g.modeNow(ctx, g.actor, g.id)
	if err != nil {
		return 0, err
	}
	return modeGroups(m), nil
}

// shapeOf is the shape a scan mode allows, as the DeepGate says it: the K-4 scope keeps External exactly as before FULL-4; accepted
// terms make it the deep scan, and the disruptive checks (when the run may do them, with any of their groups) allow the disruptive
// scripts of those groups.
func shapeOf(m exposure.ScanMode) nmapargv.Kind {
	switch {
	case !m.Full:
		return nmapargv.External
	case modeGroups(m) != 0:
		return nmapargv.ExternalDisruptive
	}
	return nmapargv.ExternalFull
}

// nmapGroups are exposure's disruptive groups in g as nmapargv names them.
func nmapGroups(dos, logins, change bool) nmapargv.Groups {
	var out nmapargv.Groups
	if dos {
		out |= nmapargv.GroupDoS
	}
	if logins {
		out |= nmapargv.GroupLogins
	}
	if change {
		out |= nmapargv.GroupChange
	}
	return out
}

// modeGroups are the disruptive groups a scan mode allows (none without the disruptive checks).
func modeGroups(m exposure.ScanMode) nmapargv.Groups {
	if !m.Disruptive {
		return 0
	}
	return nmapGroups(m.DoS, m.Logins, m.Change)
}

// fullSettings are the deep-scan settings of t's nmap runs of kind: the full sweep runs the script groups of the target's settings
// (not the run's: a scheduled scan's full sweep runs them too, as before the settings), the default scan only skips ports.
func fullSettings(t exposure.ScanTarget, kind nmapargv.Kind) sensoractive.DeepSettings {
	set := sensoractive.DeepSettings{Groups: nmapargv.AllGroups, SkipPorts: t.SkipPorts}
	if kind.IsFull() {
		set.Groups = nmapGroups(t.Groups&exposure.GroupDoS != 0, t.Groups&exposure.GroupLogins != 0, t.Groups&exposure.GroupChange != 0)
		set.Gentle = t.Gentle
	}
	return set
}

func (a exposureServiceScan) ScanServices(ctx context.Context, t exposure.ScanTarget, ip netip.Addr) (exposure.ServiceScan, error) {
	kind := nmapargv.External
	if t.Mode.Full { // the deep scan in one run: never the disruptive scripts, which are its last step (ScanDisruptive)
		kind = nmapargv.ExternalFull
	}
	got, err := a.run(ctx, t, ip, kind, nil)
	if err != nil {
		return exposure.ServiceScan{}, err
	}
	return serviceScanOf(got, ip), nil
}

// ScanOpenPorts implements exposure.PortsFirstScanner: the deep scan's port scan of every TCP port of ip (nmapargv.ExternalFullPorts),
// behind the same fences as the one full run. A scan container whose worker does not run the two runs gets nothing and exposure
// gets exposure.ErrPortsFirstUnsupported (it then runs the one full run on every port).
func (a exposureServiceScan) ScanOpenPorts(ctx context.Context, t exposure.ScanTarget, ip netip.Addr) (exposure.OpenPorts, error) {
	if !t.Mode.Full || (t.Domain == nil && a.scanOn == nil) || (t.Domain != nil && a.scanDomainOn == nil) {
		return exposure.OpenPorts{}, exposure.ErrPortsFirstUnsupported
	}
	got, err := a.run(ctx, t, ip, nmapargv.ExternalFullPorts, nil)
	switch {
	case errors.Is(err, sensoractive.ErrFullPortsUnsupported):
		return exposure.OpenPorts{}, exposure.ErrPortsFirstUnsupported
	case err != nil:
		return exposure.OpenPorts{}, err
	}
	out := exposure.OpenPorts{Ports: got.Ports, Refused: got.Refused, Open: make([]int, 0, len(got.Services))}
	for _, s := range got.Services {
		out.Open = append(out.Open, s.Port)
	}
	return out, nil
}

// ScanOpenServices implements exposure.PortsFirstScanner: -sV and the reviewed scripts on ports, the open ports of ip the port scan
// found (nmapargv.ExternalFull with a port list), behind the same fences again.
func (a exposureServiceScan) ScanOpenServices(ctx context.Context, t exposure.ScanTarget, ip netip.Addr, ports []int) (exposure.ServiceScan, error) {
	if !t.Mode.Full || len(ports) == 0 {
		return exposure.ServiceScan{}, errors.New("exposure services: the run on open ports is a deep scan's, on at least one port")
	}
	got, err := a.run(ctx, t, ip, nmapargv.ExternalFull, ports)
	switch {
	case errors.Is(err, sensoractive.ErrFullPortsUnsupported): // the worker changed since the port scan (an update)
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesOld}
	case err != nil:
		return exposure.ServiceScan{}, err
	}
	return serviceScanOf(got, ip), nil
}

// run is one nmap run of kind on ip for exposure (ports: the open ports of the deep scan's run on them, nil otherwise): the module
// switch, the typed-IP rule, the step's bound, the box's own IP or a domain's address, and the errors exposure shows. A worker that
// does not run the deep scan's two runs gives sensoractive.ErrFullPortsUnsupported as it is.
func (a exposureServiceScan) run(ctx context.Context, t exposure.ScanTarget, ip netip.Addr, kind nmapargv.Kind, ports []int) (sensoractive.External, error) {
	if a.on != nil && !a.on() {
		return sensoractive.External{}, &exposure.Unavailable{Reason: servicesOff}
	}
	if t.Typed && t.Domain == nil { // a typed IP goes only with its proof, never as the box's own address (the worker would refuse it)
		return sensoractive.External{}, &exposure.Unavailable{Reason: orText(t.TypedWhy, webTypedNoScope)}
	}
	bound := exposure.ServicesTimeout
	if kind.IsFull() {
		bound = exposure.FullServicesTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, bound) // exposure bounds the step too; this keeps the adapter honest alone
	defer cancel()
	split := kind == nmapargv.ExternalFullPorts || len(ports) > 0
	var got sensoractive.External
	var err error
	g := ownGate{actor: t.User, id: t.ID, gate: a.gate, modeNow: a.modeNow}
	switch {
	case t.Domain != nil: // An address that is not the box's, reached through a name of the verified domain
		if !kind.IsFull() || a.scanDomain == nil {
			return sensoractive.External{}, &exposure.Unavailable{Reason: fmt.Sprintf(servicesNotDeep, ip)}
		}
		dom := sensoractive.DomainIP{Scope: scopeOf(t.Domain), Chain: chainText(t.Domain)}
		if split {
			if a.scanDomainOn == nil {
				return sensoractive.External{}, sensoractive.ErrFullPortsUnsupported
			}
			got, err = a.scanDomainOn(ctx, ip, kind, ports, fullSettings(t, kind), dom, g)
		} else {
			got, err = a.scanDomain(ctx, ip, kind, fullSettings(t, kind), dom, g)
		}
	case split:
		if a.scanOn == nil {
			return sensoractive.External{}, sensoractive.ErrFullPortsUnsupported
		}
		got, err = a.scanOn(ctx, ip, kind, ports, fullSettings(t, kind), g)
	default:
		got, err = a.scan(ctx, ip, kind, fullSettings(t, kind), g)
	}
	un, isDomain := domainErr(err, t.Domain, ip.String())
	switch {
	case err == nil:
	case errors.Is(err, sensoractive.ErrFullPortsUnsupported): // nothing was sent: the caller runs the one full run instead
		return sensoractive.External{}, err
	case ctx.Err() != nil: // exposure's bound or the run's stop: exposure tells them apart
		return sensoractive.External{}, ctx.Err()
	case isDomain: // The worker's domain fence refused or stopped it, or the worker has no fence key
		return sensoractive.External{}, un
	default:
		return sensoractive.External{}, servicesErr(err, ip, bound)
	}
	return got, nil
}

// ScanDisruptive runs the disruptive scripts on ports, the open ports of ip (the box's own verified public IP) the scan found: the
// deep scan's last step, behind the same fences (exposure's gate and ModeNow right before the job: the terms must still allow the
// disruptive checks, else nothing is sent).
func (a exposureServiceScan) ScanDisruptive(ctx context.Context, t exposure.ScanTarget, ip netip.Addr, ports []int) (exposure.ServiceScan, error) {
	if a.on != nil && !a.on() {
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesOff}
	}
	groups := modeGroups(t.Mode) // the scripts of the groups the run allows; sensor-active narrows them again right before the job
	if t.Typed || t.Domain != nil || groups == 0 {
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesDisruptiveOwn}
	}
	if a.scanDisruptive == nil {
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesNoWork}
	}
	ctx, cancel := context.WithTimeout(ctx, exposure.DisruptiveTimeout)
	defer cancel()
	ports = slices.DeleteFunc(slices.Clone(ports), t.Skips) // never a port the target's settings skip
	if len(ports) == 0 {
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: servicesNoPorts}
	}
	set := sensoractive.DeepSettings{Groups: groups, SkipPorts: t.SkipPorts, Gentle: t.Gentle}
	got, err := a.scanDisruptive(ctx, ip, ports, set, ownGate{actor: t.User, id: t.ID, gate: a.gate, modeNow: a.modeNow})
	switch {
	case err == nil:
		return serviceScanOf(got, ip), nil
	case ctx.Err() != nil:
		return exposure.ServiceScan{}, ctx.Err()
	case errors.Is(err, sensoractive.ErrNotDisruptive):
		return exposure.ServiceScan{}, &exposure.Unavailable{Reason: fmt.Sprintf(servicesNotDisruptive, ip)}
	}
	return exposure.ServiceScan{}, servicesErr(err, ip, exposure.DisruptiveTimeout)
}

// servicesErr is the error exposure gets for an nmap run of the box's own IP that did not give a result.
func servicesErr(err error, ip netip.Addr, bound time.Duration) error {
	switch {
	case errors.Is(err, sensoractive.ErrStopped):
		return &exposure.Unavailable{Reason: servicesStopped}
	case errors.Is(err, sensoractive.ErrNoTime):
		return &exposure.Unavailable{Reason: fmt.Sprintf(servicesNoTime, int(bound/time.Minute))}
	case errors.Is(err, sensoractive.ErrStoppedMidRun) && errors.Is(err, sensoractive.ErrEgressUnverified): // before the start-time lines
		return &exposure.Unavailable{Reason: fmt.Sprintf(servicesNoCheckMid, ip)}
	case errors.Is(err, sensoractive.ErrStoppedMidRun):
		return &exposure.Unavailable{Reason: fmt.Sprintf(servicesNotOwnMid, ip)}
	case errors.Is(err, sensoractive.ErrEgressUnverified): // before ErrWorkerRefused, which wraps it
		return &exposure.Unavailable{Reason: fmt.Sprintf(servicesNoCheck, ip)}
	case errors.Is(err, sensoractive.ErrBusy):
		return &exposure.Unavailable{Reason: servicesBusy}
	case errors.Is(err, sensoractive.ErrNotOwnIP):
		return &exposure.Unavailable{Reason: fmt.Sprintf(servicesNotOwn, ip)}
	case errors.Is(err, sensoractive.ErrNotDeep): // Never the baseline shape instead, the run was asked as deep
		return &exposure.Unavailable{Reason: fmt.Sprintf(servicesNotDeep, ip)}
	case errors.Is(err, sensoractive.ErrFullUnsupported):
		return &exposure.Unavailable{Reason: servicesOldFull}
	case errors.Is(err, sensoractive.ErrNarrowUnsupported):
		return &exposure.Unavailable{Reason: servicesOldSettings}
	case errors.Is(err, sensoractive.ErrUnavailable):
		return &exposure.Unavailable{Reason: servicesNoWork}
	case errors.Is(err, sensoractive.ErrWorkerRefused):
		return &exposure.Unavailable{Reason: servicesOld}
	case errors.Is(err, sensoractive.ErrHostTimedOut): // Its own line, never "did not run" nor "0 services"
		return exposure.ErrServicesTimedOut
	case errors.Is(err, sensoractive.ErrAnswersEverywhere): // A router or SYN proxy answering for every port
		return exposure.ErrAnswersEverywhere
	}
	return err // logged by exposure, shown as a failure without its text (a failed ModeNow too: fail closed)
}

// serviceScanOf is what exposure is told of an nmap run of ip.
func serviceScanOf(got sensoractive.External, ip netip.Addr) exposure.ServiceScan {
	out := exposure.ServiceScan{Services: make([]exposure.ServiceRow, 0, len(got.Services)), Ports: got.Ports, Probed: got.Probed, DiscoveryCut: got.DiscoveryCut,
		AnswersEverywhere: got.AnswersEverywhere, Unfinished: got.Unfinished, Refused: got.Refused}
	for _, s := range got.Services {
		out.Services = append(out.Services, exposure.ServiceRow{IP: ip.String(), Port: s.Port, Name: s.Name, Product: s.Product, Version: s.Version, CPE: s.CPE, Extra: s.Extra, Method: s.Method, Conf: s.Conf})
	}
	for _, s := range got.Scripts { // Only a deep scan has any; exposure sanitizes them before they are stored
		row := exposure.ScriptRow{IP: ip.String(), Port: s.Port, ID: s.ID, Output: s.Output}
		for _, f := range s.Findings {
			row.Findings = append(row.Findings, exposure.ScriptFinding{State: f.State, Title: f.Title, CVEs: f.CVEs})
		}
		out.Scripts = append(out.Scripts, row)
	}
	return out
}

// exposureServicesFor builds the scanner for exposureService.
func exposureServicesFor(d deps, gate ownIPGate, modeNow func(ctx context.Context, actor, id string) (exposure.ScanMode, error)) exposureServiceScan {
	return exposureServiceScan{
		on: func() bool { return d.Reg == nil || d.Reg.Enabled("sensor-active") },
		scan: func(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, set sensoractive.DeepSettings, own sensoractive.OwnEgress) (sensoractive.External, error) {
			svc, err := sensorActiveService(ctx, d) // built once per database; it keeps ctx's values, never its end
			if err != nil {
				return sensoractive.External{}, err
			}
			return svc.ScanExternalWith(ctx, ip, kind, set, own)
		},
		scanDomain: func(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, set sensoractive.DeepSettings, dom sensoractive.DomainIP, gate sensoractive.DeepGate) (sensoractive.External, error) {
			svc, err := sensorActiveService(ctx, d)
			if err != nil {
				return sensoractive.External{}, err
			}
			return svc.ScanDomainIPWith(ctx, ip, kind, set, dom, gate)
		},
		scanOn: func(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, ports []int, set sensoractive.DeepSettings, own sensoractive.OwnEgress) (sensoractive.External, error) {
			svc, err := sensorActiveService(ctx, d)
			if err != nil {
				return sensoractive.External{}, err
			}
			if kind == nmapargv.ExternalFullPorts {
				return svc.ScanFullPortsWith(ctx, ip, set, own)
			}
			return svc.ScanFullOnWith(ctx, ip, ports, set, own)
		},
		scanDomainOn: func(ctx context.Context, ip netip.Addr, kind nmapargv.Kind, ports []int, set sensoractive.DeepSettings, dom sensoractive.DomainIP, gate sensoractive.DeepGate) (sensoractive.External, error) {
			svc, err := sensorActiveService(ctx, d)
			if err != nil {
				return sensoractive.External{}, err
			}
			return svc.ScanDomainIPOn(ctx, ip, kind, ports, set, dom, gate)
		},
		scanDisruptive: func(ctx context.Context, ip netip.Addr, ports []int, set sensoractive.DeepSettings, own sensoractive.OwnEgress) (sensoractive.External, error) {
			svc, err := sensorActiveService(ctx, d)
			if err != nil {
				return sensoractive.External{}, err
			}
			return svc.ScanDisruptiveWith(ctx, ip, ports, set, own)
		},
		gate:    gate,
		modeNow: modeNow,
	}
}
