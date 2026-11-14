package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/exposure"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// The domain fence of core (FULL-5 slice 2, D-591, plan 2026-11-14 §5): exposure's Config.DomainFence is vedette-host's exposure.token
// (the host holds the key, core never does); a deep step of exposure that carries ScanTarget.Domain goes out as a domain_ip job of the
// scan container's worker (nmap, nuclei) or through the host's own check (ZAP, OpenVAS), and each executor checks the fence itself.
// A container-only install (no vedette-host) has no DomainFence: nothing new goes to an address that is not the box's own.

// tokenHost is what the fence needs of the host client (*hostclient.Client).
type tokenHost interface {
	ExposureToken(ctx context.Context, domain, requestID, actor string) (string, error)
}

// hostDomainFence is exposure's DomainFence over vedette-host's exposure.token.
type hostDomainFence struct{ host tokenHost }

func (f hostDomainFence) Token(ctx context.Context, domain string) (string, error) {
	id, err := newUUID()
	if err != nil {
		return "", err
	}
	return f.host.ExposureToken(ctx, domain, id, "exposure")
}

// scopeOf is the wire form of exposure's domain scope.
func scopeOf(d *exposure.DomainScope) sensorlink.DomainScope {
	return sensorlink.DomainScope{Domain: d.Domain, Name: d.Name, Token: d.Token}
}

// chainText is the CNAME chain of a scope for a probe-log row.
func chainText(d *exposure.DomainScope) string {
	if d.Chain == "" {
		return d.Name + " (CNAME not known)"
	}
	return d.Chain
}

// The reasons exposure shows when the scan container's domain fence refused or stopped a step (after "… did not run: ").
const (
	domainNoKey   = "the scan container has no domain fence key (an older box, or a sensor that is not the box's own), so nothing was sent to an address that is not this box's. Update the box."
	domainForeign = "the scan container did not recognise this box's token for the domain (its copy of the box's fence key differs from the host's), so nothing was sent. Restart or update the box."
	domainNotOwn  = "%s does not have its TXT record vedette-verify=%s now, so the scan container sent nothing. Add it (keep the current one), then scan again."
	domainMoved   = "%s no longer points at %s (checked by the scan container right before the step), so nothing was sent there."
	domainNoDNS   = "the scan container could not look up the domain's TXT record or the name's address (DNS did not answer), so nothing was sent."
	domainOutside = "%s points (CNAME) outside the domain, so the scan container refused the disruptive checks there."
	domainMid     = "the scan container's domain fence stopped it while it ran (%s), and its results were discarded."
)

// domainErr maps a refusal of the worker's domain fence (or a worker without the key) to the line exposure shows; ok false for any
// other error.
func domainErr(err error, d *exposure.DomainScope, ip string) (*exposure.Unavailable, bool) {
	if errors.Is(err, sensoractive.ErrDomainUnsupported) {
		return &exposure.Unavailable{Reason: domainNoKey}, true
	}
	var r *sensoractive.DomainRefusedError
	if d == nil || !errors.As(err, &r) {
		return nil, false
	}
	if r.MidRun {
		return &exposure.Unavailable{Reason: fmt.Sprintf(domainMid, r.Reason)}, true
	}
	switch r.Reason {
	case domainfence.TokenForeign:
		return &exposure.Unavailable{Reason: domainForeign}, true
	case domainfence.NotOwned:
		return &exposure.Unavailable{Reason: fmt.Sprintf(domainNotOwn, d.Domain, d.Token)}, true
	case domainfence.NameMoved:
		return &exposure.Unavailable{Reason: fmt.Sprintf(domainMoved, d.Name, ip)}, true
	case domainfence.CNAMEOutside:
		return &exposure.Unavailable{Reason: fmt.Sprintf(domainOutside, d.Name)}, true
	}
	return &exposure.Unavailable{Reason: domainNoDNS}, true
}
