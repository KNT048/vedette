package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/exposure"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// The domain fence of core: exposure's Config.DomainFence is vedette-host's exposure.token
// (the host holds the key, core never does); a deep step of exposure that carries ScanTarget.Domain goes out as a domain_ip job of the
// scan container's worker (nmap, nuclei) or through the host's own check (ZAP, OpenVAS), and each executor checks the fence itself.
// A container-only install (no vedette-host) has no DomainFence: nothing new goes to an address that is not the box's own.

// tokenHost is what the fence needs of the host client (*hostclient.Client).
type tokenHost interface {
	ExposureToken(ctx context.Context, domain, requestID, actor string) (string, error)
	ExposureTokenForget(ctx context.Context, domain, requestID, actor string) error
}

// hostDomainFence is exposure's DomainFence over vedette-host's exposure.token.
type hostDomainFence struct{ host tokenHost }

func (f hostDomainFence) Token(ctx context.Context, domain string) (string, error) {
	id, err := newUUID()
	if err != nil {
		return "", err
	}
	tok, err := f.host.ExposureToken(ctx, domain, id, "exposure")
	var fe *hostclient.FenceError
	switch {
	case err == nil:
		return tok, nil
	case errors.As(err, &fe) && fe.Code == api.CodeFenceDomainsFull: // review r1 H1: the host's cap, said as such
		return "", exposure.ErrFenceFull
	case errors.As(err, &fe) && (fe.Code == api.CodeBusy || fe.Code == api.CodeRateLimited), !errors.As(err, &fe):
		// review r2 M-B: transient (busy, or no answer: a transport error, a time-out): "try again"
		return "", exposure.ErrFenceDown
	}
	return "", err // an older host (unknown_command), an unusable key or list: exposure falls back to a random token
}

// ListIP lists a proved typed IP on the host for the executors (exposure.token with proved).
func (f hostDomainFence) ListIP(ctx context.Context, ip string) error {
	l, ok := f.host.(interface {
		ExposureListIP(ctx context.Context, ip, requestID, actor string) error
	})
	if !ok {
		return nil
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	return l.ExposureListIP(ctx, ip, id, "exposure")
}

// Forget gives a domain's fence slot back to the host (exposure.token_forget, review r2 M-A).
func (f hostDomainFence) Forget(ctx context.Context, domain string) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	return f.host.ExposureTokenForget(ctx, domain, id, "exposure")
}

// scopeOf is the wire form of exposure's domain scope.
func scopeOf(d *exposure.DomainScope) sensorlink.DomainScope {
	sc := sensorlink.DomainScope{Domain: d.Domain, Name: d.Name, Token: d.Token, ProofAt: d.ProofAt}
	if t := d.Typed; t != nil {
		sc.Typed = &sensorlink.TypedScope{Method: t.Method, PTRName: t.PTRName, CoverDomain: t.CoverDomain, CoverToken: t.CoverToken, CoverProofAt: t.CoverProofAt}
	}
	return sc
}

// chainText is the CNAME chain of a scope for a probe-log row.
func chainText(d *exposure.DomainScope) string {
	if d.Chain == "" {
		return d.Name + " (CNAME not known)"
	}
	return d.Chain
}

// finalName is the end of the scope's CNAME chain (the name itself without a CNAME, or when the chain is not known).
func finalName(d *exposure.DomainScope) string {
	if k := strings.LastIndex(d.Chain, " -> "); k >= 0 {
		return d.Chain[k+4:]
	}
	return d.Name
}

// probeRequestMax is what scan_probe.request keeps (modules/scan/external.go clips the request there).
const probeRequestMax = 300

// keepEnd is s, or "…" and its last n-1 runes when it is longer than n (the end of a name is its registrable part).
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

// The reasons exposure shows when the scan container's domain fence refused or stopped a step (after "… did not run: ").
const (
	domainNoKey     = "the scan container has no domain fence key (an older box, or a sensor that is not the box's own), so nothing was sent to an address that is not this box's. Update the box."
	domainForeign   = "the scan container did not recognise this box's token for the domain (its copy of the box's fence key or domain list differs from the host's), so nothing was sent. Restart or update the box."
	domainOldWorker = "the scan container refused the job's ownership fields, which an older scan container does not know (a name proved by the record of another domain of this box). Update the box, then scan again."
	domainNotOwn    = "%s does not have its TXT record vedette-verify=%s now, so the scan container sent nothing. Add it (keep the current one), then scan again."
	domainMoved     = "%s no longer points at %s (checked by the scan container right before the step), so nothing was sent there."
	domainNoDNS     = "the scan container could not look up the domain's TXT record or the name's address (DNS did not answer), so nothing was sent."
	domainOutside   = "%s points (CNAME) outside the domain, so the scan container refused the disruptive checks there."
	typedNotProved  = "the proof of %s (its token file or reverse DNS name) is not found now by the scan container, so it sent nothing. Put it back, check the IP again, then scan."
	typedOldBox     = "the scan container or the host is older than this version and does not check the proof of a public IP you typed in. Update the box, then scan again."
	domainMid       = "the scan container's domain fence stopped it while it ran (%s), and its results were discarded."
)

// domainErr maps a refusal of the worker's domain fence (or a worker without the key) to the line exposure shows; ok false for any
// other error.
func domainErr(err error, d *exposure.DomainScope, ip string) (*exposure.Unavailable, bool) {
	if errors.Is(err, sensoractive.ErrDomainUnsupported) {
		return &exposure.Unavailable{Reason: domainNoKey}, true
	}
	if errors.Is(err, sensoractive.ErrTypedUnsupported) {
		return &exposure.Unavailable{Reason: typedOldBox}, true
	}
	var r *sensoractive.DomainRefusedError
	if d == nil || !errors.As(err, &r) {
		return nil, false
	}
	if r.MidRun {
		return &exposure.Unavailable{Reason: fmt.Sprintf(domainMid, r.Reason)}, true
	}
	switch r.Reason {
	case domainfence.InvalidJob: // a worker older than this version refuses the proof-name shape of a job as invalid
		return &exposure.Unavailable{Reason: domainOldWorker}, true
	case domainfence.TokenForeign:
		return &exposure.Unavailable{Reason: domainForeign}, true
	case domainfence.NotOwned:
		if d.Typed != nil {
			return &exposure.Unavailable{Reason: fmt.Sprintf(typedNotProved, ip)}, true
		}
		at := d.Domain
		if d.ProofAt != "" { // The record the worker looked for is the target's own on the parent name
			at = d.ProofAt
		}
		return &exposure.Unavailable{Reason: fmt.Sprintf(domainNotOwn, at, d.Token)}, true
	case domainfence.NameMoved:
		return &exposure.Unavailable{Reason: fmt.Sprintf(domainMoved, d.Name, ip)}, true
	case domainfence.CNAMEOutside:
		return &exposure.Unavailable{Reason: fmt.Sprintf(domainOutside, d.Name)}, true
	}
	return &exposure.Unavailable{Reason: domainNoDNS}, true
}
