package exposure

import (
	"context"
	"net/netip"

	"github.com/knt048/vedette/core/domainfence"
)

// The reasons a step to a typed IP does not run (the lines of "Not checked").
const (
	typedNoFence  = "this box has no domain fence (a container-only install, or an older vedette-host), so nothing is sent to an address that is not the box's own. Update the box."
	typedOldToken = "the token of this IP was made before the box's domain fence, so the executors cannot check it. Delete the IP and add it again."
	typedGone     = "the proof of this IP (its token file or reverse DNS name) was not found just now, so nothing was sent."
	typedTerms    = "the deep steps of a public IP you typed in run only with its testing terms accepted."
)

// typedScope is the scope of a step to the typed IP target t, from its live proof (the one the gate just looked for): the executors check the
// same proof again and refuse a forged one. why is "" with a scope, else the line of "Not checked".
func (s *Service) typedScope(ctx context.Context, t Target) (scope *DomainScope, why string) {
	if s.cfg.DomainFence == nil {
		return nil, typedNoFence
	}
	pr, ok := s.liveProof(t)
	if !ok {
		return nil, typedGone
	}
	if why := s.listTypedIP(ctx, t.Value); why != "" {
		return nil, why
	}
	tok, err := s.cfg.DomainFence.Token(ctx, t.Value)
	if err != nil || !fenceTokenRE.MatchString(tok) {
		s.cfg.Log.ErrorContext(ctx, "exposure: the domain fence gave no token for a typed IP", "target", t.Value, "error", err)
		return nil, typedNoFence
	}
	if tok != t.Token {
		return nil, typedOldToken
	}
	ts := &TypedScope{Method: domainfence.MethodFile}
	if pr.method == methodIPPTR {
		if _, ok, err := loadTargetByValue(ctx, s.cfg.DB.Reader(), pr.coverDomain); err != nil || !ok { // deleted while the scan ran: never list it again
			return nil, typedGone
		}
		ct, err := s.cfg.DomainFence.Token(ctx, pr.coverDomain)
		if err != nil || !fenceTokenRE.MatchString(ct) {
			return nil, typedNoFence
		}
		ts = &TypedScope{Method: domainfence.MethodPTR, PTRName: pr.ptrName, CoverDomain: pr.coverDomain, CoverToken: ct, CoverProofAt: pr.coverAt}
	}
	return &DomainScope{Domain: t.Value, Name: t.Value, Token: tok, Chain: t.Value, Typed: ts}, ""
}

// typedAddr is the typed IP target whose address ip is, with its scope (a deep step of a domain to an address the box has a typed
// proof for): ok false when ip is no typed IP target.
func (s *Service) typedAddr(ctx context.Context, ip netip.Addr) (t Target, ok bool) {
	t, found, err := loadTargetByValue(ctx, s.cfg.DB.Reader(), ip.String())
	if err != nil || !found || !t.Typed {
		return Target{}, false
	}
	return t, true
}

// IPLister is implemented by a DomainFence that can list a proved typed IP for the executors (host op exposure.token with proved): an IP
// nobody proved takes no place on the host's list, so typed IPs never use a domain's.
type IPLister interface {
	ListIP(ctx context.Context, ip string) error
}

const typedNotListed = "the host could not list this IP for the executors (its limit of typed IPs, or the host did not answer), so nothing was sent."

// listTypedIP lists the typed IP t on the host once per run of the box, after its proof was found; "" when listed (or no lister), else the
// line that says why not.
func (s *Service) listTypedIP(ctx context.Context, ip string) string {
	l, ok := s.cfg.DomainFence.(IPLister)
	if !ok {
		return ""
	}
	s.liveMu.Lock()
	done := s.ipListed[ip]
	s.liveMu.Unlock()
	if done {
		return ""
	}
	if err := l.ListIP(ctx, ip); err != nil {
		s.cfg.Log.ErrorContext(ctx, "exposure: the host did not list a typed IP", "ip", ip, "error", err)
		return typedNotListed
	}
	s.liveMu.Lock()
	s.ipListed[ip] = true
	s.liveMu.Unlock()
	return ""
}
