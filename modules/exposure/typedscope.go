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
