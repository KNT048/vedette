package worker

import (
	"context"
	"net/netip"
	"time"
)

// The own-IP fence of the external shape (D-514, plan exposure-real-vulns §1.3). The external shape is the only one whose target
// is public; the grammar alone would let a core that was taken over port-scan anyone from the customer's IP. So the worker checks
// by itself, right before nmap, that the box leaves the Internet through that address: the same three public services and the
// same two-of-three rule as exposure (core/egressip), up to EgressRounds rounds so every address of a load-balanced uplink can
// show, ending at the first round that names it. A round that fails or names another address is not a yes; no yes is a refusal
// (not_own_ip), fail closed. A yes counts for EgressFresh, so a second scan of the same address soon after asks nobody again.

// EgressProber asks the three public "what is my IP" services once each and returns the address two of them agree on;
// *egressip.Prober is the real one.
type EgressProber interface {
	Round(ctx context.Context) (netip.Addr, error)
}

const (
	// EgressRounds is the most rounds of the fence: exposure's full check (DeepRounds there).
	EgressRounds = 5
	// EgressFresh is how long a yes stands: exposure's CurrentFor.
	EgressFresh = 5 * time.Minute
)

// ownIP reports whether the box goes out through ip now.
func (w *Worker) ownIP(ctx context.Context, ip netip.Addr) bool {
	if w.egress == nil {
		return false // no way to check: never scan a public address unchecked
	}
	w.egressMu.Lock()
	defer w.egressMu.Unlock()
	if w.egressIP == ip && w.now().Sub(w.egressAt) < EgressFresh && !w.egressAt.After(w.now()) {
		return true
	}
	for range EgressRounds {
		a, err := w.egress.Round(ctx)
		if ctx.Err() != nil {
			return false
		}
		if err == nil && a.Unmap() == ip {
			w.egressIP, w.egressAt = ip, w.now()
			return true
		}
	}
	return false
}
