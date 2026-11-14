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
// show, ending at the first round that names it. A round that fails or names another address is not a yes; no yes is a refusal,
// fail closed: not_own_ip when some round named another address, egress_unverified when no round named any (the services could
// not be reached: no route, DNS, TLS, no agreement), or when the worker has no check. A yes counts for EgressFresh, so a second
// scan of the same address soon after asks nobody again.

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

// The refusal reasons of the fence (sensor-protocol.md 6.5).
const (
	reasonNotOwnIP   = "not_own_ip"
	reasonUnverified = "egress_unverified"
)

// ownIP reports whether the box goes out through ip now; when not, reason says why (reasonNotOwnIP, reasonUnverified).
func (w *Worker) ownIP(ctx context.Context, ip netip.Addr) (ok bool, reason string) {
	if w.egress == nil {
		return false, reasonUnverified // no way to check: never scan a public address unchecked
	}
	w.egressMu.Lock()
	defer w.egressMu.Unlock()
	if w.egressIP == ip && w.now().Sub(w.egressAt) < EgressFresh && !w.egressAt.After(w.now()) {
		return true, ""
	}
	reason = reasonUnverified
	for range EgressRounds {
		a, err := w.egress.Round(ctx)
		if ctx.Err() != nil {
			return false, reason
		}
		if err != nil {
			continue
		}
		if a.Unmap() == ip {
			w.egressIP, w.egressAt = ip, w.now()
			return true, ""
		}
		reason = reasonNotOwnIP // the services answered: the box leaves through another address
	}
	return false, reason
}
