package worker

import (
	"context"
	"net/netip"
	"time"
)

// The own-IP fence of the external shapes (D-514, plan exposure-real-vulns §1.3; the two full shapes of D-526 too). They are the
// only ones whose target is public; the grammar alone would let a core that was taken over port-scan anyone from the customer's IP. So the worker checks
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
	return w.checkIP(ctx, ip, true)
}

// checkIP is the fence; cached lets a yes of the last EgressFresh stand (the re-check of a running full job asks again).
func (w *Worker) checkIP(ctx context.Context, ip netip.Addr, cached bool) (ok bool, reason string) {
	if w.egress == nil {
		return false, reasonUnverified // no way to check: never scan a public address unchecked
	}
	w.egressMu.Lock()
	defer w.egressMu.Unlock()
	if cached && w.egressIP == ip && w.now().Sub(w.egressAt) < EgressFresh && !w.egressAt.After(w.now()) {
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

// EgressRecheck is how often a running full job checks again that the box still goes out through its target (D-526, review r1
// H1): a full run lasts up to an hour, and a line whose public address changes meanwhile (a forced PPPoE or DHCP reconnect) hands
// the old address to someone else. The re-check is the whole fence again, without the cached yes.
const EgressRecheck = 3 * time.Minute

// watchEgress re-checks ip every `every` until ctx ends. The first check that is not a yes calls kill and returns its reason;
// it returns "" when ctx ended first (the job finished, was cancelled or ran out of time).
func (w *Worker) watchEgress(ctx context.Context, ip netip.Addr, every time.Duration, kill context.CancelFunc) string {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ""
		case <-t.C:
		}
		ok, reason := w.checkIP(ctx, ip, false)
		if ctx.Err() != nil {
			return ""
		}
		if !ok {
			kill()
			return reason
		}
	}
}
