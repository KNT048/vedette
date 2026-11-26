package worker

import (
	"context"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/egressip"
)

// The own-IP fence of the external shapes (the two full shapes too). They are the
// only ones whose target is public; the grammar alone would let a core that was taken over port-scan anyone from the customer's IP. So the worker checks
// by itself, right before nmap, that the box leaves the Internet through that address: the same three public services and the
// same two-of-three rule as exposure (core/egressip), up to EgressRounds rounds so every address of a load-balanced uplink can
// show, ending at the first round that names it. A round that fails or names another address is not a yes; no yes is a refusal,
// fail closed: not_own_ip when some round named another address, egress_unverified when no round named any (the services could
// not be reached: no route, DNS, TLS, no agreement), or when the worker has no check. A yes counts for EgressFresh, so a second
// scan of the same address soon after asks nobody again.
//
// Core's ownership proof comes first: a job whose proven_at holds (egressip.ProofHolds: the address was seen as the box's egress
// within the last 90 days, never dated in the future) is the box's own without asking anyone, also while the box goes out through
// another line. That proof comes only on the authenticated job channel, for the job's one target. A proof that does not hold is
// no proof: the sighting above decides, with its reasons.

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

// ownIP reports whether ip is the box's own: core's proof of it holds, or the box goes out through it now; when not, reason says why
// (reasonNotOwnIP, reasonUnverified).
func (w *Worker) ownIP(ctx context.Context, ip netip.Addr, proof *time.Time) (ok bool, reason string) {
	return w.checkIP(ctx, ip, proof, true)
}

// proofHolds reports whether core's proof of a job's address still holds on the worker's clock.
func (w *Worker) proofHolds(proof *time.Time) bool {
	return proof != nil && egressip.ProofHolds(*proof, w.now())
}

// checkIP is the fence; cached lets a yes of the last EgressFresh stand (the re-check of a running full job asks again). Any
// answer that is not a yes forgets the yes it had (review r2 M-A): a re-check that saw the address go must not let the next job
// start on the yes from before. A proof that holds is a yes and leaves the sighting's cache alone.
func (w *Worker) checkIP(ctx context.Context, ip netip.Addr, proof *time.Time, cached bool) (ok bool, reason string) {
	if w.proofHolds(proof) {
		if cached { // the start of a job: say once on what the address was taken as the box's own
			w.log.InfoContext(ctx, "sensor_active_own_ip_by_proof", "ip", ip.String(), "proven_at", proof.UTC().Format(time.RFC3339))
		}
		return true, ""
	}
	if w.egress == nil {
		return false, reasonUnverified // no way to check: never scan a public address unchecked
	}
	w.egressMu.Lock()
	defer w.egressMu.Unlock()
	if cached && w.egressIP == ip && w.now().Sub(w.egressAt) < EgressFresh && !w.egressAt.After(w.now()) {
		return true, ""
	}
	defer func() {
		if !ok {
			w.egressIP, w.egressAt = netip.Addr{}, time.Time{}
		}
	}()
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

// EgressRecheck is how often a running full job checks again that the box still goes out through its target:
// a full run lasts up to an hour, and a line whose public address changes meanwhile (a forced PPPoE or DHCP reconnect) hands
// the old address to someone else. The re-check is the whole fence again, without the cached yes.
const EgressRecheck = 3 * time.Minute

// watchEgress re-checks ip on every value of ticks (every EgressRecheck in production) until ctx ends. The first check that is
// not a yes calls kill and returns its reason; it returns "" when ctx ended first (the job finished, was cancelled or ran out of
// time). A job with core's proof keeps running while the proof holds; a proof that runs out during the run is the sighting again.
func (w *Worker) watchEgress(ctx context.Context, ip netip.Addr, proof *time.Time, ticks <-chan time.Time, kill context.CancelFunc) string {
	for {
		select {
		case <-ctx.Done():
			return ""
		case <-ticks:
		}
		ok, reason := w.checkIP(ctx, ip, proof, false)
		if ctx.Err() != nil {
			return ""
		}
		if !ok {
			kill()
			return reason
		}
	}
}
