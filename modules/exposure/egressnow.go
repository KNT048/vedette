package exposure

import (
	"slices"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The overlap rule of the ownership proof sent to the executors (INV-13). An IP the box found keeps its proof for ValidDays from its
// latest sighting, and the gate keeps it scannable that long; the executors (the scan worker, the host's ZAP fence, the OpenVAS step)
// take it as the box's own without a sighting of their own only while the box's two addresses overlapped in time: the address was
// last seen after the box's current egress address was first seen. That is a second Internet line (both in use, the router
// balancing them, or a failover). An address last seen before the current one was first seen was replaced (a dynamic address the
// provider took back and may have given to someone else): no proof is sent, and the executors scan it only if they see the box go
// out through it themselves. Seen again later, it is not replaced any more.
//
// The data is exposure's own: the box_egress IP targets, their latest sighting (provedAt) and their first sighting (created_at, when
// the box first found the address). An address that comes back after its target was removed counts from its new target's first
// sighting; one that comes back after its proof expired, with its target kept, counts from its first sighting ever.

// egressNow is the box's current egress as its records say it: the box_egress addresses of the latest sighting (several when one
// full check saw several), and the first sighting of the newest of them.
type egressNow struct {
	known bool
	ips   []string
	by    string    // the newest current address
	first time.Time // its first sighting
}

// boxEgress says whether t is an IP the box found as its own egress address (never a typed IP or a domain).
func boxEgress(t Target) bool {
	return t.Kind == KindIP && !t.Typed && t.Method == methodBoxEgress && !t.VerifiedAt.IsZero()
}

// egressNowOf finds the current egress among all targets. It is not known (no proof is sent) when no address of the box has a
// sighting that can be dated, or when one is stored ahead of the clock (the latest sighting cannot be told).
func egressNowOf(all []Target, now time.Time) egressNow {
	var latest time.Time
	var cur []Target
	for _, t := range all {
		if !boxEgress(t) {
			continue
		}
		at := t.ownProof(now)
		if at.IsZero() { // a sighting stored ahead of the clock: which address is current cannot be told
			return egressNow{}
		}
		switch {
		case at.After(latest):
			latest, cur = at, []Target{t}
		case at.Equal(latest):
			cur = append(cur, t)
		}
	}
	if len(cur) == 0 {
		return egressNow{}
	}
	e := egressNow{known: true}
	for _, t := range cur {
		e.ips = append(e.ips, t.Value)
		if first := clampTS(t.CreatedAt, now); e.by == "" || first.After(e.first) {
			e.by, e.first = t.Value, first
		}
	}
	return e
}

// proofOf is the proof the executors get for t: its latest sighting (ownProof) when t is a current egress address or was last seen
// after the current one was first seen (ok); none otherwise. replaced is set when t was last seen before the current address was
// first seen.
func (e egressNow) proofOf(t Target, now time.Time) (at time.Time, replaced *Replaced, ok bool) {
	at = t.ownProof(now)
	switch {
	case at.IsZero(), !e.known:
		return time.Time{}, nil, false
	case slices.Contains(e.ips, t.Value), at.After(e.first):
		return at, nil, true
	}
	return time.Time{}, &Replaced{By: e.by, At: store.FormatTS(e.first)}, false
}
