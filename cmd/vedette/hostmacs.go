package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// hostMACs is the MAC addresses vedette-host reports for the box (state/net): its cards and the macvlan links of the honeypot's decoys, which have
// MACs of their own. response puts them on the never-touch list (D-179 (8)). The last good answer is served for hostNetTTL; a failed refresh keeps it;
// before the first answer the set is unknown (an error), as for the addresses. A nil reader (no host) is an empty, known set.
type hostMACs struct {
	r   netStateReader
	now func() time.Time

	mu       sync.Mutex
	at       time.Time // the last good answer; zero before the first
	failedAt time.Time // the last failed ask: no new ask for hostNetBackoff, so a hung host costs one timeout, not one per caller
	forcedAt time.Time // the last ask that skipped the TTL (Fresh)
	last     []string
}

var errHostMACsUnknown = errors.New("vedette-host has not reported the MAC addresses of the box yet")

// hostMACsFreshEvery bounds Fresh: one ask past the TTL at most this often, whoever asks.
const hostMACsFreshEvery = 2 * time.Second

// Get returns the box's MACs, from the last answer while it is younger than hostNetTTL.
func (h *hostMACs) Get(ctx context.Context) ([]string, error) { return h.get(ctx, false) }

// Fresh is Get, but asks the host again (at most every hostMACsFreshEvery) when the answer is older than that: a caller that sees a
// MAC it does not know at a box address asks before deciding, as a decoy added a moment ago has a macvlan MAC the cached answer
// lacks (WP-31 M7 review).
func (h *hostMACs) Fresh(ctx context.Context) ([]string, error) { return h.get(ctx, true) }

func (h *hostMACs) get(ctx context.Context, fresh bool) ([]string, error) {
	if h == nil || h.r == nil {
		return nil, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock() // one socket call at a time; a caller waits for it at most hostNetTimeout
	now := h.now()
	cached := !h.at.IsZero() && now.Sub(h.at) < hostNetTTL
	if fresh && cached && (now.Sub(h.at) < hostMACsFreshEvery || now.Sub(h.forcedAt) < hostMACsFreshEvery) {
		return h.last, nil
	}
	if (cached && !fresh) || (!h.failedAt.IsZero() && now.Sub(h.failedAt) < hostNetBackoff) {
		if h.at.IsZero() {
			return nil, errHostMACsUnknown
		}
		return h.last, nil
	}
	if fresh {
		h.forcedAt = now
	}
	ctx, cancel := context.WithTimeout(ctx, hostNetTimeout)
	defer cancel()
	st, err := h.r.StateNet(ctx)
	if err != nil {
		h.failedAt = h.now()
		if h.at.IsZero() {
			return nil, errHostMACsUnknown
		}
		return h.last, nil // a host that does not answer now is still the same box
	}
	var out []string
	for _, i := range st.Interfaces {
		out = append(out, strings.ToLower(i.MAC))
	}
	for _, d := range st.Decoys {
		out = append(out, strings.ToLower(d.MAC))
	}
	h.at, h.failedAt, h.last = h.now(), time.Time{}, out
	return out, nil
}
