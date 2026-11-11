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

	mu   sync.Mutex
	at   time.Time // the last good answer; zero before the first
	last []string
}

var errHostMACsUnknown = errors.New("vedette-host has not reported the MAC addresses of the box yet")

func (h *hostMACs) Get(ctx context.Context) ([]string, error) {
	if h == nil || h.r == nil {
		return nil, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock() // one socket call at a time; a caller waits for it at most hostNetTimeout
	if !h.at.IsZero() && h.now().Sub(h.at) < hostNetTTL {
		return h.last, nil
	}
	ctx, cancel := context.WithTimeout(ctx, hostNetTimeout)
	defer cancel()
	st, err := h.r.StateNet(ctx)
	if err != nil {
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
	h.at, h.last = h.now(), out
	return out, nil
}
