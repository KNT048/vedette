package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/response"
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
	infra    []response.HostInfra // the gateway and DNS servers of the same answer (D-325)
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
	infra := hostInfraOf(st)
	if !hasGateway(infra) { // a lease being renewed or a pending net.apply has no default route for a moment: the gateway is still the gateway
		for _, x := range h.infra {
			if x.Kind == "gateway" {
				infra = append(infra, x)
			}
		}
	}
	h.at, h.failedAt, h.last, h.infra = h.now(), time.Time{}, out, infra
	return out, nil
}

// Infra returns the gateway and DNS servers of the last answer (response's never-touch list, D-325), with the same freshness and the same
// "unknown before the first answer" as Get. A nil reader (no host) is an empty, known set.
func (h *hostMACs) Infra(ctx context.Context) ([]response.HostInfra, error) {
	if _, err := h.Get(ctx); err != nil {
		return nil, err
	}
	if h == nil {
		return nil, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]response.HostInfra(nil), h.infra...), nil
}

func hasGateway(l []response.HostInfra) bool {
	for _, x := range l {
		if x.Kind == "gateway" {
			return true
		}
	}
	return false
}

// hostInfraOf reads the kernel's default gateway and the gateway and DNS servers the host saved for the management card. With DHCP the
// saved configuration has none, and the DNS servers the lease gave are not reported by vedette-host (deferred); the route still is.
func hostInfraOf(st api.NetState) []response.HostInfra {
	var out []response.HostInfra
	add := func(s, kind string) {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || a.IsUnspecified() || a.IsLoopback() {
			return
		}
		out = append(out, response.HostInfra{Addr: a.Unmap().WithZone(""), Kind: kind})
	}
	if st.DefaultRoute != nil {
		add(st.DefaultRoute.Gateway, "gateway")
	}
	if m := st.Config.Mgmt; m != nil {
		add(m.Gateway, "gateway")
		for i, d := range m.DNS {
			if i >= 8 { // netplan holds a handful; a longer list is not a resolver list
				break
			}
			add(d, "dns")
		}
	}
	return out
}
