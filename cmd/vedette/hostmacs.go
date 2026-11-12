package main

import (
	"context"
	"errors"
	"net"
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
	infra    []response.HostInfra // the gateways (with their MACs) and DNS servers of the same answer (D-325, D-384)
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
	h.at, h.failedAt, h.last, h.infra = h.now(), time.Time{}, out, keepGateways(hostInfraOf(st), h.infra)
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

// keepGateways carries the last answer's gateways over the gaps of a new one: a family (IPv4, IPv6) with no gateway now (a lease being
// renewed, a pending net.apply, a router advertisement not seen yet) keeps its last gateways, and a gateway whose neighbour entry is
// missing now keeps the MAC it had. Keeping a stale one only protects more.
func keepGateways(now, last []response.HostInfra) []response.HostInfra {
	answered := len(now) // the families are judged on the new answer, not on what is carried over
	for _, p := range last {
		if p.Kind != "gateway" {
			continue
		}
		family := false
		for i := range now[:answered] {
			n := &now[i]
			if n.Kind != "gateway" || n.Addr.Is4() != p.Addr.Is4() {
				continue
			}
			family = true
			if n.Addr == p.Addr && n.MAC == "" {
				n.MAC = p.MAC
			}
		}
		if !family {
			now = append(now, p)
		}
	}
	return now
}

// hostInfraOf reads the kernel's IPv4 and IPv6 default gateways with their MACs, the DNS servers the box uses (whoever set them: a DHCP
// lease, netplan, an administrator) and the gateway and DNS servers the host saved for the management card (D-325, D-384). A host older
// than D-384 sends no IPv6 route, MAC or resolver: only the rest is read.
func hostInfraOf(st api.NetState) []response.HostInfra {
	var out []response.HostInfra
	add := func(s, kind, mac string) {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || a.IsUnspecified() || a.IsLoopback() {
			return
		}
		x := response.HostInfra{Addr: a.Unmap().WithZone(""), Kind: kind}
		if hw, err := net.ParseMAC(mac); err == nil && len(hw) == 6 {
			x.MAC = hw.String()
		}
		out = append(out, x)
	}
	for _, r := range []*api.NetRoute{st.DefaultRoute, st.DefaultRoute6} {
		if r != nil {
			add(r.Gateway, "gateway", r.MAC)
		}
	}
	dns := func(l []string, limit int) {
		for i, d := range l {
			if i >= limit {
				break
			}
			add(d, "dns", "")
		}
	}
	dns(st.Resolvers, 16) // the host sends at most 16
	if m := st.Config.Mgmt; m != nil {
		add(m.Gateway, "gateway", "")
		dns(m.DNS, 8) // netplan holds a handful; a longer list is not a resolver list
	}
	return out
}
