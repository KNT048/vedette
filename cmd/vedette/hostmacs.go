package main

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
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
	infra    []response.HostInfra // the gateways (with their pinned MACs) and DNS servers of the same answer (D-325, D-384)
	pins     map[netip.Addr]*gwPin
	// macChanged is told when the host reports a MAC for a gateway that is not one of its pinned MACs (possible ARP/ND spoofing), at
	// most once per gatewayMACSettle per gateway. It runs under mu and must not block. nil = nobody is told.
	macChanged func(gw netip.Addr, pinned []string, seen string)
}

// D-384 review (M1): the gateway's MAC comes from the box's own neighbour table, which a host on the LAN can poison. A MAC adopted at
// once would make a spoofer never-touch during exactly the attack. So the first MAC seen for a gateway address is pinned; a different
// one is reported (macChanged) and stays off the never-touch list until it has been the only MAC seen for gatewayMACSettle, over at
// least gatewayMACAnswers answers in a row; the pinned MACs stay never-touch throughout and after.
const (
	gatewayMACSettle  = 10 * time.Minute
	gatewayMACAnswers = 3
	gatewayMACKeep    = 4  // pinned MACs per gateway address; the oldest is dropped past it
	gatewayPins       = 16 // gateway addresses remembered; past it, those not in the current answer are forgotten
)

// gwPin is what core knows of one gateway address's MAC.
type gwPin struct {
	pinned    []string  // adopted MACs, oldest first; all are never-touch
	cand      string    // a different MAC the host reports, not adopted yet
	candSince time.Time // when cand was first seen
	candSeen  int       // answers in a row that reported cand
	warnedAt  time.Time // the last macChanged call for this gateway
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
	t := h.now()
	h.at, h.failedAt, h.last, h.infra = t, time.Time{}, out, keepGateways(h.pinMACs(hostInfraOf(st), t), h.infra)
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
// renewed, a pending net.apply, a router advertisement not seen yet) keeps its last gateways, with their pinned MACs. Keeping a stale
// one only protects more. (A gateway whose neighbour entry is missing for a moment keeps its MACs through pinMACs.)
func keepGateways(now, last []response.HostInfra) []response.HostInfra {
	answered := len(now) // the families are judged on the new answer, not on what is carried over
	for _, p := range last {
		if p.Kind == "gateway" && !slices.ContainsFunc(now[:answered], func(n response.HostInfra) bool { return n.Kind == "gateway" && n.Addr.Is4() == p.Addr.Is4() }) {
			now = append(now, p)
		}
	}
	return now
}

// pinMACs replaces the MAC the host reported for each gateway by the gateway's pinned MACs (one entry per MAC; a second entry for the
// same address, as the saved configuration's gateway, carries none) and records what the host reported (observe). Called under mu.
func (h *hostMACs) pinMACs(infra []response.HostInfra, now time.Time) []response.HostInfra {
	if h.pins == nil {
		h.pins = map[netip.Addr]*gwPin{}
	}
	if len(h.pins) >= gatewayPins {
		for a := range h.pins {
			if !slices.ContainsFunc(infra, func(x response.HostInfra) bool { return x.Addr == a }) {
				delete(h.pins, a)
			}
		}
	}
	var out []response.HostInfra
	done := map[netip.Addr]bool{}
	for _, x := range infra {
		if x.Kind != "gateway" {
			out = append(out, x)
			continue
		}
		p := h.pins[x.Addr]
		switch {
		case p == nil && x.MAC != "" && len(h.pins) < gatewayPins:
			p = &gwPin{pinned: []string{x.MAC}}
			h.pins[x.Addr] = p
		case p != nil && x.MAC != "":
			h.observe(x.Addr, p, x.MAC, now)
		}
		x.MAC = ""
		if p == nil || done[x.Addr] {
			out = append(out, x)
			continue
		}
		done[x.Addr] = true
		for _, m := range p.pinned {
			y := x
			y.MAC = m
			out = append(out, y)
		}
	}
	return out
}

// observe records one answer's MAC for a pinned gateway: a pinned MAC ends any candidate; another MAC becomes (or stays) the candidate,
// is reported, and is adopted once it has been seen in gatewayMACAnswers answers in a row over at least gatewayMACSettle.
func (h *hostMACs) observe(gw netip.Addr, p *gwPin, mac string, now time.Time) {
	if slices.Contains(p.pinned, mac) {
		p.cand, p.candSeen = "", 0
		return
	}
	if mac != p.cand {
		p.cand, p.candSince, p.candSeen = mac, now, 0
		if h.macChanged != nil && (p.warnedAt.IsZero() || now.Sub(p.warnedAt) >= gatewayMACSettle) {
			p.warnedAt = now
			h.macChanged(gw, slices.Clone(p.pinned), mac)
		}
	}
	p.candSeen++
	if p.candSeen >= gatewayMACAnswers && now.Sub(p.candSince) >= gatewayMACSettle {
		p.pinned = append(p.pinned, mac)
		if len(p.pinned) > gatewayMACKeep {
			p.pinned = p.pinned[1:]
		}
		p.cand, p.candSeen = "", 0
	}
}

// gatewayMACChanged is hostMACs.macChanged in production: a WARN line and a core_audit row "network.gateway_mac_changed" (user system),
// the way arpwatch reports a flip-flop. The row is written by its own goroutine: the call runs under hostMACs.mu, often while response
// holds the write transaction that asked for the never-touch list, and a second write there would wait on the first.
func gatewayMACChanged(d *deps) func(gw netip.Addr, pinned []string, seen string) {
	return func(gw netip.Addr, pinned []string, seen string) {
		if d.Log != nil {
			d.Log.Warn("the MAC address of this box's default gateway changed (a router replaced, or ARP/ND spoofing); the new MAC is not never-touch until it has stayed",
				"gateway", gw.String(), "never_touch_macs", strings.Join(pinned, ","), "new_mac", seen, "settle", gatewayMACSettle.String())
		}
		if d.DB == nil || d.Audit == nil {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := auditGatewayMAC(ctx, d, gw, pinned, seen); err != nil && d.Log != nil {
				d.Log.Warn("the gateway MAC change could not be written to the audit log", "err", err)
			}
		}()
	}
}

// auditGatewayMAC writes the core_audit row of a gateway MAC change.
func auditGatewayMAC(ctx context.Context, d *deps, gw netip.Addr, pinned []string, seen string) error {
	detail := "now " + seen + "; never-touch stays " + strings.Join(pinned, ", ") + "; " + seen + " is not never-touch until it has been the only MAC for " + gatewayMACSettle.String()
	return d.DB.Write(ctx, func(tx *sql.Tx) error {
		return d.Audit.Append(ctx, tx, audit.Entry{User: "system", Action: "network.gateway_mac_changed", Target: "default gateway " + gw.String(), Detail: detail})
	})
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
	if r := st.DefaultRoute; r != nil {
		add(r.Gateway, "gateway", r.MAC)
	}
	for i, r := range st.DefaultRoutes6 {
		if i >= 16 { // the host sends at most 16
			break
		}
		add(r.Gateway, "gateway", r.MAC)
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
