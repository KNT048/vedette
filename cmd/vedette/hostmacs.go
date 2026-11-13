package main

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
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
	decoys   map[netip.Addr]string // the decoys of the same answer: address → MAC (lower case)
	infra    []response.HostInfra  // the trusted gateways (with their pinned MACs) and DNS servers of the same answer (D-325, D-450)
	vetted   map[netip.Addr]*infraVet
	// report is told what an answer changed in the box's gateways and resolvers (action, address, detail; see vet and observe), at most
	// once per infraSettle per address and event. It runs under mu and must not block. nil = nobody is told.
	report func(action string, addr netip.Addr, detail string)
}

// D-450 review: the default gateways and the resolvers come from the box's routes, its neighbour table and resolv.conf, all of which a
// host on the LAN can steer (a rogue router advertisement or DHCP server, ARP/ND poisoning). Seeding what it steers at once would make
// that host never-touch during exactly the attack. So only the addresses of core's first answer after start are trusted at once; an
// address first seen later is a candidate, seeded neither by IP nor by MAC until it has been in infraAnswers answers in a row spanning
// at least infraSettle. A trusted gateway's first MAC is pinned; a different MAC is a candidate under the same rule, and the first pin
// is never dropped. Each step is reported (WARN + core_audit). What the administrator saved (netplan's gateway and DNS) is trusted at
// once: only the administrator writes it.
const (
	infraSettle       = 10 * time.Minute
	infraAnswers      = 3
	gatewayMACKeep    = 4  // pinned MACs per gateway address: the first, and the 3 newest adopted after it
	infraVetAddresses = 32 // addresses remembered; past it, those not in the current answer are forgotten
)

// infraVet is what core knows of one address the host reports as a default gateway or resolver.
type infraVet struct {
	trusted  bool      // seeded as never-touch
	since    time.Time // candidate: the start of its run of answers
	seen     int       // candidate: answers in a row that held it
	warnedAt time.Time // the last report of this address as new
	// gateway MACs
	pinned      []string  // adopted MACs; pinned[0] is never dropped
	cand        string    // a different MAC the host reports, not adopted yet
	candSince   time.Time // when cand was first seen
	candSeen    int       // answers in a row that reported cand
	macWarnedAt time.Time // the last report of a changed MAC
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
	decoys := map[netip.Addr]string{}
	for _, d := range st.Decoys {
		out = append(out, strings.ToLower(d.MAC))
		if a, err := netip.ParseAddr(d.IP); err == nil {
			decoys[a] = strings.ToLower(d.MAC)
		}
	}
	t, first := h.now(), h.at.IsZero()
	dynamic, saved := hostInfraOf(st)
	h.at, h.failedAt, h.last, h.decoys, h.infra = t, time.Time{}, out, decoys, keepGateways(append(h.vet(dynamic, first, t), saved...), h.infra)
	return out, nil
}

// Decoys returns the decoy addresses of the same answer as Get (Fresh with fresh), each with its MAC (inventory.Config.BoxDecoyMACs).
func (h *hostMACs) Decoys(ctx context.Context, fresh bool) (map[netip.Addr]string, error) {
	if _, err := h.get(ctx, fresh); err != nil {
		return nil, err
	}
	if h == nil || h.r == nil {
		return nil, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return maps.Clone(h.decoys), nil
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

// keepGateways carries the last answer's gateways over the gaps of a new one: a family (IPv4, IPv6) with no trusted gateway now (a lease
// being renewed, a pending net.apply, a router advertisement not seen yet, a new gateway still a candidate) keeps its last gateways, with
// their pinned MACs. Keeping a stale one only protects more. (A gateway whose neighbour entry is missing for a moment keeps its MACs
// through vet.)
func keepGateways(now, last []response.HostInfra) []response.HostInfra {
	answered := len(now) // the families are judged on the new answer, not on what is carried over
	for _, p := range last {
		if p.Kind == "gateway" && !slices.ContainsFunc(now[:answered], func(n response.HostInfra) bool { return n.Kind == "gateway" && n.Addr.Is4() == p.Addr.Is4() }) {
			now = append(now, p)
		}
	}
	return now
}

// vet keeps the entries of the host-steered part of an answer (route gateways with their MACs, resolvers) whose address is trusted, a
// gateway once per pinned MAC, and records what the answer showed. On the first answer after start every address is trusted at once.
// Later, a new address is a candidate: reported as new, counted while it stays in the answers (an answer without it starts the count
// over), trusted and reported once it has been in infraAnswers answers in a row spanning infraSettle. Called under mu.
func (h *hostMACs) vet(infra []response.HostInfra, first bool, now time.Time) []response.HostInfra {
	if h.vetted == nil {
		h.vetted = map[netip.Addr]*infraVet{}
	}
	present := map[netip.Addr]string{} // address → its kind in this answer (gateway wins over dns)
	for _, x := range infra {
		if present[x.Addr] != "gateway" {
			present[x.Addr] = x.Kind
		}
	}
	for a, v := range h.vetted {
		if _, ok := present[a]; !ok {
			v.seen = 0 // a candidate missing from an answer starts over; a trusted address stays trusted
			if len(h.vetted) > infraVetAddresses {
				delete(h.vetted, a)
			}
		}
	}
	var out []response.HostInfra
	counted, done := map[netip.Addr]bool{}, map[netip.Addr]bool{}
	for _, x := range infra {
		v := h.vetted[x.Addr]
		if v == nil {
			v = &infraVet{trusted: first}
			h.vetted[x.Addr] = v
		}
		if !v.trusted && !counted[x.Addr] {
			counted[x.Addr] = true
			h.countCandidate(x.Addr, present[x.Addr], v, now)
		}
		if !v.trusted {
			continue
		}
		if x.Kind != "gateway" {
			out = append(out, x)
			continue
		}
		if x.MAC != "" {
			h.observe(x.Addr, v, x.MAC, now)
		}
		if done[x.Addr] {
			continue
		}
		done[x.Addr] = true
		x.MAC = ""
		if len(v.pinned) == 0 {
			out = append(out, x)
		}
		for _, m := range v.pinned {
			y := x
			y.MAC = m
			out = append(out, y)
		}
	}
	return out
}

// countCandidate counts one more answer holding a candidate address, reports it when its run starts (at most once per infraSettle) and
// trusts it once the run is long enough.
func (h *hostMACs) countCandidate(a netip.Addr, kind string, v *infraVet, now time.Time) {
	what := map[string]string{"gateway": "default gateway", "dns": "DNS server"}[kind]
	if v.seen == 0 {
		v.since = now
		if v.warnedAt.IsZero() || now.Sub(v.warnedAt) >= infraSettle {
			v.warnedAt = now
			h.tell("network."+kind+"_new", a, "a new "+what+" "+a.String()+" appeared (a network change, or a rogue router or DHCP server); it is not never-touch until it has stayed "+infraSettle.String())
		}
	}
	v.seen++
	if v.seen >= infraAnswers && now.Sub(v.since) >= infraSettle {
		v.trusted = true
		h.tell("network."+kind+"_adopted", a, what+" "+a.String()+" stayed "+now.Sub(v.since).Round(time.Second).String()+" over "+strconv.Itoa(v.seen)+" answers; it is never-touch from now on")
	}
}

// observe records one answer's MAC for a trusted gateway: the first MAC seen is pinned; a pinned MAC ends any candidate; another MAC
// becomes (or stays) the candidate, is reported (at most once per infraSettle), and is adopted, and reported, once it has been seen in
// infraAnswers answers in a row over at least infraSettle (adoptions are therefore at least infraSettle apart). Past gatewayMACKeep pins
// the second-oldest is dropped: the first pin is never dropped, so rotating MACs cannot push the real router's out (review round 2).
func (h *hostMACs) observe(gw netip.Addr, v *infraVet, mac string, now time.Time) {
	switch {
	case len(v.pinned) == 0:
		v.pinned = []string{mac}
		return
	case slices.Contains(v.pinned, mac):
		v.cand, v.candSeen = "", 0
		return
	case mac != v.cand:
		v.cand, v.candSince, v.candSeen = mac, now, 0
		if v.macWarnedAt.IsZero() || now.Sub(v.macWarnedAt) >= infraSettle {
			v.macWarnedAt = now
			h.tell("network.gateway_mac_changed", gw, "now "+mac+"; never-touch stays "+strings.Join(v.pinned, ", ")+"; "+mac+" is not never-touch until it has been the only MAC for "+infraSettle.String())
		}
	}
	v.candSeen++
	if v.candSeen >= infraAnswers && now.Sub(v.candSince) >= infraSettle {
		v.pinned = append(v.pinned, mac)
		if len(v.pinned) > gatewayMACKeep {
			v.pinned = slices.Delete(v.pinned, 1, 2)
		}
		v.cand, v.candSeen = "", 0
		h.tell("network.gateway_mac_adopted", gw, mac+" was the only MAC for "+infraSettle.String()+"; never-touch now "+strings.Join(v.pinned, ", "))
	}
}

func (h *hostMACs) tell(action string, a netip.Addr, detail string) {
	if h.report != nil {
		h.report(action, a, detail)
	}
}

// infraReport is hostMACs.report in production: a WARN line and a core_audit row (user system), the way arpwatch reports a new station or
// a flip-flop. The row is written by its own goroutine: the call runs under hostMACs.mu, often while response holds the write transaction
// that asked for the never-touch list, and a second write there would wait on the first. ponytail: the goroutine's context is its own
// 30 s timeout, not the server's lifetime (deps carries none); a row cut by a shutdown is lost, the WARN line is not.
func infraReport(d *deps) func(action string, a netip.Addr, detail string) {
	return func(action string, a netip.Addr, detail string) {
		if d.Log != nil {
			d.Log.Warn("the box's gateways or DNS servers changed", "action", action, "address", a.String(), "detail", detail)
		}
		if d.DB == nil || d.Audit == nil {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := auditInfra(ctx, d, action, a, detail); err != nil && d.Log != nil {
				d.Log.Warn("a gateway or DNS change could not be written to the audit log", "action", action, "err", err)
			}
		}()
	}
}

// auditInfra writes the core_audit row of one report.
func auditInfra(ctx context.Context, d *deps, action string, a netip.Addr, detail string) error {
	return d.DB.Write(ctx, func(tx *sql.Tx) error {
		return d.Audit.Append(ctx, tx, audit.Entry{User: "system", Action: action, Target: a.String(), Detail: detail})
	})
}

// hostInfraOf reads, as dynamic, what the network can steer: the kernel's IPv4 and IPv6 default gateways with their MACs and the DNS
// servers the box uses (a DHCP lease's, a router advertisement's); and, as saved, the gateway and DNS servers the administrator saved for
// the management card (D-325, D-450). A host older than D-450 sends no IPv6 route, MAC or resolver: only the rest is read.
func hostInfraOf(st api.NetState) (dynamic, saved []response.HostInfra) {
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
	dynamic, out = out, nil
	if m := st.Config.Mgmt; m != nil {
		add(m.Gateway, "gateway", "")
		dns(m.DNS, 8) // netplan holds a handful; a longer list is not a resolver list
	}
	return dynamic, out
}
