package sensorpassive

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/content/oui"
	"github.com/knt048/vedette/core/observe"
)

// Confidence of each kind of passive observation (INV-5). The inventory ranks values by source first and
// confidence second (DATA_MODEL 5.1); passive is a low-trust source, so none of these is above 0.9.
const (
	ConfMACBinding  = 0.9 // ARP sender, DHCP ACK: the address pair is what the frame itself says
	ConfLLDPName    = 0.7 // LLDP system name: set by the device's admin
	ConfDHCPName    = 0.6 // DHCP option 12
	ConfMDNSName    = 0.6 // mDNS A record whose address is the sender's own
	ConfLLDPKind    = 0.6 // LLDP capability bits
	ConfSSDPModel   = 0.5 // SSDP SERVER header
	ConfLLDPDesc    = 0.5 // LLDP system description
	ConfMDNSModel   = 0.5 // mDNS TXT model / md
	ConfMDNSKind    = 0.5 // mDNS service type that only one kind of device advertises
	ConfSSDPKind    = 0.5 // SSDP device type InternetGatewayDevice
	ConfMDNSIotKind = 0.3
	ConfOUIVendor   = 0.4 // vendor from the IEEE OUI table (D-83): says who made the card, not what the device is
)

// Bounds on what one Engine holds between two drains (SYS-6: the network is untrusted, a flood must not
// grow memory without limit). Overflow is counted, never silent.
const (
	maxPending  = 5000
	maxMeta     = 20000
	maxFlows    = 20000
	maxSent     = 50000
	maxOthers   = 4096
	maxSeen     = 50000
	maxValue    = 200              // the inventory refuses longer values (inventory PRE-1); sensor-protocol 5.3 says free text is cut
	repeatAfter = 15 * time.Minute // the same observation is sent again at most this often
	macWindow   = 5 * time.Minute  // "other MACs" counts sources seen within this window
	seenWindow  = 24 * time.Hour   // devices_seen counts MACs seen within this window
	flowWindow  = time.Minute      // flows are summed over this window, then handed out
)

var mdnsKinds = map[string]struct {
	kind string
	conf float64
}{
	"_ipp._tcp": {"printer", ConfMDNSKind}, "_ipps._tcp": {"printer", ConfMDNSKind}, "_printer._tcp": {"printer", ConfMDNSKind},
	"_pdl-datastream._tcp": {"printer", ConfMDNSKind}, "_scanner._tcp": {"printer", ConfMDNSKind},
	"_hap._tcp": {"iot", ConfMDNSIotKind}, "_googlecast._tcp": {"iot", ConfMDNSIotKind},
}

// engineConfig is fixed for the life of an Engine: a change of settings starts a new one.
type engineConfig struct {
	Clock   func() time.Time
	Span    bool
	Extract Extract
	Filters []Filter
	OwnMACs []string
	OwnIPs  []netip.Addr
	Devices *deviceBook // devices already reported; shared by the Engines of one Service (nil: a book of its own, see bookLimits)
}

type flowKey struct {
	src, dst     netip.Addr
	sport, dport uint16
	proto        uint8
}

type flowVal struct {
	packets, bytes uint64
	first, last    time.Time
}

type obsKey struct {
	mac, ip, field, value string
}

// Engine turns frames into observations and SPAN metadata. It never does I/O: Handle takes a frame, Drain
// hands out what accumulated. Safe for concurrent use.
type Engine struct {
	clock   func() time.Time
	span    bool
	extract Extract
	filt    *matcher
	ownMAC  map[mac]bool
	ownIP   map[netip.Addr]bool

	mu         sync.Mutex
	obs        []observe.Observation
	meta       []MetaItem
	flows      map[flowKey]*flowVal
	flowsSince time.Time
	sent       map[obsKey]time.Time
	counters   map[string]uint64
	secs       [10]struct {
		sec int64
		n   int
	}
	lastPacket time.Time
	others     map[mac]time.Time
	seen       map[mac]time.Time
	book       *deviceBook
}

// newEngine compiles the filters and the own-address sets.
func newEngine(cfg engineConfig) (*Engine, error) {
	m, err := compileFilters(cfg.Filters)
	if err != nil {
		return nil, err
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	e := &Engine{
		clock: clock, span: cfg.Span, extract: cfg.Extract, filt: m,
		ownMAC: map[mac]bool{}, ownIP: map[netip.Addr]bool{},
		flows: map[flowKey]*flowVal{}, sent: map[obsKey]time.Time{}, counters: map[string]uint64{},
		others: map[mac]time.Time{}, seen: map[mac]time.Time{}, book: cfg.Devices,
	}
	if e.book == nil {
		e.book = newDeviceBook(bookLimits{PerMinute: maxNewMACsPerMinute, PerHour: maxNewMACsPerHour})
	}
	for _, s := range cfg.OwnMACs {
		if b, ok := parseMAC(s); ok {
			e.ownMAC[b] = true
		}
	}
	for _, a := range cfg.OwnIPs {
		e.ownIP[a.Unmap()] = true
	}
	e.flowsSince = clock()
	return e, nil
}

func parseMAC(s string) (mac, bool) {
	var m mac
	if len(s) != 17 {
		return m, false
	}
	for i := range 6 {
		hi, ok1 := hexVal(s[i*3])
		lo, ok2 := hexVal(s[i*3+1])
		if !ok1 || !ok2 || (i < 5 && s[i*3+2] != ':') {
			return mac{}, false
		}
		m[i] = hi<<4 | lo
	}
	return m, true
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func (e *Engine) drop(why string) { e.counters[why]++ }

// Counters returns how many packets were dropped or ignored, by reason ("malformed_arp", "excluded", ...).
func (e *Engine) Counters() map[string]uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]uint64, len(e.counters))
	for k, v := range e.counters {
		out[k] = v
	}
	return out
}

// CountDrop records a record the source could not turn into a frame.
func (e *Engine) CountDrop(why string) {
	e.mu.Lock()
	e.drop(why)
	e.mu.Unlock()
}

// Handle reads one frame. Order matters (INV-7): the exclusion filter runs on the headers before any
// field is extracted from the payload, so excluded traffic leaves nothing behind.
func (e *Engine) Handle(p Packet) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := p.At
	if now.IsZero() {
		now = e.clock()
	}
	e.measure(now)
	f, err := parseEthernet(p.Data)
	if err != nil {
		if !errors.Is(err, errIgnore) {
			e.drop("malformed_ethernet")
		}
		return
	}
	// "other MACs" counts unicast frames between two hosts that are not the box: broadcasts and the replies to the
	// box arrive on a mirror of the box's own port too, and would hide that nothing else is mirrored (INV-9).
	if f.src.usable() && !e.ownMAC[f.src] && !e.ownMAC[f.dst] && f.dst[0]&1 == 0 {
		e.noteOther(f.src, now)
	}
	switch f.ethType {
	case etherARP:
		e.handleARP(f, now)
	case etherLLDP:
		e.handleLLDP(f, now)
	case etherIPv4:
		e.handleIP(f, now)
	}
}

// measure feeds the SPAN statistics (POST-4): every frame counts, excluded or not, because it measures the
// health of the mirror, not what is kept.
func (e *Engine) measure(now time.Time) {
	sec := now.Unix()
	s := &e.secs[((sec%10)+10)%10]
	if s.sec != sec {
		s.sec, s.n = sec, 0
	}
	s.n++
	e.lastPacket = now
}

func (e *Engine) noteOther(m mac, now time.Time) {
	if _, ok := e.others[m]; !ok && len(e.others) >= maxOthers {
		e.prune(e.others, now.Add(-macWindow))
		if len(e.others) >= maxOthers {
			return // saturated: the count stops at maxOthers
		}
	}
	e.others[m] = now
}

func (e *Engine) noteDevice(m mac, now time.Time) {
	if _, ok := e.seen[m]; !ok && len(e.seen) >= maxSeen {
		e.prune(e.seen, now.Add(-seenWindow))
		if len(e.seen) >= maxSeen {
			return
		}
	}
	e.seen[m] = now
}

func (e *Engine) prune(m map[mac]time.Time, before time.Time) {
	for k, t := range m {
		if t.Before(before) {
			delete(m, k)
		}
	}
}

// Stats is what the mirror looked like in the last seconds: packets per second (rounded up, so any traffic
// shows), distinct source MACs other than the box's own seen in the last five minutes, the last frame time.
func (e *Engine) Stats(now time.Time) (pps, otherMACs int, last time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	sum := 0
	for _, s := range e.secs {
		if s.sec > now.Unix()-10 && s.sec <= now.Unix() {
			sum += s.n
		}
	}
	e.prune(e.others, now.Add(-macWindow))
	return (sum + 9) / 10, len(e.others), e.lastPacket
}

// DevicesSeen is the number of distinct devices (MACs) heard from in the last 24 hours, own box excluded.
func (e *Engine) DevicesSeen(now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.prune(e.seen, now.Add(-seenWindow))
	return len(e.seen)
}

// excluded applies the filters to the headers; it counts what it drops.
func (e *Engine) excluded(src, dst netip.Addr, sport, dport uint16) bool {
	if e.filt.excludes(src, dst, sport, dport) {
		e.drop("excluded")
		return true
	}
	return false
}

func (e *Engine) own(m mac, ip netip.Addr) bool {
	return e.ownMAC[m] || (ip.IsValid() && e.ownIP[ip])
}

// add queues an observation unless it is about the box itself (INV-6), repeats one sent recently, or would add
// a new device beyond the per-minute budget. An address that is not a unicast host address never reaches the
// sink: the observation is kept without it.
func (e *Engine) add(now time.Time, hintMAC mac, hintIP netip.Addr, field observe.Field, value string, conf float64) {
	if e.own(hintMAC, hintIP) {
		return
	}
	if hintIP.IsValid() && !unicastIP(hintIP) {
		e.drop("non_unicast_ip")
		hintIP = netip.Addr{}
	}
	if len(value) > maxValue {
		value = fit(value)
		e.drop("value_truncated")
	}
	if value == "" { // the cut can leave nothing (a name of dots and dashes): the inventory refuses an empty value
		e.drop("value_empty")
		return
	}
	switch e.book.admit(hintMAC, now) {
	case admitKnown:
	case admitNew:
	case admitWait:
		e.drop("new_macs_unconfirmed")
		return
	default:
		e.drop("new_macs_dropped")
		return
	}
	if !e.book.allowValue(hintMAC, field, value, now) {
		e.drop("values_dropped")
		return
	}
	// The vendor of a device goes out until the inventory has it: the book (the Service's, not this Engine's) remembers
	// that it is still owed, so a capture error or a failed final flush does not lose it.
	if e.book.vendorOwed(hintMAC) {
		e.queueVendor(now, hintMAC)
	}
	e.queue(now, hintMAC, hintIP, field, value, conf)
}

// queueVendor queues the vendor the OUI table gives for a MAC. The table is ours but the value goes through the same
// check as every other text (INV-3).
func (e *Engine) queueVendor(now time.Time, m mac) {
	v, ok := oui.Lookup(m)
	if !ok {
		e.book.vendorDone(m) // no vendor for this MAC (locally administered, group): nothing is owed
		return
	}
	if len(v) > maxValue || !printable(v) {
		e.drop("vendor_rejected")
		e.book.vendorDone(m)
		return
	}
	e.queue(now, m, netip.Addr{}, observe.Vendor, v, ConfOUIVendor)
}

func (e *Engine) queue(now time.Time, hintMAC mac, hintIP netip.Addr, field observe.Field, value string, conf float64) {
	k := obsKey{hintMAC.String(), hintIP.String(), string(field), value}
	if t, ok := e.sent[k]; ok && now.Sub(t) < repeatAfter {
		return
	}
	if len(e.obs) >= maxPending {
		e.drop("observations_dropped")
		return
	}
	if len(e.sent) >= maxSent {
		clear(e.sent)
	}
	e.sent[k] = now
	e.obs = append(e.obs, observe.Observation{
		AssetHint: observe.AssetHint{IP: hintIP, MAC: hintMAC.String()},
		Field:     field, Value: value, Source: observe.Passive, Confidence: conf, SeenAt: now,
	})
}

// fit cuts a value to maxValue bytes on a character boundary and drops the separators the cut leaves at the end.
func fit(s string) string {
	s = truncate(s, maxValue)
	return strings.TrimRight(s, ". -_")
}

// unicastIP reports whether a is an address a host can have: not unspecified, loopback, multicast, broadcast, 0.0.0.0/8 or 240.0.0.0/4.
func unicastIP(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
		return false
	}
	if a.Is4() {
		if b := a.As4(); b[0] == 0 || b[0] >= 240 { // 0.0.0.0/8 "this network", 240.0.0.0/4 reserved (and the broadcast)
			return false
		}
	}
	return true
}

func (e *Engine) handleARP(f frame, now time.Time) {
	a, err := parseARP(f.payload)
	if err != nil {
		e.drop("malformed_arp")
		return
	}
	if e.excluded(a.senderIP, a.targetIP, 0, 0) {
		return
	}
	if a.senderMAC != f.src || !a.senderMAC.usable() || e.own(a.senderMAC, a.senderIP) {
		if a.senderMAC != f.src {
			e.drop("arp_mac_mismatch")
		}
		return
	}
	e.noteDevice(a.senderMAC, now)
	e.add(now, a.senderMAC, a.senderIP, observe.MAC, a.senderMAC.String(), ConfMACBinding)
}

func (e *Engine) handleLLDP(f frame, now time.Time) {
	l, err := parseLLDP(f.payload)
	if err != nil {
		e.drop("malformed_lldp")
		return
	}
	who := f.src
	if l.hasMAC {
		who = l.chassisMAC
	}
	if !who.usable() || e.own(who, netip.Addr{}) {
		return
	}
	e.noteDevice(who, now)
	e.add(now, who, netip.Addr{}, observe.MAC, who.String(), ConfMACBinding)
	if l.sysName != "" {
		e.add(now, who, netip.Addr{}, observe.Hostname, l.sysName, ConfLLDPName)
	}
	if l.sysDesc != "" {
		e.add(now, who, netip.Addr{}, observe.Model, truncate(l.sysDesc, 200), ConfLLDPDesc)
	}
	switch {
	case l.caps&lldpCapAP != 0:
		e.add(now, who, netip.Addr{}, observe.Kind, "ap", ConfLLDPKind)
	case l.caps&lldpCapBridge != 0:
		e.add(now, who, netip.Addr{}, observe.Kind, "switch", ConfLLDPKind)
	case l.caps&lldpCapRouter != 0:
		e.add(now, who, netip.Addr{}, observe.Kind, "router", ConfLLDPKind)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) { // do not cut a UTF-8 sequence in half
		s = s[:len(s)-1]
	}
	return s
}

func (e *Engine) handleIP(f frame, now time.Time) {
	ip, err := parseIPv4(f.payload)
	if err != nil {
		e.drop("malformed_ipv4")
		return
	}
	var sport, dport uint16
	var udp udpDatagram
	var tcp tcpSegment
	if ip.firstFrg {
		switch ip.proto {
		case protoUDP:
			if udp, err = parseUDP(ip.payload); err != nil {
				e.drop("malformed_udp")
				return
			}
			sport, dport = udp.sport, udp.dport
		case protoTCP:
			if tcp, err = parseTCP(ip.payload); err != nil {
				e.drop("malformed_tcp")
				return
			}
			sport, dport = tcp.sport, tcp.dport
		}
	}
	if !ip.firstFrg && e.filt.hasPorts() { // no ports to compare: fail closed rather than read what may be excluded
		e.drop("fragment_skipped")
		return
	}
	if e.excluded(ip.src, ip.dst, sport, dport) {
		return
	}
	if e.own(f.src, ip.src) {
		return // the box's own traffic: no asset, no metadata (INV-6)
	}
	if f.src.usable() {
		e.noteDevice(f.src, now)
	}
	toBox := e.ownIP[ip.dst] || e.ownMAC[f.dst] // traffic to the box is the box's business, not a device's (INV-6)
	if e.span && e.extract.Flows && !toBox {
		e.countFlow(ip, sport, dport, now)
	}
	switch ip.proto {
	case protoUDP:
		if ip.firstFrg {
			e.handleUDP(f, ip, udp, now, toBox)
		}
	case protoTCP:
		if ip.firstFrg && e.span && !toBox {
			e.handleTCP(f, ip, tcp, now)
		}
	}
}

func (e *Engine) handleUDP(f frame, ip ipv4, u udpDatagram, now time.Time, toBox bool) {
	switch {
	case (u.sport == 68 && u.dport == 67) || (u.sport == 67 && u.dport == 68):
		e.handleDHCP(f, u.payload, now)
	case u.sport == 5353 || u.dport == 5353:
		e.handleMDNS(f, ip, u.payload, now)
	case u.sport == 1900 || u.dport == 1900:
		e.handleSSDP(f, ip, u.payload, now)
	case u.dport == 53 && e.span && e.extract.DNS && !toBox:
		e.handleDNSQuery(f, ip, u.payload, now)
	}
}

func (e *Engine) handleDHCP(f frame, b []byte, now time.Time) {
	m, err := parseDHCP(b)
	if err != nil {
		e.drop("malformed_dhcp")
		return
	}
	if !m.clientMAC.usable() {
		return
	}
	// the addresses inside the message are as much "the host" as the IP header: INV-7 applies to them too
	for _, a := range []netip.Addr{m.clientIP, m.yourIP, m.requestedIP} {
		if a.IsValid() && e.excluded(a, netip.Addr{}, 0, 0) {
			return
		}
	}
	switch m.op {
	case 1: // a client asks: it exists, and it may give its name. Only the client itself may speak for its MAC.
		if m.clientMAC != f.src {
			e.drop("dhcp_mac_mismatch")
			return
		}
		e.noteDevice(m.clientMAC, now)
		e.add(now, m.clientMAC, m.clientIP, observe.MAC, m.clientMAC.String(), ConfMACBinding)
		if m.hostname != "" {
			e.add(now, m.clientMAC, m.clientIP, observe.Hostname, m.hostname, ConfDHCPName)
		}
	case 2: // a server answers: the ACK binds an address to a MAC, and goes to that MAC (or to everybody)
		if m.clientMAC != f.dst && f.dst != (mac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
			e.drop("dhcp_mac_mismatch")
			return
		}
		if m.msgType == 5 && m.yourIP.IsValid() {
			e.add(now, m.clientMAC, m.yourIP, observe.MAC, m.clientMAC.String(), ConfMACBinding)
		}
	}
}

func (e *Engine) handleMDNS(f frame, ip ipv4, b []byte, now time.Time) {
	m, err := parseDNS(b)
	if err != nil {
		e.drop("malformed_mdns")
		return
	}
	if !m.response || !f.src.usable() {
		return
	}
	for _, r := range m.records {
		switch r.rtype {
		case dnsTypeA:
			host, ok := strings.CutSuffix(strings.ToLower(r.name), ".local")
			// only the sender's own address counts: a name pointing at someone else is not evidence about this MAC
			if ok && len(r.data) == 4 && netip.AddrFrom4([4]byte(r.data)) == ip.src && hostnameOK(host) {
				e.add(now, f.src, ip.src, observe.Hostname, host, ConfMDNSName)
			}
		case dnsTypePTR:
			svc, ok := strings.CutSuffix(strings.ToLower(r.name), ".local")
			if k, found := mdnsKinds[svc]; ok && found {
				e.add(now, f.src, ip.src, observe.Kind, k.kind, k.conf)
			}
		case dnsTypeTXT:
			t := txtPairs(r.data)
			for _, key := range []string{"model", "md"} {
				if v, ok := cleanText(t[key], 200); ok {
					e.add(now, f.src, ip.src, observe.Model, v, ConfMDNSModel)
					break
				}
			}
		}
	}
}

func (e *Engine) handleSSDP(f frame, ip ipv4, b []byte, now time.Time) {
	m, err := parseSSDP(b)
	if err != nil {
		if !errors.Is(err, errIgnore) {
			e.drop("malformed_ssdp")
		}
		return
	}
	if !f.src.usable() {
		return
	}
	if v, ok := cleanText(m.server, 200); ok {
		e.add(now, f.src, ip.src, observe.Model, v, ConfSSDPModel)
	}
	if strings.Contains(m.nt, "InternetGatewayDevice") {
		e.add(now, f.src, ip.src, observe.Kind, "router", ConfSSDPKind)
	}
}

// ---- SPAN metadata (only with Span on, and only the kinds the admin switched on) ----

func (e *Engine) addMeta(it MetaItem) {
	if len(e.meta) >= maxMeta {
		e.drop("metadata_dropped")
		return
	}
	e.meta = append(e.meta, it)
}

func (e *Engine) handleDNSQuery(f frame, ip ipv4, b []byte, now time.Time) {
	m, err := parseDNS(b)
	if err != nil {
		e.drop("malformed_dns")
		return
	}
	if m.response || m.opcode != 0 {
		return
	}
	for i, q := range m.questions {
		if i == 4 {
			break
		}
		name := strings.ToLower(q.name)
		if !hostnameOK(name) {
			e.drop("dns_name_rejected")
			continue
		}
		e.addMeta(MetaItem{Kind: MetaDNS, At: now, SrcMAC: f.src.String(), SrcIP: ip.src, DstIP: ip.dst, Name: name, QType: q.qtype})
	}
}

func (e *Engine) handleTCP(f frame, ip ipv4, t tcpSegment, now time.Time) {
	switch {
	case e.extract.TLSSNI && (t.dport == 443 || t.dport == 8443):
		name, err := parseClientHelloSNI(t.payload)
		if err != nil {
			if !errors.Is(err, errIgnore) {
				e.drop("malformed_tls")
			}
			return
		}
		e.addMeta(MetaItem{Kind: MetaSNI, At: now, SrcMAC: f.src.String(), SrcIP: ip.src, DstIP: ip.dst, Name: name})
	case e.extract.HTTPHost && (t.dport == 80 || t.dport == 8080):
		host, err := parseHTTPHost(t.payload)
		if err != nil {
			if !errors.Is(err, errIgnore) {
				e.drop("malformed_http")
			}
			return
		}
		e.addMeta(MetaItem{Kind: MetaHTTP, At: now, SrcMAC: f.src.String(), SrcIP: ip.src, DstIP: ip.dst, Name: host})
	}
}

func (e *Engine) countFlow(ip ipv4, sport, dport uint16, now time.Time) {
	k := flowKey{ip.src, ip.dst, sport, dport, ip.proto}
	v := e.flows[k]
	if v == nil {
		if len(e.flows) >= maxFlows {
			e.drop("flows_dropped")
			return
		}
		v = &flowVal{first: now}
		e.flows[k] = v
	}
	v.packets++
	v.bytes += uint64(ip.totalLen) //nolint:gosec // totalLen comes from a 16-bit field and is never negative
	v.last = now
}

// ---- hand-out ----

// Pending is how many observations and metadata items wait to be drained.
func (e *Engine) Pending() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.obs) + len(e.meta)
}

// Drain hands out what accumulated and clears it. Flow counters are handed out once a minute (or when final
// is true), each flow as one item with its totals.
func (e *Engine) Drain(now time.Time, final bool) ([]observe.Observation, []MetaItem) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.flows) > 0 && (final || now.Sub(e.flowsSince) >= flowWindow) {
		for k, v := range e.flows {
			if len(e.meta) >= maxMeta {
				e.drop("metadata_dropped")
				break
			}
			e.meta = append(e.meta, MetaItem{Kind: MetaFlow, At: v.last, First: v.first, SrcIP: k.src, DstIP: k.dst,
				Proto: k.proto, SrcPort: k.sport, DstPort: k.dport, Packets: v.packets, Bytes: v.bytes})
		}
		clear(e.flows)
		e.flowsSince = now
	}
	obs, meta := e.obs, e.meta
	e.obs, e.meta = nil, nil
	return obs, meta
}

// Unmark forgets that obs were sent, so a failed delivery is not suppressed as a repeat. A vendor row stays owed in
// the book, so it goes out again with the next frame of its MAC.
func (e *Engine) Unmark(obs []observe.Observation) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, o := range obs {
		delete(e.sent, obsKey{o.AssetHint.MAC, o.AssetHint.IP.String(), string(o.Field), o.Value})
	}
}

// Delivered says that obs reached the inventory or were refused by it for good: the vendor rows among them are no longer
// owed to it.
func (e *Engine) Delivered(obs []observe.Observation) {
	for _, o := range obs {
		if o.Field == observe.Vendor {
			if m, ok := parseMAC(o.AssetHint.MAC); ok {
				e.book.vendorDone(m)
			}
		}
	}
}

// Requeue puts observations whose delivery failed back at the head of the queue, to be sent as one batch later.
// They stay marked as sent, so a repeat of the same frame does not queue them twice. What does not fit under
// maxPending is dropped and counted.
func (e *Engine) Requeue(obs []observe.Observation) {
	e.mu.Lock()
	defer e.mu.Unlock()
	room := maxPending - len(e.obs)
	if room < len(obs) {
		for range len(obs) - max(room, 0) {
			e.drop("observations_dropped")
		}
		obs = obs[:max(room, 0)]
	}
	e.obs = append(append(make([]observe.Observation, 0, len(obs)+len(e.obs)), obs...), e.obs...)
}
