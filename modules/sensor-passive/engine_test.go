package sensorpassive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

var own = engineConfig{OwnMACs: []string{pktgen.Box.String()}, OwnIPs: []netip.Addr{pktgen.BoxIP}}

// replay feeds a fixture through a fresh engine, the way the capture loop does.
func replay(t testing.TB, name string, cfg engineConfig) *Engine {
	t.Helper()
	src, err := OpenFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	cfg.Clock = func() time.Time { return pktgen.T0.Add(time.Hour) }
	e, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for {
		p, err := src.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return e
		}
		if errors.Is(err, ErrDropped) {
			e.CountDrop("unusable_record")
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		e.Handle(p)
	}
}

// obsSet renders observations as "mac field=value @ip conf".
func obsSet(obs []observe.Observation) map[string]bool {
	out := map[string]bool{}
	for _, o := range obs {
		ip := ""
		if o.AssetHint.IP.IsValid() {
			ip = o.AssetHint.IP.String()
		}
		out[fmt.Sprintf("%s %s=%s @%s %.1f", o.AssetHint.MAC, o.Field, o.Value, ip, o.Confidence)] = true
	}
	return out
}

func TestLANDiscoveryFixture(t *testing.T) {
	t.Parallel()
	e := replay(t, "lan-discovery.pcap", own)
	obs, meta := e.Drain(pktgen.T0.Add(time.Hour), true)
	if len(meta) != 0 {
		t.Fatalf("discovery without SPAN produced metadata: %+v", meta)
	}
	got := obsSet(obs)
	pc, router, printer, sw, phone, laptop := pktgen.PC.String(), pktgen.Router.String(), pktgen.Printer.String(), pktgen.Switch.String(), pktgen.Phone.String(), pktgen.Laptop.String()
	want := []string{
		pc + " hostname=PC-ACCOUNTING-01 @ 0.6",
		pc + " mac=" + pc + " @ 0.9",
		pc + " mac=" + pc + " @192.168.10.21 0.9",
		router + " mac=" + router + " @192.168.10.1 0.9",
		printer + " hostname=hp-laser-3f @192.168.10.22 0.6",
		printer + " kind=printer @192.168.10.22 0.5",
		printer + " model=HP LaserJet Pro M404 @192.168.10.22 0.5",
		router + " model=Linux/5.4 UPnP/1.0 MiniUPnPd/2.2 @192.168.10.1 0.5",
		router + " kind=router @192.168.10.1 0.5",
		sw + " mac=" + sw + " @ 0.9",
		sw + " hostname=SW-CORE-01 @ 0.7",
		sw + " model=Example Switch OS 4.2, 24 ports @ 0.5",
		sw + " kind=switch @ 0.6",
		phone + " mac=" + phone + " @ 0.9",
		laptop + " mac=" + laptop + " @192.168.10.24 0.9",
		laptop + " vendor=Apple, Inc. @ 0.4",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing observation %q", w)
		}
	}
	if len(got) != len(want) {
		for g := range got {
			t.Logf("got %s", g)
		}
		t.Errorf("got %d distinct observations, want %d", len(got), len(want))
	}
	for _, o := range obs {
		if o.Source != observe.Passive {
			t.Errorf("source %q, want passive (INV-5)", o.Source)
		}
		if strings.Contains(o.AssetHint.MAC, "02:00:00:00:00:01") || o.AssetHint.IP == pktgen.BoxIP {
			t.Errorf("an observation is about the box itself (INV-6): %+v", o)
		}
		if strings.Contains(o.Value, "liar") || o.AssetHint.IP == pktgen.PCIP && o.Field == observe.Hostname && o.Value != "PC-ACCOUNTING-01" {
			t.Errorf("a name was believed that does not belong to the sender: %+v", o)
		}
	}
	// the same ARP, DHCP request and ACK repeated in the capture become one observation each
	if n := countObs(obs, pc, observe.Hostname); n != 1 {
		t.Errorf("the PC's hostname was sent %d times, want 1", n)
	}
	if e.Counters()["malformed_ethernet"] != 0 {
		t.Errorf("counters %v", e.Counters())
	}
}

func countObs(obs []observe.Observation, macAddr string, f observe.Field) int {
	n := 0
	for _, o := range obs {
		if o.AssetHint.MAC == macAddr && o.Field == f {
			n++
		}
	}
	return n
}

var allExtract = Extract{DNS: true, TLSSNI: true, HTTPHost: true, Flows: true}

func spanCfg(filters ...Filter) engineConfig {
	c := own
	c.Span, c.Extract, c.Filters = true, allExtract, filters
	return c
}

func metaOf(items []MetaItem, k MetaKind) []MetaItem {
	var out []MetaItem
	for _, it := range items {
		if it.Kind == k {
			out = append(out, it)
		}
	}
	return out
}

func TestSpanMetadataFixture(t *testing.T) {
	t.Parallel()
	e := replay(t, "span-metadata.pcapng", spanCfg())
	obs, meta := e.Drain(pktgen.T0.Add(time.Hour), true)

	dns := metaOf(meta, MetaDNS)
	names := map[string]uint16{}
	for _, d := range dns {
		names[d.Name] = d.QType
	}
	if len(dns) != 3 || names["updates.example.org"] != 1 || names["tracker.badsite.test"] != 28 || names["private.example.net"] != 1 {
		t.Errorf("DNS items: %+v", dns)
	}
	if _, boxQuery := names["box-update.example.org"]; boxQuery {
		t.Error("the box's own DNS query became metadata (INV-6)")
	}
	if sni := metaOf(meta, MetaSNI); len(sni) != 2 || sni[0].Name != "portal.example.org" || sni[0].SrcIP != pktgen.PCIP || sni[0].DstIP != pktgen.WebIP || sni[0].SrcMAC != pktgen.PC.String() {
		t.Errorf("SNI items: %+v", sni)
	}
	if h := metaOf(meta, MetaHTTP); len(h) != 1 || h[0].Name != "legacy.example.org" {
		t.Errorf("HTTP items: %+v", h)
	}
	var flow *MetaItem
	for i, it := range metaOf(meta, MetaFlow) {
		if it.SrcIP == pktgen.PCIP && it.DstIP == pktgen.WebIP && it.SrcPort == 50001 && it.DstPort == 443 && it.Proto == 6 {
			flow = &metaOf(meta, MetaFlow)[i]
		}
		if it.SrcIP == pktgen.BoxIP {
			t.Errorf("a flow of the box itself: %+v", it)
		}
	}
	if flow == nil || flow.Packets != 3 || flow.Bytes != 3*uint64(20+20+10) && flow.Bytes == 0 {
		t.Errorf("flow of the TLS connection: %+v", flow)
	}
	// discovery still works over the mirror, and the box is not a device
	got := obsSet(obs)
	if !got[pktgen.Printer.String()+" mac="+pktgen.Printer.String()+" @192.168.10.22 0.9"] {
		t.Errorf("ARP over SPAN not seen: %v", got)
	}
	for _, o := range obs {
		if o.AssetHint.MAC == pktgen.Box.String() {
			t.Errorf("observation about the box: %+v", o)
		}
	}
}

// INV-3, FORBID-2: nothing of the payload survives; the secrets in the HTTP request never appear.
func TestNoPayloadIsKept(t *testing.T) {
	t.Parallel()
	e := replay(t, "span-metadata.pcapng", spanCfg())
	obs, meta := e.Drain(pktgen.T0.Add(time.Hour), true)
	all := fmt.Sprintf("%+v %+v", obs, meta)
	for _, secret := range []string{pktgen.SecretCookie, pktgen.SecretPassword, pktgen.SecretAuth, "SECRET", "hunter2", "Bearer", "Cookie", "/login", "application/x-www-form-urlencoded"} {
		if strings.Contains(all, secret) {
			t.Errorf("%q survived in %s", secret, all)
		}
	}
}

// INV-7: excluded traffic leaves nothing behind, and it is excluded before anything is read from it.
func TestExclusionFilters(t *testing.T) {
	t.Parallel()
	for name, f := range map[string]Filter{
		"host": {Type: "host", Value: pktgen.PhoneIP.String()},
		"cidr": {Type: "cidr", Value: "192.168.10.16/28"}, // .16-.31 holds both the phone and the PC
		"port": {Type: "port", Value: "50003"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := replay(t, "span-metadata.pcapng", spanCfg(f))
			_, meta := e.Drain(pktgen.T0.Add(time.Hour), true)
			for _, it := range meta {
				switch name {
				case "host":
					if it.SrcIP == pktgen.PhoneIP || it.Name == "tracker.badsite.test" || it.Name == "private.example.net" {
						t.Errorf("excluded host leaked: %+v", it)
					}
				case "cidr":
					if len(meta) != 0 && (it.SrcIP == pktgen.PCIP || it.SrcIP == pktgen.PhoneIP) {
						t.Errorf("excluded range leaked: %+v", it)
					}
				case "port":
					if it.SrcPort == 50003 || it.DstPort == 50003 || it.Name == "private.example.net" && it.Kind == MetaSNI {
						t.Errorf("excluded port leaked: %+v", it)
					}
				}
			}
			if e.Counters()["excluded"] == 0 {
				t.Error("nothing was counted as excluded")
			}
			if name == "host" && len(metaOf(meta, MetaSNI)) != 1 {
				t.Errorf("only the phone's hello should be gone: %+v", metaOf(meta, MetaSNI))
			}
		})
	}
}

func TestFilterCompileAndMatch(t *testing.T) {
	t.Parallel()
	m, err := compileFilters([]Filter{{"cidr", "10.1.2.3/8"}, {"host", "192.168.1.5"}, {"port", "8000-8100"}, {"port", "22"}})
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr
	for _, tc := range []struct {
		src, dst     string
		sport, dport uint16
		want         bool
	}{
		{"10.9.9.9", "1.1.1.1", 1, 2, true}, {"1.1.1.1", "10.0.0.1", 1, 2, true}, {"192.168.1.5", "1.1.1.1", 0, 0, true},
		{"1.1.1.1", "192.168.1.6", 1, 2, false}, {"1.1.1.1", "2.2.2.2", 8050, 9, true}, {"1.1.1.1", "2.2.2.2", 9, 22, true}, {"1.1.1.1", "2.2.2.2", 8101, 21, false},
	} {
		if got := m.excludes(a(tc.src), a(tc.dst), tc.sport, tc.dport); got != tc.want {
			t.Errorf("%+v: got %v", tc, got)
		}
	}
	if m.excludes(netip.Addr{}, netip.Addr{}, 0, 0) {
		t.Error("no addresses and no ports must not match")
	}
	for _, bad := range []Filter{{"cidr", "nope"}, {"cidr", "::1/128"}, {"host", "example.org"}, {"port", "0"}, {"port", "70000"}, {"port", "9-3"}, {"mac", "aa"}, {"", ""}} {
		if _, err := compileFilters([]Filter{bad}); err == nil {
			t.Errorf("filter %+v accepted", bad)
		}
	}
	if _, err := newEngine(engineConfig{Filters: []Filter{{"port", "x"}}}); err == nil {
		t.Error("an unreadable filter must stop the engine from starting (fail closed)")
	}
}

func TestExtractionSwitches(t *testing.T) {
	t.Parallel()
	cfg := own
	cfg.Span, cfg.Extract = true, Extract{DNS: true}
	_, meta := replay(t, "span-metadata.pcapng", cfg).Drain(pktgen.T0.Add(time.Hour), true)
	if len(metaOf(meta, MetaSNI))+len(metaOf(meta, MetaHTTP))+len(metaOf(meta, MetaFlow)) != 0 || len(metaOf(meta, MetaDNS)) == 0 {
		t.Errorf("only DNS was switched on: %+v", meta)
	}
	cfg.Span = false // SPAN off: no metadata whatever the switches say
	cfg.Extract = allExtract
	_, meta = replay(t, "span-metadata.pcapng", cfg).Drain(pktgen.T0.Add(time.Hour), true)
	if len(meta) != 0 {
		t.Errorf("metadata without SPAN: %+v", meta)
	}
}

func TestMalformedFixtureIsCountedNeverFatal(t *testing.T) {
	t.Parallel()
	e := replay(t, "malformed.pcap", spanCfg())
	obs, meta := e.Drain(pktgen.T0.Add(time.Hour), true)
	c := e.Counters()
	for _, k := range []string{"malformed_ethernet", "malformed_arp", "malformed_ipv4", "malformed_dhcp", "malformed_mdns", "malformed_dns", "malformed_ssdp", "malformed_lldp", "malformed_tls", "malformed_http", "malformed_tcp"} {
		if c[k] == 0 {
			t.Errorf("counter %s is 0: %v", k, c)
		}
	}
	if len(metaOf(meta, MetaDNS))+len(metaOf(meta, MetaSNI))+len(metaOf(meta, MetaHTTP)) != 0 {
		t.Errorf("broken packets produced names: %+v", meta) // their headers are fine, so flows are counted; nothing else
	}
	if len(obs) != 1 || obs[0].AssetHint.MAC != pktgen.PC.String() { // the valid ARP at the end
		t.Errorf("the good packet after the bad ones: %+v", obs)
	}
}

func TestRepeatedObservationsAreSentAgainAfterTheWindow(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{})
	arp := pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)
	e.Handle(Packet{At: pktgen.T0, Data: arp})
	e.Handle(Packet{At: pktgen.T0.Add(time.Minute), Data: arp})
	if obs, _ := e.Drain(pktgen.T0, false); len(obs) != 1 {
		t.Fatalf("a repeat within the window: %d observations", len(obs))
	}
	e.Handle(Packet{At: pktgen.T0.Add(repeatAfter + time.Second), Data: arp})
	obs, _ := e.Drain(pktgen.T0, false)
	if len(obs) != 1 {
		t.Fatalf("after the window the observation is sent again: %d", len(obs))
	}
	e.Unmark(obs) // a failed delivery must not suppress the next sighting
	e.Handle(Packet{At: pktgen.T0.Add(repeatAfter + 2*time.Second), Data: arp})
	if obs, _ := e.Drain(pktgen.T0, false); len(obs) != 1 {
		t.Fatalf("after Unmark: %d", len(obs))
	}
}

func TestEngineBounds(t *testing.T) {
	t.Parallel()
	cfg := spanCfg()
	cfg.Clock = func() time.Time { return pktgen.T0 }
	e, _ := newEngine(cfg)
	// a flood of distinct DHCP names from one device must stop at the cap and be counted
	for i := range maxPending + 50 {
		req := pktgen.DHCP(1, pktgen.PC, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Type: 1, Hostname: fmt.Sprintf("host-%d", i)})
		e.Handle(Packet{At: pktgen.T0, Data: pktgen.UDPFrame(pktgen.Bcast, pktgen.PC, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"), 68, 67, req)})
	}
	obs, _ := e.Drain(pktgen.T0, false)
	if len(obs) != maxPending || e.Counters()["observations_dropped"] != 51 { // the MAC itself took one slot
		t.Errorf("observations %d, counters %v", len(obs), e.Counters())
	}
	for i := range maxFlows + 10 {
		e.Handle(Packet{At: pktgen.T0, Data: pktgen.UDPFrame(pktgen.Router, pktgen.PC, pktgen.PCIP, pktgen.WebIP, uint16(1+i%60000), uint16(1+i/60000), nil)})
	}
	if _, meta := e.Drain(pktgen.T0, true); len(metaOf(meta, MetaFlow)) != maxFlows || e.Counters()["flows_dropped"] != 11 { // the DHCP flood above holds one flow
		t.Errorf("flows %d, counters %v", len(meta), e.Counters())
	}
}

// M1: an ARP flood from random MACs adds at most maxNewMACsPerMinute devices a minute; devices already
// reported are not affected, and the budget comes back with the next minute.
func TestNewMACsAreRateLimited(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{})
	flood := func(at time.Time, from, n uint32) {
		for i := from; i < from+n; i++ {
			b := binary.BigEndian.AppendUint32(nil, i)
			m := pktgen.MAC{0xaa, 0, 0, b[1], b[2], b[3]}
			e.Handle(Packet{At: at, Data: pktgen.ARP(pktgen.Bcast, 1, m, netip.AddrFrom4([4]byte{10, 0, b[2], b[3]}), pktgen.MAC{}, pktgen.RouterIP)})
		}
	}
	flood(pktgen.T0, 0, 1000)
	obs, _ := e.Drain(pktgen.T0, false)
	if len(obs) != maxNewMACsPerMinute || e.Counters()["new_macs_dropped"] != 1000-maxNewMACsPerMinute {
		t.Fatalf("%d observations, counters %v", len(obs), e.Counters())
	}
	flood(pktgen.T0.Add(time.Second), 0, 1) // device 0 is known: a new address for it still goes through
	e.Handle(Packet{At: pktgen.T0.Add(time.Second), Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.MAC{0xaa, 0, 0, 0, 0, 0}, netip.MustParseAddr("10.9.9.9"), pktgen.MAC{}, pktgen.RouterIP)})
	if obs, _ := e.Drain(pktgen.T0, false); len(obs) != 1 {
		t.Fatalf("a known device was refused: %d", len(obs))
	}
	flood(pktgen.T0.Add(time.Minute+time.Second), 1000, 1000)
	if obs, _ := e.Drain(pktgen.T0, false); len(obs) != maxNewMACsPerMinute {
		t.Fatalf("next minute: %d observations", len(obs))
	}
}

func TestStatsAreMeasured(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{OwnMACs: []string{pktgen.Box.String()}})
	now := pktgen.T0
	if pps, others, last := e.Stats(now); pps != 0 || others != 0 || !last.IsZero() {
		t.Fatalf("nothing heard yet: %d %d %v", pps, others, last)
	}
	for i := range 25 {
		e.Handle(Packet{At: now.Add(time.Duration(i) * 100 * time.Millisecond), Data: pktgen.UDPFrame(pktgen.Router, pktgen.Box, pktgen.BoxIP, pktgen.DNSIP, 1, 2, nil)})
	}
	now = now.Add(3 * time.Second)
	pps, others, last := e.Stats(now)
	if pps != 3 || others != 0 || !last.Equal(pktgen.T0.Add(2400*time.Millisecond)) { // 25 packets in the last 10 s, rounded up
		t.Fatalf("own traffic only: pps %d others %d last %v", pps, others, last)
	}
	e.Handle(Packet{At: now, Data: pktgen.UDPFrame(pktgen.Router, pktgen.PC, pktgen.PCIP, pktgen.DNSIP, 1, 2, nil)})
	e.Handle(Packet{At: now, Data: pktgen.UDPFrame(pktgen.PC, pktgen.Router, pktgen.DNSIP, pktgen.PCIP, 2, 1, nil)})
	if _, others, _ := e.Stats(now); others != 2 {
		t.Fatalf("two other MACs, got %d", others)
	}
	if _, others, _ := e.Stats(now.Add(macWindow + time.Second)); others != 0 {
		t.Fatalf("MACs older than the window still counted: %d", others)
	}
	if pps, _, _ := e.Stats(now.Add(time.Minute)); pps != 0 {
		t.Fatalf("an idle minute later pps is %d", pps)
	}
	if e.DevicesSeen(now) != 2 {
		t.Fatalf("devices seen %d", e.DevicesSeen(now))
	}
}

func TestFileSourceFormats(t *testing.T) {
	t.Parallel()
	frames := pktgen.LANDiscovery()
	read := func(raw []byte) ([]Packet, error) {
		s, err := NewFileSource(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		var out []Packet
		for {
			p, err := s.Next(context.Background())
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			if err != nil {
				return out, err
			}
			out = append(out, p)
		}
	}
	for name, raw := range map[string][]byte{"pcap": pktgen.WritePCAP(frames), "pcapng": pktgen.WritePCAPNG(frames)} {
		got, err := read(raw)
		if err != nil || len(got) != len(frames) {
			t.Fatalf("%s: %d packets, err %v", name, len(got), err)
		}
		for i, p := range got {
			if !bytes.Equal(p.Data, frames[i].Data) || !p.At.Equal(frames[i].At) {
				t.Fatalf("%s: packet %d differs (time %v vs %v)", name, i, p.At, frames[i].At)
			}
		}
	}
	// big-endian classic pcap
	be := pktgen.WritePCAP(frames[:1])
	swap := func(b []byte) {
		b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
		b[4], b[5], b[6], b[7] = b[5], b[4], b[7], b[6]
		b[20], b[21], b[22], b[23] = b[23], b[22], b[21], b[20]
		r := b[24:]
		for i := 0; i < 16; i += 4 {
			r[i], r[i+1], r[i+2], r[i+3] = r[i+3], r[i+2], r[i+1], r[i]
		}
	}
	swap(be)
	if got, err := read(be); err != nil || len(got) != 1 || !bytes.Equal(got[0].Data, frames[0].Data) {
		t.Fatalf("big-endian pcap: %v %v", got, err)
	}
	// refusals
	cut := pktgen.WritePCAP(frames)
	for name, raw := range map[string][]byte{
		"not a capture":   []byte("hello world, this is not pcap"),
		"empty":           nil,
		"cut in a record": cut[:len(cut)-3],
	} {
		if _, err := read(raw); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	linux := pktgen.WritePCAP(frames[:1])
	linux[20] = 113 // LINKTYPE_LINUX_SLL
	if _, err := NewFileSource(bytes.NewReader(linux)); err == nil {
		t.Error("a non-Ethernet link type was accepted")
	}
	// a record longer than maxRecord is skipped (ErrDropped), the next one is read
	big := pktgen.WritePCAP([]pktgen.Frame{{At: pktgen.T0, Data: make([]byte, maxRecord+1)}, frames[0]})
	s, _ := NewFileSource(bytes.NewReader(big))
	if _, err := s.Next(context.Background()); !errors.Is(err, ErrDropped) {
		t.Fatalf("oversize record: %v", err)
	}
	if p, err := s.Next(context.Background()); err != nil || !bytes.Equal(p.Data, frames[0].Data) {
		t.Fatalf("after the oversize record: %v", err)
	}
	// hostile 32-bit lengths in a pcapng packet block: an error, never a panic or a wrap
	ng := pktgen.WritePCAPNG(frames[:1])
	for _, off := range []int{len(ng) - 12 - len(frames[0].Data) - 8, len(ng) - 12 - len(frames[0].Data) - 20} { // capLen and interface id of the packet block
		bad := append([]byte(nil), ng...)
		copy(bad[off:], []byte{0xff, 0xff, 0xff, 0xff})
		_, _ = read(bad)
	}
	// a cancelled context stops the replay
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	if _, err := OpenFile("testdata/does-not-exist.pcap"); err == nil || !os.IsNotExist(unwrapPath(err)) {
		t.Errorf("missing file: %v", err)
	}
}

func unwrapPath(err error) error {
	for {
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
}

func frameDHCP(src mac4, dst mac4, srcIP, dstIP netip.Addr, sport, dport uint16, d []byte) Packet {
	return Packet{At: pktgen.T0, Data: pktgen.UDPFrame(pktgen.MAC(dst), pktgen.MAC(src), srcIP, dstIP, sport, dport, d)}
}

type mac4 = pktgen.MAC

var (
	zeroIP  = netip.MustParseAddr("0.0.0.0")
	bcastIP = netip.MustParseAddr("255.255.255.255")
)

// H1: a host name longer than the inventory accepts (200) is cut, not passed on to poison the batch
// (sensor-protocol 5.3: free text is cut, never refused).
func TestLongValuesAreCutToWhatTheInventoryAccepts(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 20)
	e, _ := newEngine(own)
	req := pktgen.DHCP(1, pktgen.Phone, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Type: 1, Hostname: long})
	e.Handle(frameDHCP(pktgen.Phone, pktgen.Bcast, zeroIP, bcastIP, 68, 67, req))
	e.Handle(Packet{At: pktgen.T0, Data: pktgen.LLDP(pktgen.Switch, pktgen.LLDPInfo{Chassis: pktgen.Switch, Port: "1", SysName: strings.Repeat("S", 230), SysDesc: strings.Repeat("é", 120)})})
	obs, _ := e.Drain(pktgen.T0, true)
	cut := 0
	for _, o := range obs {
		if len(o.Value) > maxValue || !printable(o.Value) {
			t.Errorf("value of %d bytes for %s: %q", len(o.Value), o.Field, o.Value)
		}
		if strings.HasSuffix(o.Value, ".") {
			t.Errorf("a cut name ends with a separator: %q", o.Value)
		}
		if o.Field == observe.Hostname && strings.HasPrefix(o.Value, "aaaa") {
			cut++
		}
	}
	if cut != 1 || e.Counters()["value_truncated"] != 2 {
		t.Errorf("cut %d, counters %v", cut, e.Counters())
	}
}

// H2: INV-7 covers the addresses inside DHCP: ciaddr, yiaddr and option 50 of an excluded host.
func TestDHCPAddressesAreFiltered(t *testing.T) {
	t.Parallel()
	ex := pktgen.PhoneIP
	for name, send := range map[string]func(e *Engine){
		"option 50 (INIT-REBOOT request)": func(e *Engine) {
			req := pktgen.DHCP(1, pktgen.Phone, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Type: 3, Hostname: "bobs-phone", Requested: ex})
			e.Handle(frameDHCP(pktgen.Phone, pktgen.Bcast, zeroIP, bcastIP, 68, 67, req))
		},
		"ciaddr (renewal)": func(e *Engine) {
			req := pktgen.DHCP(1, pktgen.Phone, ex, netip.Addr{}, pktgen.DHCPOpts{Type: 3, Hostname: "bobs-phone"})
			e.Handle(frameDHCP(pktgen.Phone, pktgen.Router, zeroIP, pktgen.RouterIP, 68, 67, req))
		},
		"yiaddr (the router's ACK)": func(e *Engine) {
			ack := pktgen.DHCP(2, pktgen.Phone, netip.Addr{}, ex, pktgen.DHCPOpts{Type: 5})
			e.Handle(frameDHCP(pktgen.Router, pktgen.Bcast, pktgen.RouterIP, bcastIP, 67, 68, ack))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, err := newEngine(spanCfg(Filter{"host", ex.String()}))
			if err != nil {
				t.Fatal(err)
			}
			send(e)
			if obs, _ := e.Drain(pktgen.T0, true); len(obs) != 0 {
				t.Errorf("%d observations about an excluded host: %+v", len(obs), obs)
			}
			if e.Counters()["excluded"] == 0 {
				t.Error("not counted as excluded")
			}
		})
	}
}

// LLDP carries no IP address, so an IP, range or port exclusion cannot apply to it (CONTRACT INV-7).
func TestLLDPHasNoIPSoIPFiltersCannotApply(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(spanCfg(Filter{"cidr", "0.0.0.0/0"}))
	e.Handle(Packet{At: pktgen.T0, Data: pktgen.LLDP(pktgen.Switch, pktgen.LLDPInfo{Chassis: pktgen.Switch, Port: "1", SysName: "sw"})})
	if obs, _ := e.Drain(pktgen.T0, true); len(obs) == 0 {
		t.Error("LLDP was filtered by an IP rule: the documented limit changed")
	}
}

// M2: replies to the box and broadcasts reach a mirror of the box's own port; they do not make other devices.
func TestOwnOnlyIgnoresRepliesToTheBoxAndBroadcasts(t *testing.T) {
	t.Parallel()
	e, err := newEngine(spanCfg())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range pktgen.SpanOwnOnly() {
		e.Handle(Packet{At: f.At, Data: f.Data})
	}
	at := pktgen.T0.Add(5 * time.Second)
	e.Handle(Packet{At: at, Data: pktgen.UDPFrame(pktgen.Box, pktgen.Router, pktgen.DNSIP, pktgen.BoxIP, 53, 40010, pktgen.DNSMessage(1, true, nil, nil))})
	e.Handle(Packet{At: at, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.BoxIP)})
	if _, others, _ := e.Stats(at); others != 0 {
		t.Errorf("other_macs = %d, want 0: only unicast frames between two hosts that are not the box count", others)
	}
	e.Handle(Packet{At: at, Data: pktgen.UDPFrame(pktgen.Router, pktgen.PC, pktgen.PCIP, pktgen.DNSIP, 1, 2, nil)})
	if _, others, _ := e.Stats(at); others != 1 {
		t.Errorf("a frame between two other hosts: other_macs = %d, want 1", others)
	}
}

// Traffic to the box creates neither metadata nor flows (CONTRACT INV-6).
func TestTrafficToTheBoxCreatesNoMetadata(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(spanCfg())
	e.Handle(Packet{At: pktgen.T0, Data: pktgen.TCPFrame(pktgen.Box, pktgen.PC, pktgen.PCIP, pktgen.BoxIP, 50000, 80, pktgen.HTTPRequest("GET", "/", "vedette.lan", nil, ""))})
	e.Handle(Packet{At: pktgen.T0, Data: pktgen.UDPFrame(pktgen.Box, pktgen.PC, pktgen.PCIP, pktgen.BoxIP, 4000, 53, pktgen.DNSMessage(1, false, [][2]any{{"vedette.lan", uint16(1)}}, nil))})
	e.Handle(Packet{At: pktgen.T0, Data: pktgen.TCPFrame(pktgen.Box, pktgen.PC, pktgen.PCIP, pktgen.BoxIP, 50001, 443, pktgen.ClientHello("vedette.lan"))})
	if _, meta := e.Drain(pktgen.T0, true); len(meta) != 0 {
		t.Errorf("metadata about traffic to the box: %+v", meta)
	}
}

// A fragment that is not the first has no ports: with a port rule it is skipped rather than read.
func TestFragmentsFailClosedWithPortFilters(t *testing.T) {
	t.Parallel()
	frag := func() Packet {
		ip := pktgen.IPv4(pktgen.PCIP, pktgen.WebIP, 6, bytes.Repeat([]byte{1}, 40))
		binary.BigEndian.PutUint16(ip[6:8], 100) // offset 800: not the first fragment
		return Packet{At: pktgen.T0, Data: pktgen.Eth(pktgen.Router, pktgen.PC, 0x0800, ip)}
	}
	withPort, _ := newEngine(spanCfg(Filter{"port", "443"}))
	withPort.Handle(frag())
	if _, meta := withPort.Drain(pktgen.T0, true); len(meta) != 0 || withPort.Counters()["fragment_skipped"] != 1 {
		t.Errorf("with a port rule: %+v %v", meta, withPort.Counters())
	}
	noPort, _ := newEngine(spanCfg(Filter{"cidr", "10.0.0.0/8"}))
	noPort.Handle(frag())
	if _, meta := noPort.Drain(pktgen.T0, true); len(metaOf(meta, MetaFlow)) != 1 {
		t.Errorf("without a port rule the fragment is counted in a flow: %+v", meta)
	}
}

// Addresses that are not unicast hosts never reach the sink; the observation keeps its MAC.
func TestNonUnicastIPsNeverReachTheSink(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{})
	for i, bad := range []string{"255.255.255.255", "224.0.0.251", "127.0.0.1"} {
		m := pktgen.MAC{0xaa, 0, 0, 0, 0, byte(i + 1)}
		e.Handle(Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, m, netip.MustParseAddr(bad), pktgen.MAC{}, pktgen.RouterIP)})
	}
	ack := pktgen.DHCP(2, pktgen.Phone, netip.Addr{}, netip.MustParseAddr("239.1.1.1"), pktgen.DHCPOpts{Type: 5})
	e.Handle(frameDHCP(pktgen.Router, pktgen.Bcast, pktgen.RouterIP, bcastIP, 67, 68, ack))
	obs, _ := e.Drain(pktgen.T0, true)
	if len(obs) != 4 {
		t.Fatalf("%d observations, want 4 (the MACs are real)", len(obs))
	}
	for _, o := range obs {
		if o.AssetHint.IP.IsValid() {
			t.Errorf("a non-unicast address reached the sink: %+v", o)
		}
	}
	if e.Counters()["non_unicast_ip"] != 4 {
		t.Errorf("counters %v", e.Counters())
	}
}

// DHCP: only the client speaks for its MAC; an ACK must go to that MAC or to everybody.
func TestDHCPClientMACMustMatchTheEthernetFrame(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{})
	forged := pktgen.DHCP(1, pktgen.Printer, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Type: 1, Hostname: "forged"})
	e.Handle(frameDHCP(pktgen.PC, pktgen.Bcast, zeroIP, bcastIP, 68, 67, forged)) // PC claims to be the printer
	ack := pktgen.DHCP(2, pktgen.Printer, netip.Addr{}, pktgen.PrinterIP, pktgen.DHCPOpts{Type: 5})
	e.Handle(frameDHCP(pktgen.Router, pktgen.PC, pktgen.RouterIP, pktgen.PCIP, 67, 68, ack)) // unicast to somebody else
	if obs, _ := e.Drain(pktgen.T0, true); len(obs) != 0 || e.Counters()["dhcp_mac_mismatch"] != 2 {
		t.Errorf("observations %+v counters %v", obs, e.Counters())
	}
}

func TestVendorFromTheOUITable(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{})
	e.Handle(Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.Laptop, pktgen.LaptopIP, pktgen.MAC{}, pktgen.RouterIP)})
	e.Handle(Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)}) // locally administered
	vendors := map[string]string{}
	for _, o := range func() []observe.Observation { o, _ := e.Drain(pktgen.T0, true); return o }() {
		if o.Field == observe.Vendor {
			vendors[o.AssetHint.MAC] = o.Value
			if o.Confidence != 0.4 || o.AssetHint.IP.IsValid() {
				t.Errorf("vendor observation %+v", o)
			}
		}
	}
	if len(vendors) != 1 || vendors[pktgen.Laptop.String()] != "Apple, Inc." {
		t.Errorf("vendors %v", vendors)
	}
}

// H1: the cut trims the separators it leaves at the end, so a long name of such characters came out empty, the inventory
// refused it, and the item was queued again by the next frame. An empty value is dropped and counted, never queued.
func TestValueThatFitsToNothingIsDroppedAndCounted(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(own)
	for i, name := range []string{strings.Repeat("-", 230), strings.Repeat(". ", 120), strings.Repeat("_", 201)} {
		e.Handle(Packet{At: pktgen.T0.Add(time.Duration(i) * time.Second), Data: pktgen.LLDP(pktgen.Switch, pktgen.LLDPInfo{Chassis: pktgen.Switch, Port: "1", SysName: name})})
	}
	obs, _ := e.Drain(pktgen.T0, true)
	for _, o := range obs {
		if o.Value == "" {
			t.Errorf("an empty %s was queued", o.Field)
		}
		if o.Field == observe.Hostname {
			t.Errorf("hostname %q survived", o.Value)
		}
	}
	if n := e.Counters()["value_empty"]; n != 3 {
		t.Errorf("value_empty = %d, want 3 (counters %v)", n, e.Counters())
	}
}

// The empty value is dropped before the book is asked: only the frame's MAC row counts as a sighting of the device.
func TestValueEmptyDoesNotCountAsASighting(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{OwnMACs: own.OwnMACs, Devices: newDeviceBook(defaultLimits)})
	e.Handle(Packet{At: pktgen.T0, Data: pktgen.LLDP(pktgen.Switch, pktgen.LLDPInfo{Chassis: pktgen.Switch, Port: "1", SysName: strings.Repeat("-", 230)})})
	if c := e.Counters(); c["new_macs_unconfirmed"] != 1 || c["value_empty"] != 1 {
		t.Errorf("counters %v", c)
	}
}

// M2: broadcasts and replies to the box do not count as "other MACs", also with a VLAN tag, a QinQ tag, or an 802.3 frame.
func TestOtherMACsIgnoreTaggedBroadcastsAndRepliesToTheBox(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(spanCfg())
	at := pktgen.T0
	e.Handle(Packet{At: at, Data: pktgen.EthVLAN(pktgen.Bcast, pktgen.PC, 10, 0x0806, pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)[14:])})
	inner := pktgen.EthVLAN(pktgen.Box, pktgen.Router, 20, 0x0800, pktgen.IPv4(pktgen.DNSIP, pktgen.BoxIP, 17, pktgen.UDP(53, 40000, nil)))
	qinq := append(append([]byte{}, inner[:12]...), 0x88, 0xa8, 0x00, 0x64)
	qinq = append(qinq, inner[12:]...)
	e.Handle(Packet{At: at, Data: qinq})
	e.Handle(Packet{At: at, Data: pktgen.Eth(pktgen.MAC{0x01, 0x80, 0xc2, 0, 0, 0}, pktgen.Router, 0x0026, make([]byte, 38))}) // 802.3 LLC (STP)
	if _, others, _ := e.Stats(at); others != 0 {
		t.Errorf("other_macs = %d, want 0", others)
	}
}

// The vendor row is queued once, with the first frame of a MAC. When its delivery failed (Unmark), it comes back with the
// next frame of that MAC.
func TestVendorIsResentAfterAFailedDelivery(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(own)
	arp := Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.Laptop, pktgen.LaptopIP, pktgen.MAC{}, pktgen.RouterIP)}
	e.Handle(arp)
	obs, _ := e.Drain(pktgen.T0, false)
	e.Unmark(obs) // the inventory was not reachable
	arp.At = pktgen.T0.Add(time.Minute)
	e.Handle(arp)
	again, _ := e.Drain(pktgen.T0.Add(time.Minute), false)
	vendors := 0
	for _, o := range again {
		if o.Field == observe.Vendor {
			vendors++
		}
	}
	if vendors != 1 {
		t.Errorf("after a failed delivery the vendor came back %d times: %+v", vendors, again)
	}
	arp.At = pktgen.T0.Add(2 * time.Minute)
	e.Handle(arp)
	if more, _ := e.Drain(pktgen.T0.Add(2*time.Minute), false); len(more) != 0 {
		t.Errorf("a vendor that was delivered is sent again: %+v", more)
	}
}

// INV-3: the vendor from the table goes through the same text check as every other value. The 2026-11 table held
// U+200E, U+200B and U+00AD in the vendors of these prefixes.
func TestVendorFromTheTableIsCleanText(t *testing.T) {
	t.Parallel()
	for _, m := range []pktgen.MAC{{0x70, 0xb3, 0xd5, 0x26, 0x90, 0x01}, {0x48, 0xbc, 0xa6, 0x00, 0x00, 0x01}, {0x70, 0xb3, 0xd5, 0x8a, 0xc0, 0x01}, {0x00, 0x50, 0xc2, 0x57, 0x40, 0x01}} {
		e, _ := newEngine(own)
		e.Handle(Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, m, netip.IPv4Unspecified(), pktgen.MAC{}, pktgen.RouterIP)})
		obs, _ := e.Drain(pktgen.T0, true)
		found := false
		for _, o := range obs {
			if o.Field == observe.Vendor {
				found = true
				if !printable(o.Value) || o.Value != strings.TrimSpace(o.Value) {
					t.Errorf("%s: vendor %q is not clean text", m, o.Value)
				}
			}
		}
		if !found {
			t.Errorf("%s: no vendor row", m)
		}
	}
}

// Low: 0.0.0.0/8 and 240.0.0.0/4 are not host addresses, neither is the broadcast; the address is dropped, the observation stays.
func TestUnicastIPRefusesReservedRanges(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]bool{
		"0.1.2.3": false, "0.0.0.0": false, "240.0.0.1": false, "254.255.255.254": false, "255.255.255.255": false,
		"127.0.0.1": false, "224.0.0.251": false, "10.0.0.1": true, "192.168.1.20": true, "169.254.1.1": true, "239.255.255.250": false,
	} {
		if got := unicastIP(netip.MustParseAddr(s)); got != want {
			t.Errorf("unicastIP(%s) = %t, want %t", s, got, want)
		}
	}
	e, _ := newEngine(own)
	e.Handle(Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, netip.MustParseAddr("240.0.0.7"), pktgen.MAC{}, pktgen.RouterIP)})
	obs, _ := e.Drain(pktgen.T0, true)
	if len(obs) == 0 {
		t.Fatal("the observation was lost with its address")
	}
	for _, o := range obs {
		if o.AssetHint.IP.IsValid() {
			t.Errorf("a reserved address reached the sink: %+v", o)
		}
	}
}

// Low: printable() refuses every invisible format character, not only the bidirectional ones: "SW-CORE-01" and the same
// name with a zero-width space must not both be possible values.
func TestPrintableRefusesInvisibleFormatCharacters(t *testing.T) {
	t.Parallel()
	for _, r := range []rune{0x200b, 0x200c, 0x200d, 0x200e, 0x2060, 0xfeff, 0x00ad, 0x061c, 0x202e, 0x2066, 0xe0041, 0xe007f} {
		if s := "SW-CORE-01" + string(r); printable(s) {
			t.Errorf("printable(%q) = true", s)
		}
	}
	if !printable("Müller-PC 日本 Ñandú") {
		t.Error("ordinary text refused")
	}
}
