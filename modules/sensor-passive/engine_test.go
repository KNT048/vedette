package sensorpassive

import (
	"bytes"
	"context"
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
	pc, router, printer, sw, phone := pktgen.PC.String(), pktgen.Router.String(), pktgen.Printer.String(), pktgen.Switch.String(), pktgen.Phone.String()
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
	// a flood of distinct ARP senders and distinct flows must stop at the caps and be counted
	for i := range maxPending + 50 {
		m := pktgen.MAC{0xaa, 0, 0, byte(i >> 16), byte(i >> 8), byte(i)}
		e.Handle(Packet{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, m, netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), pktgen.MAC{}, pktgen.RouterIP)})
	}
	obs, _ := e.Drain(pktgen.T0, false)
	if len(obs) != maxPending || e.Counters()["observations_dropped"] != 50 {
		t.Errorf("observations %d, counters %v", len(obs), e.Counters())
	}
	for i := range maxFlows + 10 {
		e.Handle(Packet{At: pktgen.T0, Data: pktgen.UDPFrame(pktgen.Router, pktgen.PC, pktgen.PCIP, pktgen.WebIP, uint16(1+i%60000), uint16(1+i/60000), nil)})
	}
	if _, meta := e.Drain(pktgen.T0, true); len(metaOf(meta, MetaFlow)) != maxFlows || e.Counters()["flows_dropped"] != 10 {
		t.Errorf("flows %d, counters %v", len(meta), e.Counters())
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
