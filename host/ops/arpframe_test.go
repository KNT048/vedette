package ops

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
)

var (
	macA = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a}
	macB = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b}
)

func TestARPProbeFrameBytes(t *testing.T) {
	t.Parallel()
	f := probeFrame(macA, netip.MustParseAddr("192.168.10.250"))
	// dst broadcast, src macA, ARP, Ethernet/IPv4 6/4, request, sender macA 0.0.0.0, target 00:..:00 192.168.10.250
	const want = "ffffffffffff" + "02000000000a" + "0806" + "0001" + "0800" + "06" + "04" + "0001" +
		"02000000000a" + "00000000" + "000000000000" + "c0a80afa"
	if got := hex.EncodeToString(f); got != want {
		t.Fatalf("probe frame\n got %s\nwant %s", got, want)
	}
	if len(f) != 42 {
		t.Fatalf("length %d", len(f))
	}
}

func TestARPRequestFrameRoundTrip(t *testing.T) {
	t.Parallel()
	src, gw := netip.MustParseAddr("192.168.10.250"), netip.MustParseAddr("192.168.10.1")
	f := requestFrame(macA, src, gw)
	p, err := parseARP(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Op != arpOpRequest || p.SenderMAC != macA || p.SenderIP != src || p.TargetIP != gw || p.TargetMAC != [6]byte{} {
		t.Fatalf("%+v", p)
	}
	rep := encodeARP(macA, arpPacket{Op: arpOpReply, SenderMAC: macB, SenderIP: gw, TargetMAC: macA, TargetIP: src})
	q, err := parseARP(rep)
	if err != nil {
		t.Fatal(err)
	}
	if q.Op != arpOpReply || q.SenderMAC != macB || q.SenderIP != gw || q.TargetMAC != macA || q.TargetIP != src {
		t.Fatalf("%+v", q)
	}
	pr, err := parseARP(probeFrame(macA, gw))
	if err != nil || pr.SenderIP != netip.IPv4Unspecified() {
		t.Fatalf("probe: %+v %v", pr, err)
	}
}

func TestParseARPRefusesEveryOtherShape(t *testing.T) {
	t.Parallel()
	good := requestFrame(macA, netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1"))
	mut := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(good)) }
	cases := map[string][]byte{
		"empty":         nil,
		"41 bytes":      good[:41],
		"43 bytes":      append(bytes.Clone(good), 0),
		"60 bytes":      append(bytes.Clone(good), make([]byte, 18)...),
		"ethertype ip":  mut(func(b []byte) []byte { b[12], b[13] = 0x08, 0x00; return b }),
		"vlan tag":      mut(func(b []byte) []byte { b[12], b[13] = 0x81, 0x00; return b }),
		"hw type 6":     mut(func(b []byte) []byte { b[15] = 6; return b }),
		"proto ipv6":    mut(func(b []byte) []byte { b[16], b[17] = 0x86, 0xdd; return b }),
		"hw len 8":      mut(func(b []byte) []byte { b[18] = 8; return b }),
		"proto len 16":  mut(func(b []byte) []byte { b[19] = 16; return b }),
		"opcode 0":      mut(func(b []byte) []byte { b[21] = 0; return b }),
		"opcode 3":      mut(func(b []byte) []byte { b[21] = 3; return b }),
		"opcode 0x0101": mut(func(b []byte) []byte { b[20] = 1; return b }),
	}
	for name, b := range cases {
		if p, err := parseARP(b); err == nil {
			t.Errorf("%s: parsed as %+v", name, p)
		}
	}
}

func TestARPFrameOfAcceptsWirePadding(t *testing.T) {
	t.Parallel()
	good := requestFrame(macA, netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1"))
	padded := append(bytes.Clone(good), bytes.Repeat([]byte{0xAA}, 18)...) // 60 bytes: the Ethernet minimum, padding with leaked bytes
	f, ok := arpFrameOf(padded)
	if !ok || !bytes.Equal(f, good) {
		t.Fatalf("a padded frame was not cut to the 42 bytes: %v %x", ok, f)
	}
	for _, n := range []int{0, 1, 41, 61, 100, 1500} {
		if _, ok := arpFrameOf(make([]byte, n)); ok {
			t.Errorf("a %d-byte frame was accepted", n)
		}
	}
	if f, ok := arpFrameOf(good); !ok || len(f) != 42 {
		t.Error("an exact 42-byte frame was refused")
	}
}

func FuzzParseARP(f *testing.F) {
	f.Add(probeFrame(macA, netip.MustParseAddr("10.0.0.1")))
	f.Add(requestFrame(macA, netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")))
	f.Add(encodeARP(macA, arpPacket{Op: arpOpReply, SenderMAC: macB, SenderIP: netip.MustParseAddr("10.0.0.1"), TargetMAC: macA, TargetIP: netip.MustParseAddr("10.0.0.2")}))
	f.Add([]byte{})
	f.Add(make([]byte, 60))
	f.Fuzz(func(t *testing.T, b []byte) {
		if fr, ok := arpFrameOf(b); ok && len(fr) != arpFrameLen {
			t.Fatalf("arpFrameOf returned %d bytes", len(fr))
		}
		p, err := parseARP(b)
		if err != nil {
			return
		}
		// Accepted: the input was exactly 42 bytes, the packet is one of the two opcodes, and re-encoding it with the
		// frame's own Ethernet destination gives the same bytes back except where the Ethernet source differs from the ARP sender.
		if len(b) != arpFrameLen || (p.Op != arpOpRequest && p.Op != arpOpReply) || !p.SenderIP.Is4() || !p.TargetIP.Is4() {
			t.Fatalf("accepted %x as %+v", b, p)
		}
		var dst [6]byte
		copy(dst[:], b[0:6])
		again := encodeARP(dst, p)
		again2 := bytes.Clone(again)
		copy(again2[6:12], b[6:12])
		if !bytes.Equal(again2, b) {
			t.Fatalf("round trip differs:\n in  %x\n out %x", b, again2)
		}
	})
}
