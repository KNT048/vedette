package ops

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeSock is a packet socket under the test's control: a script of what Recv returns, and a record of what was sent.
type fakeSock struct {
	mu       sync.Mutex
	mac      [6]byte
	sent     [][]byte
	inbox    [][]byte // returned one per Recv; when empty Recv waits (shortened) and times out
	closed   int
	sendErr  error
	recvErr  error
	onSend   func(frame []byte) // may push a reply into the inbox
	timeouts int
}

func (s *fakeSock) MAC() [6]byte { return s.mac }
func (s *fakeSock) Send(f []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, append([]byte(nil), f...))
	if s.onSend != nil {
		s.onSend(f)
	}
	return nil
}

func (s *fakeSock) Recv(wait time.Duration) ([]byte, error) {
	s.mu.Lock()
	if s.recvErr != nil {
		defer s.mu.Unlock()
		return nil, s.recvErr
	}
	if len(s.inbox) > 0 {
		f := s.inbox[0]
		s.inbox = s.inbox[1:]
		s.mu.Unlock()
		return f, nil
	}
	s.timeouts++
	s.mu.Unlock()
	tm := time.NewTimer(min(wait, 2*time.Millisecond))
	<-tm.C
	return nil, errRecvTimeout
}

func (s *fakeSock) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	return nil
}

func (s *fakeSock) push(f []byte) { s.mu.Lock(); s.inbox = append(s.inbox, f); s.mu.Unlock() }

func fastProber(s *fakeSock) *arpProber {
	return &arpProber{
		dial:   func(string) (arpSocket, error) { return s, nil },
		probes: 3, gap: 20 * time.Millisecond, wait: 40 * time.Millisecond, gwEvery: 20 * time.Millisecond, gwTotal: 100 * time.Millisecond,
	}
}

var (
	probed = netip.MustParseAddr("192.168.10.250")
	gwIP   = netip.MustParseAddr("192.168.10.1")
)

func reply(sender [6]byte, ip, target netip.Addr) []byte {
	return encodeARP(macA, arpPacket{Op: arpOpReply, SenderMAC: sender, SenderIP: ip, TargetMAC: macA, TargetIP: target})
}

func TestProbeNoConflictSendsThreeProbesAndListensTwoSeconds(t *testing.T) {
	t.Parallel()
	s := &fakeSock{mac: macA}
	start := time.Now()
	res, err := fastProber(s).Probe(context.Background(), "eth0", probed)
	if err != nil || res.Conflict {
		t.Fatalf("%+v %v", res, err)
	}
	if len(s.sent) != 3 {
		t.Fatalf("sent %d probes", len(s.sent))
	}
	for _, f := range s.sent {
		p, err := parseARP(f)
		if err != nil || p.Op != arpOpRequest || p.SenderIP != netip.IPv4Unspecified() || p.TargetIP != probed || p.SenderMAC != macA {
			t.Fatalf("not an RFC 5227 probe: %+v %v", p, err)
		}
	}
	if d := time.Since(start); d < 2*20*time.Millisecond+40*time.Millisecond {
		t.Fatalf("probing took %v: the gaps and the final wait were not observed", d)
	}
	if s.closed != 1 {
		t.Fatalf("closed %d times", s.closed)
	}
}

func TestProbeConflictOnAnyARPFromTheAddress(t *testing.T) {
	t.Parallel()
	cases := map[string][]byte{
		"reply from the address":   reply(macB, probed, gwIP),
		"request from the address": encodeARP(macB, arpPacket{Op: arpOpRequest, SenderMAC: macB, SenderIP: probed, TargetIP: gwIP}),
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := &fakeSock{mac: macA}
			s.push(f)
			res, err := fastProber(s).Probe(context.Background(), "eth0", probed)
			if err != nil || !res.Conflict || res.MAC != "02:00:00:00:00:0b" {
				t.Fatalf("%+v %v", res, err)
			}
			if s.closed != 1 {
				t.Fatalf("closed %d", s.closed)
			}
		})
	}
}

func TestProbeIgnoresOurOwnMACAndOtherHostsAndGarbage(t *testing.T) {
	t.Parallel()
	s := &fakeSock{mac: macA}
	s.push(reply(macA, probed, gwIP)) // our own frame looped back
	s.push(reply(macB, gwIP, probed)) // another host, another address
	s.push([]byte{1, 2, 3})           // junk
	s.push(nil)                       // a frame the socket said to ignore
	res, err := fastProber(s).Probe(context.Background(), "eth0", probed)
	if err != nil || res.Conflict {
		t.Fatalf("%+v %v", res, err)
	}
}

// A conflicting host whose card delivers a longer frame (FCS kept, a trailer) is still seen: refusing long frames
// would make the probe say "free" for an address in use.
func TestProbeSeesAConflictInALongerFrame(t *testing.T) {
	t.Parallel()
	for _, extra := range []int{22, 100, 1000} {
		s := &fakeSock{mac: macA}
		s.push(append(reply(macB, probed, gwIP), make([]byte, extra)...))
		res, err := fastProber(s).Probe(context.Background(), "eth0", probed)
		if err != nil || !res.Conflict {
			t.Fatalf("a %d-byte ARP reply from the probed address was ignored: %+v %v", 42+extra, res, err)
		}
	}
}

// RFC 5227 2.1.1: another host probing the same address during our probe is a conflict too.
func TestProbeConflictWhenAnotherHostProbesTheSameAddress(t *testing.T) {
	t.Parallel()
	s := &fakeSock{mac: macA}
	s.push(probeFrame(macB, probed))
	res, err := fastProber(s).Probe(context.Background(), "eth0", probed)
	if err != nil || !res.Conflict || res.MAC != "02:00:00:00:00:0b" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestProbeConflictDecision(t *testing.T) {
	t.Parallel()
	other := netip.MustParseAddr("192.168.10.77")
	cases := []struct {
		name string
		k    arpPacket
		want bool
	}{
		{"reply from the address", arpPacket{Op: arpOpReply, SenderMAC: macB, SenderIP: probed, TargetIP: other}, true},
		{"request from the address", arpPacket{Op: arpOpRequest, SenderMAC: macB, SenderIP: probed, TargetIP: other}, true},
		{"another host probes the address", arpPacket{Op: arpOpRequest, SenderMAC: macB, SenderIP: netip.IPv4Unspecified(), TargetIP: probed}, true},
		{"our own probe looped back", arpPacket{Op: arpOpRequest, SenderMAC: macA, SenderIP: netip.IPv4Unspecified(), TargetIP: probed}, false},
		{"another host probes another address", arpPacket{Op: arpOpRequest, SenderMAC: macB, SenderIP: netip.IPv4Unspecified(), TargetIP: other}, false},
		{"a reply to a 0.0.0.0 probe is not a probe", arpPacket{Op: arpOpReply, SenderMAC: macB, SenderIP: netip.IPv4Unspecified(), TargetIP: probed}, false},
		{"another address talking", arpPacket{Op: arpOpRequest, SenderMAC: macB, SenderIP: other, TargetIP: probed}, false},
	}
	for _, c := range cases {
		if got := probeConflict(c.k, macA, probed); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// Only a reply from the gateway's address, addressed to our source address, answers the gateway check.
func TestGatewayCheckAcceptsOnlyAReplyToUs(t *testing.T) {
	t.Parallel()
	other := netip.MustParseAddr("192.168.10.77")
	for name, f := range map[string][]byte{
		"the gateway's own request":     encodeARP(macB, arpPacket{Op: arpOpRequest, SenderMAC: macB, SenderIP: gwIP, TargetIP: other}),
		"the gateway's reply to a peer": reply(macB, gwIP, other),
		"a gratuitous request":          encodeARP(macB, arpPacket{Op: arpOpRequest, SenderMAC: macB, SenderIP: gwIP, TargetIP: gwIP}),
		"a reply from our own MAC":      reply(macA, gwIP, probed),
		"a reply from another address":  reply(macB, other, probed),
	} {
		s := &fakeSock{mac: macA}
		s.push(f)
		if err := fastProber(s).GatewayCheck(context.Background(), "eth0", probed, gwIP); !errors.Is(err, ErrGatewaySilent) {
			t.Errorf("%s answered the gateway check: %v", name, err)
		}
	}
	s := &fakeSock{mac: macA}
	s.push(reply(macB, gwIP, probed))
	if err := fastProber(s).GatewayCheck(context.Background(), "eth0", probed, gwIP); err != nil {
		t.Fatalf("the gateway's reply to us was refused: %v", err)
	}
}

// The socket is bound to one card; a frame that arrives on another card's index, or one we sent, is dropped.
func TestARPFromCard(t *testing.T) {
	t.Parallel()
	if !arpFromCard(3, 3, false) {
		t.Error("a frame of our card was dropped")
	}
	if arpFromCard(4, 3, false) {
		t.Error("a frame of another card (the SPAN mirror) was kept")
	}
	if arpFromCard(3, 3, true) {
		t.Error("our own outgoing frame was kept")
	}
}

func TestProbeAcceptsAPaddedReply(t *testing.T) {
	t.Parallel()
	s := &fakeSock{mac: macA}
	s.push(append(reply(macB, probed, gwIP), make([]byte, 18)...))
	res, err := fastProber(s).Probe(context.Background(), "eth0", probed)
	if err != nil || !res.Conflict {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestProbeContextCancelStopsAndCloses(t *testing.T) {
	t.Parallel()
	s := &fakeSock{mac: macA}
	p := fastProber(s)
	p.gap, p.wait = time.Hour, time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)
	start := time.Now()
	_, err := p.Probe(ctx, "eth0", probed)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 2*time.Second || s.closed != 1 {
		t.Fatalf("took %v, closed %d", time.Since(start), s.closed)
	}
	// Already cancelled before the first probe: nothing is sent.
	s2 := &fakeSock{mac: macA}
	if _, err := fastProber(s2).Probe(ctx, "eth0", probed); !errors.Is(err, context.Canceled) || len(s2.sent) != 0 || s2.closed != 1 {
		t.Fatalf("pre-cancelled: err %v sent %d closed %d", err, len(s2.sent), s2.closed)
	}
}

func TestProbeClosesTheSocketOnEveryErrorPath(t *testing.T) {
	t.Parallel()
	for name, mk := range map[string]func() *fakeSock{
		"send error":    func() *fakeSock { return &fakeSock{mac: macA, sendErr: errors.New("boom")} },
		"receive error": func() *fakeSock { return &fakeSock{mac: macA, recvErr: errors.New("boom")} },
	} {
		s := mk()
		if _, err := fastProber(s).Probe(context.Background(), "eth0", probed); err == nil || s.closed != 1 {
			t.Errorf("%s: err %v closed %d", name, err, s.closed)
		}
		s = mk()
		if err := fastProber(s).GatewayCheck(context.Background(), "eth0", probed, gwIP); err == nil || s.closed != 1 {
			t.Errorf("gateway, %s: err %v closed %d", name, err, s.closed)
		}
	}
}

func TestProbeRefusesBadInputBeforeOpeningASocket(t *testing.T) {
	t.Parallel()
	opened := 0
	p := &arpProber{dial: func(string) (arpSocket, error) { opened++; return &fakeSock{}, nil }, probes: 3}
	for _, iface := range []string{"", "-x", "a b", "eth0\n", "a/b", "abcdefghijklmnop"} {
		if _, err := p.Probe(context.Background(), iface, probed); err == nil {
			t.Errorf("interface %q was accepted", iface)
		}
	}
	if _, err := p.Probe(context.Background(), "eth0", netip.MustParseAddr("fd00::1")); err == nil {
		t.Error("an IPv6 address was probed")
	}
	if err := p.GatewayCheck(context.Background(), "eth0", probed, netip.MustParseAddr("fd00::1")); err == nil {
		t.Error("an IPv6 gateway was checked")
	}
	if opened != 0 {
		t.Fatalf("%d sockets opened for bad input", opened)
	}
	p.dial = func(string) (arpSocket, error) { return nil, errors.New("no socket") }
	if _, err := p.Probe(context.Background(), "eth0", probed); err == nil {
		t.Error("a dial error was swallowed")
	}
}

func TestGatewayCheckAnswersAfterRetries(t *testing.T) {
	t.Parallel()
	s := &fakeSock{mac: macA}
	// The third request is answered.
	s.onSend = func([]byte) {
		if len(s.sent) == 3 {
			s.inbox = append(s.inbox, reply(macB, gwIP, probed))
		}
	}
	if err := fastProber(s).GatewayCheck(context.Background(), "eth0", probed, gwIP); err != nil {
		t.Fatal(err)
	}
	if len(s.sent) != 3 || s.closed != 1 {
		t.Fatalf("sent %d, closed %d", len(s.sent), s.closed)
	}
	p, err := parseARP(s.sent[0])
	if err != nil || p.Op != arpOpRequest || p.SenderIP != probed || p.TargetIP != gwIP || p.SenderMAC != macA {
		t.Fatalf("not a request from the new address: %+v %v", p, err)
	}
}

func TestGatewayCheckTimesOutAndIgnoresOurOwnFrames(t *testing.T) {
	t.Parallel()
	s := &fakeSock{mac: macA}
	s.push(reply(macA, gwIP, probed)) // our MAC claiming the gateway's address
	s.push(reply(macB, probed, gwIP)) // someone else
	start := time.Now()
	err := fastProber(s).GatewayCheck(context.Background(), "eth0", probed, gwIP)
	if !errors.Is(err, ErrGatewaySilent) {
		t.Fatalf("err = %v", err)
	}
	if n := len(s.sent); n < 3 || n > 6 {
		t.Fatalf("%d requests in a window of 5 retry intervals", n)
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
	if s.closed != 1 {
		t.Fatalf("closed %d", s.closed)
	}
}

func TestGatewayCheckContextCancel(t *testing.T) {
	t.Parallel()
	s := &fakeSock{mac: macA}
	p := fastProber(s)
	p.gwTotal, p.gwEvery = time.Hour, time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := p.GatewayCheck(ctx, "eth0", probed, gwIP); !errors.Is(err, context.DeadlineExceeded) || s.closed != 1 {
		t.Fatalf("err %v closed %d", err, s.closed)
	}
}

func TestRealTimingsAreTheOnesOfD101(t *testing.T) {
	t.Parallel()
	p := newARPProber()
	if p.probes != 3 || p.gap != time.Second || p.wait != 2*time.Second || p.gwEvery != time.Second || p.gwTotal != 15*time.Second {
		t.Fatalf("%+v", p)
	}
}
