package ops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// The ARP checks of net.apply (D-101): is a new static address already taken, and does the gateway
// answer from the new address. The logic is here and runs over arpSocket; arp_linux.go opens the
// real socket. Tests never open one.

// ErrARPUnsupported is what the real socket says on a system that is not Linux.
var ErrARPUnsupported = errors.New("ops: ARP checks need Linux")

// ErrGatewaySilent means the gateway did not answer in the time given.
var ErrGatewaySilent = errors.New("ops: the gateway did not answer ARP")

// ProbeResult is the answer of Probe: Conflict when another host uses the address, with its MAC.
type ProbeResult struct {
	Conflict bool
	MAC      string
}

// Prober is the seam of Deps.Probe: the two ARP checks. The real one sends and reads 42-byte ARP
// frames on a packet socket; tests give a fake and never touch a socket.
type Prober interface {
	// Probe tests whether ip is in use on iface (RFC 5227: three probes one second apart, then two
	// seconds of listening). The caller must not hold the address on iface yet.
	Probe(ctx context.Context, iface string, ip netip.Addr) (ProbeResult, error)
	// GatewayCheck asks gw from src every second for up to 15 seconds; nil when it answers,
	// ErrGatewaySilent when it does not.
	GatewayCheck(ctx context.Context, iface string, src, gw netip.Addr) error
}

// arpSocket is one open packet socket on one interface. Recv waits at most wait for one frame
// and returns errRecvTimeout when nothing came (a nil frame with a nil error means "ignore this
// one", for example a frame the host itself sent). Close is safe to call twice.
type arpSocket interface {
	Send(frame []byte) error
	Recv(wait time.Duration) ([]byte, error)
	MAC() [6]byte
	Close() error
}

var errRecvTimeout = errors.New("ops: arp receive timeout")

// arpFromCard reports whether a frame read from a packet socket belongs to the card the socket is
// for: not one the host sent itself (looped back by the packet socket) and received on that card's
// index. The socket is bound to one card, but this is checked again for every frame.
func arpFromCard(gotIndex, wantIndex int, outgoing bool) bool {
	return !outgoing && gotIndex == wantIndex
}

// recvSlice bounds one blocking read, so a cancelled context is noticed within this time.
const recvSlice = 250 * time.Millisecond

type arpProber struct {
	dial    func(iface string) (arpSocket, error)
	probes  int
	gap     time.Duration // between probes
	wait    time.Duration // after the last probe
	gwEvery time.Duration
	gwTotal time.Duration
}

// newARPProber is the production prober: the timings of RFC 5227 as D-101 fixes them, on the real socket.
func newARPProber() *arpProber {
	return &arpProber{dial: dialARP, probes: 3, gap: time.Second, wait: 2 * time.Second, gwEvery: time.Second, gwTotal: 15 * time.Second}
}

// listen reads frames for up to d and reports the first one that match accepts. Frames that do not
// parse are ignored; a closed context ends the wait with its error.
func (p *arpProber) listen(ctx context.Context, s arpSocket, d time.Duration, match func(arpPacket) bool) (arpPacket, bool, error) {
	end := time.Now().Add(d)
	for {
		if err := ctx.Err(); err != nil {
			return arpPacket{}, false, err
		}
		left := time.Until(end)
		if left <= 0 {
			return arpPacket{}, false, nil
		}
		raw, err := s.Recv(min(left, recvSlice))
		if errors.Is(err, errRecvTimeout) {
			continue
		}
		if err != nil {
			return arpPacket{}, false, fmt.Errorf("ops: read ARP: %w", err)
		}
		frame, ok := arpFrameOf(raw)
		if !ok {
			continue
		}
		pk, err := parseARP(frame)
		if err != nil {
			continue
		}
		if match(pk) {
			return pk, true, nil
		}
	}
}

func (p *arpProber) open(iface string) (arpSocket, error) {
	if !validIfaceName(iface) {
		return nil, errors.New("ops: not a valid interface name")
	}
	return p.dial(iface)
}

// probeConflict is the RFC 5227 test of one frame during our probe: another host (not our MAC)
// that uses the address as its sender IP, or that is itself probing it (sender 0.0.0.0, a request
// whose target is the address, section 2.1.1).
func probeConflict(k arpPacket, mine [6]byte, ip netip.Addr) bool {
	if k.SenderMAC == mine {
		return false
	}
	return k.SenderIP == ip || (k.Op == arpOpRequest && k.SenderIP.IsUnspecified() && k.TargetIP == ip)
}

// Probe implements Prober. Any ARP frame whose sender IP is the probed address, or a probe of the
// same address, from a MAC other than the box's own, is a conflict.
func (p *arpProber) Probe(ctx context.Context, iface string, ip netip.Addr) (ProbeResult, error) {
	if !ip.Is4() {
		return ProbeResult{}, errors.New("ops: only IPv4 addresses are probed")
	}
	s, err := p.open(iface)
	if err != nil {
		return ProbeResult{}, err
	}
	defer func() { _ = s.Close() }()
	mac := s.MAC()
	frame := probeFrame(mac, ip)
	for i := range p.probes {
		if err := ctx.Err(); err != nil {
			return ProbeResult{}, err
		}
		if err := s.Send(frame); err != nil {
			return ProbeResult{}, fmt.Errorf("ops: send ARP probe: %w", err)
		}
		wait := p.gap
		if i == p.probes-1 {
			wait = p.wait
		}
		pk, hit, err := p.listen(ctx, s, wait, func(k arpPacket) bool { return probeConflict(k, mac, ip) })
		if err != nil {
			return ProbeResult{}, err
		}
		if hit {
			return ProbeResult{Conflict: true, MAC: net.HardwareAddr(pk.SenderMAC[:]).String()}, nil
		}
	}
	return ProbeResult{}, nil
}

// GatewayCheck implements Prober: only an ARP reply from the gateway's address, addressed to our
// source address and not from the box's own MAC, answers. A request or an announcement from the
// gateway, or a reply meant for another host, proves nothing about our own path.
func (p *arpProber) GatewayCheck(ctx context.Context, iface string, src, gw netip.Addr) error {
	if !src.Is4() || !gw.Is4() {
		return errors.New("ops: the gateway check is IPv4 only")
	}
	s, err := p.open(iface)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	mac := s.MAC()
	frame := requestFrame(mac, src, gw)
	end := time.Now().Add(p.gwTotal)
	for time.Now().Before(end) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.Send(frame); err != nil {
			return fmt.Errorf("ops: send ARP request: %w", err)
		}
		_, hit, err := p.listen(ctx, s, min(p.gwEvery, time.Until(end)), func(k arpPacket) bool {
			return k.Op == arpOpReply && k.SenderIP == gw && k.TargetIP == src && k.SenderMAC != mac
		})
		if err != nil {
			return err
		}
		if hit {
			return nil
		}
	}
	return ErrGatewaySilent
}
