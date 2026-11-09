//go:build linux

package ops

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// packetARP is an AF_PACKET socket bound to one interface and to the ARP ethertype, so the kernel
// delivers nothing else (D-101). It is the only code that opens a raw socket in the host. It sends
// frames built by encodeARP and returns raw frames; it never interprets them.
type packetARP struct {
	mu     sync.Mutex
	fd     int
	closed bool
	index  int
	mac    [6]byte
}

// htons is the protocol number in the byte order the kernel expects in a sockaddr_ll.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func dialARP(iface string) (arpSocket, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("ops: interface %s: %w", iface, err)
	}
	if len(ifc.HardwareAddr) != 6 {
		return nil, fmt.Errorf("ops: interface %s has no Ethernet address", iface)
	}
	// Protocol 0: the socket receives nothing until bind sets the protocol and the card in one step, so no
	// frame of any other card (the SPAN card mirrors a whole network) is queued before it is bound.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("ops: open packet socket: %w", err)
	}
	s := &packetARP{fd: fd, index: ifc.Index}
	copy(s.mac[:], ifc.HardwareAddr)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: ifc.Index}); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("ops: bind packet socket to %s: %w", iface, err)
	}
	return s, nil
}

func (s *packetARP) MAC() [6]byte { return s.mac }

func (s *packetARP) Send(frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("socket closed")
	}
	return unix.Sendto(s.fd, frame, 0, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: s.index, Halen: 6, Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}})
}

func (s *packetARP) Recv(wait time.Duration) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("socket closed")
	}
	tv := unix.NsecToTimeval(wait.Nanoseconds())
	if err := unix.SetsockoptTimeval(s.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}
	buf := make([]byte, arpReadBuf) // a longer frame is cut by the kernel; arpFrameOf reads its first 42 bytes only
	n, from, err := unix.Recvfrom(s.fd, buf, 0)
	switch {
	case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
		return nil, errRecvTimeout
	case err != nil:
		return nil, err
	}
	ll, ok := from.(*unix.SockaddrLinklayer)
	if !ok || !arpFromCard(ll.Ifindex, s.index, ll.Pkttype == unix.PACKET_OUTGOING) {
		return nil, nil // our own frame looped back, or a frame of another card: ignored
	}
	return buf[:n], nil
}

func (s *packetARP) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return unix.Close(s.fd)
}
