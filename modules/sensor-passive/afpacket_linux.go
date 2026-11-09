//go:build linux

package sensorpassive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// ErrNoLiveCapture is returned by OpenLive where there is no AF_PACKET. On Linux it is never returned.
var ErrNoLiveCapture = errors.New("sensorpassive: live capture needs Linux (AF_PACKET); replay a recording instead")

// liveSource is a read-only AF_PACKET socket on one interface (INV-1, INV-2). Receiving needs only
// CAP_NET_RAW. The type has no write method and no code path in this file calls send, sendto, sendmsg or
// write on the descriptor; TestContract_INV1 checks both.
//
// Promiscuous mode is a receive filter of the card, not a transmission: a SPAN port delivers frames
// addressed to other hosts and the card drops them unless it is promiscuous.
type liveSource struct {
	fd  int
	buf []byte
}

// OpenLive opens a receive-only capture on the named interface (INV-1, INV-2). Verified by effect on the lab
// VM only (deferred): unit tests cannot open a raw socket without privileges and must not touch a real card.
func OpenLive(iface string) (Source, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("sensorpassive: interface %q: %w", iface, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("sensorpassive: open capture socket (needs CAP_NET_RAW): %w", err)
	}
	fail := func(what string, err error) (Source, error) {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("sensorpassive: %s on %q: %w", what, iface, err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		return fail("bind", err)
	}
	mreq := packetMreq{ifindex: int32(ifc.Index), typ: 1} // PACKET_MR_PROMISC
	if _, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), syscall.SOL_PACKET, syscall.PACKET_ADD_MEMBERSHIP,
		uintptr(unsafe.Pointer(&mreq)), unsafe.Sizeof(mreq), 0); e != 0 {
		return fail("promiscuous membership", e)
	}
	// Wake up every second so the loop can flush and see a stop request while the line is quiet.
	tv := syscall.NsecToTimeval(int64(time.Second))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fail("receive timeout", err)
	}
	return &liveSource{fd: fd, buf: make([]byte, 65536)}, nil
}

type packetMreq struct {
	ifindex int32
	typ     uint16
	alen    uint16
	addr    [8]byte
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Next implements Source.
func (s *liveSource) Next(ctx context.Context) (Packet, error) {
	if err := ctx.Err(); err != nil {
		return Packet{}, err
	}
	n, _, err := syscall.Recvfrom(s.fd, s.buf, 0)
	switch {
	case err == nil:
		return Packet{At: time.Now(), Data: append([]byte(nil), s.buf[:n]...)}, nil
	case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EINTR):
		return Packet{}, ErrIdle
	default:
		return Packet{}, fmt.Errorf("sensorpassive: receive: %w", err)
	}
}

// Close implements Source.
func (s *liveSource) Close() error { return syscall.Close(s.fd) }
