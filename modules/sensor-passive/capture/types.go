// Package capture is the capture half of the passive discovery module: the part that runs in the sensor container
// (vedette-sensor passive). It reads frames from a receive-only Source, turns them into observations with fail-closed parsers,
// and reports them to core over the sensor link (Link). It never sends a frame (INV-1) and holds no database: core decides what
// is kept.
package capture

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// Packet is one captured Ethernet frame. Data is owned by the receiver of Next.
type Packet struct {
	At   time.Time
	Data []byte
}

// ErrIdle is returned by Source.Next when nothing arrived for about a second and ctx is still alive; it
// lets the capture loop flush and notice a stop request while the line is quiet.
var ErrIdle = errors.New("capture: no packet yet")

// ErrDropped is returned by Source.Next for a record that cannot be a usable frame (too large, wrong link
// type); the loop counts it and asks for the next one.
var ErrDropped = errors.New("capture: unusable record")

// Source is where frames come from. It has no way to write to the network and must never get one (INV-1,
// FORBID-1): there is no Write, Send or Inject method on any implementation, and TestContract_INV1 fails if
// one appears. Next returns io.EOF at the end of a recording; a live source never ends.
type Source interface {
	Next(ctx context.Context) (Packet, error)
	Close() error
}

// Extract says which SPAN metadata is read (D-56). Discovery (ARP, DHCP, mDNS, SSDP, LLDP) does not depend on it.
type Extract struct {
	DNS      bool
	TLSSNI   bool
	HTTPHost bool
	Flows    bool
}

// Filter is one exclusion rule (D-56, INV-7): Type is "cidr", "host" or "port".
type Filter struct {
	Type  string
	Value string
}

// Settings is what to listen on and what to read, as core decided (the config of the sensor protocol, sensor-protocol.md 6.1).
type Settings struct {
	Interface string // "" = not configured: the capture idles
	Span      bool   // the interface is a SPAN/TAP port: metadata is extracted, the card has no IP
	Extract   Extract
	Filters   []Filter
}

// Interface is a network card of the machine the capture runs on, as that machine sees it. Its MAC and addresses are "the
// box itself" (INV-6), and the list goes to core in every heartbeat (sensor-protocol.md 6.3).
type Interface struct {
	Name      string
	MAC       string // aa:bb:cc:dd:ee:ff
	Link      bool
	Addresses []netip.Prefix // IPv4 only; the prefix is what the heartbeat reports
}

// MetaKind names the kind of a SPAN metadata item.
type MetaKind string

// The four kinds of SPAN metadata (D-43). There is no other.
const (
	MetaDNS  MetaKind = "dns"  // a DNS query name
	MetaSNI  MetaKind = "sni"  // the server name of a TLS ClientHello
	MetaHTTP MetaKind = "http" // the Host header of an HTTP request
	MetaFlow MetaKind = "flow" // an IPv4 5-tuple with counters
)

// MetaItem is one piece of SPAN metadata. It is a closed type on purpose: these are the only fields that
// ever leave a packet (INV-3, FORBID-2), so a payload byte has nowhere to go. Which fields are set depends
// on Kind: DNS: Name, QType; SNI and HTTP: Name; Flow: Proto, SrcPort, DstPort, Packets, Bytes, First.
type MetaItem struct {
	Kind    MetaKind
	At      time.Time // when it was seen (flows: the last packet)
	SrcMAC  string
	SrcIP   netip.Addr
	DstIP   netip.Addr
	Name    string // DNS, SNI, HTTP
	QType   uint16 // DNS
	Proto   uint8  // flow: 6 TCP, 17 UDP, other IP protocols as is
	SrcPort uint16 // flow
	DstPort uint16 // flow
	Packets uint64 // flow
	Bytes   uint64 // flow
	First   time.Time
}

// MetadataSink receives SPAN metadata in batches, in order. The `logs` module will implement it (S-LOG-4); on the wire
// there is no metadata until then (D-112 (7)), so the sensor binary leaves it nil and the default drops everything.
type MetadataSink interface {
	Metadata(ctx context.Context, seq uint64, items []MetaItem) error
}

// NoMetadata is the default MetadataSink.
type NoMetadata struct{}

// Metadata implements MetadataSink.
func (NoMetadata) Metadata(context.Context, uint64, []MetaItem) error { return nil }
