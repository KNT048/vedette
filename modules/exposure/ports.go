package exposure

import (
	"context"
	"net/netip"

	"github.com/knt048/vedette/core/events"
)

// Event names published by this module (CONTRACT, Events).
const (
	EventSnapshotCreated = "exposure.snapshot.created"
	EventTargetVerified  = "exposure.target.verified"
)

// SnapshotCreatedEvent is the payload of exposure.snapshot.created.
type SnapshotCreatedEvent struct {
	TargetID string `json:"target_id"`
	Date     string `json:"date"`
	Counts   Counts `json:"counts"`
}

// TargetVerifiedEvent is the payload of exposure.target.verified: a domain proved, an IP found for the
// first time, or an IP that had expired and was seen again.
type TargetVerifiedEvent struct {
	TargetID string `json:"target_id"`
}

// Publisher is the event bus as this module needs it; *events.Bus satisfies it. Events go out after
// the transaction commits and a failed publish is logged, never rolled back into the change.
type Publisher interface {
	Publish(ctx context.Context, e events.Event) error
}

// Resolver looks up TXT records; *net.Resolver satisfies it. Tests pass a fake: no test asks real DNS.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// EgressProber asks the three public "what is my IP" services once each (one round, D-81) and returns the
// address that at least two of them agree on, or ErrNoAgreement or ErrServicesDown. The answers are untrusted;
// the implementation parses them with net/netip. PublicServiceProber is the real one.
type EgressProber interface {
	Round(ctx context.Context) (netip.Addr, error)
}

// ScanTarget is what the scan module is told about the target it scans. User is who asked: the actor of the checks the runner
// makes through ScannableIP.
type ScanTarget struct {
	ID    string
	Kind  Kind
	Value string
	User  string
}

// Runner does the scan itself. It belongs to the scan module (D-55), which registers it with
// Service.SetRunner; exposure only decides whether a scan may happen (INV-1) and keeps the result.
// What it returns came from other hosts, so the service limits it before storing it (INV-10).
type Runner interface {
	Scan(ctx context.Context, t ScanTarget) (Content, error)
}

// Gateway tells the page which device probably answers the open ports of the box's public IP (S-EXP-1, D-492). cmd/vedette
// implements it from the host's default route, the inventory and the findings; exposure reads no other module's tables.
type Gateway interface {
	Gateway(ctx context.Context) (GatewayDevice, error)
}

// GatewayDevice is the LAN default gateway and what Vedette knows of it. IP is the zero value when the box cannot tell its gateway;
// DeviceID is empty when no inventory device has that IP. Name is an untrusted label. OpenExploited counts the open findings
// (confirmed or suspected) of the device.
type GatewayDevice struct {
	IP            netip.Addr
	DeviceID      string
	Name          string
	OpenExploited int
}
