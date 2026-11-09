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

// ScanTarget is what the scan module is told about the target it scans.
type ScanTarget struct {
	ID    string
	Kind  Kind
	Value string
}

// Runner does the scan itself. It belongs to the scan module (D-55), which registers it with
// Service.SetRunner; exposure only decides whether a scan may happen (INV-1) and keeps the result.
// What it returns came from other hosts, so the service limits it before storing it (INV-10).
type Runner interface {
	Scan(ctx context.Context, t ScanTarget) (Content, error)
}
