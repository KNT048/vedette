package reports

import (
	"context"
	"time"
)

// Everything reports reads from another module comes through these ports (FORBID-4): cmd/vedette adapts the real services.

// Device is a device as the reports need it.
type Device struct {
	ID        string
	Name      string // hostname, else the IP
	IP        string
	Kind      string
	OS        string // "" = unknown
	Approved  bool
	Fragile   bool
	FirstSeen time.Time
	Ports     []int    // open TCP/UDP service ports
	KevKeys   []string // inventory KEV keys of the software on the device ("vendor|product")
	Sources   []string // the source of each of vendor, model and OS that is known
}

// Inventory lists every device.
type Inventory interface {
	Devices(ctx context.Context) ([]Device, error)
}

// Finding is a finding as the reports need it. Status is one of confirmed, suspected, mitigated, patched, false_positive,
// not_relevant; Severity one of critical, high, medium, low, info.
type Finding struct {
	ID, AssetID, CVE string
	Status, Severity string
	FirstSeen        time.Time
	ResolvedAt       time.Time // zero = not closed
}

// Findings lists every finding.
type Findings interface {
	All(ctx context.Context) ([]Finding, error)
}

// KEVEntry is one entry of the exploited-vulnerability list.
type KEVEntry struct {
	CVE, Vendor, Product string
	Key                  string    // the key inventory uses to match software ("vendor|product")
	DateAdded            time.Time // a day, midnight UTC
}

// KEV lists the exploited-vulnerability list and says when it was last pulled (zero = never).
type KEV interface {
	Entries(ctx context.Context) (entries []KEVEntry, pulledAt time.Time, err error)
}

// Mail is the digest sent by email. Path is the page of Vedette the mail links to.
type Mail struct {
	Title, What, Action string
	Items               []string
	Path                string
}

// Mailer sends through the email channel of notify (INV-4). Ready says whether it can now and, when it cannot, why in a
// sentence for a person.
type Mailer interface {
	Ready(ctx context.Context) (ok bool, reason string)
	Send(ctx context.Context, to []string, m Mail) error
}

// Block is a piece of data given to the AI, fenced there as untrusted.
type Block struct{ Source, Text string }

// Summary is the AI's answer.
type Summary struct {
	Paragraphs          []string
	Model, Profile      string
	TokensIn, TokensOut int
}

// AI asks the ai module for a commentary. Job is "weekly-report" or "pdpl-assessment". Errors that a person should see are
// *apierr.Error.
type AI interface {
	Available(job string) bool
	Summarize(ctx context.Context, actor, job, task string, data []Block) (Summary, error)
}

// Modules says whether a module is on.
type Modules interface {
	Enabled(id string) bool
}
