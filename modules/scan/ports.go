package scan

import (
	"context"
	"time"

	"github.com/knt048/vedette/core/events"
)

// Device is an inventory device as the scan module sees it.
type Device struct {
	ID       string
	Label    string // host name, or the IP when there is none
	IP       string // "" or "—" when unknown
	Kind     string // inventory kind; "unknown" until classified
	Approved bool
	Fragile  bool
	Services []OpenPort
}

// OpenPort is an open port the inventory knows on a device.
type OpenPort struct {
	Port int
	Name string // nmap service name: http, https, ssh, ...
}

// Decision is inventory.VulnScanPolicy as scan needs it (D-126).
type Decision struct {
	Allowed bool
	Reason  string // inventory's reason: ok, box, no_ip, scope_not_confirmed, out_of_scope, regular_scan_never,
	// declared_by_hand, fragile_passive_only, unclassified_passive_only
	Careful bool   // fragile or unclassified: a quarter of the rate (D-126 (2))
	IP      string // the address the decision was made for
}

// ReasonGone is the policy reason of a device deleted since the device list was read (review L6): it leaves the list.
const ReasonGone = "gone"

// Policy reasons of the inventory that scan maps to its own (contract.ts ScanTarget.reason).
const (
	reasonBox        = "box"
	reasonNever      = "regular_scan_never"
	reasonOutOfScope = "out_of_scope"
	reasonNoScope    = "scope_not_confirmed"
)

// FindingRef is a finding of a device: the CVEs scan may confirm or clear on it.
type FindingRef struct {
	ID      string
	AssetID string
	CVE     string
	Status  string // suspected, confirmed, mitigated, patched, false_positive, not_relevant
}

// Evidence is what a confirming scan hands the findings module (S-SCAN-3): cleaned and capped already.
type Evidence struct {
	Summary   string // one sentence plus how to check it yourself
	Template  string // template path in the pack
	Request   string
	Response  string
	CheckedAt time.Time
}

// Findings is the findings module as scan needs it. Nil: results stay in the run, nothing is confirmed
// (CONTRACT, behaviour when findings is off).
type Findings interface {
	List(ctx context.Context, assetID string) ([]FindingRef, error)
	// ConfirmFromScan records a match and returns the id of the finding (INV-8). It is the only call: a scan without a
	// match is "no match reported" and never touches a finding (D-133 (5)).
	ConfirmFromScan(ctx context.Context, assetID, cve string, ev Evidence) (string, error)
}

// Publisher is the event bus as this module needs it; *events.Bus satisfies it.
type Publisher interface {
	Publish(ctx context.Context, e events.Event) error
}

// Output is what one nuclei run printed: its JSONL, or nothing when it was cut at the cap.
type Output struct {
	JSONL     []byte
	Truncated bool // over nucleiargv.MaxOutput: the run is discarded (INV-10)
}

// KEVFeed is feeds' record of the KEV entries it announced (feeds.vuln.new_kev), read by the catch-up of the rescan
// job: the bus is best-effort (D-144), so an entry announced while scan was off or the process was down is found
// here. Nil: no catch-up, only the bus.
type KEVFeed interface {
	// NewKEVSince lists the entries announced after (at, cve), oldest first, at most limit.
	NewKEVSince(ctx context.Context, at time.Time, cve string, limit int) ([]AnnouncedKEV, error)
}

// AnnouncedKEV is one announced entry and when feeds announced it.
type AnnouncedKEV struct {
	NewKEV
	At time.Time
}
