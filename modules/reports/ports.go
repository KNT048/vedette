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
	Box       bool     // this Vedette box: listed on the Devices page, so counted in the weekly report; not in the PDPL inventory
	NoDevice  bool     // a product added by hand with neither a name nor an IP: Name is the product and inventory.NoDevice (D-471)
	Sources   []string // the source of each of vendor, model and OS that is known
}

// Inventory lists every device.
type Inventory interface {
	Devices(ctx context.Context) ([]Device, error)
}

// Finding is a finding as the reports need it. Status is one of confirmed, suspected, mitigated, patched, false_positive,
// not_relevant, risk_accepted (D-498); Severity one of critical, high, medium, low, info.
type Finding struct {
	ID, AssetID, CVE string
	Status, Severity string
	FirstSeen        time.Time
	ResolvedAt       time.Time // zero = not closed
	ResolvedBy       string    // who closed it ("" = open)
	Source           string    // the exploited list of the CVE ("vulncheck-kev" names VulnCheck KEV among the report's sources); "" = CISA or unknown
	AcceptedUntil    time.Time // risk_accepted: the last day of the acceptance (D-498); zero otherwise
}

// Findings lists every finding.
type Findings interface {
	All(ctx context.Context) ([]Finding, error)
}

// Fix is what NVD's ranges say about the one release that closes an installed software on a device (findings.FixedInForAll, D-490):
// the same for every finding of that software, with Closed telling whether it closes this finding. Group is the software it is about
// (CISA gives one phone's CVEs several product names; the software is one). Kind is "fixed" (Fixed is a release outside the affected
// range of every finding of the software; Version is the device's), "none" (NVD's ranges name no release that clears them all),
// "up_to" (NVD names no fixed release, Fixed is the last affected one), "distro" (the distribution's security updates carry it),
// "feature_update" (a Windows release Microsoft no longer updates: Fixed names the later release NVD gives the fix for, D-546) or
// "esu" (the fixing Windows build Fixed comes only with Extended Security Updates, D-546).
// Distro names the distribution the device runs ("" = none we know).
type Fix struct {
	Kind, Group, Version, Fixed, Distro string
	Closed                              bool
}

// Remedies says the Fix of open findings, by finding id; a finding it cannot say anything about is not in the map.
type Remedies interface {
	Fixes(ctx context.Context, fs []Finding) (map[string]Fix, error)
}

// Incident is an incident of notify as the report names it. Kind is login_accepted, trap, failed_logins, bad_connection or anomaly
// (notify reads it; a new-device incident is not here: Devices counts those).
type Incident struct {
	Kind, Severity, Title string
	LastSeen              time.Time
}

// IncidentWeek is the incidents last seen in the window: how many of each kind (all of them, however many) and the few that matter most.
type IncidentWeek struct {
	Traps, FailedLogins, AcceptedLogins, BadConnections, Other int
	Top                                                        []Incident
}

// Incidents reads the incidents last seen since the given time (notify.IncidentsSince). ok is false when notify is off: the report
// then has no section.
type Incidents interface {
	Week(ctx context.Context, since time.Time, top int) (week IncidentWeek, ok bool, err error)
}

// KEVEntry is one entry of the exploited-vulnerability list.
type KEVEntry struct {
	CVE, Vendor, Product string
	Display              string    // the product name Findings shows (feeds.DisplayOf); "" = "<vendor> <product>"
	Key                  string    // the key inventory uses to match software ("vendor|product")
	DateAdded            time.Time // a day, midnight UTC
}

// KEV lists the exploited-vulnerability list and says when it was last pulled (zero = never). NewlyExploited is the Home
// headline as numbers (W1-24, D-485): the CVEs newly exploited in the last 7 days and how many of their products are in use.
type KEV interface {
	Entries(ctx context.Context) (entries []KEVEntry, pulledAt time.Time, err error)
	NewlyExploited(ctx context.Context) (cves, productsInUse int, err error)
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
