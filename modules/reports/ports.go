package reports

import (
	"context"
	"time"
)

// Everything reports reads from another module comes through these ports (FORBID-4): cmd/vedette adapts the real services.

// Device is a device as the reports need it. The list leaves out the devices a person ignored.
type Device struct {
	ID       string
	Name     string // hostname, else the IP
	IP       string
	Kind     string
	OS       string // "" = unknown
	Approved bool   // false = "Not added yet"
	Fragile  bool
	Ports    []int    // open TCP/UDP service ports
	Box      bool     // this Vedette box: counted like the Devices page counts it; not in the PDPL inventory
	Agent    bool     // an agent on the device reports its software (osquery, Wazuh, the box's own host agent)
	Sources  []string // the source of each of vendor, model and OS that is known
}

// Inventory lists the devices a person did not ignore.
type Inventory interface {
	Devices(ctx context.Context) ([]Device, error)
}

// Finding is an open finding as the PDPL assessment reads it. Status is confirmed (a scan or a person confirmed it) or suspected:
// handled findings never arrive. Severity is one of critical, high, medium, low, info.
type Finding struct {
	ID, AssetID, CVE string
	Status, Severity string
	FirstSeen        time.Time
	Agent            bool // the version compared is the one the device's own agent reports
}

// Findings lists every open finding of a watched device, for the PDPL assessment.
type Findings interface {
	All(ctx context.Context) ([]Finding, error)
}

// FindingView is a finding as findings.View shows it on every page, with the events that changed its state. The shapes are the
// findings contract's, so the document carries the same status, severity, verification, fix and handled line as the Findings page.
type FindingView struct {
	ID, CVE      string
	Device       DeviceRef
	Product      string // the software line, as Findings names it ("" = the fix's product)
	Version      string // the version the finding was matched on ("" = none)
	Status       string // the one status now (findings.StatusOf): an open code, or the resolution once handled
	Urgency      int    // the stored layer, 1 to 5
	Severity     *CveSeverity
	Verification Verification
	Fix          Fix
	Handled      *Handled // the handling now; nil while open
	FirstSeen    time.Time
	Events       []FindingEvent // oldest first: created, handled, reopened, acceptance_expired
}

// FindingEvent is one change of a finding's state (fnd_finding_event). Handled is set on a handled event: who and how, from the
// event's stored fields, so the report says how it was handled at that time even when it was handled again since.
type FindingEvent struct {
	At      time.Time
	Kind    string // created, handled, reopened, acceptance_expired
	Handled *Handled
}

// FindingViews reads the findings of the watched devices (a device a person ignored is left out, as on every findings list) and
// the urgency reasons of the few the document lists.
type FindingViews interface {
	Views(ctx context.Context) ([]FindingView, error)
	Reasons(ctx context.Context, ids []string) (map[string][]Reason, error)
}

// Exposure reads every external exposure target as the report's section shows it, with the changes inside the period.
type Exposure interface {
	Targets(ctx context.Context, from, to time.Time) ([]ExposureTarget, error)
}

// DetectionCount is how many incidents of a kind had activity in the period, and when the newest was.
type DetectionCount struct {
	Kind   string
	N      int
	LastAt time.Time
}

// Detection is one incident of the period that matters: its kind, title, severity and device (DeviceID "" = none).
type Detection struct {
	Kind, Title, Severity string
	DeviceID, DeviceName  string
	Devices               int // how many devices it names; DeviceID is the first
	At                    time.Time
}

// Detections reads the incidents with activity in the period (notify): every kind counted whole, and the top few by severity
// then recency.
type Detections interface {
	Period(ctx context.Context, from, to time.Time, top int) ([]DetectionCount, []Detection, error)
}

// FeedHealth is one enabled vulnerability feed: when it last loaded and whether that is older than its schedule allows.
type FeedHealth struct {
	ID, Name string
	LastOK   time.Time // zero = never
	Stale    bool
}

// Feeds reads the health of the vulnerability feeds.
type Feeds interface {
	Health(ctx context.Context) ([]FeedHealth, error)
}

// KEVEntry is one entry of the exploited-vulnerability list (the PDPL risks name a finding's product by it).
type KEVEntry struct {
	CVE, Vendor, Product string
	Display              string // the product name Findings shows (feeds.DisplayOf); "" = "<vendor> <product>"
}

// KEV lists the exploited-vulnerability list.
type KEV interface {
	Entries(ctx context.Context) ([]KEVEntry, error)
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

// AI asks the ai module for a commentary. Job is "pdpl-assessment". Errors that a person should see are *apierr.Error.
type AI interface {
	Available(job string) bool
	Summarize(ctx context.Context, actor, job, task string, data []Block) (Summary, error)
}

// Modules says whether a module is on.
type Modules interface {
	Enabled(id string) bool
}
