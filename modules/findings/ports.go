package findings

import "context"

// Event names published by this module (CONTRACT, Events).
const (
	EventCreated       = "findings.finding.created"
	EventStatusChanged = "findings.finding.status_changed"
	// EventSeverityRaised: a repeated match raised the severity of an open finding (review H2, M-a of #663): a
	// product finding whose NVD ranges arrived and put its version inside (basis version), so it may now be critical.
	EventSeverityRaised = "findings.finding.severity_raised"
)

// CreatedEvent is the payload of findings.finding.created.
type CreatedEvent struct {
	FindingID string   `json:"finding_id"`
	AssetID   string   `json:"asset_id"`
	CVE       string   `json:"cve"`
	Severity  Severity `json:"severity"`
	Basis     Basis    `json:"basis"`
}

// StatusChangedEvent is the payload of findings.finding.status_changed. From and To are equal only when a
// scan matched a finding a person closed as false_positive, not_relevant or risk_accepted: someone has to decide (POST-2).
type StatusChangedEvent struct {
	FindingID string `json:"finding_id"`
	From      Status `json:"from"`
	To        Status `json:"to"`
	// Reason is set when Vedette changed the status by itself (D-530): ReasonNotAffectedVersion when it closed the
	// finding, ReasonMatchesAgain when it reopened one it had closed, ReasonRiskExpired when a risk acceptance ran out
	// (D-498). Empty for a person's action or a scan.
	Reason string `json:"reason,omitempty"`
}

// ReasonMatchesAgain is the StatusChangedEvent reason of a finding Vedette reopened because the device matches the
// entry again after Vedette had closed it as not affected (D-530).
const ReasonMatchesAgain = "matches_again"

// SeverityRaisedEvent is the payload of findings.finding.severity_raised. The status is unchanged (still open).
type SeverityRaisedEvent struct {
	FindingID    string   `json:"finding_id"`
	AssetID      string   `json:"asset_id"`
	CVE          string   `json:"cve"`
	FromSeverity Severity `json:"from_severity"`
	ToSeverity   Severity `json:"to_severity"`
	Basis        Basis    `json:"basis"` // the basis after the raise (version)
}

// Publisher is the event bus as this module needs it. core/events is not built yet; the real bus
// satisfies this by adapting its Publish. Events go out after the transaction commits, and a failed
// publish is logged, never rolled back into the change.
type Publisher interface {
	Publish(ctx context.Context, name string, payload any) error
}

// AssetView is the device a finding is about, as the finding list and page show it (FindingAsset).
type AssetView struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`     // the name the Devices page shows (hostname, else vendor and model, else IP); never the id (D-484)
	Hostname *string `json:"hostname"` // nil when the device has no name
	IP       string  `json:"ip"`       // "—" when the device has no IP address (hand-added, LLDP only)
	Kind     string  `json:"kind"`     // one of the inventory kinds; anything else is shown as "unknown"
	Display  string  `json:"display"`  // first software's display name, else the kind
}

// NoIP is the IP of a device without an address, as the inventory API writes it.
const NoIP = "—"

// HasIP reports whether the device has an address a scan or a person can reach.
func (a *AssetView) HasIP() bool { return a != nil && a.IP != "" && a.IP != NoIP }

// Inventory is what findings reads from the inventory module (Kien's; not built yet).
type Inventory interface {
	// Assets returns the devices with these ids. Unknown ids are absent from the map.
	Assets(ctx context.Context, ids []string) (map[string]AssetView, error)
	// MatchInput returns the device with its software for the matcher; ok is false when it does not exist.
	MatchInput(ctx context.Context, assetID string) (a Asset, ok bool, err error)
	// AssetIDs returns the id of every device, with no cap. Reconcile matches each of them and treats a finding whose
	// device is not in the list as orphaned, so a short answer must never be returned: any read error is an error.
	AssetIDs(ctx context.Context) ([]string, error)
}

// KevInfo is the KEV entry shown with a finding (FindingRow.kev, INV-8).
type KevInfo struct {
	Name           string   `json:"name"`
	Vendor         string   `json:"vendor"`
	Product        string   `json:"product"`
	Display        string   `json:"display"` // plain-language product; empty means "<vendor> <product>"
	RequiredAction string   `json:"required_action"`
	Links          []string `json:"links"`
	DateAdded      string   `json:"date_added"`
	DueDate        *string  `json:"due_date"`
	Ransomware     bool     `json:"ransomware"`
	EPSS           *float64 `json:"epss"`
	HasTemplate    bool     `json:"has_template"`
}

// Feeds is what findings reads from the feeds module (WP-20; not built yet). findings never reads
// feeds_* tables (FORBID-5 of feeds).
type Feeds interface {
	// KevInfo returns the KEV entries of these CVEs. CVEs that are not on the list are absent.
	KevInfo(ctx context.Context, cves []string) (map[string]KevInfo, error)
	// Vulns returns the exploited-vulnerability list with the NVD affected ranges, for matching.
	Vulns(ctx context.Context) ([]Vuln, error)
}
