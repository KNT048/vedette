package findings

import "context"

// Event names published by this module (CONTRACT, Events).
const (
	EventCreated       = "findings.finding.created"
	EventStatusChanged = "findings.finding.status_changed"
)

// CreatedEvent is the payload of findings.finding.created.
type CreatedEvent struct {
	FindingID string   `json:"finding_id"`
	AssetID   string   `json:"asset_id"`
	CVE       string   `json:"cve"`
	Severity  Severity `json:"severity"`
	Basis     Basis    `json:"basis"`
}

// StatusChangedEvent is the payload of findings.finding.status_changed. From and To are equal when a
// scan matched a finding a person closed as false_positive or not_relevant: someone has to decide.
type StatusChangedEvent struct {
	FindingID string `json:"finding_id"`
	From      Status `json:"from"`
	To        Status `json:"to"`
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
	Hostname *string `json:"hostname"` // nil when the device has no name
	IP       string  `json:"ip"`
	Kind     string  `json:"kind"`    // one of the inventory kinds; anything else is shown as "unknown"
	Display  string  `json:"display"` // first software's display name, else the kind
}

// Inventory is what findings reads from the inventory module (Kien's; not built yet).
type Inventory interface {
	// Assets returns the devices with these ids. Unknown ids are absent from the map.
	Assets(ctx context.Context, ids []string) (map[string]AssetView, error)
	// MatchInput returns the device with its software for the matcher; ok is false when it does not exist.
	MatchInput(ctx context.Context, assetID string) (a Asset, ok bool, err error)
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
