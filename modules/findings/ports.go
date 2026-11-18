package findings

import (
	"context"
	"time"
)

// Event names published by this module (CONTRACT, Events).
const (
	EventCreated       = "findings.finding.created"
	EventStatusChanged = "findings.finding.status_changed"
	// EventSeverityRaised: a repeated match raised the severity of an open finding (review H2, M-a of #663): a
	// product finding whose NVD ranges arrived and put its version inside (basis version), so it may now be critical.
	EventSeverityRaised = "findings.finding.severity_raised"
	// EventUncheckedAdded: exploited CVEs entered a device's "could not be checked" list for the first time
	// (#939): one event per device and match write, listing them; never again for the same device and CVE, never for a CVE the device
	// has or had a finding for. Published under the Backlog mark from Reconcile's backlog write, like findings.finding.created.
	EventUncheckedAdded = "findings.unchecked.added"
)

// UncheckedAddedEvent is the payload of findings.unchecked.added.
type UncheckedAddedEvent struct {
	AssetID   string              `json:"asset_id"`
	AssetName string              `json:"asset_name"` // the name the matcher gives the device (Asset.Name)
	CVEs      []UncheckedAddedCVE `json:"cves"`       // in list order, each once
}

// UncheckedAddedCVE is one CVE of an UncheckedAddedEvent: the row it is listed on and why it could not be checked.
type UncheckedAddedCVE struct {
	CVE        string          `json:"cve"`
	SoftwareID string          `json:"software_id"` // "os:<asset>" for the network OS a device states without a software row
	Software   string          `json:"software"`
	Version    string          `json:"version"`
	Reason     UncheckedReason `json:"reason"`
	NVDPending bool            `json:"nvd_pending,omitempty"` // no_nvd_data while NVD has not answered yet: say "waiting for NVD's data"
}

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
	// Reason is set when Vedette changed the status by itself: ReasonNotAffectedVersion when it closed the
	// finding, ReasonMatchesAgain when it reopened one it had closed, ReasonRiskExpired when a risk acceptance ran out.
	// Empty for a person's action or a scan.
	Reason string `json:"reason,omitempty"`
	// AcceptedBy and AcceptedUntil (YYYY-MM-DD) are set only with ReasonRiskExpired: who accepted the risk and its last day.
	AcceptedBy    string `json:"accepted_by,omitempty"`
	AcceptedUntil string `json:"accepted_until,omitempty"`
}

// ReasonMatchesAgain is the StatusChangedEvent reason of a finding Vedette reopened because the device matches the
// entry again after Vedette had closed it as not affected.
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
	Name     string  `json:"name"`     // the name the Devices page shows (hostname, else vendor and model, else IP); never the id
	Hostname *string `json:"hostname"` // nil when the device has no name
	IP       string  `json:"ip"`       // "—" when the device has no IP address (hand-added, LLDP only)
	Kind     string  `json:"kind"`     // one of the inventory kinds; anything else is shown as "unknown"
	Display  string  `json:"display"`  // the device's OS, else its kind; GET /findings/{id} puts the matched software here (matchedOn, #905)
	Approved bool    `json:"approved"` // false: the device is not added yet (nobody approved it); its findings say so and offer Add device and Ignore
	Ignored  bool    `json:"ignored"`  // a person ignored the device: its findings are under Findings > Ignored
	Box      bool    `json:"-"`        // the Vedette box itself: never given a risk marker
}

// NoIP is the IP of a device without an address, as the inventory API writes it.
const NoIP = "—"

// HasIP reports whether the device has an address a scan or a person can reach.
func (a *AssetView) HasIP() bool { return a != nil && a.IP != "" && a.IP != NoIP }

// Inventory is what findings reads from the inventory module (not built yet).
type Inventory interface {
	// Assets returns the devices with these ids. Unknown ids are absent from the map. An ignored device (inventory INV-38) is
	// present: reconcile's orphan pass relies on it, so a pass whose IgnoredIDs read failed never deletes an ignored device's
	// findings and the decisions on them (inventory's DeviceRefs, TestDeviceRefsKeepsAnIgnoredDevice).
	Assets(ctx context.Context, ids []string) (map[string]AssetView, error)
	// MatchInput returns the device with its software for the matcher; ok is false when it does not exist.
	MatchInput(ctx context.Context, assetID string) (a Asset, ok bool, err error)
	// AssetIDs returns the id of every device, with no cap. Reconcile matches each of them and treats a finding whose
	// device is not in the list as orphaned, so a short answer must never be returned: any read error is an error.
	AssetIDs(ctx context.Context) ([]string, error)
	// IgnoredIDs returns the devices a person ignored (inventory INV-38), with no cap; any read error is an error. They are
	// not in AssetIDs: reconcile closes their open findings and never treats their findings as orphaned.
	IgnoredIDs(ctx context.Context) ([]string, error)
	// IsIgnored says whether a person ignored the device; false when it does not exist. Asked inside a write.
	IsIgnored(ctx context.Context, assetID string) (bool, error)
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
	Source         string   `json:"source"` // "cisa-kev" or "vulncheck-kev": which list the entry is on, so every text names it
	// Published is the day NVD published the CVE ("2017-03-14"), never CISA's date_added; nil when NVD has not answered.
	Published *string `json:"published"`
}

// CVSS is the CVSS base score shown with a finding (FindingRow.cvss, INV-22, #825): feeds' newest CVSS version, NVD's own score
// before another scorer's (CNA or CISA ADP), CVSS 2.0 only when NVD has nothing newer, always with its vector (feeds INV-28). The band
// follows from Score and Version (FIRST's table for 3.x and 4.0, NVD's v2 table for 2.0); the pages compute it.
type CVSS struct {
	Score   float64 `json:"score"`
	Version string  `json:"version"` // "4.0", "3.1", "3.0" or "2.0"
	Source  string  `json:"source"`  // "nvd" (NVD's Primary) or "cna" (Secondary: the CNA or CISA ADP)
	Vector  string  `json:"vector"`  // NVD's vector string ("CVSS:3.1/AV:N/…", v2 "AV:N/AC:L/…")
}

// TierStatus is what the tier feeds of feeds hold: "off", "loading" or "ready" for epss-all and nvd-recent,
// the day of the EPSS scores and the first published day nvd-recent covers (zero unless ready).
type TierStatus struct {
	EPSS, Recent          string
	EPSSDate, RecentSince time.Time
}

// Feeds is what findings reads from the feeds module (WP-20; not built yet). findings never reads
// feeds_* tables (FORBID-5 of feeds).
type Feeds interface {
	// KevInfo returns the KEV entries of these CVEs. CVEs that are not on the list are absent.
	KevInfo(ctx context.Context, cves []string) (map[string]KevInfo, error)
	// CVSS returns the CVSS base score of these CVEs (INV-22). CVEs without a known score are absent.
	CVSS(ctx context.Context, cves []string) (map[string]CVSS, error)
	// Vulns returns the exploited-vulnerability list with the NVD affected ranges, for matching.
	Vulns(ctx context.Context) ([]Vuln, error)
	// TierStatus says what the tier feeds hold, for GET /findings/plan.
	TierStatus(ctx context.Context) (TierStatus, error)
	// TierVulns returns the CVEs of the tier data (nvd-recent, with the EPSS of epss-all) published in the last 12 months whose NVD
	// affected entries name a CPE keep accepts, each with those entries only. None while nvd-recent is not ready or the feeds
	// module is off; no EPSS while epss-all is not ready.
	TierVulns(ctx context.Context, keep func(cpe string) bool) ([]TierVuln, error)
	// TierDistro returns the tier CVEs (as TierVulns: published in the last 12 months, EPSS) for which a distribution feed that is on
	// has a fixed row of one of pkgs, each with those rows in Distro and no Affected, and the releases ("ubuntu/24.04") among pkgs'
	// that the distribution feeds hold rows for. Nothing while nvd-recent is not ready or the feeds module is off.
	TierDistro(ctx context.Context, pkgs []DistroPackage) (vulns []TierVuln, covered map[string]bool, err error)
	// TierStamp changes whenever what TierVulns or TierDistro returns may have changed: a pull or switch of epss-all, nvd-recent,
	// nvd-kev, ubuntu-osv or debian-tracker, or the feeds module turned on or off (feeds' Store.TierStamp plus the module switch, cmd/vedette).
	TierStamp(ctx context.Context) (string, error)
}
