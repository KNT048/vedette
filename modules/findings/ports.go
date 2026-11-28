package findings

import (
	"context"
)

// Event names published by this module (CONTRACT, Events).
const (
	EventCreated       = "findings.finding.created"
	EventStatusChanged = "findings.finding.status_changed"
	// EventUrgencyRaised: an open finding rose into a more urgent layer of 1–4 (UrgencyRaisedEvent; the finding's urgency_changed). Published
	// under the Backlog mark for old news (counted, never sent). notify tells a finding again only at a more urgent layer than any it was
	// told at, so a rise into a layer it was told at is no second alert.
	EventUrgencyRaised = "findings.finding.urgency_raised"
	// EventFirstRun: the rises of one first-run window in one pass (a signal source's first load, or the box's own first discovery),
	// told as one summary (FirstRunEvent); none of them sends an alert of its own (their urgency_raised go under the Backlog mark).
	EventFirstRun = "findings.urgency.first_run"
)

// UrgencyRaisedEvent is the payload of findings.finding.urgency_raised. At is the rise's time (RFC 3339).
type UrgencyRaisedEvent struct {
	FindingID string   `json:"finding_id"`
	AssetID   string   `json:"asset_id"`
	CVE       string   `json:"cve"`
	Severity  Severity `json:"severity"`
	Basis     Basis    `json:"basis"`
	From      int      `json:"from"`
	To        int      `json:"to"`
	At        string   `json:"at"`
}

// FirstRunEvent is the payload of findings.urgency.first_run: one first-run window's rises in one pass. Key names the window ("install",
// or a source and the day of its first load); Layer is the most urgent of them; the lists hold up to MaxBackfillListed.
type FirstRunEvent struct {
	Key      string `json:"key"`
	At       string `json:"at"` // the pass's time (RFC 3339): each pass's summary is its own notice; a later one says "N more"
	Findings int    `json:"findings"`
	Devices  int    `json:"devices"`
	Layer    int    `json:"layer"`
	// Exploited counts the findings of Findings that are exploited (Finding.Exploited): the only ones an alert tells, listed or not
	Exploited  int      `json:"exploited"`
	FindingIDs []string `json:"finding_ids"`
	CVEList    []string `json:"cve_list"`
}

// MaxBackfillListed caps the lists of a FirstRunEvent.
const MaxBackfillListed = 50

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
	// finding, ReasonFixedByUpdate when it closed it as patched because the device's version moved out of the range (alerts and
	// response send nothing for either),ReasonMatchesAgain when it reopened one it had closed, ReasonRiskExpired when a risk acceptance ran out,
	// ReasonDeviceVersion when the version the device reports confirmed it or no longer does. Empty for a person's action or a scan.
	Reason string `json:"reason,omitempty"`
	// AcceptedBy and AcceptedUntil (YYYY-MM-DD) are set only with ReasonRiskExpired: who accepted the risk and its last day.
	AcceptedBy    string `json:"accepted_by,omitempty"`
	AcceptedUntil string `json:"accepted_until,omitempty"`
}

// ReasonDeviceVersion is the StatusChangedEvent reason of a finding the version the device itself reports (its SNMP answer or its
// own agent) confirmed (to confirmed), or no longer confirms (back to suspected): Finding.SettleByDevice. Alerts and response
// rules treat a change to confirmed like a scan's confirmation.
const ReasonDeviceVersion = "device_version"

// ReasonMatchesAgain is the StatusChangedEvent reason of a finding Vedette reopened because the device matches the
// entry again after Vedette had closed it as not affected.
const ReasonMatchesAgain = "matches_again"

// ReasonStillDetected is the StatusChangedEvent reason of a finding a person marked patched that Vedette reopened because a newer reading
// of the device still shows the flaw.
const ReasonStillDetected = "still_detected"

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
	Display  string  `json:"display"`  // the device's OS, else its kind; GET /findings/{id} puts the matched software here (matchedRow, #905)
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
	// ToReviewIDs returns the devices of the Devices list's To review, with no cap: not added yet, not quiet, not ignored, never the
	// box. Needs your input counts the ones with no open finding as one grouped card that opens that list.
	ToReviewIDs(ctx context.Context) ([]string, error)
	// IsIgnored says whether a person ignored the device; false when it does not exist. Asked inside a write.
	IsIgnored(ctx context.Context, assetID string) (bool, error)
	// EffectiveSoftware returns the device's software as one row per software, the strongest source's reading (inventory INV-50):
	// agent > a person's entry > SNMP > a scan banner, a weaker less precise form of the same release being the same release. Every
	// reader that says what version a device runs reads this, never a single source's row.
	EffectiveSoftware(ctx context.Context, assetID string) ([]EffectiveSoftware, error)
	// Lines returns the software lines with these ids, in any state (a finding keeps naming a line that was removed); unknown ids are
	// absent. The lists name each finding's line with it and search it by name.
	Lines(ctx context.Context, ids []string) (map[string]Line, error)
}

// Line is a software line as the lists of findings name it (inventory.LineRef).
type Line struct {
	ID, AssetID, Display, ProductKey string
	Version                          string // "" when the line has no version
}

// EffectiveSoftware is one software of a device as inventory's effective row gives it (inventory.EffectiveSoftware).
type EffectiveSoftware struct {
	ID, Vendor, Product, Display string
	Version, PkgVersion          string // "" when none
	Packaged                     bool
	CPE                          string
	Source                       string
	SetBy                        string // who entered it, for a person's entry
	SeenAt                       string
	AlsoSeen                     []AlsoSeen
	Differs                      bool // a weaker source reads another release, newer than this row's source did
}

// AlsoSeen is another source's reading of an EffectiveSoftware.
type AlsoSeen struct {
	ID, Source, Version, PkgVersion, SeenAt string
	SameRelease                             bool
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

// Feeds is what findings reads from the feeds module (not built yet). findings never reads
// feeds_* tables (FORBID-5 of feeds).
type Feeds interface {
	// KevInfo returns the KEV entries of these CVEs. CVEs that are not on the list are absent.
	KevInfo(ctx context.Context, cves []string) (map[string]KevInfo, error)
	// CVSS returns the CVSS base score of these CVEs (INV-22). CVEs without a known score are absent.
	CVSS(ctx context.Context, cves []string) (map[string]CVSS, error)
	// Vulns returns the exploited-vulnerability list with the NVD affected ranges, for matching.
	Vulns(ctx context.Context) ([]Vuln, error)
	// MatchSet returns what the match pass compares the devices with: every exploited-list entry (as Vulns) and every other catalogue
	// CVE whose ranges name a product of scope (MatchScope.Keep) or that scope pins, each with its ranges as the catalogue's precedence
	// gives them (NVD's when NVD has any, else the CVE record's; Vuln.Origin), its publication day, EPSS and the distributions' word on
	// the scope's packages. None while the feeds module is off. A scope of no device (NewMatchScope(nil, pinned)) gives the pinned CVEs'
	// entries only, exploited-list entries among them: a reader of a few CVEs pays for those alone.
	MatchSet(ctx context.Context, scope MatchScope) ([]Vuln, error)
	// Exploited says which of cves any exploitation signal names, whatever its age or the reporting window (feeds
	// Store.ExploitationSignalled): an exploited-list entry, an exploited statement, a public exploit or scan template, an intrusion alert
	// here. A claim its source's quality rule rejects is none. CVEs no signal names are absent.
	Exploited(ctx context.Context, cves []string) (map[string]bool, error)
	// Unsupported says which of cves have a record that states the product unsupported by its vendor when the CVE was assigned (the CVE
	// Program's unsupported-when-assigned tag, as the record's description carries it). CVEs it does not tag are absent.
	Unsupported(ctx context.Context, cves []string) (map[string]bool, error)
}
