package mcpserver

import (
	"context"
	"errors"
)

// Source is the read-only view of the box the tools answer from: devices (inventory), findings and the vulnerability feeds.
// cmd/vedette implements it on top of those modules' own services and handlers (no module reads another's
// tables). Every value it returns is already reduced to the fields below: an allow-list, so a field a source module adds later
// never reaches an agent by accident (INV-7). Text fields are data, never instructions.
type Source interface {
	// Assets returns the devices of the inventory, at most the inventory's own list cap. ErrSourceOff when inventory is off.
	Assets(ctx context.Context) ([]Asset, error)
	// Asset returns one device; ok is false when there is no such device.
	Asset(ctx context.Context, id string) (a Asset, ok bool, err error)
	// Findings returns every finding, newest first. ErrSourceOff when the findings module is off.
	Findings(ctx context.Context) ([]Finding, error)
	// Finding returns one finding; ok is false when there is no such finding.
	Finding(ctx context.Context, id string) (f Finding, ok bool, err error)
	// CVE returns what the catalogue holds about an upper-case CVE id (its brief); ok is false when it holds nothing.
	// ErrSourceOff when the feeds module is off.
	CVE(ctx context.Context, cve string) (e CVEEntry, ok bool, err error)
	// IOC looks an IP address or a domain up in the indicator feeds. ErrNotIOC when the value is neither.
	IOC(ctx context.Context, value string) (IOCAnswer, error)
	// Hot returns the vulnerabilities added to the exploited lists in the window ("24h" or "7d").
	Hot(ctx context.Context, window string) ([]HotCVE, error)
}

// SourceOffError says the module that holds a scope's data is off, so the tool has nothing to answer from.
type SourceOffError struct{ Module string }

func (e SourceOffError) Error() string { return "mcpserver: the " + e.Module + " module is off" }

// ErrNotIOC is returned by Source.IOC for a value that is not an IP address or a domain.
var ErrNotIOC = errors.New("mcpserver: not an IP address or a domain")

// Asset is a device as an agent sees it. Not included: the MAC address, notes (free text people type), observation sources and
// confidences, scan settings and the KEV keys of the software (feeds data: the feeds scope has lookup_cve for that).
type Asset struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	IP        *string      `json:"ip"`
	Hostname  *string      `json:"hostname"`
	Kind      string       `json:"kind"`
	Vendor    *string      `json:"vendor"`
	Model     *string      `json:"model"`
	OS        *string      `json:"os"`
	Approved  bool         `json:"approved"`
	Ignored   bool         `json:"ignored"` // a person said it needs no watching (inventory)
	FirstSeen string       `json:"first_seen"`
	LastSeen  string       `json:"last_seen"`
	Services  []NetService `json:"services"`
	Software  []Software   `json:"software"`
}

// NetService is a port seen open on a device.
type NetService struct {
	Port    int     `json:"port"`
	Proto   string  `json:"proto"`
	Name    string  `json:"name"`
	Product *string `json:"product"`
	Version *string `json:"version"`
}

// Software is a product found on a device.
type Software struct {
	Name    string  `json:"name"`
	Vendor  string  `json:"vendor"`
	Product string  `json:"product"`
	Version *string `json:"version"`
}

// Finding is an exploited vulnerability matched to a device. Not included: who changed its status and the notes they wrote
// (users and free text, INV-7), and the raw request and response of a scan check (open question 3 of the contract).
type Finding struct {
	ID         string  `json:"id"`
	AssetID    string  `json:"asset_id"`
	CVE        string  `json:"cve"`
	Status     string  `json:"status"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Basis      string  `json:"basis"`
	FirstSeen  string  `json:"first_seen"`
	LastSeen   string  `json:"last_seen"`
	ResolvedAt *string `json:"resolved_at"`
	// AcceptedUntil (YYYY-MM-DD) is the last day of a risk acceptance, only with status risk_accepted.
	AcceptedUntil string `json:"accepted_until,omitempty"`
	// Urgency is the status code of the finding's urgency layer: under_attack, exploited, public_exploit, critical_edge or
	// update_recommended.
	Urgency string `json:"urgency,omitempty"`
	// Fix is the fix of the finding in one sentence and Verification says that a person, a safe check or the device confirmed it, or
	// that nobody has: the words the finding page and the assistant use, without the name of the person (users are not returned, INV-7).
	Fix          string        `json:"fix,omitempty"`
	Verification string        `json:"verification,omitempty"`
	Evidence     *Evidence     `json:"evidence"`
	History      []HistoryStep `json:"history"`
}

// Evidence names the scan check that confirmed a finding. Its summary is not included: it names the device, its address and
// software (inventory data, INV-2).
type Evidence struct {
	Template  string `json:"template"`
	CheckedAt string `json:"checked_at"`
}

// HistoryStep is one change of a finding: when and what, not who.
type HistoryStep struct {
	At     string `json:"at"`
	Action string `json:"action"`
}

// CVEEntry is what the box's catalogue holds about one CVE (feeds' brief): the CVE record's own words, the scores, the exploited-list
// entry when a list has it, the affected versions with the fixed releases, the record's solution and workaround and the references by
// tag. The exploited-list fields are empty for a CVE no list has.
type CVEEntry struct {
	CVE             string   `json:"cve"`
	Vendor          string   `json:"vendor"`
	Product         string   `json:"product"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	RequiredAction  string   `json:"required_action"`
	Source          string   `json:"source"` // the list that has it: "cisa-kev", "vulncheck-kev" (VulnCheck KEV) or a custom feed's id
	DateAdded       string   `json:"date_added,omitempty"`
	DueDate         *string  `json:"due_date"`
	Ransomware      bool     `json:"ransomware"`
	EPSS            *float64 `json:"epss"`
	HasScanTemplate bool     `json:"has_scan_template"`
	Links           []string `json:"links"`

	Title            string       `json:"title,omitempty"`
	Published        string       `json:"published,omitempty"`
	NVDStatus        string       `json:"nvd_status,omitempty"` // NVD's own word ("Analyzed", "Deferred"); empty until NVD answered
	Weaknesses       []Weakness   `json:"weaknesses,omitempty"`
	CVSS             *CVSS        `json:"cvss,omitempty"`
	AffectedVersions []string     `json:"affected_versions,omitempty"`
	AffectedFrom     string       `json:"affected_versions_from,omitempty"` // nvd, cna (the CVE record's own list) or adp
	FixedReleases    []FixedTrain `json:"fixed_releases,omitempty"`
	Solution         string       `json:"solution,omitempty"`
	Workaround       string       `json:"workaround,omitempty"`
	References       []Reference  `json:"references,omitempty"`
	NVDURL           string       `json:"nvd_url,omitempty"`
	RecordURL        string       `json:"record_url,omitempty"`
}

// Weakness is a CWE of the CVE with its name.
type Weakness struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CVSS is the CVE's base score with its vector read into words.
type CVSS struct {
	Score              float64 `json:"score"`
	Severity           string  `json:"severity"`
	Version            string  `json:"version"`
	Vector             string  `json:"vector"`
	AttackVector       string  `json:"attack_vector"`
	PrivilegesRequired string  `json:"privileges_required"`
	UserInteraction    string  `json:"user_interaction"`
}

// FixedTrain is the fixed release a vendor states for one release train of a product.
type FixedTrain struct {
	Train   string `json:"train"`
	Release string `json:"release"`
}

// Reference is one reference of the CVE with the group its tags put it in ("vendor-advisory", "patch", "mitigation", "exploit" …).
type Reference struct {
	URL   string `json:"url"`
	Group string `json:"group"`
}

// IOCAnswer is what the indicator feeds say about a value. Listed is false when no feed lists it (or it can never be an
// indicator, such as a private address); the other fields are then empty.
type IOCAnswer struct {
	Value     string   `json:"value"`
	Type      string   `json:"type"`
	Listed    bool     `json:"listed"`
	Verdict   *string  `json:"verdict"`
	Category  string   `json:"category"`
	Sources   []string `json:"sources"`
	Score     *float64 `json:"score"`
	FirstSeen *string  `json:"first_seen"`
	LastSeen  *string  `json:"last_seen"`
}

// HotCVE is a vulnerability recently added to an exploited list.
type HotCVE struct {
	CVE             string   `json:"cve"`
	Vendor          string   `json:"vendor"`
	Product         string   `json:"product"`
	DateAdded       string   `json:"date_added"`
	Ransomware      bool     `json:"ransomware"`
	EPSS            *float64 `json:"epss"`
	HasScanTemplate bool     `json:"has_scan_template"`
}
