package inventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/knt048/vedette/content/devicetypes"
)

// Kinds are the 13 kinds behaviour is keyed on: the fragile and regular-scan settings list them, and every device type acts
// as one of them (devicetypes.ActsAs). The device types themselves are devicetypes.IDs (contract.ts AssetKind).
var Kinds = devicetypes.Kinds

// Limits (INV-4, INV-13).
const (
	MaxImportBytes = 200_000
	MaxImportRows  = 500
	MaxLANRanges   = 16
	MaxListed      = 2000 // GET /inventory/devices (API_CONVENTIONS 4)
	MaxCatalogHits = 30
	maxLabel       = 64
	maxVersion     = 40
	maxNotes       = 2000
	maxObsValue    = 200
)

// ErrNotFound is returned when a device or software row does not exist.
var ErrNotFound = errors.New("inventory: not found")

// ErrInvalid is wrapped by errors about data a sensor or agent sent (SYS-2, SYS-6). Errors about what a
// person typed are *apierr.Error with their own code.
var ErrInvalid = errors.New("inventory: invalid input")

// Event is what Service publishes after a transaction commits. core/events.Bus takes the same two fields;
// cmd/vedette adapts (see Publisher).
type Event struct {
	Name string
	Data any
}

// Publisher announces events. The real implementation is core/events.Bus (WP-04b); a nil Publisher drops events.
type Publisher interface {
	Publish(ctx context.Context, e Event) error
}

// PublisherFunc adapts a function to Publisher.
type PublisherFunc func(ctx context.Context, e Event) error

// Publish implements Publisher.
func (f PublisherFunc) Publish(ctx context.Context, e Event) error { return f(ctx, e) }

// Event names (CONTRACT "Events").
const (
	EventAssetDiscovered = "inventory.asset.discovered"
	EventAssetUpdated    = "inventory.asset.updated"
	EventAssetDeleted    = "inventory.asset.deleted"
	EventAssetMerged     = "inventory.asset.merged"
	EventAssetApproved   = "inventory.asset.approved"  // a person approved a discovered device (B9b)
	EventAssetIgnored    = "inventory.asset.ignored"   // a person ignored a device: {asset_id, actor}
	EventAssetUnignored  = "inventory.asset.unignored" // a person stopped ignoring a device: {asset_id, actor}
	EventSoftwareChanged = "inventory.software.changed"
	EventMatchChanged    = "inventory.match.changed"
	EventSettingsChanged = "inventory.settings.changed"
)

// AssetEvent is the data of the asset and software events. Notify is set on discovered events: the
// notify_new setting at that moment (INV-9), so notify need not read inventory settings.
type AssetEvent struct {
	AssetID string `json:"asset_id"`
	Notify  bool   `json:"notify,omitempty"` // on discovered: the new-device setting was on; on updated: the device now deserves its new-device notice (it was quiet, INV-49)
	// Match is set when what the findings matcher reads of the device besides its software changed: the folded OS,
	// the model, or the OS the device states itself (MatchDevice.StatedOS). Only observations set it.
	Match bool `json:"match,omitempty"`
	// Learning is set on discovered events when the source that found the device (passive sensor, active scan, SNMP, agent, vulnerability
	// scan) first reported to this box less than LearningWindow ago (MK-1): notify folds such devices into one summary.
	Learning bool `json:"learning,omitempty"`
	// ScanOn is set on inventory.asset.updated when a person turned the device's network scan on: sensor-active queues it for
	// the next window, as a newly discovered device.
	ScanOn bool `json:"scan_on,omitempty"`
	// Actor is the person who approved (inventory.asset.approved), ignored (inventory.asset.ignored) or deleted
	// (inventory.asset.deleted) the device; "" for the system.
	Actor string `json:"actor,omitempty"`
}

// MergeEvent is the data of inventory.asset.merged: device From was the same device as Into and is gone; what other modules
// keep about From belongs to Into now. It goes out before the inventory.asset.deleted of From.
type MergeEvent struct {
	From  string `json:"from"`
	Into  string `json:"into"`
	Actor string `json:"actor"`
}

// MatchEvent is the data of inventory.match.changed: the asset now matches an exploited CVE by product.
type MatchEvent struct {
	AssetID string `json:"asset_id"`
	CVE     string `json:"cve"`
	Basis   string `json:"basis"` // "product" (version needs affected ranges from feeds); never "confirmed"
}

// SettingsEvent is the data of inventory.settings.changed.
type SettingsEvent struct {
	Scope string `json:"scope"` // "scan" or "notify_new"
}

// KEVProduct is one vendor/product pair of CISA KEV with the number of exploited CVEs.
type KEVProduct struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Count   int    `json:"kev_count"`
}

// KEV is the view of the feeds module the inventory needs (INV-10, INV-12). feeds (WP-20) implements it;
// until then cmd/vedette passes EmbeddedKEVProducts and no CVE source.
type KEV interface {
	// Products lists every vendor/product pair ever in KEV; Version changes when the list does.
	Products(ctx context.Context) (version string, list []KEVProduct, err error)
	// CVEIndex reads the exploited lists once and returns their CVE ids by match key. A caller reads it once per request (a device
	// page, an agent report, a rematch) and looks up every software line in it.
	CVEIndex(ctx context.Context) (KEVIndex, error)
}

// KEVIndex returns the CVE ids exploited for any of the keys ("vendorproject|product", lower-case); a "multiple products" entry of a
// vendor matches every key of that vendor. It only reads memory and is safe for concurrent use.
type KEVIndex func(keys []string) []string

// BoxPackages lists the packages installed on the box itself (dpkg, confidence 1.0). cmd/vedette implements it
// with vedette-host's GET /v1/state/packages on an appliance; a container-only install has none. A nil list means "no list
// from this host" (kept as is), never "no packages".
type BoxPackages interface {
	Packages(ctx context.Context) ([]SoftwareItem, error)
}

// FindingCounter says how many findings are attached to devices (owned by findings; inventory may not
// read fnd_* tables). nil means zero.
type FindingCounter interface {
	CountByAsset(ctx context.Context) (map[string]int, error)
}

// RiskSource is the badge of every device that has one, from findings' one device status function (inventory may not read fnd_*
// tables): its most urgent open finding status with the distinct CVEs at it, else needs_input with the items waiting for a person. A
// device that is absent has none.
type RiskSource interface {
	DeviceStatuses(ctx context.Context) (map[string]Risk, error)
}

// The device badge words (contract.ts DEVICE_STATUSES) and "none" for a device without a badge (the Devices search's filter).
const (
	RiskUnderAttack   = "under_attack"
	RiskExploited     = "exploited"
	RiskPublicExploit = "public_exploit"
	RiskCriticalEdge  = "critical_edge"
	RiskUpdate        = "update_recommended"
	RiskNeedsInput    = "needs_input"
	RiskNone          = "none"
)

// RiskLevels are the words of the badge filter, most urgent first.
var RiskLevels = []string{RiskUnderAttack, RiskExploited, RiskPublicExploit, RiskCriticalEdge, RiskUpdate, RiskNeedsInput, RiskNone}

// Risk is the badge of a device in every list (contract.ts DeviceBadge): nil when it has none.
type Risk struct {
	Code  string `json:"code"`  // one of RiskLevels but none
	Count int    `json:"count"` // distinct CVEs at that status; for needs_input the items waiting for a person
}

// riskWords is the badge's text, as the pages show it (also the CSV's risk column): "2 exploited", "Update recommended", "" when none.
func riskWords(r *Risk) string {
	if r == nil {
		return ""
	}
	switch r.Code {
	case RiskUnderAttack:
		return fmt.Sprintf("%d under attack here", r.Count)
	case RiskExploited:
		return fmt.Sprintf("%d exploited", r.Count)
	case RiskPublicExploit:
		return fmt.Sprintf("%d with a public exploit", r.Count)
	case RiskCriticalEdge:
		return fmt.Sprintf("%d critical on an edge device", r.Count)
	case RiskUpdate:
		return "Update recommended"
	case RiskNeedsInput:
		return "Needs your input"
	}
	return ""
}

// riskLevel is the filter word of a device's badge.
func riskLevel(r *Risk) string {
	if r == nil {
		return RiskNone
	}
	return r.Code
}

// ModuleGate says whether another module is on (modreg.Registry implements it).
type ModuleGate interface{ Enabled(id string) bool }

// SoftwareItem is software to store for a device.
type SoftwareItem struct {
	Display, Vendor, Product, Version, CPE string
	KevKeys                                []string
	Confidence                             float64
	// Guess is a sensor's guess (observe.Software.Guess): stored without match keys, so it raises no finding.
	Guess bool
	// Packaged: an agent read it from the operating system's package database (observe.Software.Packaged). Stored only for
	// source agent.
	Packaged bool
	// PkgVersion and PkgSource: a deb row's full Debian version and source package. Stored only with Packaged; a value
	// that is not a Debian version or package name is dropped (the row stays, without a distribution decision).
	PkgVersion, PkgSource string
	// Instance tells two readings of one product by one source apart (observe.Software.Instance).
	Instance string
}

// Observed is a value with where it came from (contract.ts Observed).
type Observed struct {
	Value      string  `json:"value"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	SeenAt     string  `json:"seen_at"`
	// Basis is how Vedette knows the value besides its source (INV-44): "stated" (the device announced it over LLDP on its own
	// vendor's card: the OS, and the model of the same frame), "guess" (nmap's OS fingerprint) or "" (the source and confidence
	// say it all).
	Basis string `json:"basis,omitempty"`
	// SoftwareID names the software row the value is read from: the OS or firmware row a person declared (INV-45); "" when an
	// observation gives it.
	SoftwareID string `json:"software_id,omitempty"`
}

// Software is one software line as a row of a device list (contract.ts Software): SoftwareLine.row.
type Software struct {
	ID         string   `json:"id"`
	Display    string   `json:"display"`
	Vendor     string   `json:"vendor"`
	Product    string   `json:"product"`
	Version    *string  `json:"version"`
	Kev        []string `json:"kev"`
	Source     string   `json:"source"`
	Confidence float64  `json:"confidence"`
	// Basis is "guess" on the row of nmap's OS fingerprint (no version, no match key), "" otherwise (INV-44).
	Basis string `json:"basis,omitempty"`
	// NotInstalled: a person said this software is not installed on the device (INV-41 (6)). Readers that tell what the device runs
	// (the assistant, MCP) take Device.Running, which leaves it out.
	NotInstalled bool `json:"not_installed"`
	// live: a person's entry that is the line's value on a present line; seenAt: when its source last read it. Read by declaredIdentity.
	live   bool
	seenAt string
}

// ServiceRow is a service seen listening on a device (contract.ts Service).
type ServiceRow struct {
	Port       int     `json:"port"`
	Proto      string  `json:"proto"`
	Name       string  `json:"name"`
	Product    *string `json:"product,omitempty"`
	Version    *string `json:"version,omitempty"`
	Detail     *string `json:"detail,omitempty"` // what the service said about the device besides product and version
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	// Address is the other address of the device a scan found the port on (INV-57); nil for the main address and an agent's list.
	Address *string `json:"address,omitempty"`
}

// AssetCore is what a device row and a device detail share. The JSON names are the wire names.
type AssetCore struct {
	ID       string  `json:"id"`
	Site     string  `json:"site"`
	IP       string  `json:"ip"` // "—" when unknown
	MAC      *string `json:"mac"`
	Hostname *string `json:"hostname"` // the host name the network reports (observations), never a person's name for the device
	// UserName is the name a person gave the device in Vedette; nil = none, the naming rule names it (DisplayName).
	UserName   *string `json:"name"`
	Kind       string  `json:"kind"`
	KindSource *string `json:"kind_source"` // the source of the kind's observation; nil for the default unknown
	// Guess is what the identification rules say the device most likely is, only while Kind is unknown. It is never the kind:
	// nothing behaves on it; a person confirms it by setting the kind.
	Guess       *devicetypes.Guess `json:"guess"`
	Vendor      *Observed          `json:"vendor"`
	Model       *Observed          `json:"model"`
	OS          *Observed          `json:"os"`
	Services    []ServiceRow       `json:"services"`
	FirstSeen   string             `json:"first_seen"`
	LastSeen    string             `json:"last_seen"`
	Approved    bool               `json:"approved"`
	Fragile     bool               `json:"fragile"`
	Origin      string             `json:"origin"`
	Notes       *string            `json:"notes,omitempty"`
	IsBox       bool               `json:"is_box"`
	FirstScanAt *string            `json:"first_scan_at"`
	ApprovedAt  *string            `json:"approved_at"` // when a person (or osquery enrolment) approved it; nil when not approved, added by hand, or approved before approval times were recorded
	RegularScan string             `json:"regular_scan"`
	// ScanSource and SNMPSource say whether the box's network scan and its SNMP reads are on for this device ("on" or "off", the
	// default resolved: on for a device a sensor found, off for one added by hand).
	ScanSource string `json:"scan_source"`
	SNMPSource string `json:"snmp_source"`
	// IgnoredAt is when a person ignored the device: known, not watched. nil = watched.
	IgnoredAt *string `json:"ignored_at"`
	// PrivateMAC: its MAC is a private (randomised) address the device picks for itself and changes, not one a maker burned in or a
	// stable virtual one (PrivateMAC).
	PrivateMAC bool `json:"private_mac"`
	// Quiet: not approved, but not in To review either: a private-address device with no open service that has not stayed past
	// a day (INV-49). It is listed with the approved devices and moves to To review when it earns a look.
	Quiet bool `json:"quiet"`
}

// Summary is the source of the most trusted value and the confidence of the weakest (DATA_MODEL 5.1 (5)).
type Summary struct {
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
}

// Device is a row of the device list (contract.ts DeviceRow).
type Device struct {
	AssetCore
	Software      []Software  `json:"software"`
	Suspicious    bool        `json:"suspicious"`
	FindingsCount int         `json:"findings_count"`
	Risk          *Risk       `json:"risk"` // the device's risk marker, nil when clean
	Summary       *Summary    `json:"summary"`
	Sources       []string    `json:"sources"` // what feeds the device, in the words of the Devices search (#849, SourceWords); set by DevicesPage only
	ident         []*Observed // current hostname and MAC observations: the summary of a device with no vendor, model or OS
	// observedHW is the maker and model the observations give, before a declared OS row fills them (fillDeclaredHardware): the naming rule
	// reads these, as Names does, so a device is named alike on every page. nil on a Device not read by loadDevices.
	observedHW *[2]string
}

// DetailAsset is the asset of a device detail.
type DetailAsset struct {
	AssetCore
	Software []SoftwareLine `json:"software"`
	// OSCorrection is the OS a person set (INV-41), with what the sources read now; absent when none.
	OSCorrection *OSCorrection `json:"os_correction,omitempty"`
}

// ObservationRow is one observation of a device detail (contract.ts Observation).
type ObservationRow struct {
	ID         string  `json:"id"`
	Field      string  `json:"field"`
	Value      string  `json:"value"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	SeenAt     string  `json:"seen_at"`
	Current    bool    `json:"current"`
	// ContradictsType: an nmap OS guess the device's type rules out (osguess.go): kept and shown, never the device's OS.
	ContradictsType bool   `json:"contradicts_type,omitempty"`
	Basis           string `json:"basis,omitempty"` // Observed.Basis, of an OS or model observation
}

// Detail is GET /inventory/devices/{id} (contract.ts DeviceDetail).
type Detail struct {
	Asset         DetailAsset `json:"asset"`
	Suspicious    bool        `json:"suspicious"`
	FindingsCount int         `json:"findings_count"`
	Risk          *Risk       `json:"risk"` // the device's risk marker, nil when clean, for the box, or when not read
	// RiskUnavailable: the marker could not be read (findings failed).
	RiskUnavailable bool             `json:"risk_unavailable"`
	Observations    []ObservationRow `json:"observations"`
	Kinds           []string         `json:"kinds"`
	PossibleSame    []PossibleSame   `json:"possible_same"` // devices that may be the same machine
	// ManualAt is when a person last entered or changed something on the device (INV-46, manualAt); nil when nothing was.
	ManualAt *string `json:"manual_at"`
	// DetectedDiffers are the fields where a trusted source reads something other than what a person entered (INV-47); empty when none.
	DetectedDiffers []Differs `json:"detected_differs"`
	// Addresses are every address of the device, the main one first (INV-57).
	Addresses []Address `json:"addresses"`
}

// Counts are the numbers behind the filter chips of the device list.
// Every count but Ignored leaves the ignored devices out.
type Counts struct {
	All     int `json:"all"`
	Pending int `json:"pending"`
	Fragile int `json:"fragile"`
	Manual  int `json:"manual"`
	Ignored int `json:"ignored"`
}

// DeviceList is GET /inventory/devices.
type DeviceList struct {
	Items           []Device `json:"items"`
	Counts          Counts   `json:"counts"`
	NotifyNew       bool     `json:"notify_new"`
	NotifyAvailable bool     `json:"notify_available"`
	// RiskUnavailable: the risk markers could not be read (findings failed): no row has one and a risk filter was not applied.
	RiskUnavailable bool `json:"risk_unavailable"`
}
