package inventory

import (
	"context"
	"errors"

	"github.com/knt048/vedette/content/devicetypes"
)

// Kinds are the 13 kinds behaviour is keyed on (D-511): the fragile and regular-scan settings list them, and every device type acts
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
	EventAssetApproved   = "inventory.asset.approved" // a person approved a discovered device (D-474, B9b)
	EventSoftwareChanged = "inventory.software.changed"
	EventMatchChanged    = "inventory.match.changed"
	EventSettingsChanged = "inventory.settings.changed"
)

// AssetEvent is the data of the asset and software events. Notify is set on discovered events: the
// notify_new setting at that moment (INV-9), so notify need not read inventory settings.
type AssetEvent struct {
	AssetID string `json:"asset_id"`
	Notify  bool   `json:"notify,omitempty"`
	// Match is set when what the findings matcher reads of the device besides its software changed (D-510): the folded OS,
	// the model, or the OS the device states itself (MatchDevice.StatedOS). Only observations set it.
	Match bool `json:"match,omitempty"`
	// Learning is set on discovered events when the source that found the device (passive sensor, active scan, SNMP, agent, vulnerability
	// scan) first reported to this box less than LearningWindow ago (D-474, MK-1): notify folds such devices into one summary.
	Learning bool `json:"learning,omitempty"`
	// Actor is the person who approved (inventory.asset.approved) or deleted (inventory.asset.deleted) the device; "" for the system.
	Actor string `json:"actor,omitempty"`
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

// KEVProduct is one vendor/product pair of CISA KEV with the number of exploited CVEs (D-30).
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
	// CVEs returns the CVE ids exploited for any of the keys ("vendorproject|product", lower-case).
	// A "multiple products" entry of a vendor matches every key of that vendor.
	CVEs(ctx context.Context, keys []string) ([]string, error)
}

// BoxPackages lists the packages installed on the box itself (dpkg, confidence 1.0; D-53, D-470). cmd/vedette implements it
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

// ModuleGate says whether another module is on (modreg.Registry implements it).
type ModuleGate interface{ Enabled(id string) bool }

// SoftwareItem is software to store for a device.
type SoftwareItem struct {
	Display, Vendor, Product, Version, CPE string
	KevKeys                                []string
	Confidence                             float64
	// Guess is a sensor's guess (observe.Software.Guess, D-501): stored without match keys, so it raises no finding.
	Guess bool
	// Packaged: an agent read it from the operating system's package database (observe.Software.Packaged, D-474). Stored only for
	// source agent.
	Packaged bool
}

// Observed is a value with where it came from (contract.ts Observed).
type Observed struct {
	Value      string  `json:"value"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	SeenAt     string  `json:"seen_at"`
}

// Software is one software row (contract.ts Software).
type Software struct {
	ID         string   `json:"id"`
	Display    string   `json:"display"`
	Vendor     string   `json:"vendor"`
	Product    string   `json:"product"`
	Version    *string  `json:"version"`
	Kev        []string `json:"kev"`
	Source     string   `json:"source"`
	Confidence float64  `json:"confidence"`
}

// SoftwareView is Software with CVE ids instead of keys (contract.ts SoftwareView).
type SoftwareView struct {
	ID         string   `json:"id"`
	Display    string   `json:"display"`
	Vendor     string   `json:"vendor"`
	Product    string   `json:"product"`
	Version    *string  `json:"version"`
	KevCVEs    []string `json:"kev_cves"`
	Source     string   `json:"source"`
	Confidence float64  `json:"confidence"`
}

// ServiceRow is a service seen listening on a device (contract.ts Service).
type ServiceRow struct {
	Port       int     `json:"port"`
	Proto      string  `json:"proto"`
	Name       string  `json:"name"`
	Product    *string `json:"product,omitempty"`
	Version    *string `json:"version,omitempty"`
	Detail     *string `json:"detail,omitempty"` // what the service said about the device besides product and version (D-511)
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
}

// AssetCore is what a device row and a device detail share. The JSON names are the wire names.
type AssetCore struct {
	ID         string  `json:"id"`
	Site       string  `json:"site"`
	IP         string  `json:"ip"` // "—" when unknown
	MAC        *string `json:"mac"`
	Hostname   *string `json:"hostname"`
	Kind       string  `json:"kind"`
	KindSource *string `json:"kind_source"` // the source of the kind's observation; nil for the default unknown (D-511)
	// Guess is what the identification rules say the device most likely is, only while Kind is unknown (D-511). It is never the kind:
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
	ApprovedAt  *string            `json:"approved_at"` // when a person (or osquery enrolment) approved it; nil when not approved, added by hand, or approved before D-471
	RegularScan string             `json:"regular_scan"`
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
	Summary       *Summary    `json:"summary"`
	ident         []*Observed // current hostname and MAC observations: the summary of a device with no vendor, model or OS
}

// DetailAsset is the asset of a device detail.
type DetailAsset struct {
	AssetCore
	Software []SoftwareView `json:"software"`
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
}

// Detail is GET /inventory/devices/{id} (contract.ts DeviceDetail).
type Detail struct {
	Asset         DetailAsset      `json:"asset"`
	Suspicious    bool             `json:"suspicious"`
	FindingsCount int              `json:"findings_count"`
	Observations  []ObservationRow `json:"observations"`
	Kinds         []string         `json:"kinds"`
}

// Counts are the numbers behind the filter chips of the device list.
type Counts struct {
	All     int `json:"all"`
	Pending int `json:"pending"`
	Fragile int `json:"fragile"`
	Manual  int `json:"manual"`
}

// DeviceList is GET /inventory/devices.
type DeviceList struct {
	Items           []Device `json:"items"`
	Counts          Counts   `json:"counts"`
	NotifyNew       bool     `json:"notify_new"`
	NotifyAvailable bool     `json:"notify_available"`
}
