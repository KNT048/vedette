package sensoractive

import (
	"context"
	"errors"
	"net/netip"
)

// Settings is the part of the inventory's scan settings this module obeys (S-INV-1). The adapter in
// cmd/vedette fills it from inventory.Settings; strings are in the inventory's own notation.
type Settings struct {
	Enabled        bool
	ScopeConfirmed bool
	LANRanges      []string // CIDR
	Exclusions     []string // IPv4 or CIDR
	Days           []int    // 1 = Monday ... 7 = Sunday
	From, To       string   // HH:MM in the organization's time zone; To before From crosses midnight
	Rate           int      // packets per second
}

// Decision is the answer of the inventory's ScanPolicy (PRE-2).
type Decision struct {
	Allowed     bool
	Rate        int    // packets per second the scan may use
	Reason      string // the inventory's reason, passed through in sensor.scan.blocked
	FirstGentle bool   // the one gentle scan of a fragile device (D-45)
	// Fragile and Unclassified describe the device (fragile, kind still unknown): IdentifyDevice picks its scan shape from them (D-501).
	// Never is regular_scan=never: IdentifyDevice refuses it outright (D-126 (1)).
	Fragile, Unclassified, Never bool
}

// Asset is a device as the scanner needs it.
type Asset struct {
	ID string
	IP netip.Addr // invalid when the inventory knows no IP
	// Approved: a person approved the device (or its osquery enrolment did). SNMP credentials go only to approved devices (D-512):
	// a device nobody vouched for may be a rogue one that collects communities.
	Approved bool
}

// Inventory is what this module asks of the inventory (INV-1, INV-2, INV-5). The real implementation is
// an adapter over inventory.Service in cmd/vedette.
type Inventory interface {
	Settings(ctx context.Context) (Settings, error)
	// InScope reports whether ip is inside lan_ranges and outside the exclusions (SYS-7).
	InScope(ctx context.Context, ip netip.Addr) (bool, error)
	ScanPolicy(ctx context.Context, assetID string) (Decision, error)
	MarkFirstScan(ctx context.Context, assetID string) error
	Asset(ctx context.Context, assetID string) (Asset, error)     // ErrNotFound when unknown
	Addresses(ctx context.Context) (map[netip.Addr]string, error) // IP -> device id of every known device
	KnownMACs(ctx context.Context) ([]string, error)              // MAC of every known device (uncapped): a sweep charges only MACs not in it
	// ProtectedIPs lists the addresses a sweep must not probe: devices declared by hand, devices set to
	// regular_scan=never, fragile or unclassified devices after their one gentle scan, and the box itself. It
	// is by IP, so a new MAC at a protected address does not make it fair game.
	ProtectedIPs(ctx context.Context) ([]netip.Addr, error)
	// BoxIPs lists only the addresses that are the box (its own device, its cards, the decoys): never probed, not even by an SNMP read
	// of a fragile device (D-512).
	BoxIPs(ctx context.Context) ([]netip.Addr, error)
}

// PendingGentle is an optional part of Inventory (D-511, review of #714 round 2): the devices whose one gentle scan is still to come
// (discovered, kind unknown, not fragile, not set to never, not the box, not declared by hand, no first scan yet). Devices reach the
// queue only through inventory.asset.discovered, which fires for new devices; inventory migration 0004 cleared the first scan of
// devices seen before, so Tick queues these once per start (INSERT OR IGNORE, idempotent).
type PendingGentle interface {
	PendingGentleScans(ctx context.Context) ([]string, error)
}

// Event is what Service publishes after a transaction commits; cmd/vedette adapts it to core/events.
type Event struct {
	Name string
	Data any
}

// Publisher announces events. A nil Publisher drops them.
type Publisher interface {
	Publish(ctx context.Context, e Event) error
}

// PublisherFunc adapts a function to Publisher.
type PublisherFunc func(ctx context.Context, e Event) error

// Publish implements Publisher.
func (f PublisherFunc) Publish(ctx context.Context, e Event) error { return f(ctx, e) }

// Event names (CONTRACT "Events").
const (
	EventScanStarted  = "sensor.scan.started"
	EventScanFinished = "sensor.scan.finished"
	EventScanBlocked  = "sensor.scan.blocked"
)

// StartedEvent is the data of sensor.scan.started.
type StartedEvent struct {
	JobID   string `json:"job_id"`
	Kind    string `json:"kind"` // "sweep" or "device"
	Targets int    `json:"targets"`
}

// FinishedEvent is the data of sensor.scan.finished.
type FinishedEvent struct {
	JobID      string `json:"job_id"`
	Targets    int    `json:"targets"`
	NewDevices int    `json:"new_devices"`
	Status     string `json:"status"` // done, stopped or failed
}

// BlockedEvent is the data of sensor.scan.blocked: a device was not scanned and no packet was sent.
type BlockedEvent struct {
	AssetID string `json:"asset_id"`
	Reason  string `json:"reason"`
}

// Job kinds and statuses of sa_job.
const (
	KindSweep  = "sweep"
	KindDevice = "device"
	KindSNMP   = "snmp" // a Test or the window's round of SNMP reads (D-512)

	StatusRunning = "running"
	StatusDone    = "done"
	StatusStopped = "stopped"
	StatusFailed  = "failed"
)

// Errors of the entry points. ErrBlocked, ErrOutsideWindow and the ErrNot* errors mean no packet was sent.
var (
	ErrNotFound          = errors.New("sensoractive: device not found")
	ErrBlocked           = errors.New("sensoractive: scan blocked by the inventory's policy")
	ErrOutsideWindow     = errors.New("sensoractive: outside the scan window")
	ErrScanningOff       = errors.New("sensoractive: active scanning is off")          // INV-2
	ErrScopeNotConfirmed = errors.New("sensoractive: the scan scope is not confirmed") // INV-2
	ErrNoRanges          = errors.New("sensoractive: no network range to scan")        // INV-2
	ErrUnavailable       = errors.New("sensoractive: nmap is not available")           // INV-6
	ErrStopped           = errors.New("sensoractive: the run was stopped")             // PRE-3
)

// Health is the module's state for the status page (INV-6): "ok", or "unavailable" with a message. Zone is
// the time zone the windows are read in (INV-3). Warning is set while a full sweep cannot fit in one window at
// the configured rate (an estimate, D-523: one packet an address on the box's own networks, nmapargv.SweepProbes or more
// behind a router); the sweep then takes several days.
type Health struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Zone    string `json:"zone"`
	Warning string `json:"warning,omitempty"`
}

// Probe is one row of the probe log (INV-9). Argv is the flag part of the command line that was approved, up
// to and including "-oX -", as stored with the row (a later change of the templates does not rewrite it); the
// addresses it was run on are in Target as merged ranges ("a.b.c.d-e.f.g.h,i.j.k.l"). Shape is the template (sweep, normal or gentle) and Rate the --max-rate of it.
type Probe struct {
	Time   string   `json:"time"`
	Shape  string   `json:"shape"`
	Rate   int      `json:"rate"`
	Target string   `json:"target"`
	Argv   []string `json:"argv"`
	Result string   `json:"result"`
	JobID  string   `json:"job_id"`
}
