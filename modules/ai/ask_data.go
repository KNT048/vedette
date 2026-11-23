package ai

import (
	"context"

	"github.com/knt048/vedette/core/conn/read"
)

// The doors "Ask your data" reads through (S-AI-5). ai never reads the tables of another module: cmd/vedette adapts the
// exported reads of inventory, findings and feeds to Data, and the read tools of the connections come from core/conn/read.
// Every text field below is untrusted: it came from a device, a scan or a feed. The tools clean it and fence it; nothing here decides.

// AssetRow is a device of the inventory as the tools show it.
type AssetRow struct {
	ID       string
	Name     string // hostname, else model, else the IP
	IP       string
	Kind     string
	Vendor   string
	Model    string
	OS       string
	Approved bool
	// Ignored marks a device a person said needs no watching (inventory): not waiting for review, not scanned, no findings.
	Ignored  bool
	Ports    []string // "3389/tcp rdp"
	Software []string // "Display name version"
	LastSeen string
	// FirstSeen, Origin and SeenBy say how the box knows the device, so the AI can name it the way the Devices page does: when it was
	// first seen, whether it was found on the network ("discovered") or added by hand ("manual"), and which source gave the values
	// above (scan, sensor, agent, manual; the source of the most trusted value). None of them is personal data; the notes of a
	// device are not read (free text a person typed).
	FirstSeen string
	Origin    string
	SeenBy    string
	// IsBox marks the Vedette box itself: it is searched like any device, but the citation names it apart, as Devices and Reports
	// do not count it as a device of the network. Not sent to the model.
	IsBox bool
}

// FindingRow is a finding (a device matched to a known vulnerability).
type FindingRow struct {
	ID       string
	AssetID  string
	Asset    string // name of the device
	AssetIP  string
	CVE      string
	Status   string // confirmed, suspected, mitigated, patched, false_positive, not_relevant, risk_accepted
	Severity string
	Basis    string // version, product, scan, person
	// Urgency is why the finding matters now: under_attack (an intrusion alert on this network named the CVE), exploited (attackers
	// use it), public_exploit (working exploit code is public), critical_edge (a critical flaw on a device attackers target first) or
	// update_recommended (no sign of exploitation). Only the first two are being exploited.
	Urgency    string
	Confidence float64
	Evidence   string // the summary of the scan that confirmed it; "" = none
	FirstSeen  string
	LastSeen   string
	// AcceptedUntil (YYYY-MM-DD) is the last day of a risk acceptance, only with status risk_accepted; "" otherwise.
	AcceptedUntil string
	// Fix is the fix of this device in one sentence, the one the finding page shows; Confirmation says who or what confirmed the finding,
	// or that nobody has; Workaround (get_finding only) is the CVE record's workaround, or "No workaround is published: install the fix."
	Fix, Confirmation, Workaround string
}

// IOCFact is an indicator (an IP address or a domain) that feeds list.
type IOCFact struct {
	Kind      string
	Value     string
	FirstSeen string
	LastSeen  string
	Sources   []string // names of the feeds that list it now; empty = no feed lists it any more
}

// Data is what the product read tools search. A nil Data in Config leaves those tools out.
type Data interface {
	// Assets returns every device.
	Assets(ctx context.Context) ([]AssetRow, error)
	// Findings returns every finding, newest first.
	Findings(ctx context.Context) ([]FindingRow, error)
	// Finding returns one finding; ok is false when there is none with that id.
	Finding(ctx context.Context, id string) (FindingRow, bool, error)
	// IOC returns the indicator for a kind ("ip" or "domain") and a value as the AI wrote it; the adapter canonicalises it. ok is
	// false when no feed has ever listed it, and also when the value can never be an indicator (a private address).
	IOC(ctx context.Context, kind, value string) (IOCFact, bool, error)
}

// ConnReader is core/conn/read (the *read.Reader): the read tools of the connections and the one way to call them. A nil ConnReader
// in Config leaves connection tools out.
type ConnReader interface {
	ListReadTools(ctx context.Context) ([]read.ReadTool, error)
	CallRead(ctx context.Context, connID, tool string, args map[string]any) (string, error)
}

// UpdateRow is one update of a device as device_updates shows it (findings.UpdateAction): what to install and what it clears.
type UpdateRow struct {
	Action     string // the sentence of the Findings page: "Upgrade Mozilla Firefox from 115.0 to 128.1 or later"
	Software   string
	Version    string   // installed
	Fixed      string   // the release or build to install; "" when none is named
	CVEs       []string // worst first
	Worst      string   // highest severity among them; "" when none is scored
	Ransomware int      // exploited: CVEs known to be used in ransomware
	Likely     int      // planned: CVEs likely to be exploited soon (EPSS)
	// How each exploited finding is known: confirmed (a scan proved it), detected (the device's agent or another trusted source
	// reported the version and it is inside the affected range), reported (the agent reported the version, Vedette could not compare
	// it), suspected (a network guess: a banner, a fingerprint, the product name only).
	Confirmed, Detected, Reported, Suspected int
	// NVDLag (a recommended Windows update): the update is Microsoft's newest, newer than every fix NVD names, so it fixes at least
	// the CVEs listed; the newest update's CVEs are not analysed by NVD yet.
	NVDLag bool
}

// DeviceUpdates is what to install on one device to clear its CVEs (findings.DeviceUpdates).
type DeviceUpdates struct {
	Open      int         // open urgent findings of the device (urgency under_attack to critical_edge)
	Exploited []UpdateRow // open urgent findings a named update fixes, one row per update
	NoUpdate  []UpdateRow // open urgent findings no update is named for, one row per software
	Planned   []UpdateRow // recommended updates: CVEs on no exploited list ("Recommended updates")
	PlanRan   bool        // false: the recommended updates are not compared yet
	// PlanCompared: the last comparison included this device; false: it has no version the comparison trusts (or is newer than
	// the last comparison), so no recommended update is known, which is not "none".
	PlanCompared bool
	PlanOff      bool // the feeds module is off: recommended updates are not listed
}

// Updates is the door of the device_updates tool. A nil Updates in Config leaves the tool out.
type Updates interface {
	// DeviceUpdates returns the updates of one device by its id; ok is false when there is no such device.
	DeviceUpdates(ctx context.Context, assetID string) (DeviceUpdates, bool, error)
}
