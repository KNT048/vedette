package ai

import (
	"context"

	"github.com/knt048/vedette/core/conn/read"
)

// The doors "Ask your data" reads through (S-AI-5, D-211). ai never reads the tables of another module: cmd/vedette adapts the
// exported reads of inventory, findings and feeds to Data, and the read tools of the connections come from core/conn/read (D-127).
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
	// do not count it as a device of the network (D-422). Not sent to the model.
	IsBox bool
}

// FindingRow is a finding (a device matched to an exploited vulnerability).
type FindingRow struct {
	ID         string
	AssetID    string
	Asset      string // name of the device
	AssetIP    string
	CVE        string
	Status     string // confirmed, suspected, mitigated, patched, false_positive, not_relevant
	Severity   string
	Basis      string // version, product, scan
	Confidence float64
	Evidence   string // the summary of the scan that confirmed it; "" = none
	FirstSeen  string
	LastSeen   string
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
