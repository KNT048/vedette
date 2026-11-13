// Package observe is the narrow interface through which sensors and agents (sensor-passive,
// sensor-active, agent-intake, scan) report what they saw about devices to the inventory without
// importing it (rules/modules.md: modules talk through interfaces in core/). The inventory
// implements Sink, SoftwareSink and ServiceSink; everything arriving here is untrusted (SYS-6) and is validated
// by the implementation, not by the caller.
package observe

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

// ErrRejected is what a Sink returns when it refuses one observation of a batch at its boundary (before any
// write): Index is the position in the batch, Err the reason. The caller may drop that item and send the rest;
// any other error (a busy or failing store) says nothing about the items and is retried as a whole.
type ErrRejected struct { //nolint:errname // the name is the API agreed with the sensors
	Index int
	Err   error
}

func (e *ErrRejected) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("observation %d rejected", e.Index)
	}
	return e.Err.Error()
}

// Unwrap lets errors.Is see the reason (inventory.ErrInvalid).
func (e *ErrRejected) Unwrap() error { return e.Err }

// Source says who saw a value. The inventory ranks values by it (DATA_MODEL 5.1).
type Source string

// The sources of an observation.
const (
	Manual  Source = "manual"
	Agent   Source = "agent"
	SNMP    Source = "snmp"
	Nmap    Source = "nmap"
	Scan    Source = "scan"
	Passive Source = "passive"
)

// Field is the property of a device an observation is about.
type Field string

// The observable fields.
const (
	Hostname Field = "hostname"
	MAC      Field = "mac"
	Vendor   Field = "vendor"
	Model    Field = "model"
	OS       Field = "os"
	Kind     Field = "kind"
)

// ValidSource reports whether s is one of the sources.
func ValidSource(s Source) bool {
	switch s {
	case Manual, Agent, SNMP, Nmap, Scan, Passive:
		return true
	}
	return false
}

// ValidField reports whether f is one of the fields.
func ValidField(f Field) bool {
	switch f {
	case Hostname, MAC, Vendor, Model, OS, Kind:
		return true
	}
	return false
}

// AssetHint identifies the device an observation is about: the MAC first, then the IP. At least one
// must be set. A hint that matches no device creates one (unapproved, DATA_MODEL 5.1).
type AssetHint struct {
	IP  netip.Addr // IPv4 only; the zero value means unknown
	MAC string     // any common notation; stored lower-case aa:bb:cc:dd:ee:ff
}

// Observation is one thing seen about one field of one device.
type Observation struct {
	AssetHint  AssetHint
	Field      Field
	Value      string
	Source     Source
	Confidence float64   // 0..1
	SeenAt     time.Time // zero means now
}

// Sink receives observations. A batch is stored in one transaction: all of it or none of it.
type Sink interface {
	Record(ctx context.Context, obs []Observation) error
}

// Software is one package or product an agent saw on a device.
type Software struct {
	Display    string // name the user recognises
	Vendor     string
	Product    string
	Version    string // may be empty
	CPE        string // optional
	KevKeys    []string
	Confidence float64
	// Guess marks software a sensor only guessed (an OS from nmap's fingerprint, D-501): it is stored and shown, but gets no KEV match
	// keys, so it raises no finding until a person adds it with its version. A Windows release a device named in its NTLM answer is
	// one too, with a version but no patch level (D-504).
	Guess bool
	// Packaged marks an agent's row read from the operating system's package database (osquery deb_packages or rpm_packages, Wazuh's
	// deb and rpm packages, the box's dpkg list): the distribution ships its fixes, so findings can say "install your distribution's
	// security updates" (D-474, MK-2). Programs and apps from other lists are false.
	Packaged bool
}

// Approver accepts the device an enrolled agent reports on (D-503): the person who made the enrolment token and ran the install
// vouched for the machine. mac is the MAC of the agent's card that holds hint.IP ("" when it reported none): the device is approved
// only when it was never seen with another MAC, so an address DHCP gave to a new machine never approves the old machine's row.
// found says the hint points to a device at all; a device a person marked suspicious, the box, one already approved or one seen with
// another MAC is left as it is. On that same machine's row (not the box) an OS the agent reported before agents sent a kind gives the
// device its kind (AgentKindOfOS, agent rank). reason is the audit detail (which token, made by whom). agentSaw is for a caller that
// is not answering a report from the machine right now (agent-intake's job after an upgrade): the device counts as found only when
// the agent itself once reported mac on it (an agent mac observation of that value), so a stored address another machine took since,
// seen with no MAC, is never approved.
type Approver interface {
	ApproveEnrolled(ctx context.Context, hint AssetHint, mac, reason string, agentSaw bool) (found bool, err error)
}

// SoftwareSink receives the full software list of one device from one source. The list replaces the
// rows that source reported before (rows of other sources are untouched).
type SoftwareSink interface {
	ReplaceSoftware(ctx context.Context, hint AssetHint, source Source, items []Software) error
}

// Service is one port a sensor saw open on a device (D-350).
type Service struct {
	Port    int    // 1..65535
	Proto   string // "tcp" or "udp"
	Name    string // the service name, such as "ssh"; may be empty
	Product string // may be empty
	Version string // may be empty
	// Detail is what the service said about the device besides product and version (nmap's extra info and device type, the page
	// title, the certificate subject; D-511): evidence for identifying the device, never software. May be empty.
	Detail     string
	Confidence float64
}

// ServiceSink receives the full list of open ports of one device from one source. The list replaces the rows
// that source reported before (rows of other sources are untouched); an empty list says that source saw none open.
// AddServices is for a partial look (a gentle scan of a few ports): ports not listed yet are added, a port the source already
// listed keeps what it said and is only marked seen, and nothing is removed.
type ServiceSink interface {
	ReplaceServices(ctx context.Context, hint AssetHint, source Source, items []Service) error
	AddServices(ctx context.Context, hint AssetHint, source Source, items []Service) error
}
