package exposure

import (
	"context"
	"net/netip"
	"regexp"
	"time"

	"github.com/knt048/vedette/core/events"
)

// Event names published by this module (CONTRACT, Events).
const (
	EventScanWritten    = "exposure.scan.written"
	EventTargetVerified = "exposure.target.verified"
)

// ScanWrittenEvent is the payload of exposure.scan.written: a scan wrote its rows. Opened are the services that are open now and
// were not before this scan (new, or open again after a scan had closed them); First says the target had no rows before, so
// everything it found is new and nothing is a change (the baseline).
type ScanWrittenEvent struct {
	TargetID string     `json:"target_id"`
	RunID    string     `json:"run_id"`
	At       string     `json:"at"` // when the rows were written (RFC 3339 UTC, milliseconds)
	First    bool       `json:"first"`
	Counts   ScanCounts `json:"counts"`
	// Opened and NewIssues name the target that holds each row once the tree settled: a port this scan found on a name its child target
	// took over while it ran is the child's.
	Opened    []OpenedService `json:"opened"`
	NewIssues []NewIssue      `json:"new_issues"` // the issues that are open now and were not before this scan
}

// TargetVerifiedEvent is the payload of exposure.target.verified: a domain proved, an IP found for the
// first time, or an IP that had expired and was seen again.
type TargetVerifiedEvent struct {
	TargetID string `json:"target_id"`
}

// Publisher is the event bus as this module needs it; *events.Bus satisfies it. Events go out after
// the transaction commits and a failed publish is logged, never rolled back into the change.
type Publisher interface {
	Publish(ctx context.Context, e events.Event) error
}

// Resolver looks up TXT records; *net.Resolver satisfies it. Tests pass a fake: no test asks real DNS.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// EgressProber asks the three public "what is my IP" services once each (one round) and returns the
// address that at least two of them agree on, or ErrNoAgreement or ErrServicesDown. The answers are untrusted;
// the implementation parses them with net/netip. PublicServiceProber is the real one.
type EgressProber interface {
	Round(ctx context.Context) (netip.Addr, error)
}

// ScanTarget is what the scan module is told about the target it scans. User is who asked: the actor of the checks the runner
// makes through ScannableIP.
type ScanTarget struct {
	ID    string
	Kind  Kind
	Value string
	User  string
	// Mode is what this scan may do: Full once the target's testing terms are accepted, else the basic scope. Every
	// scanner seam reads it here, and only here.
	Mode ScanMode
	// SkipPorts are the TCP ports this scan leaves out on every address (the target's deep-scan settings): no engine is sent to
	// them and nothing is concluded about them. SkipPaths are URL path prefixes the web scans leave out (ZAP; nuclei by the first
	// request of a template, as far as it can tell). Gentle is the slower speed. None of them is a permission; they only narrow.
	SkipPorts []int
	SkipPaths []string
	Gentle    bool
	// Typed: the target is a public IP a person typed in (INV-35); its proof is looked for again before the steps that reach the address.
	Typed bool
	// TypedWhy is, for a typed IP whose deep steps cannot run, the line that says why (no testing terms, no fence, the proof not found): the
	// executors take nothing without a scope, so the steps say this instead of reaching the box-only fence.
	TypedWhy string
	// Domain is set on a deep step of a domain's scan sent to a public address that is not the box's own verified IP:
	// the domain, the name under it that resolved to the address at the core-side re-check right before the step, and the
	// domain's box-bound token from DomainFence. The scanner then runs the job with scope domain_ip and its executor checks the fence
	// itself. nil on every other step: an IP target, a domain's by-name checks, or a deep step to the box's own IP.
	Domain *DomainScope
	// Proof is, on a domain's scan, the domain target whose record proved it at the gate (the target itself, or a parent of the box
	// that covers it) with that target's stored token: the host's re-check of a web page asks that domain's record (ZAP).
	Proof *ProofOwner
	// ProvenAt is, on the scan of an IP the box found as its own egress, the latest sighting of it that the gate took it on
	// (Target.ownProof): the executors' own-IP fences (the host's ZAP fence) take the address on it while the box goes out through
	// another line, for ValidDays from it. Zero on every other target.
	ProvenAt time.Time
	// Names is, on a domain's scan, which names under it this scan reaches (its scope, without the names its enabled children scan
	// themselves), read when the scan starts. The runner lists the other names it finds without probing them (Content.Listed); nil on an
	// IP target.
	Names *NamePlan
	// Grant is, on a page of the active web scan that asks for the disruptive rules, the host's grant of the person's press that
	// started the scan (DisruptiveGranter); "" when none came. The host runs the disruptive rules only with one that holds.
	Grant string
	// dropped says why deepGate took the disruptive checks out of a step the run allowed them on (dropNotOwn, dropCNAME, dropNAT);
	// "" when it did not. Only the lines of the deep scan read it.
	dropped string
}

// ProofOwner is the domain whose record proves a scanned domain, and that domain's stored token. ProofAt is set when the
// record is the domain's own on a parent name of it (the zone apex): Domain is then the scanned target itself.
type ProofOwner struct{ Domain, Token, ProofAt string }

// DomainScope is the domain_ip scope of one deep step: the job fields {domain, name, ip, token} without the
// address and ports, which the seam call carries.
type DomainScope struct {
	Domain string // the verified domain (the target's value)
	Name   string // the domain itself or a name under it that resolved to the address right before the step
	Token  string // the domain's box-bound token (16 hex), from DomainFence
	// ProofAt is the parent name of Domain (the zone apex) where Domain's own record sits, which the executors check instead
	// of Domain; "" when the record is on Domain (or on _vedette-verify.<Domain>).
	ProofAt string
	// Chain is Name's CNAME chain as core saw it right before the step ("www.acme.example -> acme.edge.example.net"; just the name
	// without a CNAME; "" when the lookup failed), written in the step's probe-log row.
	Chain string
	// Typed is set for a step to a public IP a person typed in (INV-35): Domain, Name and Chain are then the IP literal, Token is the
	// box-bound token of that literal, and the executors check the IP's own proof (the token file, or reverse DNS) instead of a domain's record.
	Typed *TypedScope
}

// TypedScope is the proof the executors check again for a typed IP: the method, and for reverse DNS the PTR name and the domain of this box
// that proves it (its box-bound token, and the parent name its record sits on when it is not its own).
type TypedScope struct {
	Method       string // "file" or "ptr"
	PTRName      string
	CoverDomain  string
	CoverToken   string
	CoverProofAt string
}

// DomainFence gives the box-bound token of a verified domain (host op exposure.token: hex HMAC-SHA256 of the
// host's fence key over the domain, first 16 characters). Core never holds the key. Config.DomainFence nil means
// this box has no domain fence: no deep step goes to a public address that is not the box's own verified IP.
type DomainFence interface {
	Token(ctx context.Context, domain string) (string, error)
}

// HostResolver looks up a name's addresses; *net.Resolver satisfies it. The core-side re-check of a deep step to a domain's address
// asks it through Config.Resolver: a Resolver that does not implement it fails closed. Tests pass a fake: no test asks real DNS.
type HostResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Runner does the scan itself. It belongs to the scan module, which registers it with
// Service.SetRunner; exposure only decides whether a scan may happen (INV-1) and keeps the result.
// What it returns came from other hosts, so the service limits it before storing it (INV-10).
type Runner interface {
	Scan(ctx context.Context, t ScanTarget) (Content, error)
}

// PathChecker measures the vantage of a run (observe.go): what the network between the box and the Internet answers on a port for an
// address that is never routed (the RFC 5737 documentation ranges). A firewall's SIP or SCCP helper, a transparent proxy or a SYN proxy
// accepts a connect for any destination; an egress filter refuses one for any destination. Either way what the box sees on that port
// says nothing about a target (INV-44). cmd/vedette implements it with plain TCP connects that reach no one.
type PathChecker interface {
	// PathAnswers says, for each of ports, what a TCP connect to the never-routed addresses got: PortOpen (accepted), PortClosed (a
	// reset, or an ICMP refusal) or PortSilent (no answer), as two of the three addresses agree (PortSilent when they do not). An
	// error: nothing is known of these ports this run.
	PathAnswers(ctx context.Context, ports []int) (map[int]string, error)
	// SameAsPath says whether what ip answers on port (on a web or TLS port the TLS certificate, else the status, Server header and
	// page title of GET /; on any other port the banner a server that speaks first sends, nothing sent) is what a never-routed
	// address gets through the same network on that port: true when it is the network's own answer (a proxy's error page,
	// certificate or banner, or nothing sent by either), false when the target's own service answered. An error when nothing was
	// compared, a web or TLS read of the target that got no answer among them: the port stays the network's, its row is not retired.
	SameAsPath(ctx context.Context, ip netip.Addr, port int) (bool, error)
}

// Gateway tells the page which device probably answers the open ports of the box's public IP (S-EXP-1). cmd/vedette
// implements it from the host's default route, the inventory and the findings; exposure reads no other module's tables.
type Gateway interface {
	Gateway(ctx context.Context) (GatewayDevice, error)
}

// Appliances finds the inventory devices of the appliance families (content/adminpages) that ports on the Internet name (INV-33),
// all families in one read. cmd/vedette implements it from the inventory and the findings; exposure reads no other module's tables.
type Appliances interface {
	ApplianceDevices(ctx context.Context, qs []ApplianceQuery) (map[string]ApplianceMatch, error)
}

// ApplianceQuery says what makes a device one of a family: a device type of Kinds ("" and "unknown" included when listed), and its own
// vendor, model or OS that Device matches, or a software row with one of KevKeys (KEV vendor|product of the family's own OS, lower
// case). A PC, a switch, an access point or a NAS of the same vendor is not the family's appliance.
type ApplianceQuery struct {
	Family  string
	KevKeys []string
	Device  *regexp.Regexp
	Kinds   []string
}

// ApplianceMatch is the devices of one family: at most MaxApplianceDevices, More the others.
type ApplianceMatch struct {
	Devices []ApplianceDevice
	More    int
}

// GatewayDevice is the LAN default gateway and what Vedette knows of it. IP is the zero value when the box cannot tell its gateway;
// DeviceID is empty when no inventory device has that IP. Name is an untrusted label. OpenExploited counts the open findings
// (confirmed or suspected) of the device.
type GatewayDevice struct {
	IP            netip.Addr
	DeviceID      string
	Name          string
	OpenExploited int
}
