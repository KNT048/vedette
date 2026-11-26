package sensorlink

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"time"

	"github.com/knt048/vedette/internal/jsonstrict"
)

// The bodies of the protocol (sensor-protocol.md section 6). Decoding is strict (internal/jsonstrict: unknown field, repeated
// key, nesting over 32 and trailing data are errors) and the decoders check what is structural about the whole body: sizes,
// counts, types, ranges. What is about one observation (a MAC that does not match, a value that is dirty, a time outside the
// window) is not checked here: core answers those item by item in rejected[].

// Config is the answer to GET /config (passive): what the capture process may do right now.
type Config struct {
	Interface string   `json:"interface"` // "" = do not capture
	Span      bool     `json:"span"`
	Extract   Extract  `json:"extract"`
	Filters   []Filter `json:"filters"`
}

// Extract holds the four metadata switches.
type Extract struct {
	DNS   bool `json:"dns"`
	SNI   bool `json:"sni"`
	HTTP  bool `json:"http"`
	Flows bool `json:"flows"`
}

// Filter is one exclusion rule: Type is cidr, host or port.
type Filter struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ConfigReply is what a Backend returns for GET /config. NotModified answers 304 (the sensor's ETag is current).
type ConfigReply struct {
	NotModified bool
	ETag        string
	Config      Config
}

// ObservationsRequest is the body of POST /observations.
type ObservationsRequest struct {
	Epoch string            `json:"epoch"`
	Seq   int64             `json:"seq"`
	Items []ObservationItem `json:"items"`
}

// ObservationItem is one thing a sensor saw. There is deliberately no source: core sets it from the role.
type ObservationItem struct {
	MAC        string    `json:"mac,omitempty"`
	IP         string    `json:"ip,omitempty"`
	Field      string    `json:"field"`
	Value      string    `json:"value"`
	Confidence float64   `json:"confidence"`
	SeenAt     time.Time `json:"seen_at"`
}

// ObservationsReply is the 200 of POST /observations: partial success, never retried.
type ObservationsReply struct {
	AckSeq   int64      `json:"ack_seq"`
	Rejected []Rejected `json:"rejected"`
}

// Rejected is one refused item: its index in the request and why (invalid_item, out_of_window, budget_exhausted, refused).
type Rejected struct {
	Index int    `json:"index"`
	Code  string `json:"code"`
}

// MetadataRequest is the body of POST /metadata (passive role): what the capture read on a mirror port, reduced to what the
// bad-address matching needs: which LAN address asked for which name, or opened a flow to which address. Nothing else of a
// packet is on the wire (no port, no counter, no payload), and core keeps none of it: only the matches with a threat feed are
// stored. There is no epoch and no seq: a batch sent twice makes the same matches, which core keeps once.
type MetadataRequest struct {
	Items []MetadataItem `json:"items"`
}

// MetadataItem is one thing seen on the mirror port. Kind is one of MetaKinds; Src is the IPv4 address of the LAN device; Dest is
// the name it asked for or connected to (dns, sni, http: lower case, no trailing dot) or the IPv4 address of a flow.
type MetadataItem struct {
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
	Src  string    `json:"src"`
	Dest string    `json:"dest"`
}

// The kinds of a MetadataItem.
const (
	MetaDNS  = "dns"  // a DNS query name
	MetaSNI  = "sni"  // the server name of a TLS ClientHello
	MetaHTTP = "http" // the Host header of an HTTP request
	MetaFlow = "flow" // the destination address of an IPv4 flow
)

// MetaKinds is the closed set of metadata kinds.
var MetaKinds = []string{MetaDNS, MetaSNI, MetaHTTP, MetaFlow}

// PassiveHeartbeat is the heartbeat body of the passive role.
type PassiveHeartbeat struct {
	Version     string           `json:"version"`
	Interfaces  []HeartbeatIface `json:"interfaces"`
	Span        HeartbeatSpan    `json:"span"`
	Drops       map[string]int64 `json:"drops"`
	DevicesSeen int64            `json:"devices_seen"`
	// CaptureError says why the capture on the chosen card is not running now (proto 4): one of CaptureErrors, "" (or
	// absent) while it runs or while no card is chosen. Never the error text: that stays in the sensor's log.
	CaptureError string `json:"capture_error,omitempty"`
}

// The reasons a passive heartbeat may give in capture_error (sensor-protocol.md 6.3). A reason of a good shape outside this set is
// shown by core as CaptureFailed, so a newer sensor does not make core refuse its heartbeat (like DropKeys).
const (
	CaptureNoPermission   = "no_permission"   // the capture socket cannot be opened: no CAP_NET_RAW (rootless Docker or Podman)
	CaptureNoInterface    = "no_interface"    // the card core named is not on this machine
	CaptureFiltersInvalid = "filters_invalid" // the filters from core cannot be read: nothing is captured until they change
	CaptureFailed         = "capture_failed"  // anything else: the capture opened and failed, or could not open for another reason
)

// CaptureErrors is the closed set of capture_error reasons.
var CaptureErrors = []string{CaptureNoPermission, CaptureNoInterface, CaptureFiltersInvalid, CaptureFailed}

// HeartbeatIface is one network card the sensor sees.
type HeartbeatIface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	Link bool     `json:"link"`
	IPv4 []string `json:"ipv4"`
}

// HeartbeatSpan is what the sensor measured on the SPAN port.
type HeartbeatSpan struct {
	PPS          int64      `json:"pps"`
	OtherMACs    int64      `json:"other_macs"`
	LastPacketAt *time.Time `json:"last_packet_at"`
}

// ActiveHeartbeat is the heartbeat body of the active role.
type ActiveHeartbeat struct {
	Version string          `json:"version"`
	Nmap    HeartbeatNmap   `json:"nmap"`
	Nuclei  HeartbeatNuclei `json:"nuclei"`
	// SNMP (protocol 5) says the worker runs snmp jobs. A worker of protocol 4 leaves it out: core then never sends it one,
	// so the jobs reply such a worker gets keeps the shape of protocol 4.
	SNMP bool `json:"snmp,omitempty"`
	// DomainIP (protocol 5) says the worker runs domain_ip jobs (nmap's full shapes and nuclei at depth full
	// on an address a name under a verified domain resolves to): it holds the box's fence key and checks the domain fence itself
	// (core/domainfence). A worker without the key (a remote sensor, a container-only install, an older worker) leaves it out: core
	// then never sends it one.
	DomainIP bool `json:"domain_ip,omitempty"`
	// TypedIP says the worker also checks the proof of a typed public IP in a domain_ip job (a job with DomainScope.Typed). A worker
	// with DomainIP and without TypedIP never gets one.
	TypedIP bool `json:"typed_ip,omitempty"`
	// OwnProof says the worker takes core's ownership proof of the box's own public IP (Job.ProvenAt, NucleiJob.ProvenAt): an
	// external nmap job or an own_ip nuclei job whose proof holds (egressip.ProofHolds) runs without a fresh sighting of the
	// address. A worker that leaves it out gets no proof: core then sends the job as before and the worker's own sighting decides.
	OwnProof bool `json:"own_proof,omitempty"`
}

// ScopeDomainIP is the scope of a domain_ip job: one public IPv4 target that is not the box's own egress, reached because a
// name under a verified domain resolves to it; the job carries Domain and the worker checks the domain fence before the tool starts.
const ScopeDomainIP = "domain_ip"

// DomainScope is what a domain_ip job carries for the worker's fence (plan 2026-11-14 §5): the verified domain, the name under it that
// resolved to the job's one target, and the box-bound token core got from vedette-host (exposure.token). The worker re-derives the
// token from its own key; core's word is not trusted for it.
type DomainScope struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Token  string `json:"token"`
	// ProofAt: the name above Domain where Domain's token sits (the zone apex or a parent name), checked there by the worker's fence;
	// Name may then be any name under ProofAt, not only under Domain. Omitted when the record is on Domain. A worker that does not
	// know the field, or this meaning of it, refuses the job as invalid_job (the check fails closed).
	ProofAt string `json:"proof_at,omitempty"`
	// Typed (protocol 5, heartbeat typed_ip): the job is for a public IP a person typed in, proved by its own token file or by reverse
	// DNS instead of a domain's record. Domain and Name are then the IP literal and Token is the box-bound token of that literal; the
	// worker checks the proof itself (core/domainfence). A worker that does not know the field refuses the job (invalid_job), and core
	// sends it only to a worker whose heartbeat says typed_ip.
	Typed *TypedScope `json:"typed,omitempty"`
}

// TypedScope is the proof of a typed IP a job carries: Method "file" (the token file served on the IP) or "ptr" (the IP's reverse DNS
// name, proved by a domain of this box: its box-bound token and, when its record sits on a parent name, that name).
type TypedScope struct {
	Method       string `json:"method"`
	PTRName      string `json:"ptr_name,omitempty"`
	CoverDomain  string `json:"cover_domain,omitempty"`
	CoverToken   string `json:"cover_token,omitempty"`
	CoverProofAt string `json:"cover_proof_at,omitempty"`
}

// HeartbeatNmap says whether the worker can run nmap.
type HeartbeatNmap struct {
	Present bool   `json:"present"`
	Version string `json:"version"`
	// Full (protocol 5) says the worker runs the external_full and external_disruptive shapes, behind its own-IP fence. An
	// older worker leaves it out: core then never sends it one.
	Full bool `json:"full,omitempty"`
	// Ports (protocol 5) says the worker runs the port_versions shape, whose job carries its ports. An older worker leaves it
	// out: core then never sends it one (the weekly scan of every port then records the open ports without their versions).
	Ports bool `json:"ports,omitempty"`
}

// HeartbeatNuclei says whether the worker can run nuclei: Present is "the pinned binary runs -version"; Pack is
// the version and SHA-256 of the template pack whose index the worker read from its image, both "" when there is none.
type HeartbeatNuclei struct {
	Present bool          `json:"present"`
	Version string        `json:"version"`
	Pack    HeartbeatPack `json:"pack"`
	// OwnIP (protocol 5) says the worker runs nuclei jobs of scope own_ip, with its own-IP fence. An older worker leaves it
	// out: core then never sends it one.
	OwnIP bool `json:"own_ip,omitempty"`

	// protocol 5 before its first release: Full says the worker runs nuclei jobs of depth full (the deep scan of the
	// box's own public IP, with the own-IP fence and the pack's sets). An older worker leaves it out: core then never sends it one.
	Full bool `json:"full,omitempty"`
}

// HeartbeatPack names the template pack baked into the scan image.
type HeartbeatPack struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// JobsReply is the answer to GET /jobs (active).
type JobsReply struct {
	Instance string   `json:"instance"`
	Jobs     []Job    `json:"jobs"`
	Cancel   []string `json:"cancel"`
}

// Job kinds (protocol 2; snmp: protocol 5). A job that carries no kind is an nmap job: the kind is the only thing protocol 2 added to
// nmap's.
const (
	KindNmap   = "nmap"
	KindNuclei = "nuclei"
	KindSNMP   = "snmp"
)

// Job is one job of the worker. There is no argv, flag, path or URL on the wire: the worker builds the command
// itself. An nmap job fills Shape, Rate and Targets; a nuclei job fills Nuclei (its fields sit at the top level on the wire:
// pack, templates, targets, rate, max_host_errors). A kind this version does not know decodes to a Job with only ID and
// Kind, so the worker can refuse it (invalid_job) instead of failing the whole poll; whatever else the object holds is not read.
type Job struct {
	ID       string
	Kind     string // "nmap", "nuclei", or "" (= nmap, a job of a core that does not send the kind)
	TimeoutS int

	Shape   string   // nmap
	Rate    int      // nmap
	Targets []string // nmap
	// Scope and Domain (protocol 5): an nmap job of a full shape with Scope ScopeDomainIP carries Domain (its one target is the
	// address); "" and nil on every other nmap job, which keeps the shape an older worker knows.
	Scope  string
	Domain *DomainScope
	// Ports (protocol 5) are the ports of a port_versions job (1..20, ascending), sent only to a worker whose heartbeat says
	// nmap.ports, and of an external -sV batch (1..40, ascending, with HostTimeoutS); nil on every other nmap job, which keeps the
	// shape an older worker knows. A worker from before the external discovery runs its own earlier line for the discovery job,
	// which core recognises and reports as an older worker before sending any batch.
	Ports []int
	// HostTimeoutS is the --host-timeout in seconds of an external -sV batch (nmapargv.BatchFlags: 60..120), the only nmap job
	// whose host timeout core picks from the time left; 0 on every other job (omitempty keeps their shape). A worker built before
	// this field decodes jobs strictly and fails its whole poll on it, so the batch job expires unread (ErrWorkerLost) and the
	// service step keeps the batches that finished; only while the box updates.
	HostTimeoutS int
	// ProvenAt is, on an nmap job of an external shape (external, external_full, external_disruptive; never domain_ip), the latest
	// sighting of its one target as the box's own public IP, from which the address stays proven for egressip.ProofValid. Core
	// sends it only to a worker whose heartbeat says own_proof; nil on every other job, which keeps the shape an older worker knows.
	ProvenAt *time.Time

	Nuclei *NucleiJob // nuclei, nil for the others
	SNMP   *SNMPJob   // snmp, nil for the others
}

// SNMPJob is a round of SNMP reads (protocol 5): for each target, in order, the worker sends the target's own
// credential to the target's address and nowhere else, with read-only GETs of a fixed list of objects it owns (no object identifier
// is on the wire, as no argv is). Rate is packets a second. A credential travels inside its target: SNMP is set up
// per device, and the secret of a device goes only to that device's read address, so the wire has no way to name another one.
type SNMPJob struct {
	Rate    int          `json:"rate"`
	Targets []SNMPTarget `json:"targets"`
}

// SNMPCredential is one way to sign in to an SNMP agent. Version is "v2c" (Community) or "v3" (User, Auth "sha" or "sha256" with
// AuthPass, Priv "aes128" with PrivPass, or Priv "" for authNoPriv). Port is the UDP port the agent answers on: 0 (left out of the
// JSON) is SNMPPort, 161. Port was added to protocol
// 5 before its first release, as the nuclei job's scope was: core leaves it out for 161, so a worker built before it gets the shape it
// knows for every credential of the default port. It holds secrets: printing or logging it gives "[redacted]"; only the JSON of the
// job carries them, inside the mutual-TLS link.
type SNMPCredential struct {
	Version   string `json:"version"`
	Port      int    `json:"port,omitempty"`
	Community string `json:"community,omitempty"`
	User      string `json:"user,omitempty"`
	Auth      string `json:"auth,omitempty"`
	AuthPass  string `json:"auth_pass,omitempty"`
	Priv      string `json:"priv,omitempty"`
	PrivPass  string `json:"priv_pass,omitempty"`
}

// Format implements fmt.Formatter for every verb: the credential never reaches a log line through fmt.
func (SNMPCredential) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("[redacted]")) }

// SNMPTarget is one device of an snmp job: the address its reads go to (the device's read address) and its credential.
type SNMPTarget struct {
	IP         string         `json:"ip"`
	Credential SNMPCredential `json:"credential"`
}

// The limits of an snmp job (sensor-protocol.md section 9).
const (
	MaxSNMPTargets = 64  // targets of a job, like an nmap batch
	MaxSNMPValue   = 512 // bytes of one value of an answer (an SNMP DisplayString is at most 255)
	MaxSNMPSeconds = 3600
	SNMPPort       = 161 // the UDP port of an SNMP agent (RFC 3417), what a credential without a port is sent to
)

// The per-target statuses of an snmp result.
const (
	SNMPStatusOK          = "ok"           // the agent answered
	SNMPStatusNoAnswer    = "no_answer"    // nothing came back: no agent, a firewall, or a wrong v2c community (an agent drops those silently)
	SNMPStatusAuthFailed  = "auth_failed"  // v3: the agent said the digest is wrong or it could not decrypt
	SNMPStatusUnknownUser = "unknown_user" // v3: the agent does not know the user
	SNMPStatusError       = "error"        // anything else: an error status, a message that does not decode
)

// The versions and algorithms of an SNMPCredential (no v1, no MD5, no DES, no noAuthNoPriv).
const (
	SNMPv2c        = "v2c"
	SNMPv3         = "v3"
	SNMPAuthSHA    = "sha"
	SNMPAuthSHA256 = "sha256"
	SNMPPrivAES128 = "aes128"
)

// SNMPStatuses is the closed set of the per-target statuses of an snmp result.
var SNMPStatuses = []string{SNMPStatusOK, SNMPStatusNoAnswer, SNMPStatusAuthFailed, SNMPStatusUnknownUser, SNMPStatusError}

// SNMPAnswer is what the worker got from one target with its credential: the status and, when Status is ok, the values the agent
// gave. Every value is untrusted text (SYS-6).
type SNMPAnswer struct {
	Target string     `json:"target"`
	Status string     `json:"status"`
	Values SNMPValues `json:"values"`
}

// SNMPValues are the objects the worker reads ("" when the agent has none): MIB-2 system, ENTITY-MIB entPhysical for index 1, and
// MikroTik's software version.
// EntClass is entPhysicalClass as a decimal number, SysObjectID a dotted object identifier.
type SNMPValues struct {
	SysDescr    string `json:"sys_descr"`
	SysObjectID string `json:"sys_object_id"`
	SysName     string `json:"sys_name"`
	EntClass    string `json:"ent_class"`
	EntModel    string `json:"ent_model"`
	EntSoftware string `json:"ent_software"`
	EntSerial   string `json:"ent_serial"`
	// OSVersion is a vendor MIB's software version, read only for the device that has it: MIKROTIK-MIB mtxrLicVersion.0, the
	// RouterOS version ("6.49.10"), which MikroTik's sysDescr ("RouterOS RB4011iGS+") does not carry (#910, #919).
	OSVersion string `json:"os_version,omitempty"`
}

func (v SNMPValues) all() []string {
	return []string{v.SysDescr, v.SysObjectID, v.SysName, v.EntClass, v.EntModel, v.EntSoftware, v.EntSerial, v.OSVersion}
}

// CheckSNMPJob is the grammar of an snmp job, the same for core before it dispatches and for the worker before it sends anything: a
// rate of 1..1000 and 1..64 unique canonical IPv4 targets (local is checked by the caller with core/localnet, which this package does
// not import), each with one credential of a known shape (a v2c community or a v3 user of 1..64 printable characters, v3 passwords of
// 8..64, a port of 1..65535 or none).
func CheckSNMPJob(j *SNMPJob) error {
	if j == nil {
		return invalid("snmp job")
	}
	if j.Rate < 1 || j.Rate > 1000 {
		return invalid("snmp rate")
	}
	if len(j.Targets) < 1 || len(j.Targets) > MaxSNMPTargets {
		return invalid("snmp targets")
	}
	seen := map[string]bool{}
	for _, t := range j.Targets {
		a, err := netip.ParseAddr(t.IP)
		if err != nil || !a.Is4() || a.String() != t.IP || seen[t.IP] {
			return invalid("snmp target")
		}
		seen[t.IP] = true
		if err := checkSNMPCredential(t.Credential); err != nil {
			return err
		}
	}
	return nil
}

// printable reports whether s is lo..64 bytes of printable ASCII (a community, a v3 user or password).
func printable(s string, lo int) bool {
	if len(s) < lo || len(s) > 64 {
		return false
	}
	for _, c := range []byte(s) {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func checkSNMPCredential(c SNMPCredential) error {
	if c.Port < 0 || c.Port > 65535 {
		return invalid("snmp port")
	}
	switch c.Version {
	case SNMPv2c:
		if !printable(c.Community, 1) || c.User != "" || c.Auth != "" || c.AuthPass != "" || c.Priv != "" || c.PrivPass != "" {
			return invalid("snmp v2c credential")
		}
	case SNMPv3:
		switch {
		case c.Community != "" || !printable(c.User, 1):
			return invalid("snmp v3 user")
		case c.Auth != SNMPAuthSHA && c.Auth != SNMPAuthSHA256, !printable(c.AuthPass, 8):
			return invalid("snmp v3 authentication")
		case c.Priv == "" && c.PrivPass != "", c.Priv != "" && (c.Priv != SNMPPrivAES128 || !printable(c.PrivPass, 8)):
			return invalid("snmp v3 privacy")
		}
	default:
		return invalid("snmp version")
	}
	return nil
}

// NucleiJob is what a nuclei run is made of: template ids, never paths; the worker maps them
// through the index of the pack named here. Scope (protocol 5) is "" or "lan" (private targets, the scan module) or
// "own_ip" (one public target, the box's own IP, for exposure: the worker checks by itself that the box goes out through it
// before nuclei starts). Core leaves it out of a LAN job, so an older worker gets the shape it knows.
type NucleiJob struct {
	Pack          JobPack        `json:"pack"`
	Templates     []string       `json:"templates"`
	Targets       []NucleiTarget `json:"targets"`
	Rate          int            `json:"rate"`
	MaxHostErrors int            `json:"max_host_errors"`
	Scope         string         `json:"scope,omitempty"`

	// protocol 5 before its first release, as scope: the depth of an own_ip job. Depth is "" (the read-only KEV
	// checks) or "full" (the deep scan of a target whose testing terms were accepted: nucleiargv's full shape, templates of
	// the pack's deep set); Disruptive (full only) adds the disruptive set (the extra tick of the terms). Core leaves both out of
	// every other job and sends a full one only to a worker whose heartbeat said nuclei.full, so an older decoder never gets one;
	// if it did, strict decoding refuses it and nothing runs.
	Depth      string `json:"depth,omitempty"`
	Disruptive bool   `json:"disruptive,omitempty"`
	// Domain: the fence fields of a job of scope domain_ip (depth full only); nil on every other job.
	Domain *DomainScope `json:"domain,omitempty"`
	// ProvenAt: on a job of scope own_ip, the latest sighting of its one target as the box's own public IP (Job.ProvenAt); sent only
	// to a worker whose heartbeat says own_proof, nil on every other job.
	ProvenAt *time.Time `json:"proven_at,omitempty"`
}

// JobPack names the pack a job was planned against.
type JobPack struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// NucleiTarget is one place nuclei sends requests to. Scheme is "http", "https" or "" (a network template on host:port).
type NucleiTarget struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
}

type nmapWire struct {
	ID       string       `json:"id"`
	Kind     string       `json:"kind,omitempty"`
	Shape    string       `json:"shape"`
	Rate     int          `json:"rate"`
	Targets  []string     `json:"targets"`
	TimeoutS int          `json:"timeout_s"`
	Scope    string       `json:"scope,omitempty"`
	Domain   *DomainScope `json:"domain,omitempty"`
	Ports    []int        `json:"ports,omitempty"`
	HostS    int          `json:"host_timeout_s,omitempty"`
	ProvenAt *time.Time   `json:"proven_at,omitempty"`
}

type nucleiWire struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	TimeoutS int    `json:"timeout_s"`
	NucleiJob
}

type snmpWire struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	TimeoutS int    `json:"timeout_s"`
	SNMPJob
}

// MarshalJSON writes the job in the shape of its kind.
func (j Job) MarshalJSON() ([]byte, error) {
	switch j.Kind {
	case "", KindNmap:
		return json.Marshal(nmapWire{ID: j.ID, Kind: j.Kind, Shape: j.Shape, Rate: j.Rate, Targets: j.Targets, TimeoutS: j.TimeoutS, Scope: j.Scope, Domain: j.Domain, Ports: j.Ports, HostS: j.HostTimeoutS, ProvenAt: j.ProvenAt})
	case KindNuclei:
		if j.Nuclei == nil {
			return nil, errors.New("sensorlink: a nuclei job without its fields")
		}
		return json.Marshal(nucleiWire{ID: j.ID, Kind: j.Kind, TimeoutS: j.TimeoutS, NucleiJob: *j.Nuclei})
	case KindSNMP:
		if j.SNMP == nil {
			return nil, errors.New("sensorlink: an snmp job without its fields")
		}
		return json.Marshal(snmpWire{ID: j.ID, Kind: j.Kind, TimeoutS: j.TimeoutS, SNMPJob: *j.SNMP})
	}
	return json.Marshal(struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}{j.ID, j.Kind})
}

// UnmarshalJSON reads a job strictly (unknown fields are errors; repeated keys were already refused by the caller's
// jsonstrict pass, which walks nested objects too), by its kind.
func (j *Job) UnmarshalJSON(raw []byte) error {
	var head struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return err
	}
	strict := func(v any) error {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		return dec.Decode(v)
	}
	switch head.Kind {
	case "", KindNmap:
		var w nmapWire
		if err := strict(&w); err != nil {
			return err
		}
		*j = Job{ID: w.ID, Kind: w.Kind, Shape: w.Shape, Rate: w.Rate, Targets: w.Targets, TimeoutS: w.TimeoutS, Scope: w.Scope, Domain: w.Domain, Ports: w.Ports, HostTimeoutS: w.HostS, ProvenAt: w.ProvenAt}
	case KindNuclei:
		var w nucleiWire
		if err := strict(&w); err != nil {
			return err
		}
		n := w.NucleiJob
		*j = Job{ID: w.ID, Kind: w.Kind, TimeoutS: w.TimeoutS, Nuclei: &n}
	case KindSNMP:
		var w snmpWire
		if err := strict(&w); err != nil {
			return err
		}
		n := w.SNMPJob
		*j = Job{ID: w.ID, Kind: w.Kind, TimeoutS: w.TimeoutS, SNMP: &n}
	default:
		*j = Job{ID: head.ID, Kind: head.Kind}
	}
	return nil
}

// JobResult is the body of POST /jobs/{id}/result.
type JobResult struct {
	Status    string `json:"status"` // done, failed, stopped, refused
	Reason    string `json:"reason"`
	ExitCode  int    `json:"exit_code"`
	Truncated bool   `json:"truncated"`
	XMLB64    string `json:"xml_b64"`             // nmap's stdout
	JSONLB64  string `json:"jsonl_b64,omitempty"` // nuclei's stdout (protocol 2); a result carries at most one of the two
	// HostErrors (protocol 3, nuclei only): per target, the timeouts nuclei logged, so core can see a device stop answering
	// when stdout holds matches only (scan INV-6). At most MaxHostErrors entries, one per target, only for targets with
	// at least one timeout.
	HostErrors []HostError `json:"host_errors,omitempty"`
	// SNMP (protocol 5, snmp jobs only): one answer per target the worker got to, only on a done result.
	SNMP []SNMPAnswer `json:"snmp,omitempty"`

	xml   []byte // the decoded XMLB64, set by the server's decoder
	jsonl []byte // the decoded JSONLB64
}

// JobProgress is the body of POST /jobs/{id}/progress (protocol 5, #830): how far a running nmap or nuclei job is, read by the
// worker from what the tool prints anyway (nmap's <taskprogress> lines of --stats-every, nuclei's -ms lines). Advisory only: core
// shows it and never decides anything from it. The worker sends at most one every ProgressEvery per job and never retries one.
type JobProgress struct {
	Phase string `json:"phase"` // one of ProgressPhases
	// Percent of the phase, 0..100; -1 when the tool gave none (nuclei: Done and Total say it).
	Percent float64 `json:"percent"`
	// Done and Total count template x target checks of a nuclei job (0 and 0: no count); 0 <= Done <= Total <= MaxProgressCount.
	Done  int64 `json:"done"`
	Total int64 `json:"total"`
	// RemainingS is the tool's own estimate of the seconds left in the phase (nmap's "remaining"), 0 when none, at most MaxProgressRemaining.
	RemainingS int `json:"remaining_s"`
}

// ProgressPhases are the phases a worker may report: nmap's host discovery, port scan, service detection and scripts, and
// nuclei's checks.
var ProgressPhases = []string{"discovery", "ports", "services", "scripts", "vulns"}

// MaxProgressCount bounds Done and Total of a JobProgress, MaxProgressRemaining its RemainingS (nmap caps its own estimate at 10
// days; a job lives at most 2 hours, so more is noise).
const (
	MaxProgressCount     = 1 << 20
	MaxProgressRemaining = 86400
)

// HostError is the timeout count of one target of a nuclei job.
type HostError struct {
	Target      string `json:"target"`      // host:port of one of the job's targets
	Errors      int    `json:"errors"`      // 1..MaxHostErrorCount
	Unreachable bool   `json:"unreachable"` // the worker's verdict: Errors reached the job's max_host_errors
}

// MaxHostErrorCount caps HostError.Errors.
const MaxHostErrorCount = 1 << 20

type instanceReply struct {
	Instance string `json:"instance"`
}

var (
	errInvalid  = errors.New("invalid body")
	errTooLarge = errors.New("payload too large")

	epochRE    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	jobIDRE    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	versionRE  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	ifaceRE    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
	macRE      = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	dropKeyRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	packVerRE  = regexp.MustCompile(`^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,4}$`)
	sha256RE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nmapVerRE  = regexp.MustCompile(`^[0-9A-Za-z._+-]{0,32}$`)
	hostPortRE = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{1,5}$`)
	etagRE     = regexp.MustCompile(`^"[A-Za-z0-9._:-]{1,64}"$`)
	resultCode = map[string]bool{"": true, "invalid_job": true, "busy": true, "nmap_missing": true, "nuclei_missing": true, "pack_mismatch": true, "pack_invalid": true, "exec_failed": true, "deadline": true, "cancelled": true, "not_own_ip": true, "egress_unverified": true,
		// The refusals of the domain fence (core/domainfence.Reasons; invalid_job is above)
		"token_foreign": true, "target_not_owned": true, "name_moved": true, "ownership_unchecked": true, "cname_outside": true}
	resultStat = map[string]bool{"done": true, "failed": true, "stopped": true, "refused": true}
)

const maxSeq = 1<<53 - 1

// The limits of the passive heartbeat (sensor-protocol.md section 9).
const (
	MaxHeartbeatIfaces   = 32
	MaxHeartbeatPrefixes = 8
	MaxDropKeys          = 64
)

// DropKeys is the set of the counters a passive heartbeat carries in drops (sensor-protocol.md 6.3): what the capture process
// counts instead of passing on. A key outside it (of a good shape) is ignored by core and logged once, so a newer sensor does
// not make core refuse its heartbeat. The capture package's tests check that every counter the capture can produce is here.
var DropKeys = []string{
	"arp_mac_mismatch", "batch_dropped", "capture_failed", "dhcp_mac_mismatch", "dns_name_rejected", "excluded", "filters_invalid",
	"flows_dropped", "fragment_skipped", "malformed_arp", "malformed_dhcp", "malformed_dns", "malformed_ethernet", "malformed_http",
	"malformed_ipv4", "malformed_lldp", "malformed_mdns", "malformed_ssdp", "malformed_tcp", "malformed_tls", "malformed_udp", "metadata_dropped",
	"metadata_failed", "new_macs_dropped", "new_macs_unconfirmed", "non_unicast_ip", "observation_failed", "observation_rejected",
	"observations_dropped", "unusable_record", "value_empty", "value_meaningless", "value_truncated", "values_dropped", "vendor_rejected",
}

// ValidDropKey reports whether k is in DropKeys.
func ValidDropKey(k string) bool { return slices.Contains(DropKeys, k) }

// ValidIfaceName reports whether s is a card name of the protocol (sensor-protocol.md section 5).
func ValidIfaceName(s string) bool { return ifaceRE.MatchString(s) }

// virtualRE names links that are not network cards: loopback, container and virtual links, bridges, bonds, VPN tunnels,
// VLANs, and the box's own container bridge vedette0 (install.sh). One rule for the Box network page (core) and
// for the sensor's cards without a host (sensor-passive).
var virtualRE = regexp.MustCompile(`^(lo|veth|podman|cni|docker|br|virbr|vdh|bond|tun|tap|wg|dummy|vnet|macvtap|ifb|vedette)|[.@]`)

// VirtualIfaceName reports whether s names a link that is not a network card (see virtualRE): never a default card, and
// never offered as a card to listen on.
func VirtualIfaceName(s string) bool { return virtualRE.MatchString(s) }

// ValidMAC reports whether s is a MAC of the protocol: six lower-case hex pairs separated by colons.
func ValidMAC(s string) bool { return macRE.MatchString(s) }

func invalid(what string) error {
	return fmt.Errorf("%w: %s", errInvalid, what)
}

func decodeObservations(raw []byte) (*ObservationsRequest, error) {
	var r ObservationsRequest
	if err := jsonstrict.Decode(raw, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	switch {
	case !epochRE.MatchString(r.Epoch):
		return nil, invalid("epoch")
	case r.Seq < 1 || r.Seq > maxSeq:
		return nil, invalid("seq")
	case len(r.Items) < 1 || len(r.Items) > MaxItems:
		return nil, invalid("items")
	}
	return &r, nil
}

// decodeMetadata checks the body of POST /metadata item by item: a sensor sends only items it has already checked, so one item
// that is not of the protocol's shape refuses the whole body (400) rather than letting a part of it through.
func decodeMetadata(raw []byte) (*MetadataRequest, error) {
	var r MetadataRequest
	if err := jsonstrict.Decode(raw, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	if len(r.Items) < 1 || len(r.Items) > MaxMetadataItems {
		return nil, invalid("items")
	}
	for _, it := range r.Items {
		if !ValidMetadataItem(it) {
			return nil, invalid("metadata item")
		}
	}
	return &r, nil
}

// ValidMetadataItem reports whether it has the shape of the protocol: a known kind, a time, an IPv4 source in canonical form, and a
// destination that is an IPv4 address in canonical form (flow) or a host name of at most 253 bytes of lower-case letters, digits,
// '-', '_' and dots between non-empty labels of at most 63 bytes (the other kinds). The sensor checks its items with it before it
// sends them, and core checks them again.
func ValidMetadataItem(it MetadataItem) bool {
	if !slices.Contains(MetaKinds, it.Kind) || it.At.IsZero() || !canonicalIPv4(it.Src) {
		return false
	}
	if it.Kind == MetaFlow {
		return canonicalIPv4(it.Dest)
	}
	return metaNameOK(it.Dest)
}

func canonicalIPv4(s string) bool {
	if len(s) > 15 {
		return false
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4() && a.String() == s
}

func metaNameOK(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	label := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '.':
			if label == 0 {
				return false
			}
			label = 0
			continue
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
		if label++; label > 63 {
			return false
		}
	}
	return label > 0
}

// ValidVersion reports whether s is a SemVer of the form a heartbeat may carry. core checks its own build version with it at start
// (the -ldflags -X main.version of a release must be SemVer), so the three binaries agree on what a version looks like.
func ValidVersion(s string) bool { return len(s) <= 64 && versionRE.MatchString(s) }

func decodePassiveHeartbeat(raw []byte) (*PassiveHeartbeat, error) {
	var h PassiveHeartbeat
	if err := jsonstrict.Decode(raw, &h); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	if !versionRE.MatchString(h.Version) || len(h.Version) > 64 {
		return nil, invalid("version")
	}
	if len(h.Interfaces) > 32 {
		return nil, invalid("interfaces")
	}
	names := map[string]bool{}
	for _, i := range h.Interfaces {
		if names[i.Name] { // two cards of one name: the list would say two things about one card
			return nil, invalid("interface name repeated")
		}
		names[i.Name] = true
		if !ifaceRE.MatchString(i.Name) || !macRE.MatchString(i.MAC) || len(i.IPv4) > 8 {
			return nil, invalid("interface")
		}
		for _, p := range i.IPv4 {
			if pf, err := netip.ParsePrefix(p); err != nil || !pf.Addr().Is4() {
				return nil, invalid("ipv4")
			}
		}
	}
	if h.Span.PPS < 0 || h.Span.OtherMACs < 0 || h.DevicesSeen < 0 {
		return nil, invalid("counter")
	}
	if h.CaptureError != "" && !dropKeyRE.MatchString(h.CaptureError) { // the shape of a drop key: a lower-case word, at most 48 bytes
		return nil, invalid("capture_error")
	}
	if len(h.Drops) > MaxDropKeys {
		return nil, invalid("drops")
	}
	for k, v := range h.Drops {
		if !dropKeyRE.MatchString(k) || v < 0 { // unknown keys of a good shape pass: core ignores them (forward compatibility)
			return nil, invalid("drops")
		}
	}
	return &h, nil
}

func decodeActiveHeartbeat(raw []byte) (*ActiveHeartbeat, error) {
	var h ActiveHeartbeat
	if err := jsonstrict.Decode(raw, &h); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	if !versionRE.MatchString(h.Version) || len(h.Version) > 64 || !nmapVerRE.MatchString(h.Nmap.Version) || !nmapVerRE.MatchString(h.Nuclei.Version) {
		return nil, invalid("version")
	}
	if p := h.Nuclei.Pack; p.Version != "" && !packVerRE.MatchString(p.Version) || p.SHA256 != "" && !sha256RE.MatchString(p.SHA256) || (p.Version == "") != (p.SHA256 == "") {
		return nil, invalid("nuclei pack")
	}
	return &h, nil
}

// decodeJobResult checks the body of a job result. A decoded XML over 8 MiB or JSONL over 4 MiB is errTooLarge (413), not a
// syntax error.
func decodeJobResult(raw []byte) (*JobResult, error) {
	var r JobResult
	if err := jsonstrict.Decode(raw, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	if !resultStat[r.Status] || !resultCode[r.Reason] || r.ExitCode < -1 || r.ExitCode > 255 {
		return nil, invalid("result")
	}
	if r.XMLB64 != "" && r.JSONLB64 != "" {
		return nil, invalid("xml_b64 and jsonl_b64 together")
	}
	if err := checkHostErrors(&r); err != nil {
		return nil, err
	}
	if err := checkSNMPAnswers(&r); err != nil {
		return nil, err
	}
	var err error
	if r.xml, err = decodeOutput(&r, r.XMLB64, MaxResultXML, "xml_b64"); err != nil {
		return nil, err
	}
	if r.jsonl, err = decodeOutput(&r, r.JSONLB64, MaxResultJSONL, "jsonl_b64"); err != nil {
		return nil, err
	}
	return &r, nil
}

// decodeJobProgress checks the body of a progress report: a known phase, a percent of -1 or 0..100, a count in range, a remaining
// time of 0..MaxProgressRemaining. Anything else is 400 and changes nothing.
func decodeJobProgress(raw []byte) (*JobProgress, error) {
	var p JobProgress
	if err := jsonstrict.Decode(raw, &p); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	switch {
	case !slices.Contains(ProgressPhases, p.Phase):
		return nil, invalid("progress phase")
	case p.Percent != -1 && (math.IsNaN(p.Percent) || p.Percent < 0 || p.Percent > 100):
		return nil, invalid("progress percent")
	case p.Done < 0 || p.Total < 0 || p.Done > p.Total || p.Total > MaxProgressCount:
		return nil, invalid("progress count")
	case p.RemainingS < 0 || p.RemainingS > MaxProgressRemaining:
		return nil, invalid("progress remaining")
	}
	return &p, nil
}

// checkHostErrors checks the shape of host_errors: only on a done result, at most one entry per target, a canonical
// private-looking host:port (the job itself is checked by the Dispatcher, which knows the targets).
func checkHostErrors(r *JobResult) error {
	if len(r.HostErrors) == 0 {
		return nil
	}
	if r.Status != "done" || len(r.HostErrors) > MaxHostErrors {
		return invalid("host_errors")
	}
	for i, h := range r.HostErrors {
		if !hostPortRE.MatchString(h.Target) || h.Errors < 1 || h.Errors > MaxHostErrorCount {
			return invalid("host_errors entry")
		}
		for _, p := range r.HostErrors[:i] {
			if p.Target == h.Target {
				return invalid("host_errors target twice")
			}
		}
	}
	return nil
}

// checkSNMPAnswers checks the shape of snmp: only on a done result without another output, at most one answer per target and
// MaxSNMPTargets in all, a known status, values of at most MaxSNMPValue bytes and only on an ok answer. Whether a target belongs to
// the job is the Dispatcher's check, which knows the job.
func checkSNMPAnswers(r *JobResult) error {
	if len(r.SNMP) == 0 {
		return nil
	}
	if r.Status != "done" || len(r.SNMP) > MaxSNMPTargets || r.XMLB64 != "" || r.JSONLB64 != "" || len(r.HostErrors) > 0 {
		return invalid("snmp")
	}
	for i, a := range r.SNMP {
		if !slices.Contains(SNMPStatuses, a.Status) {
			return invalid("snmp answer")
		}
		if ip, err := netip.ParseAddr(a.Target); err != nil || !ip.Is4() || ip.String() != a.Target {
			return invalid("snmp answer target")
		}
		for _, p := range r.SNMP[:i] {
			if p.Target == a.Target {
				return invalid("snmp target twice")
			}
		}
		for _, v := range a.Values.all() {
			if len(v) > MaxSNMPValue || (v != "" && a.Status != SNMPStatusOK) {
				return invalid("snmp value")
			}
		}
	}
	return nil
}

// decodeOutput decodes one base64 output field against its cap: "" is nothing, a field on a result that is not done is invalid.
func decodeOutput(r *JobResult, b64 string, limit int, name string) ([]byte, error) {
	if base64.StdEncoding.DecodedLen(len(b64)) > limit+3 {
		return nil, errTooLarge
	}
	if b64 == "" {
		return nil, nil
	}
	if r.Status != "done" {
		return nil, invalid(name + " on a result that is not done")
	}
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(buf, []byte(b64))
	if err != nil {
		return nil, invalid(name)
	}
	if n > limit {
		return nil, errTooLarge
	}
	return buf[:n], nil
}

// XML is the nmap output the server's decoder found in a result (nil when there is none). It is not set on a JobResult a
// sensor builds; the sensor puts the bytes in XMLB64 with SetXML.
func (r *JobResult) XML() []byte { return r.xml }

// JSONL is the nuclei output the server's decoder found in a result (nil when there is none).
func (r *JobResult) JSONL() []byte { return r.jsonl }

// SetJSONL fills JSONLB64 from the raw nuclei output.
func (r *JobResult) SetJSONL(b []byte) { r.JSONLB64 = base64.StdEncoding.EncodeToString(b) }

// SetXML fills XMLB64 from the raw nmap output.
func (r *JobResult) SetXML(b []byte) { r.XMLB64 = base64.StdEncoding.EncodeToString(b) }
