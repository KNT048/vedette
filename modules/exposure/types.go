package exposure

import "time"

// Limits and defaults (CONTRACT INV-4, INV-5, INV-8, INV-11).
const (
	ValidDays          = 30 // an IP is valid this long after the box last saw it
	ExpiringDays       = 5  // at most this many days left: validity "expiring"
	DeepRounds         = 5  // rounds of a full check (finds every IP of a load balancer); a round asks each of the three services once
	LightRounds        = 1  // rounds of the check at a short interval
	MinIntervalMin     = 5  // auto-detect interval bounds and default, in minutes (5 minutes to 24 hours)
	MaxIntervalMin     = 1440
	DefaultIntervalMin = 60
	MaxTargets         = 20
	MaxAttemptsPerHour = 10 // Detect now and the check of an IP, which ask public services: shared, per box
	CertWarnDays       = 30
	DeepEvery          = time.Hour       // a full check runs at most this often by itself; shorter intervals do light checks
	EnableGap          = 5 * time.Minute // turning auto-detect on checks at once, unless it checked within this time
	ModuleID           = "exposure"
	// SystemUser is the actor of everything the box does by itself (the audit trail of auto-detect).
	SystemUser = "system"
)

// DomainCheckEvery is the least time between two ownership checks of one domain target: a check is a few DNS lookups, so a person
// who just changed a record can check again soon, and a loop cannot hammer the resolver.
const DomainCheckEvery = 30 * time.Second

// The box-wide bound of the ownership checks people trigger (the button, and the check of a name just added): a burst of
// DomainCheckBurst, then one more every DomainCheckRefill. Per target there is still one check every DomainCheckEvery.
const (
	DomainCheckBurst  = 20
	DomainCheckRefill = 10 * time.Second
)

// Kind is what a target is: a domain or a public IP.
type Kind string

// The values of exp_target.kind.
const (
	KindDomain Kind = "domain"
	KindIP     Kind = "ip"
)

// BlockedReason says why a target cannot be scanned yet (INV-1). The empty value means it can.
type BlockedReason string

// The values of Target.blocked_reason.
const (
	BlockedUnverified BlockedReason = "unverified"
	BlockedExpired    BlockedReason = "expired"
	BlockedTxtMissing BlockedReason = "txt_missing"
	// BlockedProofMissing: a typed public IP's proof (the token file, or the reverse DNS name) is not found now (INV-35).
	BlockedProofMissing BlockedReason = "proof_missing"
	BlockedNoCommitment BlockedReason = "no_commitment"
	// BlockedNotCurrent: the latest full check did not see this IP, so the box no longer
	// reaches the Internet through this IP (INV-13).
	BlockedNotCurrent BlockedReason = "ip_not_current"
)

const (
	methodDNS        = "dns_txt"
	methodBoxEgress  = "box_egress"
	methodIPFile     = "ip_file" // a typed IP, proved by the token file served on it (INV-35)
	methodIPPTR      = "ip_ptr"  // a typed IP, proved by forward-confirmed reverse DNS (INV-35)
	validityValid    = "valid"
	validityExpiring = "expiring"
	validityExpired  = "expired"
	statusUnverified = "unverified"
	statusVerified   = "verified"
	statusExpired    = "expired"
	dayFormat        = "2006-01-02"
	maxContentRows   = 5000 // INV-10: rows kept per list of one snapshot
	maxContentText   = 500  // INV-10: characters kept per text
	tokenBytes       = 8
)

// Check is the outcome of the last attempt to prove ownership (Target.last_check).
type Check struct {
	At      string `json:"at"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	// Covers (stored with the check by checkDoc, never in the API) says the check found this domain target's own record on its own
	// name or its _vedette-verify name, which covers the names under it. A record of its own token on a parent name
	// proves it only, so covered_by never names it.
	Covers bool `json:"-"`
	// Via (stored with the check, never in the API) is the value of the other domain target of the box whose token proved this one
	// at its last passing check, "" when the target's own token did. It only labels the proof (covered_by); coverage is decided
	// by the record found now, never by this.
	Via string `json:"-"`
}

// Commitment is who ticked "my company owns it and I am authorized to scan it", and when.
type Commitment struct {
	By string `json:"by"`
	At string `json:"at"`
	// Version and Sentence: the exact sentence the administrator saw next to Scan now; nil on a commitment recorded earlier.
	// UserID and Method are kept in the row and the audit line, not in the API: who by id, and how two-step was met (app, email, sso).
	UserID, Method string  `json:"-"`
	Version        *string `json:"version"`
	Sentence       *string `json:"sentence"`
}

// current says the commitment is of the sentence in force: a missing one, one recorded before versions and one of an older
// version all count as not confirmed for it.
func (c *Commitment) current() bool {
	return c != nil && c.Version != nil && *c.Version == NoticeVersion
}

// Counts are the numbers of one snapshot (INV-8).
type Counts struct {
	Subdomains    int `json:"subdomains"`
	IPs           int `json:"ips"`
	Ports         int `json:"ports"`
	AdminPanels   int `json:"admin_panels"`
	CertsExpiring int `json:"certs_expiring"`
}

// Target is one stored row. Timestamps are UTC, at millisecond precision.
type Target struct {
	ID         string
	Kind       Kind
	Value      string
	Method     string // "dns_txt", "box_egress" or "" while unverified
	Token      string
	VerifiedAt time.Time // zero while unverified; for an IP, the last time the box saw it
	LastCheck  *Check
	Commitment *Commitment
	Terms      *Terms // the testing terms; nil when not accepted
	// Typed: a public IP a person typed in (INV-35), proved by a token file on it or by reverse DNS. false for a domain and for an IP
	// the box found as its own egress address. Its Token is the one the proof file carries.
	Typed      bool
	CreatedAt  time.Time
	LastScanAt time.Time // zero when never scanned
	// proofDomain and proofToken are, after the scan gate, the domain target whose token proved this one now (itself, a parent target
	// of the box, or a target of the box that sits under the name where its record was found) and that token: the domain and token the
	// executors' fence checks. proofAt is the name the record sits on when it is not proofDomain itself (the zone apex, or a parent
	// name of this target): the executors look for the token there and accept any name under it. Never stored.
	proofDomain, proofToken, proofAt string
}

// TargetView is the API shape of a target (contract.ts Target), with the derived fields filled in.
type TargetView struct {
	ID         string      `json:"id"`
	Kind       Kind        `json:"kind"`
	Value      string      `json:"value"`
	Status     string      `json:"status"`
	Method     *string     `json:"method"`
	Token      string      `json:"token"`
	VerifiedAt *string     `json:"verified_at"`
	ExpiresAt  *string     `json:"expires_at"`
	Validity   *string     `json:"validity"`
	LastCheck  *Check      `json:"last_check"`
	Commitment *Commitment `json:"commitment"`
	// CommitmentNotice is the sentence an administrator's first Scan now confirms, with this target's name in it; nil once
	// the target has a commitment of the current sentence (an older one is asked again once).
	CommitmentNotice *Notice `json:"commitment_notice"`
	// Terms is the acceptance of the testing terms, nil when none; TermsNotice is the current text with this target in it,
	// always sent (the page shows it to accept, or to read again after a new version). FullScan says scans run at full depth.
	Terms       *Terms      `json:"terms"`
	TermsNotice TermsNotice `json:"terms_notice"`
	FullScan    bool        `json:"full_scan"`
	// TermsWarning says, on GET /exposure/targets/{id} of an IP, that the box goes out through carrier-grade NAT (the disruptive
	// tick is then refused); nil otherwise and in lists.
	TermsWarning  *string        `json:"terms_warning,omitempty"`
	Scannable     bool           `json:"scannable"`
	BlockedReason *BlockedReason `json:"blocked_reason"`
	CreatedAt     string         `json:"created_at"`
	LastScanAt    *string        `json:"last_scan_at"`
	// LastScanFinishedAt is when the newest scan (LastScanAt is its start) ended; nil while its OpenVAS step runs, when never
	// scanned, or when its end is not known.
	LastScanFinishedAt *string `json:"last_scan_finished_at"`
	Latest             *Counts `json:"latest"`
	// OpenPorts are the first MaxOpenPorts open ports of the newest snapshot, in its order (Latest.Ports is the total), so
	// the list page can say what is open (S-EXP-1); nil when never scanned.
	OpenPorts []PortRow `json:"open_ports"`
	// Proof says where a domain's TXT record goes and which verified domain of the box covers it already; nil for an IP.
	Proof *ProofHint `json:"proof"`
	// Origin says who added the target: "person" (typed in) or "box" (a public IP the box found as its own egress address).
	Origin string `json:"origin"`
	// IPProof tells a typed IP's person where the token file goes and which reverse DNS names would prove it; nil for a domain and for
	// an IP the box found.
	IPProof *IPProofHint `json:"ip_proof"`
	// NextCheckAt is when a typed IP's proof is looked at again by itself (INV-35); nil for any other target and while unproved.
	NextCheckAt *string `json:"next_check_at"`
	// ScanState is where the target stands for scanning: unproved, expired, paused, needs_terms, ready, queued or scanning.
	ScanState string `json:"scan_state"`
	// OpenExposures is the number of open ports of the newest scan (0 when never scanned): the count the target row shows.
	OpenExposures int `json:"open_exposures"`
	// Schedule is how often the target is scanned by itself, when next and why not (INV-36).
	Schedule *ScheduleView `json:"schedule"`
}

// MaxOpenPorts bounds TargetView.OpenPorts (a domain can have hundreds of names on 80 and 443).
const MaxOpenPorts = 20

// GatewayView is the API shape of the gateway note (contract.ts Gateway): the device that probably answers the open ports of the
// box's public IP, or a gap in what is known. IP is nil when the box cannot tell its gateway, DeviceID and Name are nil when the
// gateway is not in the inventory.
type GatewayView struct {
	IP            *string `json:"ip"`
	DeviceID      *string `json:"device_id"`
	Name          *string `json:"name"`
	OpenExploited int     `json:"open_exploited"`
}

// LastRun is the last detection of the box's public IPs, automatic or by a click (BoxIP.last_run).
type LastRun struct {
	At      string `json:"at"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// BoxIP is the auto-detect state of the box (CONTRACT INV-11), the API shape of BoxIpSettings.
type BoxIP struct {
	Auto        bool     `json:"auto"`
	IntervalMin int      `json:"interval_min"`
	LastRun     *LastRun `json:"last_run"`
	// RetryInMin is nil while attempts are left. When the MaxAttemptsPerHour attempts of the last hour are used up it is the
	// minutes until the next one is possible (1 or more), so the page can say it on the button.
	RetryInMin *int `json:"retry_in_min"`
}

// DetectResult is what a detection found: the IPs it added or renewed, and a sentence about it.
type DetectResult struct {
	Items   []TargetView `json:"items"`
	Message string       `json:"message"`
}

// VerifyResult is the answer of "check again" for one target (POST-2). Not found is verified:false.
type VerifyResult struct {
	Verified bool       `json:"verified"`
	Message  string     `json:"message"`
	Target   TargetView `json:"target"`
}

// The content of a scan, as the scan module hands it over (INV-10: it came from other hosts, so it is
// untrusted and the service limits it before storing).
type (
	// HostRow is a name under the domain (INV-27). IP is the first of its IPv4 addresses ("" when it has none). Source, CNAME
	// and IPs come from newer scans; a row of an older snapshot has no source and the kinds of its addresses are unknown.
	HostRow struct {
		Name   string   `json:"name"`
		IP     string   `json:"ip"`
		Source string   `json:"source,omitempty"`
		CNAME  string   `json:"cname,omitempty"`
		IPs    []HostIP `json:"ips,omitempty"`
		// LookupFailed: the name's address lookup got no clear answer this time; the row is the previous scan's, carried forward.
		LookupFailed bool `json:"lookup_failed,omitempty"`
	}
	// HostIP is one address of a name with its kind (INV-27): box (this box's verified, current IP), public (any other public
	// address) or private (never dialed). Contacted: the check by name (GET / on 80 and 443) went to this address.
	HostIP struct {
		IP        string `json:"ip"`
		Family    string `json:"family"`
		Class     string `json:"class"`
		Contacted bool   `json:"contacted,omitempty"`
		// Deep is what this run's deep scan did with the address (DeepScanned, DeepWaiting, DeepFence,
		// DeepRefused, DeepIncomplete; "" when the domain's testing terms are not accepted, or for an IPv6 or private address); LastDeep when an
		// earlier or this run last deep-scanned it (rotation); NextInLine its place among the addresses left by the cap.
		Deep       string `json:"deep,omitempty"`
		LastDeep   string `json:"last_deep,omitempty"`
		NextInLine int    `json:"next_in_line,omitempty"`
		// LastTried: when a run last took the address in turn (scanned, incomplete or refused at the re-check): the
		// rotation goes by the later of LastDeep and LastTried, so an address that keeps being refused does not stay first.
		LastTried string `json:"last_tried,omitempty"`
	}
	// PortRow is an open port.
	// LastSeen and Misses are set only on a port this scan did not report, kept from an earlier scan (INV-22): LastSeen is the
	// day a scan last saw it open; Misses is how many scans in a row that checked its address missed it (1 = "missed by the last scan";
	// Unchecked = the last scan did not check the address, so the row is as it was).
	PortRow struct {
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Service  string `json:"service"`
		Product  string `json:"product,omitempty"`
		LastSeen string `json:"last_seen,omitempty"`
		Misses   int    `json:"misses,omitempty"`
		// Unchecked: the newest scan did not check the address, so the row (and Misses) is as an earlier scan left it.
		Unchecked bool `json:"unchecked,omitempty"`
		// Ident is how service identification named the port's service (identifyPorts): IdentProbed, IdentPort (only the
		// usual service of the port number), IdentNone (nothing identified); "" when it did not run on the port or the row is older.
		Ident string `json:"ident,omitempty"`
		// What the deep scan's scripts read on the port: the names of its TLS certificate (subject common name, then the
		// DNS names of its subject alternative names), its web page's title and its HTTP Server header. Untrusted, sanitized.
		CertNames []string `json:"cert_names,omitempty"`
		Title     string   `json:"title,omitempty"`
		Server    string   `json:"server,omitempty"`
		// Location is where the port's first page redirects, as the deep scan's http-title read it (a FortiGate SSL-VPN sends
		// the browser to /remote/login). Untrusted, sanitized.
		Location string `json:"location,omitempty"`
		// Appliance is the appliance family the port names (appliance.go), set when the port is read, never stored; nil when none.
		Appliance *Appliance `json:"appliance,omitempty"`
	}
	// AdminRow is an admin page that is open to the Internet. Risk is "danger" or "warn".
	AdminRow struct {
		URL     string `json:"url"`
		Product string `json:"product"`
		IP      string `json:"ip"`
		Port    int    `json:"port"`
		Risk    string `json:"risk"`
		// Appliance is the appliance family the page belongs to (appliance.go), set when the row is read, never stored; nil when none.
		Appliance *Appliance `json:"appliance,omitempty"`
	}
	// CertRow is a certificate and when it expires (RFC 3339, UTC, milliseconds).
	CertRow struct {
		Host      string `json:"host"`
		Issuer    string `json:"issuer"`
		ExpiresAt string `json:"expires_at"`
	}
)

// Content is what one scan found. Services, Checks and NotChecked are S-EXP-2 (INV-19): what service identification read, and
// what the scan checked and did not check.
type Content struct {
	Hosts       []HostRow       `json:"hosts"`
	Ports       []PortRow       `json:"ports"`
	AdminPanels []AdminRow      `json:"admin_panels"`
	Certs       []CertRow       `json:"certs"`
	Services    []ServiceRow    `json:"services"`
	Templates   []TemplateRow   `json:"templates"` // INV-23: the safe templates that ran on those services
	Checks      []CheckRow      `json:"checks"`
	NotChecked  []NotCheckedRow `json:"not_checked"`
	WebFindings []WebFindingRow `json:"web_findings"` // INV-24: alerts of the passive web scan (ZAP), not exploited CVEs
	Greenbone   []GreenboneRow  `json:"greenbone"`    // INV-25: results of the optional deep scan (Greenbone, QoD >= 70)
	// Unresolved are the names whose address lookup got no clear answer this time (INV-27): not stored as such; saveScan carries
	// their previous rows forward (carryHosts).
	Unresolved []string `json:"-"`
	// The NSE script results of a deep scan, stored in exp_snapshot.scripts (migration 0010).
	// Not in the API yet ("-"): the snapshot schema of api/openapi.json has no such field and the response decoder refuses unknown
	// ones; showing them is the page's step (contract.ts, openapi, then this tag becomes "scripts").
	Scripts []ScriptRow `json:"-"`
}

// Snapshot is the result of one scan day (contract.ts Snapshot). Vulns and VersionGaps are not stored: they are computed when the
// snapshot is read, from its services and the current list of exploited vulnerabilities (INV-20), so a new KEV entry shows without
// a rescan.
type Snapshot struct {
	ID        string `json:"id"`
	Date      string `json:"date"`
	ScannedAt string `json:"scanned_at"`
	// StartedAt is when the scan started (the name of the scan on every page) and FinishedAt when its last step ended; FinishedAt
	// is nil while OpenVAS still runs, and on a snapshot stored before these times were kept whose end is not known.
	StartedAt  string  `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
	Content
	// GreenboneRun is the state of the snapshot's OpenVAS step and when it started: the page's OpenVAS heading
	// follows it, and shows the start in the viewer's time zone.
	GreenboneRun GreenboneRun `json:"greenbone_run"`
	Vulns        []VulnRow    `json:"vulns"`
	VersionGaps  []GapRow     `json:"version_gaps"`
	Counts       Counts       `json:"counts"`
}

// SnapshotMeta is a snapshot without its lists.
type SnapshotMeta struct {
	ID         string  `json:"id"`
	Date       string  `json:"date"`
	ScannedAt  string  `json:"scanned_at"`
	StartedAt  string  `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
	Counts     Counts  `json:"counts"`
}

// DiffItem is one thing that appeared or disappeared between two days.
type DiffItem struct {
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

// DiffChange is a thing that changed between two days, with what it changed from and to.
type DiffChange struct {
	DiffItem
	From string `json:"from"`
	To   string `json:"to"`
}

// Diff compares two scan days (contract.ts Diff).
type Diff struct {
	From    string       `json:"from"`
	To      string       `json:"to"`
	Added   []DiffItem   `json:"added"`
	Removed []DiffItem   `json:"removed"`
	Changed []DiffChange `json:"changed"`
}

// MaxIgnored is the most IPs the Ignored list holds; a full list refuses to take one more (400 too_many).
const MaxIgnored = 200

// IgnoredIP is one entry of the Ignored list (contract.ts IgnoredIp).
type IgnoredIP struct {
	Value     string `json:"value"`
	IgnoredBy string `json:"ignored_by"`
	IgnoredAt string `json:"ignored_at"`
}
