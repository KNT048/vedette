package exposure

import "time"

// Limits and defaults (CONTRACT INV-4, INV-5, INV-8, INV-11; kien 2026-11-09).
const (
	ValidDays          = 30 // an IP is valid this long after the box last saw it
	ExpiringDays       = 5  // at most this many days left: validity "expiring"
	DeepRounds         = 5  // rounds of a full check (finds every IP of a load balancer); a round asks each of the three services once
	LightRounds        = 1  // rounds of the check at a short interval
	MinIntervalMin     = 1  // auto-detect interval bounds and default, in minutes (kien: 1 minute to 24 hours)
	MaxIntervalMin     = 1440
	DefaultIntervalMin = 60
	MaxTargets         = 20
	MaxAttemptsPerHour = 10
	CertWarnDays       = 30
	DeepEvery          = time.Hour       // a full check runs at most this often by itself; shorter intervals do light checks
	EnableGap          = 5 * time.Minute // turning auto-detect on checks at once, unless it checked within this time
	ModuleID           = "exposure"
	// SystemUser is the actor of everything the box does by itself (the audit trail of auto-detect).
	SystemUser = "system"
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
	BlockedUnverified   BlockedReason = "unverified"
	BlockedExpired      BlockedReason = "expired"
	BlockedTxtMissing   BlockedReason = "txt_missing"
	BlockedNoCommitment BlockedReason = "no_commitment"
	// BlockedNotCurrent is answered by CheckScannable and Scan only (never a Target.blocked_reason): the box no longer
	// reaches the Internet through this IP (INV-13).
	BlockedNotCurrent BlockedReason = "ip_not_current"
)

const (
	methodDNS        = "dns_txt"
	methodBoxEgress  = "box_egress"
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
}

// Commitment is who ticked "my company owns it and I am authorized to scan it", and when (D-26).
type Commitment struct {
	By string `json:"by"`
	At string `json:"at"`
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
	CreatedAt  time.Time
	LastScanAt time.Time // zero when never scanned
}

// TargetView is the API shape of a target (contract.ts Target), with the derived fields filled in.
type TargetView struct {
	ID            string         `json:"id"`
	Kind          Kind           `json:"kind"`
	Value         string         `json:"value"`
	Status        string         `json:"status"`
	Method        *string        `json:"method"`
	Token         string         `json:"token"`
	VerifiedAt    *string        `json:"verified_at"`
	ExpiresAt     *string        `json:"expires_at"`
	Validity      *string        `json:"validity"`
	LastCheck     *Check         `json:"last_check"`
	Commitment    *Commitment    `json:"commitment"`
	Scannable     bool           `json:"scannable"`
	BlockedReason *BlockedReason `json:"blocked_reason"`
	CreatedAt     string         `json:"created_at"`
	LastScanAt    *string        `json:"last_scan_at"`
	Latest        *Counts        `json:"latest"`
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
	// HostRow is a subdomain and the address it points at.
	HostRow struct {
		Name string `json:"name"`
		IP   string `json:"ip"`
	}
	// PortRow is an open port.
	PortRow struct {
		IP      string `json:"ip"`
		Port    int    `json:"port"`
		Service string `json:"service"`
		Product string `json:"product,omitempty"`
	}
	// AdminRow is an admin page that is open to the Internet. Risk is "danger" or "warn".
	AdminRow struct {
		URL     string `json:"url"`
		Product string `json:"product"`
		IP      string `json:"ip"`
		Port    int    `json:"port"`
		Risk    string `json:"risk"`
	}
	// CertRow is a certificate and when it expires (RFC 3339, UTC, milliseconds).
	CertRow struct {
		Host      string `json:"host"`
		Issuer    string `json:"issuer"`
		ExpiresAt string `json:"expires_at"`
	}
)

// Content is what one scan found.
type Content struct {
	Hosts       []HostRow  `json:"hosts"`
	Ports       []PortRow  `json:"ports"`
	AdminPanels []AdminRow `json:"admin_panels"`
	Certs       []CertRow  `json:"certs"`
}

// Snapshot is the result of one scan day (contract.ts Snapshot).
type Snapshot struct {
	ID        string `json:"id"`
	Date      string `json:"date"`
	ScannedAt string `json:"scanned_at"`
	Content
	Counts Counts `json:"counts"`
}

// SnapshotMeta is a snapshot without its lists.
type SnapshotMeta struct {
	ID        string `json:"id"`
	Date      string `json:"date"`
	ScannedAt string `json:"scanned_at"`
	Counts    Counts `json:"counts"`
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
