package reports

// The periodic security report as the API shapes it (contract.ts ReportDefinition, ReportDocument, SentReport). Statuses, severity,
// verification, fix and the handled line are the findings contract's shapes; incident kinds the detection ones; proof states and
// issue engines the exposure ones.

// Sections are the section switches of the report.
type Sections struct {
	Summary    bool `json:"summary"`
	Handled    bool `json:"handled"`
	Open       bool `json:"open"`
	New        bool `json:"new"`
	Exposure   bool `json:"exposure"`
	Detections bool `json:"detections"`
	Coverage   bool `json:"coverage"`
}

func (s Sections) any() bool {
	return s.Summary || s.Handled || s.Open || s.New || s.Exposure || s.Detections || s.Coverage
}

// Options are what the document is made with. Period is last_7_days, last_30_days or calendar_month; Grouping device or cve.
type Options struct {
	Period             string   `json:"period"`
	Grouping           string   `json:"grouping"`
	IncludeNotAdded    bool     `json:"include_not_added"`
	IncludeNotRelevant bool     `json:"include_not_relevant"`
	Sections           Sections `json:"sections"`
	Charts             bool     `json:"charts"`
}

// DefaultOptions is the report before anyone saves it: the last 7 days, every section, devices not added yet in, not relevant out.
var DefaultOptions = Options{Period: PeriodLast7, Grouping: "device", IncludeNotAdded: true, IncludeNotRelevant: false, Charts: true,
	Sections: Sections{Summary: true, Handled: true, Open: true, New: true, Exposure: true, Detections: true, Coverage: true}}

// The periods a report covers.
const (
	PeriodLast7   = "last_7_days"
	PeriodLast30  = "last_30_days"
	PeriodMonth   = "calendar_month" // the last whole calendar month in the organisation's time zone
	groupDevice   = "device"
	groupCVE      = "cve"
	triggerManual = "manual"
	triggerSched  = "schedule"
)

// Definition is the one report: its name, options and recipients, and the key of its schedule in core/schedule.
type Definition struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Options     Options  `json:"options"`
	Recipients  []string `json:"recipients"`
	ScheduleKey string   `json:"schedule_key"`
	UpdatedAt   string   `json:"updated_at"`
	UpdatedBy   string   `json:"updated_by"`
}

// DefinitionInput is the body of PUT /reports/definition.
type DefinitionInput struct {
	Name       string   `json:"name"`
	Options    Options  `json:"options"`
	Recipients []string `json:"recipients"`
}

// CveSeverity is the CVSS base score of a CVE and its band (findings contract). nil = "Not scored yet".
type CveSeverity struct {
	Band    string  `json:"band"`
	Score   float64 `json:"score"`
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
}

// DeviceRef is a device as the report names it; Added false = "Not added yet".
type DeviceRef struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Added bool   `json:"added"`
}

// Verification says how sure Vedette is that the device is affected (findings contract).
type Verification struct {
	Verified string  `json:"verified"`
	Basis    string  `json:"basis"`
	By       *string `json:"by"`
	At       *string `json:"at"`
}

// Fix is what fixes a finding (findings contract).
type Fix struct {
	Key     string  `json:"key"`
	Kind    string  `json:"kind"`
	Product string  `json:"product"`
	Version *string `json:"version"`
	Ref     *string `json:"ref"`
	URL     *string `json:"url"`
}

// Reason is one urgency layer of 1 to 4 that applies, with its evidence (findings contract).
type Reason struct {
	Layer  int     `json:"layer"`
	Source string  `json:"source"`
	Name   string  `json:"name"`
	Date   string  `json:"date"`
	URL    *string `json:"url"`
	Detail *string `json:"detail"`
	Due    *string `json:"due"`
}

// Handled is who handled a finding and how, from stored fields (findings contract): "Patched by Vedette: version moved 6.24 →
// 7.23". By is "system" when Vedette handled it.
type Handled struct {
	Resolution    string  `json:"resolution"`
	Via           string  `json:"via"`
	By            string  `json:"by"`
	At            string  `json:"at"`
	Note          *string `json:"note"`
	AcceptedUntil *string `json:"accepted_until"`
	FromVersion   *string `json:"from_version"`
	ToVersion     *string `json:"to_version"`
}

// ReportFinding is one finding as the document lists it.
type ReportFinding struct {
	FindingID    string       `json:"finding_id"`
	CVE          string       `json:"cve"`
	Device       DeviceRef    `json:"device"`
	Product      string       `json:"product"`
	Version      *string      `json:"version"`
	Status       string       `json:"status"`
	Reasons      []Reason     `json:"reasons"`
	Severity     *CveSeverity `json:"severity"`
	Verification Verification `json:"verification"`
	Fix          Fix          `json:"fix"`
	FirstSeen    string       `json:"first_seen"`
}

// HandledItem is one finding handled in the period.
type HandledItem struct {
	FindingID string       `json:"finding_id"`
	CVE       string       `json:"cve"`
	Product   string       `json:"product"`
	Severity  *CveSeverity `json:"severity"`
	Handled   Handled      `json:"handled"`
	// ReopenedAt: the finding opened again after this handling, inside the period, and is open at its end (it is in Still open too).
	// Absent otherwise, and in documents sent before it existed.
	ReopenedAt *string `json:"reopened_at,omitempty"`
}

// DocPeriod is the time a document covers, in the zone it was read in.
type DocPeriod struct {
	Kind string `json:"kind"`
	From string `json:"from"`
	To   string `json:"to"`
	TZ   string `json:"tz"`
}

// StatusCount is how many open findings have one status.
type StatusCount struct {
	Status string `json:"status"`
	N      int    `json:"n"`
}

// FirstThing is one of the three things to do first: one CVE on one product, most urgent first.
type FirstThing struct {
	Status       string       `json:"status"`
	CVE          string       `json:"cve"`
	FindingID    string       `json:"finding_id"`
	Product      string       `json:"product"`
	Severity     *CveSeverity `json:"severity"`
	Fix          Fix          `json:"fix"`
	Devices      []DeviceRef  `json:"devices"`
	DeviceCount  int          `json:"device_count"`
	FindingCount int          `json:"finding_count"`
}

// ReportSummary is section 1.
type ReportSummary struct {
	OpenByStatus []StatusCount `json:"open_by_status"`
	OpenNow      int           `json:"open_now"`
	OpenBefore   int           `json:"open_before"`
	New          int           `json:"new"`
	Handled      int           `json:"handled"`
	// Reopened: findings open at the end that opened again in the period after a handling (handled in the period, or before it), so
	// open_now = open_before + new - handled + reopened. Absent when none, and in documents sent before it existed.
	Reopened int          `json:"reopened,omitempty"`
	First    []FirstThing `json:"first"`
}

// HandledTotal is how many findings were handled one way.
type HandledTotal struct {
	Resolution string `json:"resolution"`
	Via        string `json:"via"`
	N          int    `json:"n"`
}

// HandledDevice is the findings of one device handled in the period.
type HandledDevice struct {
	Device DeviceRef     `json:"device"`
	Items  []HandledItem `json:"items"`
}

// ReportHandled is section 2: the proof of what was done.
type ReportHandled struct {
	Totals     []HandledTotal  `json:"totals"`
	Devices    []HandledDevice `json:"devices"`
	More       int             `json:"more"`
	MedianDays *float64        `json:"median_days"`
	// NotRelevantLeftOut: findings closed as not relevant in the period that the report leaves out ("Include not relevant" off), so
	// the report says why its count is lower than Findings › Handled. Absent in documents sent before it existed.
	NotRelevantLeftOut int `json:"not_relevant_left_out,omitempty"`
}

// OpenGroup is one device or one CVE of Still open.
type OpenGroup struct {
	Key    string          `json:"key"`
	Label  string          `json:"label"`
	Status string          `json:"status"`
	Items  []ReportFinding `json:"items"`
	// Total is every open finding of the group, listed or not (a report lists 100 rows at most): the header says "70 of 147 shown".
	Total int `json:"total"`
}

// ReportOpen is section 3.
type ReportOpen struct {
	Grouping string      `json:"grouping"`
	Total    int         `json:"total"`
	Groups   []OpenGroup `json:"groups"`
	More     int         `json:"more"`
}

// ReportNew is section 4.
type ReportNew struct {
	Total int             `json:"total"`
	Open  int             `json:"open"` // of Total, the findings still open at the end of the period, listed or not
	Items []ReportFinding `json:"items"`
	More  int             `json:"more"`
}

// ExposureService is an open port of a target, or one closed in the period.
type ExposureService struct {
	IP            string  `json:"ip"`
	Port          int     `json:"port"`
	Proto         string  `json:"proto"`
	Name          *string `json:"name"`
	Product       *string `json:"product"`
	Version       *string `json:"version"`
	Change        *string `json:"change"`
	CertExpiresAt *string `json:"cert_expires_at"`
}

// ExposureIssues counts the open issues of one engine and severity, and how many of them are new in the period.
type ExposureIssues struct {
	Engine   string `json:"engine"`
	Severity string `json:"severity"`
	Open     int    `json:"open"`
	New      int    `json:"new"`
}

// ExposureTarget is one external exposure target.
type ExposureTarget struct {
	TargetID   string            `json:"target_id"`
	Kind       string            `json:"kind"`
	Value      string            `json:"value"`
	Parent     *string           `json:"parent"`
	Proof      string            `json:"proof"`
	LastScanAt *string           `json:"last_scan_at"`
	Services   []ExposureService `json:"services"`
	Issues     []ExposureIssues  `json:"issues"`
}

// ReportExposure is section 5.
type ReportExposure struct {
	ModuleOn bool             `json:"module_on"`
	Targets  []ExposureTarget `json:"targets"`
}

// KindCountAt is how many incidents of a kind, and the newest.
type KindCountAt struct {
	Kind   string `json:"kind"`
	N      int    `json:"n"`
	LastAt string `json:"last_at"`
}

// TopDetection is one incident that matters.
type TopDetection struct {
	Kind     string     `json:"kind"`
	Title    string     `json:"title"`
	Severity string     `json:"severity"`
	Device   *DeviceRef `json:"device"`
	// DeviceCount: how many devices the incident names when more than one (Device is the first by name), so the report says "12
	// devices" instead of one device's name. Absent for one device, and in documents sent before it existed.
	DeviceCount int    `json:"device_count,omitempty"`
	At          string `json:"at"`
}

// ReportDetections is section 6.
type ReportDetections struct {
	ModuleOn bool           `json:"module_on"`
	ByKind   []KindCountAt  `json:"by_kind"`
	Top      []TopDetection `json:"top"`
}

// SourceOn says whether a module that sees the network is on.
type SourceOn struct {
	ID string `json:"id"`
	On bool   `json:"on"`
}

// FeedState is one vulnerability feed's health.
type FeedState struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	LastOKAt *string `json:"last_ok_at"`
	Stale    bool    `json:"stale"`
}

// ReportCoverage is section 7: what Vedette can and cannot see.
type ReportCoverage struct {
	Devices   int         `json:"devices"`
	WithAgent int         `json:"with_agent"`
	NotAdded  int         `json:"not_added"`
	Sources   []SourceOn  `json:"sources"`
	Feeds     []FeedState `json:"feeds"`
}

// Document is the report as made at GeneratedAt; a section switched off is absent.
type Document struct {
	DefinitionID string            `json:"definition_id"`
	Title        string            `json:"title"`
	GeneratedAt  string            `json:"generated_at"`
	Org          string            `json:"org"`
	Period       DocPeriod         `json:"period"`
	Options      Options           `json:"options"`
	Summary      *ReportSummary    `json:"summary,omitempty"`
	Handled      *ReportHandled    `json:"handled,omitempty"`
	Open         *ReportOpen       `json:"open,omitempty"`
	New          *ReportNew        `json:"new,omitempty"`
	Exposure     *ReportExposure   `json:"exposure,omitempty"`
	Detections   *ReportDetections `json:"detections,omitempty"`
	Coverage     *ReportCoverage   `json:"coverage,omitempty"`
	AISummary    *AiSummary        `json:"ai_summary"`
}

// SentPeriod is the period of a sent report.
type SentPeriod struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// SentItem is one send attempt, as the History tab lists it.
type SentItem struct {
	ID           string     `json:"id"`
	DefinitionID string     `json:"definition_id"`
	Title        string     `json:"title"`
	SentAt       string     `json:"sent_at"`
	Period       SentPeriod `json:"period"`
	Trigger      string     `json:"trigger"`
	Recipients   []string   `json:"recipients"`
	Status       string     `json:"status"`
	Error        *string    `json:"error"`
	SentBy       *string    `json:"sent_by"`
}

// SentReport is a send attempt with the document exactly as it was sent (INV-2).
type SentReport struct {
	SentItem
	Document Document `json:"document"`
}
