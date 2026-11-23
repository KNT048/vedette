package reports

// ModuleID is the id of this module in MANIFEST.yaml.
const ModuleID = "reports"

// These types are the JSON of the API (web/src/features/reports/contract.ts). The handlers decode them into the generated
// oas types, so a drift between this file and api/openapi.json fails loudly instead of sending a wrong body.

// FindingRow is one finding as the report shows it.
type FindingRow struct {
	ID       string `json:"id"`
	CVE      string `json:"cve"`
	Device   string `json:"device"`
	AssetID  string `json:"asset_id"`
	Product  string `json:"product"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
	Since    string `json:"since"`
	By       string `json:"by,omitempty"`    // who closed it, on the rows of what was done
	Agent    bool   `json:"agent,omitempty"` // the device's own agent reported the version compared: "Detected by the agent", not "Suspected"
	// DeviceApproved is false when the device is still to review (inventory not approved), so not in the Devices list yet. A finding
	// whose device inventory does not know counts as approved.
	DeviceApproved bool `json:"device_approved"`

	noDevice     bool // the device is a product added by hand with no device (Device.NoDevice)
	notExploited bool // the finding's CVE is not one attackers use (Finding.Exploited is false): an action's wording says "exploited" only when no finding of it is
}

// TopRisk is one of the biggest open risks of the week: the open findings of one product, as Findings names it.
// Device is the device's name, or the first names and how many more; FindingID is its worst finding.
type TopRisk struct {
	Product   string `json:"product"`
	Device    string `json:"device"`
	Devices   int    `json:"devices"`
	Open      int    `json:"open"`
	Confirmed int    `json:"confirmed"`
	Severity  string `json:"severity"`
	CVE       string `json:"cve"`
	FindingID string `json:"finding_id"`
	// Action is what to do this week, one sentence naming the device(s) and, when NVD's ranges say, the fixed version.
	// Empty in a report sent by an older release.
	Action string `json:"action,omitempty"`
}

// ActionItem is one line of "what is left". Kind is fix, verify, review_devices or plan_os. Fix and verify are about
// one top risk: Product and Count (its open findings) are set, CVE and FindingID are its worst finding.
type ActionItem struct {
	Kind      string `json:"kind"`
	CVE       string `json:"cve,omitempty"`
	Device    string `json:"device,omitempty"`
	FindingID string `json:"finding_id,omitempty"`
	Product   string `json:"product,omitempty"`
	Count     int    `json:"count,omitempty"`
	Text      string `json:"text,omitempty"` // fix and verify: the sentence of the top risk's Action
}

// HappenedLine is one incident of the week that matters.
type HappenedLine struct {
	Kind     string `json:"kind"` // login_accepted, trap, failed_logins, bad_connection or anomaly
	Title    string `json:"title"`
	Severity string `json:"severity"`
	At       string `json:"at"` // last seen
}

// Happened is "what happened this week" from the incidents of notify: counts of incidents seen in the week, per kind,
// and the few that matter most. Summary is the one sentence the page and the email both say.
type Happened struct {
	Traps          int            `json:"traps"`
	FailedLogins   int            `json:"failed_logins"`
	AcceptedLogins int            `json:"accepted_logins"`
	BadConnections int            `json:"bad_connections"`
	Other          int            `json:"other"`
	Summary        string         `json:"summary"`
	Top            []HappenedLine `json:"top"`
}

// Tokens is what an AI call cost.
type Tokens struct {
	Input  int `json:"input"`
	Output int `json:"output"`
}

// AiSummary is the AI commentary. It is always shown as "AI generated" and never changes a figure (INV-5).
type AiSummary struct {
	Paragraphs  []string `json:"paragraphs"`
	Model       string   `json:"model"`
	Profile     string   `json:"profile,omitempty"`
	Tokens      Tokens   `json:"tokens"`
	GeneratedAt string   `json:"generated_at"`
}

// Period is the week a report covers.
type Period struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Counts are the figures at the top of the weekly report.
type Counts struct {
	NewFindings int `json:"new_findings"`
	Resolved    int `json:"resolved"` // closed this week, accepted risks left out
	// Accepted counts the risks accepted this week, AcceptedUntil (YYYY-MM-DD) the earliest day one of them ends.
	Accepted         int    `json:"accepted,omitempty"`
	AcceptedUntil    string `json:"accepted_until,omitempty"`
	OpenConfirmed    int    `json:"open_confirmed"`
	OpenSuspected    int    `json:"open_suspected"`
	Devices          int    `json:"devices"`
	DevicesUnapprove int    `json:"devices_unapproved"`
	DevicesNew       int    `json:"devices_new"`
	KevNew           int    `json:"kev_new"`     // newly exploited in the last 7 days, as Home counts them
	KevMatched       int    `json:"kev_matched"` // their products in use, as Home counts them (before it, CVEs on a device)
	// The findings closed as not relevant among the figures above: NotRelevant different findings, NotRelevantNew of NewFindings and
	// NotRelevantResolved of Resolved. A reader that leaves them out subtracts these. omitempty: a sent report is read back into this
	// struct and written out again, and one sent before these counts must stay without them (a 0 would read as "none" and stop the
	// reader counting its rows); a real 0 left out reads the same, as its rows hold no not relevant finding either.
	NotRelevant         int `json:"not_relevant,omitempty"`
	NotRelevantNew      int `json:"not_relevant_new,omitempty"`
	NotRelevantResolved int `json:"not_relevant_resolved,omitempty"`
}

// WeeklyView is the part of the weekly report that changes when the devices not approved yet (not in the Devices list) are left
// out: the counts, the top risks and the actions computed again over the approved devices and their findings. The lists are not
// repeated; a reader filters them by FindingRow.DeviceApproved.
type WeeklyView struct {
	Counts   Counts       `json:"counts"`
	TopRisks []TopRisk    `json:"top_risks"`
	Actions  []ActionItem `json:"actions"`
}

// Source says where a group of figures came from and when (INV-1).
type Source struct {
	ID string `json:"id"`
	At string `json:"at"`
}

// WeeklyReport is the one-page report. The lists hold at most MaxRows rows; the counts are of everything.
type WeeklyReport struct {
	Period      Period       `json:"period"`
	GeneratedAt string       `json:"generated_at"`
	Counts      Counts       `json:"counts"`
	TopRisks    []TopRisk    `json:"top_risks"`
	NewFindings []FindingRow `json:"new_findings"`
	Resolved    []FindingRow `json:"resolved"`
	Open        []FindingRow `json:"open"`
	Actions     []ActionItem `json:"actions"`
	Happened    *Happened    `json:"happened"` // nil when notify is off or the report was sent by an older release
	Sources     []Source     `json:"sources"`
	AISummary   *AiSummary   `json:"ai_summary"`
	// ApprovedOnly is the report without the devices not approved yet and their findings; nil in reports sent before it.
	ApprovedOnly *WeeklyView `json:"approved_only,omitempty"`
}

// WeeklyPreview is GET /reports/weekly/preview.
type WeeklyPreview struct {
	Report      WeeklyReport `json:"report"`
	AIAvailable bool         `json:"ai_available"`
}

// Schedule is the send schedule. Day is 1 = Monday … 7 = Sunday.
type Schedule struct {
	Enabled    bool     `json:"enabled"`
	Day        int      `json:"day"`
	Hour       int      `json:"hour"`
	Recipients []string `json:"recipients"`
	NextRun    *string  `json:"next_run"`
}

// ScheduleInput is the body of PUT /reports/schedule.
type ScheduleInput struct {
	Enabled    bool     `json:"enabled"`
	Day        int      `json:"day"`
	Hour       int      `json:"hour"`
	Recipients []string `json:"recipients"`
}

// HistoryItem is one send attempt.
type HistoryItem struct {
	ID         string   `json:"id"`
	TS         string   `json:"ts"`
	Trigger    string   `json:"trigger"`
	Recipients []string `json:"recipients"`
	Status     string   `json:"status"`
	Error      string   `json:"error,omitempty"`
}

// HistoryEntry is a send attempt with the figures of that week (INV-2).
type HistoryEntry struct {
	HistoryItem
	Report WeeklyReport `json:"report"`
}

// PdplOrg is what the organisation tells the assessment about itself.
type PdplOrg struct {
	Name              string `json:"name"`
	TaxCode           string `json:"tax_code"`
	Address           string `json:"address"`
	Sector            string `json:"sector"`
	Employees         int    `json:"employees"`
	DataVolume        string `json:"data_volume"`
	Size              string `json:"size"`
	ProcessingService bool   `json:"processing_service"`
	ContactName       string `json:"contact_name"`
	ContactEmail      string `json:"contact_email"`
	ContactPhone      string `json:"contact_phone"`
	Sensitive         bool   `json:"sensitive"`
	CrossBorder       bool   `json:"cross_border"`
	Processors        bool   `json:"processors"`
	Level             string `json:"level"`
}

// Measure is one technical measure the box can see (INV-8). Status is ok, attention or unknown; n counts what it found and
// names lists the first few.
type Measure struct {
	ID     string   `json:"id"`
	Status string   `json:"status"`
	N      int      `json:"n"`
	Names  []string `json:"names"`
}

// Obligation is one duty of the law (INV-6). Done is null when the box cannot know.
type Obligation struct {
	ID      string `json:"id"`
	Applies bool   `json:"applies"`
	Regime  string `json:"regime"`
	Done    *bool  `json:"done"`
}

// KindCount counts the devices of one kind.
type KindCount struct {
	Kind string `json:"kind"`
	N    int    `json:"n"`
}

// KeySystem is a server, NAS or firewall.
type KeySystem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	IP   string `json:"ip"`
	Kind string `json:"kind"`
	OS   string `json:"os"`
}

// SourceCount counts the facts one source supplied.
type SourceCount struct {
	Source string `json:"source"`
	N      int    `json:"n"`
}

// PdplInventory is the device picture of the assessment.
type PdplInventory struct {
	Total      int           `json:"total"`
	Approved   int           `json:"approved"`
	Unapproved int           `json:"unapproved"`
	Fragile    int           `json:"fragile"`
	ByKind     []KindCount   `json:"by_kind"`
	KeySystems []KeySystem   `json:"key_systems"`
	Sources    []SourceCount `json:"sources"`
}

// Coverage says whether a module that feeds the assessment is on.
type Coverage struct {
	Module string `json:"module"`
	On     bool   `json:"on"`
}

// PdplReport is the generated self-assessment.
type PdplReport struct {
	ID          string        `json:"id"`
	GeneratedAt string        `json:"generated_at"`
	Org         PdplOrg       `json:"org"`
	Inventory   PdplInventory `json:"inventory"`
	Measures    []Measure     `json:"measures"`
	Risks       []FindingRow  `json:"risks"`
	Obligations []Obligation  `json:"obligations"`
	Coverage    []Coverage    `json:"coverage"`
	AISummary   *AiSummary    `json:"ai_summary"`
	// ApprovedOnly is the inventory, measures and risks without the devices not approved yet and their findings; nil in reports
	// generated before it.
	ApprovedOnly *PdplView `json:"approved_only,omitempty"`
}

// PdplView is the part of the assessment that changes when the devices not approved yet are left out. Its "unapproved" measure is
// the full report's: leaving those devices out of the view does not approve them.
type PdplView struct {
	Inventory PdplInventory `json:"inventory"`
	Measures  []Measure     `json:"measures"`
	Risks     []FindingRow  `json:"risks"`
}

// PdplDefaults are values the form starts with.
type PdplDefaults struct {
	Name string `json:"name"`
}

// PdplState is GET /reports/pdpl.
type PdplState struct {
	Org         *PdplOrg     `json:"org"`
	Defaults    PdplDefaults `json:"defaults"`
	Report      *PdplReport  `json:"report"`
	AIAvailable bool         `json:"ai_available"`
}
