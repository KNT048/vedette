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
}

// ActionItem is one line of "what is left". Kind is fix, verify, review_devices or plan_os.
type ActionItem struct {
	Kind      string `json:"kind"`
	CVE       string `json:"cve,omitempty"`
	Device    string `json:"device,omitempty"`
	FindingID string `json:"finding_id,omitempty"`
	Count     int    `json:"count,omitempty"`
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
	NewFindings      int `json:"new_findings"`
	Resolved         int `json:"resolved"`
	OpenConfirmed    int `json:"open_confirmed"`
	OpenSuspected    int `json:"open_suspected"`
	Devices          int `json:"devices"`
	DevicesUnapprove int `json:"devices_unapproved"`
	DevicesNew       int `json:"devices_new"`
	KevNew           int `json:"kev_new"`
	KevMatched       int `json:"kev_matched"`
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
	NewFindings []FindingRow `json:"new_findings"`
	Resolved    []FindingRow `json:"resolved"`
	Open        []FindingRow `json:"open"`
	Actions     []ActionItem `json:"actions"`
	Sources     []Source     `json:"sources"`
	AISummary   *AiSummary   `json:"ai_summary"`
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

// KindCount, KeySystem and SourceCount are the parts of the inventory block.
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
