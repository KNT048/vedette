package reports

// ModuleID is the id of this module in MANIFEST.yaml.
const ModuleID = "reports"

// These types are the JSON of the API (web/src/features/reports/contract.ts). The handlers decode them into the generated
// oas types, so a drift between this file and api/openapi.json fails loudly instead of sending a wrong body.

// FindingRow is one finding as the PDPL assessment lists it.
type FindingRow struct {
	ID       string `json:"id"`
	CVE      string `json:"cve"`
	Device   string `json:"device"`
	AssetID  string `json:"asset_id"`
	Product  string `json:"product"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
	Since    string `json:"since"`
	Agent    bool   `json:"agent,omitempty"` // the device's own agent reported the version compared: "Detected by the agent", not "Suspected"
	// DeviceApproved is false when the device is still to review (inventory not approved), so not in the Devices list yet. A finding
	// whose device inventory does not know counts as approved.
	DeviceApproved bool `json:"device_approved"`
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
