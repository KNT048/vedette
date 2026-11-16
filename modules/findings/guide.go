package findings

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/knt048/vedette/content/devicetypes"
)

// The "What to do" part of FindingDetail (web/src/features/findings/contract.ts). The shapes live here,
// next to the detail that carries them, so findings can compose the response without importing
// mitigation (D-57 (6)); mitigation builds them. The JSON tags are the API's.

// CodeStep is a command or setting the person pastes themselves (D-3: Vedette never runs it).
type CodeStep struct {
	Title      string `json:"title"`
	Code       string `json:"code"`
	Note       string `json:"note,omitempty"`
	SideEffect string `json:"side_effect,omitempty"` // stated before the person copies the command (INV-4)
	// Check (an AI config block only, #897 r2): the addresses the block names that are not addresses the box knows for the finding;
	// the page asks the person to check them before pasting.
	Check []string `json:"check,omitempty"`
}

// Alternative is the second way of a firewall guide.
type Alternative struct {
	Title string     `json:"title"`
	Intro string     `json:"intro"`
	Steps []CodeStep `json:"steps"`
}

// FirewallGuide is the guide for one firewall vendor.
type FirewallGuide struct {
	Vendor      string       `json:"vendor"` // fortigate, mikrotik or generic
	Label       string       `json:"label"`
	Detected    bool         `json:"detected"` // the inventory has a device of this vendor (INV-5)
	Intro       string       `json:"intro"`
	Steps       []CodeStep   `json:"steps"`
	Alternative *Alternative `json:"alternative,omitempty"`
	Verify      []CodeStep   `json:"verify"`
	Undo        []CodeStep   `json:"undo"`
	Plain       []string     `json:"plain,omitempty"`
}

// Source is a reference of a pack.
type Source struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Patch is the fix part of a pack.
type Patch struct {
	Summary    string   `json:"summary"`
	Fixed      string   `json:"fixed"`
	Steps      []string `json:"steps"`
	SideEffect string   `json:"side_effect"`
	URL        string   `json:"url"`
}

// Workaround is the "cannot patch yet" part of a pack.
type Workaround struct {
	Summary    string   `json:"summary"`
	Steps      []string `json:"steps"`
	SideEffect string   `json:"side_effect"`
}

// MitigationPack is a recommendation confirmed by the Vedette maintainers (D-21).
type MitigationPack struct {
	CVE         string          `json:"cve"`
	ConfirmedBy string          `json:"confirmed_by"`
	ConfirmedAt time.Time       `json:"confirmed_at"`
	DraftedWith string          `json:"drafted_with"`
	Sources     []Source        `json:"sources"`
	Patch       Patch           `json:"patch"`
	Workaround  Workaround      `json:"workaround"`
	Firewall    []FirewallGuide `json:"firewall"`
	Checklist   []string        `json:"checklist"`
}

// Command is a labelled command of an indicator.
type Command struct {
	Label string `json:"label"`
	Code  string `json:"code"`
}

// Indicator is one sign of compromise to look for; the commands are text only (INV-6).
type Indicator struct {
	Kind     string    `json:"kind"` // file, web, log or process
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	Commands []Command `json:"commands,omitempty"`
}

// CompromiseCheck is the "Am I already compromised?" block.
type CompromiseCheck struct {
	Summary    string      `json:"summary"`
	Indicators []Indicator `json:"indicators"`
	IfFound    []string    `json:"if_found"`
}

// Recheck says how to check again whether the flaw is still there.
type Recheck struct {
	Steps []string `json:"steps"`
	Code  string   `json:"code,omitempty"`
}

// Tokens is the token use of one AI result.
type Tokens struct {
	Input  int `json:"input"`
	Output int `json:"output"`
}

// Citation is a source an AI result cites.
type Citation struct {
	Title string `json:"title"`
	URL   string `json:"url,omitempty"`
}

// AIResult is a result of the customer's own AI. It is always shown as "AI generated" and never as
// a confirmed recommendation (INV-3 of mitigation).
type AIResult struct {
	Skill      string     `json:"skill"` // explain or mitigation-config
	TS         time.Time  `json:"ts"`
	Model      string     `json:"model"`
	Profile    string     `json:"profile,omitempty"`
	Tokens     Tokens     `json:"tokens"`
	Paragraphs []string   `json:"paragraphs"`
	Steps      []string   `json:"steps"`
	Citations  []Citation `json:"citations"`
	// Configs are the ready config blocks of a mitigation-config answer (M2-2): the device's own workaround and a rule per firewall
	// vendor, each with its side effect; absent for explain and for answers stored before them.
	Configs []CodeStep `json:"configs,omitempty"`
	// Shortened: a part of the answer was longer than Vedette keeps, so the page says it was shortened (never cut mid-sentence).
	Shortened bool `json:"shortened,omitempty"`
	// NoConfigReason: why no config or no firewall rule helps (a local flaw, no open port serves it), in the AI's words (#897 r1 H1).
	NoConfigReason string `json:"no_config_reason,omitempty"`
}

// AIResults holds the last result per skill.
type AIResults struct {
	Explain *AIResult `json:"explain"`
	Config  *AIResult `json:"config"`
}

// AIAvailable says whether an AI profile is assigned and allowed for each job (D-29).
type AIAvailable struct {
	Explain bool `json:"explain"`
	Config  bool `json:"config"`
}

// AppliedEntry is one item marked "Applied".
type AppliedEntry struct {
	Item string    `json:"item"`
	TS   time.Time `json:"ts"`
	User string    `json:"user"`
}

// Guide is what mitigation adds to a finding. The zero Guide is what a finding shows while mitigation
// is off: no pack, no compromise block, nothing applied, no AI.
type Guide struct {
	Pack        *MitigationPack  `json:"pack"`
	Compromise  *CompromiseCheck `json:"compromise"`
	Recheck     Recheck          `json:"recheck"`
	AI          AIResults        `json:"ai"`
	AIAvailable AIAvailable      `json:"ai_available"`
	Applied     []AppliedEntry   `json:"applied"`
}

// Normalize makes every list non-nil, because the API schema wants [] and never null.
func (g *Guide) Normalize() {
	if g.Pack != nil {
		p := g.Pack
		p.Sources = orEmpty(p.Sources)
		p.Patch.Steps = orEmpty(p.Patch.Steps)
		p.Workaround.Steps = orEmpty(p.Workaround.Steps)
		p.Checklist = orEmpty(p.Checklist)
		p.Firewall = orEmpty(p.Firewall)
		for i := range p.Firewall {
			f := &p.Firewall[i]
			f.Steps, f.Verify, f.Undo = orEmpty(f.Steps), orEmpty(f.Verify), orEmpty(f.Undo)
			if f.Alternative != nil {
				f.Alternative.Steps = orEmpty(f.Alternative.Steps)
			}
		}
	}
	if c := g.Compromise; c != nil {
		c.Indicators, c.IfFound = orEmpty(c.Indicators), orEmpty(c.IfFound)
	}
	g.Recheck.Steps = orEmpty(g.Recheck.Steps)
	for _, r := range []*AIResult{g.AI.Explain, g.AI.Config} {
		if r != nil {
			r.Paragraphs, r.Steps, r.Citations = orEmpty(r.Paragraphs), orEmpty(r.Steps), orEmpty(r.Citations)
		}
	}
	g.Applied = orEmpty(g.Applied)
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// Row is a finding as the list shows it (FindingRow): the stored finding, the device and the KEV entry.
type Row struct {
	ID             string       `json:"id"`
	AssetID        string       `json:"asset_id"`
	CVE            string       `json:"cve"`
	Status         Status       `json:"status"`
	Severity       Severity     `json:"severity"`
	Confidence     float64      `json:"confidence"`
	Basis          Basis        `json:"basis"`
	Evidence       *evidenceDoc `json:"evidence"`
	FirstSeen      time.Time    `json:"first_seen"`
	LastSeen       time.Time    `json:"last_seen"`
	ResolvedBy     *string      `json:"resolved_by"`
	ResolvedAt     *time.Time   `json:"resolved_at"`
	ResolutionNote *string      `json:"resolution_note"`
	AcceptedUntil  *string      `json:"accepted_until"` // YYYY-MM-DD, the last day of a risk acceptance (D-498)
	History        []historyDoc `json:"history"`
	Asset          *AssetView   `json:"asset"`
	Kev            *KevInfo     `json:"kev"`
	CVSS           *CVSS        `json:"cvss"` // nil: no score known ("No score", never 0; INV-22)
	// Fix is the one update that fixes this finding together with the device's other open findings of the same software (D-545):
	// set on the list only, for an open finding; nil when Vedette cannot name one.
	Fix *RowFix `json:"fix"`
	// Known is the version of the software the finding was matched on, set by Detail for the guidance (Guidance reads the Row); the
	// page reads Detail.KnownVersion.
	Known *KnownVersion `json:"-"`
}

// Version sources of KnownVersion (M2-3): who told Vedette the version.
const (
	VersionByAgent  = "agent"  // the device's own agent (osquery, Wazuh, the box's package list)
	VersionBySNMP   = "snmp"   // the device answered Vedette's SNMP read of its address
	VersionByStated = "stated" // the device states it on the network itself (LLDP)
	VersionByScan   = "scan"   // a network scan read it from a service the device answers with
	VersionByManual = "manual" // a person typed it on the Devices page
)

// KnownVersion is the version of the software a finding was matched on, as the device's row gives it, and who gave it (M2-3,
// widening D-548/D-612 from agent rows to every source): the page says it and how it is refreshed, never "find which version".
type KnownVersion struct {
	Software string `json:"software"` // display name of the row
	Version  string `json:"version"`
	Source   string `json:"source"` // one of the VersionBy constants
}

// knownVersion is the KnownVersion of row s of device a; nil when the row has no version or its source is not known.
func knownVersion(a Asset, s Software) *KnownVersion {
	if !versionGiven(s.Version) {
		return nil
	}
	src := ""
	switch {
	case s.ID == osSoftwareID(a.ID): // the network OS the device states itself (INV-4c): SNMP when its own SNMP answer says it
		src = VersionByStated
		if a.SNMPOS != "" && a.SNMPOS == a.StatedOS {
			src = VersionBySNMP
		}
	case s.Source == "agent", s.Source == "snmp", s.Source == "manual":
		src = s.Source
	case s.Source == "scan", s.Source == "nmap":
		src = VersionByScan
	case s.Source == "passive":
		src = VersionByStated
	default:
		return nil
	}
	name := softwareName(s.Display, s.Version)
	if src == VersionByManual {
		name = clean(s.Display) // the "I updated <software>" button names the row as inventory does (review r1 L4)
	}
	return &KnownVersion{Software: name, Version: clean(s.Version), Source: src}
}

type historyDoc struct {
	TS   time.Time `json:"ts"`
	User string    `json:"user"`
	Act  string    `json:"action"`
	Note string    `json:"note,omitempty"`
}

// Detail is a finding with its "What to do" part (FindingDetail).
type Detail struct {
	Row
	Guide
	FixedIn *FixedIn `json:"fixed_in"` // null when NVD's ranges do not say which release fixes it (D-488)
	// KnownVersion is Row.Known on the page: the version the box has for the matched software and who gave it (M2-3); null when none.
	KnownVersion *KnownVersion `json:"known_version"`
}

func newRow(r Record, a *AssetView, k *KevInfo, c *CVSS) Row {
	row := Row{
		ID: r.ID, AssetID: r.AssetID, CVE: r.CVE, Status: r.Status, Severity: r.Severity, Confidence: r.Confidence, Basis: r.Basis,
		Evidence: newEvidenceDoc(r.Evidence), FirstSeen: r.FirstSeen.UTC(), LastSeen: r.LastSeen.UTC(),
		History: make([]historyDoc, 0, len(r.History)), Asset: a, Kev: k, CVSS: c,
	}
	if r.ResolvedBy != "" {
		row.ResolvedBy = &r.ResolvedBy
	}
	if !r.ResolvedAt.IsZero() {
		t := r.ResolvedAt.UTC()
		row.ResolvedAt = &t
	}
	if r.ResolutionNote != "" {
		row.ResolutionNote = &r.ResolutionNote
	}
	if !r.AcceptedUntil.IsZero() {
		d := r.AcceptedUntil.UTC().Format(time.DateOnly)
		row.AcceptedUntil = &d
	}
	for _, h := range r.History {
		row.History = append(row.History, historyDoc{TS: h.TS.UTC(), User: h.User, Act: h.Action, Note: h.Note})
	}
	if k != nil {
		kk := *k
		if kk.Display == "" {
			kk.Display = kk.Vendor + " " + kk.Product
		}
		if kk.Links == nil {
			kk.Links = []string{}
		}
		row.Kev = &kk
	}
	if a != nil {
		aa := shownAsset(*a)
		row.Asset = &aa
		// Findings created before D-484 named a device without hostname or IP by its id in the evidence.
		if row.Evidence != nil && r.AssetID != "" && strings.Contains(row.Evidence.Summary, r.AssetID) {
			ev := *row.Evidence
			ev.Summary = strings.ReplaceAll(ev.Summary, r.AssetID, aa.Name)
			row.Evidence = &ev
		}
	}
	return row
}

// shownAsset is a device as every findings answer shows it (GET /findings, GET /findings/{id}, GET /findings/summary): a kind outside
// the inventory's device types is "unknown", and the name is never the internal id (D-484): the software it runs, else the kind.
func shownAsset(a AssetView) AssetView {
	if !validKind(a.Kind) {
		a.Kind = "unknown"
	}
	if a.Name == "" || a.Name == a.ID {
		a.Name = a.Display
		if a.Name == "" {
			a.Name = a.Kind
		}
	}
	return a
}

// validKind: k is one of the inventory's device types (D-511, content/devicetypes).
func validKind(k string) bool { return devicetypes.Valid(k) }

// Into encodes v as JSON and decodes it into one of the generated response types, which all describe
// the same shape under different names (the generated FindingDetail of GET /findings/{id}, of
// POST …/status, …/applied and …/ai). The generated decoder rejects anything that does not fit the
// OpenAPI schema, so a drift between this code and the contract fails loudly.
func Into[T any, P interface {
	*T
	json.Unmarshaler
}](v any) (*T, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("findings: encoding response: %w", err)
	}
	var out T
	if err := P(&out).UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("findings: response does not fit the API schema: %w", err)
	}
	return &out, nil
}

// addAppliedToHistory shows each "Applied" entry as a history row "applied:<item>", as the finding page
// of the GUI expects, ordered by time. The sort is stable, so on a tie the stored rows stay first.
// findings only copies what the Guide holds; it does not know where the entries come from.
func (d *Detail) addAppliedToHistory() {
	for _, a := range d.Applied {
		d.History = append(d.History, historyDoc{TS: a.TS.UTC(), User: a.User, Act: "applied:" + a.Item})
	}
	sort.SliceStable(d.History, func(i, j int) bool { return d.History[i].TS.Before(d.History[j].TS) })
}
