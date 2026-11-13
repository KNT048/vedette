package findings

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
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
}

func newRow(r Record, a *AssetView, k *KevInfo) Row {
	row := Row{
		ID: r.ID, AssetID: r.AssetID, CVE: r.CVE, Status: r.Status, Severity: r.Severity, Confidence: r.Confidence, Basis: r.Basis,
		Evidence: newEvidenceDoc(r.Evidence), FirstSeen: r.FirstSeen.UTC(), LastSeen: r.LastSeen.UTC(),
		History: make([]historyDoc, 0, len(r.History)), Asset: a, Kev: k,
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
		aa := *a
		if !validKind(aa.Kind) {
			aa.Kind = "unknown"
		}
		if aa.Name == "" || aa.Name == aa.ID { // never show an internal id (D-484): the software it runs, else the kind
			aa.Name = aa.Display
			if aa.Name == "" {
				aa.Name = aa.Kind
			}
		}
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

func validKind(k string) bool {
	switch k {
	case "firewall", "router", "switch", "ap", "nas", "server", "pc", "printer", "camera", "nvr", "iot", "web", "unknown":
		return true
	}
	return false
}

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
