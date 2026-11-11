package ai

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/ai/provider"
)

// CVEFacts is what the box holds about a CVE on the exploited list (feeds). Every text field is untrusted: it came from a feed.
type CVEFacts struct {
	CVE            string
	Vendor         string
	Product        string
	Name           string
	Description    string
	RequiredAction string
	DateAdded      string
	Links          []string
	Ransomware     bool
	HasTemplate    bool
}

// AssetFact is a device the CVE matches (findings and inventory). Status is the status of the finding.
type AssetFact struct {
	Name   string // hostname, else the IP
	IP     string
	Kind   string
	Basis  string // version or product
	Status string // open, confirmed, ...
}

// Facts is the door to the data of other modules: ai reads it, never their tables.
type Facts interface {
	// CVE returns the exploited-list entry; ok is false when the box has no data for the CVE.
	CVE(ctx context.Context, id string) (CVEFacts, bool, error)
	// AffectedAssets returns the devices the CVE matches, with the finding status of each.
	AffectedAssets(ctx context.Context, cve string) ([]AssetFact, error)
}

// Citation names a source of a result. The box builds citations; the model never supplies a link.
type Citation struct {
	Title string `json:"title"`
	URL   string `json:"url,omitempty"`
}

// ExplainResult is what explaining a CVE for this box produced (S-AI-2). It always carries model, profile and tokens: the page
// shows it as AI-generated and never as a confirmed recommendation (INV-5, S-AI-6).
type ExplainResult struct {
	CVE             string     `json:"cve"`
	GeneratedAt     string     `json:"generated_at"`
	Cached          bool       `json:"cached"`
	Affected        string     `json:"affected"`
	Why             string     `json:"why"`
	PatchSteps      []string   `json:"patch_steps"`
	TempMitigations []string   `json:"temp_mitigations"`
	DetectionHints  []string   `json:"detection_hints"`
	Citations       []Citation `json:"citations"`
	Model           string     `json:"model"`
	Profile         string     `json:"profile"`
	Tokens          struct {
		Input  int `json:"input"`
		Output int `json:"output"`
	} `json:"tokens"`
}

// explainBody is what is stored in ai_result.payload: the result without what the row columns hold.
type explainBody struct {
	Affected        string     `json:"affected"`
	Why             string     `json:"why"`
	PatchSteps      []string   `json:"patch_steps"`
	TempMitigations []string   `json:"temp_mitigations"`
	DetectionHints  []string   `json:"detection_hints"`
	Citations       []Citation `json:"citations"`
}

// explainAnswer is the schema the model must follow. The affected status is decided by the box from the matches and the scan
// result (as the mock does), so the model cannot claim "yes" for a device nobody checked.
type explainAnswer struct {
	Why             string   `json:"why"`
	PatchSteps      []string `json:"patch_steps"`
	TempMitigations []string `json:"temp_mitigations"`
	DetectionHints  []string `json:"detection_hints"`
}

const explainSchema = `{"type":"object","properties":{"why":{"type":"string"},"patch_steps":{"type":"array","items":{"type":"string"}},"temp_mitigations":{"type":"array","items":{"type":"string"}},"detection_hints":{"type":"array","items":{"type":"string"}}},"required":["why","patch_steps","temp_mitigations","detection_hints"],"additionalProperties":false}`

const explainTask = `Explain one exploited vulnerability for this company's network. Use only the facts in the data blocks: the feed entry and the list of matching devices. Say in "why" whether and how it touches these devices, in plain English for a small-company IT person, in at most 6 sentences. The box has already decided the affected status (given in the question); do not contradict it. In "patch_steps" give the steps to update to a fixed version, in "temp_mitigations" what to do until it is patched, in "detection_hints" signs of exploitation to look for. Leave a list empty when the status is "no". Do not invent version numbers, product names or links that are not in the data. Reply with one JSON object only.`

const (
	maxWhy       = 1200
	maxListItems = 8
	maxItemChars = 500
)

var cveRE = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// cleanText removes control characters, turns line breaks and tabs into spaces and trims: the form in which a model's text is
// stored. The after_ai hooks look at this form, so what they check is what is kept (INV-12).
func cleanText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
	return strings.TrimSpace(s)
}

// cleanLine is cleanText cut to n characters.
func cleanLine(s string, n int) string { return clipRunes(cleanText(s), n) }

func cleanList(in []string) []string {
	out := []string{}
	for _, s := range in {
		if s = cleanLine(s, maxItemChars); s != "" && len(out) < maxListItems {
			out = append(out, s)
		}
	}
	return out
}

// parseExplain reads the model's answer strictly: one JSON object with exactly the schema's fields, and a non-empty "why".
func parseExplain(text string) (explainAnswer, error) {
	var a explainAnswer
	dec := json.NewDecoder(bytes.NewReader([]byte(strings.TrimSpace(text))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil || dec.More() {
		return explainAnswer{}, ErrBadOutput
	}
	if !hasKeys(text, "why", "patch_steps", "temp_mitigations", "detection_hints") { // the schema says all four are required
		return explainAnswer{}, ErrBadOutput
	}
	a.Why = cleanLine(a.Why, maxWhy)
	if a.Why == "" {
		return explainAnswer{}, ErrBadOutput
	}
	a.PatchSteps, a.TempMitigations, a.DetectionHints = cleanList(a.PatchSteps), cleanList(a.TempMitigations), cleanList(a.DetectionHints)
	return a, nil
}

// hasKeys reports whether text is a JSON object that has every one of the keys (the "required" of the schema is the model's
// promise; the box checks it, a missing key would otherwise read as an empty section).
func hasKeys(text string, keys ...string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(strings.TrimSpace(text)), &m) != nil {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

// affectedOf is the box's own answer to "does it affect me": no matching device, no; a finding confirmed by a scan, yes; a match
// that nobody confirmed, unknown.
func affectedOf(assets []AssetFact) string {
	if len(assets) == 0 {
		return "no"
	}
	for _, a := range assets {
		if a.Status == "confirmed" {
			return "yes"
		}
	}
	return "unknown"
}

func feedBlock(f CVEFacts) DataBlock {
	var b strings.Builder
	fmt.Fprintf(&b, "CVE: %s\nVendor: %s\nProduct: %s\nName: %s\nDescription: %s\nRequired action (CISA): %s\nAdded to the exploited list: %s\nUsed in ransomware campaigns: %t\nPublic check template exists: %t\nLinks: %s\n",
		f.CVE, f.Vendor, f.Product, f.Name, f.Description, f.RequiredAction, f.DateAdded, f.Ransomware, f.HasTemplate, strings.Join(f.Links, " "))
	return DataBlock{Kind: DataFeed, Source: "exploited list entry " + f.CVE, Text: b.String()}
}

// explainKnowledgeQuery is what the documents are searched with for a CVE: the product and the names of the devices it matches, not
// the long text of the entry or the addresses (numbers match every network document).
func explainKnowledgeQuery(f CVEFacts, assets []AssetFact) string {
	parts := []string{f.Vendor, f.Product, f.Name}
	for _, a := range assets {
		parts = append(parts, a.Name, a.Kind)
	}
	return strings.Join(parts, " ")
}

func inventoryBlock(assets []AssetFact) DataBlock {
	var b strings.Builder
	if len(assets) == 0 {
		b.WriteString("No device in the inventory matches this product.\n")
	}
	for _, a := range assets {
		fmt.Fprintf(&b, "- %s, IP %s, kind %s, matched by %s, finding status %s\n", a.Name, a.IP, a.Kind, a.Basis, a.Status) // IP apart from the name (D-205)
	}
	return DataBlock{Kind: "inventory", Source: "devices on this box matching the product", Text: b.String()}
}

// citationsFor builds the sources of an explanation: the feed's links that are plain http(s) addresses, and the count of matching
// devices. Only the box makes citations, so a model cannot slip in a link.
func citationsFor(f CVEFacts, assets []AssetFact) []Citation {
	out := []Citation{}
	for _, l := range f.Links {
		u, err := url.Parse(l)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || len(l) > 2000 || len(out) == 2 {
			continue
		}
		out = append(out, Citation{Title: strings.TrimPrefix(u.Hostname(), "www."), URL: l})
	}
	n := len(assets)
	title := fmt.Sprintf("Inventory: %d devices matching", n)
	if n == 1 {
		title = "Inventory: 1 device matching"
	}
	return append(out, Citation{Title: title})
}

func (s *Service) explainView(row explainBody, cve string, at time.Time, cached bool, model, profile string, tin, tout int) ExplainResult {
	r := ExplainResult{CVE: cve, GeneratedAt: FormatTS(at), Cached: cached, Affected: row.Affected, Why: row.Why, PatchSteps: row.PatchSteps,
		TempMitigations: row.TempMitigations, DetectionHints: row.DetectionHints, Citations: row.Citations, Model: model, Profile: profile}
	r.Tokens.Input, r.Tokens.Output = tin, tout
	return r
}

type explainRow struct {
	body      explainBody
	model     string
	profile   string
	tin, tout int
	created   time.Time
}

func (s *Service) loadExplain(ctx context.Context, cve, hash string) (explainRow, bool, error) {
	q := `SELECT payload, model, profile, tokens_in, tokens_out, created_at FROM ai_result WHERE kind = 'explain' AND key = ?`
	args := []any{cve}
	if hash != "" {
		q += ` AND inputs_hash = ?`
		args = append(args, hash)
	}
	var payload, created string
	var r explainRow
	err := s.cfg.DB.Reader().QueryRowContext(ctx, q+` ORDER BY created_at DESC, rowid DESC LIMIT 1`, args...).Scan(&payload, &r.model, &r.profile, &r.tin, &r.tout, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return explainRow{}, false, nil
	}
	if err != nil {
		return explainRow{}, false, fmt.Errorf("ai: read explanation: %w", err)
	}
	if err := json.Unmarshal([]byte(payload), &r.body); err != nil {
		return explainRow{}, false, fmt.Errorf("ai: stored explanation of %s is not readable: %w", cve, err)
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", created)
	if err != nil {
		return explainRow{}, false, fmt.Errorf("ai: stored explanation time: %w", err)
	}
	r.created = t
	return r, true, nil
}

// explainInputs is what an explanation of one CVE is made of: the feed entry and the devices it matches now, as the two data blocks of
// the prompt, and the hash of both (the key of the cached result). found is false when the box has no data for the CVE.
type explainInputs struct {
	facts  CVEFacts
	assets []AssetFact
	feed   DataBlock
	inv    DataBlock
	hash   string
}

func (s *Service) explainInputs(ctx context.Context, cve string) (explainInputs, bool, error) {
	if s.cfg.Facts == nil {
		return explainInputs{}, false, apiUnavailable("The box has no vulnerability data to explain from. Turn on the feeds module in Settings, Modules.")
	}
	facts, ok, err := s.cfg.Facts.CVE(ctx, cve)
	if err != nil {
		return explainInputs{}, false, fmt.Errorf("ai: read CVE: %w", err)
	}
	if !ok {
		return explainInputs{}, false, nil
	}
	assets, err := s.cfg.Facts.AffectedAssets(ctx, cve)
	if err != nil {
		return explainInputs{}, false, fmt.Errorf("ai: read devices: %w", err)
	}
	feed, inv := feedBlock(facts), inventoryBlock(assets)
	// The answer also depends on what the prompt carries besides the data: the memory lines that would be sent now (after the hooks)
	// and the company rules of the job. Editing either makes the cached explanation a miss.
	har := s.harness.Load()
	mem, err := s.memoryForCall(ctx, har.runner, JobExplainFinding)
	if err != nil {
		return explainInputs{}, false, err
	}
	// The pieces of the knowledge base the call would carry are part of the answer's inputs: a changed document is a cache miss.
	know, err := s.knowledgeForCall(ctx, har.runner, JobExplainFinding, explainKnowledgeQuery(facts, assets))
	if err != nil {
		return explainInputs{}, false, err
	}
	var rules []string
	for _, r := range har.rules {
		if r.Enabled && r.appliesTo(JobExplainFinding) {
			rules = append(rules, r.Text)
		}
	}
	hash := HashContent("explain-v2\n" + feed.Text + "\n" + inv.Text + "\nmemory:" + mem.block.Text + knowledgeKey(know) + "\nrules:" + strings.Join(rules, "\n"))
	return explainInputs{facts: facts, assets: assets, feed: feed, inv: inv, hash: hash}, true, nil
}

// CachedCVE returns the explanation generated before for a CVE, without calling the AI (INV-6), but only one that was made from
// the feed entry and the devices the box holds now. After a device is patched or added, or the entry changes, nothing is cached:
// "affected" is the box's own decision and must not be served from a state that no longer exists (review M2). The news half
// arrives with slice 6.
func (s *Service) CachedCVE(ctx context.Context, id string) (*ExplainResult, error) {
	cve := strings.ToUpper(id)
	if !cveRE.MatchString(cve) {
		return nil, apierr.New(http.StatusBadRequest, "invalid_cve", "A CVE ID looks like CVE-2022-27593.")
	}
	if s.cfg.Facts == nil {
		return nil, nil //nolint:nilnil // nothing cached: the box has no data to compare with
	}
	in, found, err := s.explainInputs(ctx, cve)
	if err != nil || !found {
		return nil, err
	}
	r, ok, err := s.loadExplain(ctx, cve, in.hash)
	if err != nil || !ok {
		return nil, err
	}
	v := s.explainView(r.body, cve, r.created, true, r.model, r.profile, r.tin, r.tout)
	return &v, nil
}

// ExplainCVE has the AI explain a CVE for the devices of this box (S-AI-2). A second request with the same CVE, feed entry and
// matching devices answers from the stored result and spends no tokens (INV-6); a change in the devices or the feed asks again.
func (s *Service) ExplainCVE(ctx context.Context, actor, id string) (ExplainResult, error) {
	cve := strings.ToUpper(id)
	if err := s.Ready(JobExplainFinding); err != nil {
		return ExplainResult{}, err
	}
	if !cveRE.MatchString(cve) {
		return ExplainResult{}, apierr.New(http.StatusBadRequest, "invalid_cve", "A CVE ID looks like CVE-2022-27593.")
	}
	if s.cfg.Facts == nil {
		return ExplainResult{}, apiUnavailable("The box has no vulnerability data to explain from. Turn on the feeds module in Settings, Modules.")
	}
	in, found, err := s.explainInputs(ctx, cve)
	if err != nil {
		return ExplainResult{}, err
	}
	if !found {
		return ExplainResult{}, apierr.New(http.StatusNotFound, "unknown_cve", "This CVE is not on the exploited list the box holds. The AI only explains CVEs the box has data for.")
	}
	facts, assets, feed, inv, hash := in.facts, in.assets, in.feed, in.inv, in.hash
	if r, ok, err := s.loadExplain(ctx, cve, hash); err != nil {
		return ExplainResult{}, err
	} else if ok {
		return s.explainView(r.body, cve, r.created, true, r.model, r.profile, r.tin, r.tout), nil
	}

	affected := affectedOf(assets)
	var answer explainAnswer
	var body explainBody
	now := s.cfg.Clock()
	res, err := s.RunJob(ctx, JobSpec{
		Job: JobExplainFinding, Actor: actor, Task: explainTask,
		Question:       fmt.Sprintf("Explain %s for this company. The box has decided the affected status is %q.", cve, affected),
		Data:           []DataBlock{feed, inv},
		KnowledgeQuery: explainKnowledgeQuery(facts, assets),
		Schema:         &provider.Schema{Name: "explain_cve", JSON: json.RawMessage(explainSchema)},
		MaxTokens:      1200,
		Summary:        fmt.Sprintf("Explained %s for %d matching devices", cve, len(assets)),
		Check: func(text string) error {
			var perr error
			answer, perr = parseExplain(text)
			return perr
		},
		// The result is stored in the same transaction as the activity row of the call.
		Store: func(ctx context.Context, tx *sql.Tx, r JobResult) error {
			body = explainBody{Affected: affected, Why: answer.Why, PatchSteps: answer.PatchSteps, TempMitigations: answer.TempMitigations,
				DetectionHints: answer.DetectionHints, Citations: citationsFor(facts, assets)}
			if affected == "no" { // nothing to patch or look for: the lists stay empty whatever the model wrote
				body.PatchSteps, body.TempMitigations, body.DetectionHints = []string{}, []string{}, []string{}
			}
			payload, err := json.Marshal(body)
			if err != nil {
				return fmt.Errorf("ai: encode explanation: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO ai_result (id, kind, key, inputs_hash, payload, model, profile, tokens_in, tokens_out, asked_by, activity_id, created_at)
				VALUES (?, 'explain', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, store.NewID("res"), cve, hash, string(payload), r.Model, r.Profile, r.TokensIn, r.TokensOut, actor, r.ActivityID, FormatTS(now)); err != nil {
				return fmt.Errorf("ai: store explanation: %w", err)
			}
			return nil
		},
	})
	if err != nil {
		return ExplainResult{}, err
	}
	return s.explainView(body, cve, now, false, res.Model, res.Profile, res.TokensIn, res.TokensOut), nil
}
