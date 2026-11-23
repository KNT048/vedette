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
	Source         string // "cisa-kev" or "vulncheck-kev": who says it is exploited
	// Brief is everything the box holds about the CVE as the text of a data block (the CVE brief: its weakness, scores, affected versions,
	// fixed releases, solution, workaround, references numbered from 1); Refs are those references. Empty Brief: the box writes the block
	// from the exploited-list entry above.
	Brief string
	// BriefKey is Brief without the numbers that change every day: the saved answer is keyed on it, so the next day's score is no reason
	// to ask (and pay) again. Empty: Brief is used.
	BriefKey string
	Refs     []BriefRef
}

// Listed reports whether an exploited list has the CVE: only then does Source name the list. A CVE the catalogue holds that no list has
// is no claim that attackers use it.
func (f CVEFacts) Listed() bool { return f.Source != "" }

// ListLabel names the exploited list an entry is on, for prompts and texts: VulnCheck's entries are never CISA's.
func ListLabel(source string) string {
	if source == "vulncheck-kev" {
		return "VulnCheck KEV"
	}
	return "CISA KEV"
}

// AssetFact is a device the CVE matches (findings and inventory). Status is the status of the finding.
type AssetFact struct {
	Name   string // hostname, else the IP
	IP     string
	Kind   string
	Basis  string // version, product, scan or person
	Status string // confirmed or suspected
	// Fix is this device's fix in one sentence and Confirmation says who or what confirmed the finding, both as the finding page shows them.
	Fix, Confirmation string
	// IsBox marks the Vedette box itself: the citation names it apart, as Devices and Reports do. Not sent to the model.
	IsBox bool
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

// ExplainResult is what asking the AI about a CVE for this box produced (S-AI-2): the four answers of "Ask my AI". It always carries
// model, profile and tokens: the page shows it as AI-generated and never as a confirmed recommendation (INV-5, S-AI-6).
type ExplainResult struct {
	CVE         string          `json:"cve"`
	GeneratedAt string          `json:"generated_at"`
	Cached      bool            `json:"cached"`
	Affected    string          `json:"affected"`
	Answers     []ExplainAnswer `json:"answers"`
	Citations   []Citation      `json:"citations"`
	Model       string          `json:"model"`
	Profile     string          `json:"profile"`
	Tokens      struct {
		Input  int `json:"input"`
		Output int `json:"output"`
	} `json:"tokens"`
}

// ExplainAnswer is one of the four answers: its key (AnswerKeys), a few sentences, and the references it rests on (the box's own).
type ExplainAnswer struct {
	Key   string        `json:"key"`
	Text  string        `json:"text"`
	Links []ExplainLink `json:"links"`
}

// ExplainLink is a reference an answer cites.
type ExplainLink struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// explainBody is what is stored in ai_result.payload: the result without what the row columns hold.
type explainBody struct {
	Affected  string          `json:"affected"`
	Answers   []ExplainAnswer `json:"answers"`
	Citations []Citation      `json:"citations"`
}

// explainAnswer is the schema the model must follow. The affected status is decided by the box from the matches and the scan
// result (as the mock does), so the model cannot claim "yes" for a device nobody checked.
type explainAnswer struct {
	Answers []briefAnswerIn `json:"answers"`
}

const explainSchema = `{"type":"object","properties":{` + briefAnswersSchema + `},"required":["answers"],"additionalProperties":false}`

const explainTask = `Answer four questions about one vulnerability for this company's network. Use only the facts in the data blocks: the CVE brief and the list of matching devices (each device line says how it was found, who confirmed it and the fix for it). The box has already decided the affected status (given in the question); do not contradict it. In "answers" give exactly four answers, in this order, each with its "key": "affected" (Am I affected? Yes, no or needs a check, with the evidence: the devices and their versions, who or what confirmed them as the device lines say, and any condition the CVE brief names, such as a CPU feature or an enabled option), "fix" (How do I fix it? The exact release the device lines name as the fix, or, when no device matches, the fixed releases the CVE brief states per release train), "workaround" (What if I cannot patch yet? The workaround of the CVE brief, or its sentence that none is published), "urgency" (How urgent? Whether attackers use it and which list says so, the attack conditions and the privileges required). Each answer is one to three short sentences of plain English. Its "refs" are the numbers of the references of the CVE brief it rests on: every claim a reference supports carries its number, and no number that is not listed. Name no version number, product or link that is not in the data. Never work out a fixed release from an affected version, and never call the "before" end of an affected range a fix. Write what is true; never write a paragraph that explains why something is absent. Give firewall or gateway rules, and back-up and roll-back steps, only when the attack is over the network and a matching device has an open port for the product. Reply with one JSON object only.`

var cveRE = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// cleanText removes control characters and invisible format characters (bidi controls, zero-width spaces: what is shown must be what
// is read, #897 r2 M4), turns line breaks (also U+2028/U+2029) and tabs into spaces and trims: the form in which a model's text is
// stored. The after_ai hooks look at this form, so what they check is what is kept (INV-12).
func cleanText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || unicode.In(r, unicode.Zl, unicode.Zp) {
			return ' '
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
	return strings.TrimSpace(s)
}

// cleanLine is cleanText cut to n characters.
func cleanLine(s string, n int) string { return clipRunes(cleanText(s), n) }

// parseExplain reads the model's answer strictly: one JSON object with the four answers, once each, none empty.
func parseExplain(text string) (explainAnswer, error) {
	var a explainAnswer
	dec := json.NewDecoder(bytes.NewReader([]byte(strings.TrimSpace(text))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil || dec.More() || !hasKeys(text, "answers") || !validAnswers(a.Answers) {
		return explainAnswer{}, ErrBadOutput
	}
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

// affectedOf is the box's own answer to "does it affect me": no matching device, no; a confirmed finding (a scan, a person, or the version the device itself reports), yes; a match
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

// feedBlock is the exploited-list entry as a data block. Every text field came from a feed, so each goes through sanitizeWeb like the
// pages of CVE news do: valid UTF-8, no control or format characters (bidi overrides, zero-width), blank runs collapsed. A link is
// cleaned and then kept only when it is still one http(s) token.
func feedBlock(f CVEFacts) DataBlock {
	if f.Brief != "" { // the caller wrote the block from the CVE brief: its own text, already one line per fact
		return DataBlock{Kind: DataFeed, Source: "CVE brief " + f.CVE, Text: f.Brief}
	}
	links := make([]string, 0, len(f.Links))
	for _, l := range f.Links {
		if l = sanitizeWeb(l); l != "" && !strings.ContainsAny(l, " \n") {
			links = append(links, l)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CVE: %s\nVendor: %s\nProduct: %s\nName: %s\nDescription: %s\nExploited-list source: %s\nRequired action (from that source): %s\nAdded to the exploited list: %s\nUsed in ransomware campaigns: %t\nPublic check template exists: %t\nLinks: %s\n",
		sanitizeWeb(f.CVE), sanitizeWeb(f.Vendor), sanitizeWeb(f.Product), sanitizeWeb(f.Name), sanitizeWeb(f.Description), ListLabel(f.Source), sanitizeWeb(f.RequiredAction), sanitizeWeb(f.DateAdded), f.Ransomware, f.HasTemplate, strings.Join(links, " "))
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
		fmt.Fprintf(&b, "- %s, IP %s, kind %s, matched by %s, finding status %s", a.Name, a.IP, a.Kind, a.Basis, a.Status) // IP apart from the name
		if a.Confirmation != "" {
			fmt.Fprintf(&b, "; %s", a.Confirmation)
		}
		if a.Fix != "" {
			fmt.Fprintf(&b, "; %s", a.Fix)
		}
		b.WriteString("\n")
	}
	return DataBlock{Kind: "inventory", Source: "devices on this box matching the product", Text: b.String()}
}

// citationsFor builds the sources of an explanation: the feed's links that are plain http(s) addresses, and the count of matching
// devices, the Vedette box named apart. Only the box makes citations, so a model cannot slip in a link.
func citationsFor(f CVEFacts, assets []AssetFact) []Citation {
	out := []Citation{}
	for _, r := range f.Refs { // the brief's references, the vendor's own first
		u, err := url.Parse(r.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || len(r.URL) > 2000 || len(out) == 2 {
			continue
		}
		out = append(out, Citation{Title: cleanLine(r.Title, 80), URL: r.URL})
	}
	for _, l := range f.Links {
		if len(f.Refs) > 0 {
			break
		}
		u, err := url.Parse(l)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || len(l) > 2000 || len(out) == 2 {
			continue
		}
		out = append(out, Citation{Title: strings.TrimPrefix(u.Hostname(), "www."), URL: l})
	}
	others, box := 0, false
	for _, a := range assets {
		if a.IsBox {
			box = true
		} else {
			others++
		}
	}
	return append(out, Citation{Title: "Inventory: " + boxApart(others, box) + " matching"})
}

func (s *Service) explainView(row explainBody, cve string, at time.Time, cached bool, model, profile string, tin, tout int) ExplainResult {
	r := ExplainResult{CVE: cve, GeneratedAt: FormatTS(at), Cached: cached, Affected: row.Affected, Answers: row.Answers, Citations: row.Citations, Model: model, Profile: profile}
	if r.Answers == nil {
		r.Answers = []ExplainAnswer{}
	}
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
	know   knowCall // the passages the hash was made with; the call uses these, not a second retrieval
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
	keyText := feed.Text
	if facts.BriefKey != "" {
		keyText = facts.BriefKey
	}
	hash := HashContent("explain-v3\n" + keyText + "\n" + inv.Text + "\nmemory:" + mem.block.Text + knowledgeKey(know) + "\nrules:" + strings.Join(rules, "\n"))
	return explainInputs{facts: facts, assets: assets, feed: feed, inv: inv, hash: hash, know: know}, true, nil
}

// CachedCVE returns the explanation generated before for a CVE, without calling the AI (INV-6), but only one that was made from
// the feed entry and the devices the box holds now. After a device is patched or added, or the entry changes, nothing is cached:
// "affected" is the box's own decision and must not be served from a state that no longer exists (review M2). News is CachedNews.
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
		return ExplainResult{}, apierr.New(http.StatusNotFound, "unknown_cve", "The box's catalogue has no record of this CVE. The AI only answers about CVEs the box has data for.")
	}
	facts, assets, feed, inv, hash := in.facts, in.assets, in.feed, in.inv, in.hash
	know := in.know
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
		knowledge:      &know,
		Schema:         &provider.Schema{Name: "explain_cve", JSON: json.RawMessage(explainSchema)},
		MaxTokens:      6000, // the answer runs to about 1,000 tokens; the rest is room for thinking (briefMaxTokens)
		Summary:        fmt.Sprintf("Explained %s for %d matching devices", cve, len(assets)),
		Check: func(text string) error {
			var perr error
			answer, perr = parseExplain(text)
			return perr
		},
		// The result is stored in the same transaction as the activity row of the call.
		Store: func(ctx context.Context, tx *sql.Tx, r JobResult) error {
			kept, _ := keepAnswers(answer.Answers, facts.Refs)
			body = explainBody{Affected: affected, Answers: make([]ExplainAnswer, 0, len(kept)), Citations: append(citationsFor(facts, assets), documentsCite(r.Documents)...)}
			for _, k := range kept {
				x := ExplainAnswer{Key: k.Key, Text: k.Text, Links: []ExplainLink{}}
				for _, l := range k.Links {
					x.Links = append(x.Links, ExplainLink(l))
				}
				body.Answers = append(body.Answers, x)
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
