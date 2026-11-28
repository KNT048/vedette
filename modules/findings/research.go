package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/knt048/vedette/core/pagetext"
	"github.com/knt048/vedette/core/store"
)

// P-12 The customer's AI researches what the box cannot decide. Where the box's own readers (the record's rows, NVD, a vendor's CSAF
// or plain-text ranges on a reference page) decide nothing, the check asks the research job once per (CVE, product, release line), for
// every device and version on that line: findings hands it a digest of what the box read for free (the record's rows and who wrote
// each, the references with their tags, the pages the box read) and the kinds of devices the line runs on, never a device's name or
// address. The answer is kept as the line's reading (fnd_line_statement, P-6) with the research behind it (fnd_line_research: the
// layer, where the quote was found, the tokens and every step), and applied by the match like any reading:
//
//   - "affected" with a quote the box found (in text the AI's tools returned, in the digest, or on a live fetch of the cited page)
//     opens a finding, range origin ai_read; with no checked quote it decides nothing;
//   - "not affected" never closes anything: it waits for a person in the review queue (GET /findings/review);
//   - "unsure" keeps the CVE possible with the AI's reason.
//
// A reading survives a re-read of the CVE record (a new stamp: a reader update, a new row elsewhere) while its quote is still found in
// the new record text or on the cited page: its record identity moves on, no tokens are spent.

// ResearchRequest is one research: one CVE for one release line (Item), with the public record, the pages the box read and the digest
// findings built from them. Deeper is a person's "Research deeper": the strong layer now.
type ResearchRequest struct {
	CVE, Description string
	Rows             []string
	Item             ProposeItem
	Pages            []FetchedPage
	Digest           string
	Platforms        []string // the kinds of devices the line runs on ("workstation, Microsoft Windows 11 Pro"), no names or addresses
	Deeper           bool
	// Excerpts are what the AI reads of the pages (researchExcerpts); Pages stay whole for the quote check. VendorRows: the record has
	// rows its writer, the vendor, states; VendorPage: a page of the vendor was read.
	Excerpts               []Excerpt
	VendorRows, VendorPage bool
}

// Excerpt is one passage cut from a page the box read: Source is the page's number in ResearchRequest.Pages (1-based).
type Excerpt struct {
	Source int
	URL    string
	Text   string
}

// excerptBudget is the most characters of excerpts one research carries.
const excerptBudget = 24000

// researchExcerpts cuts from the pages the box read (in their order: the vendor's first) the passages that name the CVE or an advisory
// the record cites (pagetext.Cut: a table row with its header rows, a heading's section, a paragraph with its heading, a short page
// whole, the head of a page about the CVE and its rows naming the product), each passage once, at most excerptBudget characters.
func researchExcerpts(cve string, rec CVERecordText, pages []FetchedPage, product string) []Excerpt {
	refs := make([]string, 0, len(rec.Refs))
	for _, r := range rec.Refs {
		refs = append(refs, r.URL)
	}
	advs := pagetext.AdvisoryIDs(rec.Description+"\n"+rec.Solution, refs)
	ids := pagetext.IDPattern(cve, advs)
	vendor, name, _ := strings.Cut(product, "|")
	prx := pagetext.ProductPattern(vendor, strings.ReplaceAll(name, "_", " "))
	seen := map[string]bool{}
	var out []Excerpt
	total := 0
	for i, p := range pages {
		if p.Status != "ok" {
			continue
		}
		for _, ps := range pagetext.Cut(p.Blocks, ids, prx, pagetext.Dedicated(p.URL, p.Title, cve, advs, p.Vendor)) {
			key := strings.ToLower(strings.Join(strings.Fields(ps.Text), " "))
			if seen[key] {
				continue // the same passage twice (mirrored errata, a page and its copy)
			}
			if total+len(ps.Text) > excerptBudget {
				return out
			}
			seen[key] = true
			total += len(ps.Text)
			out = append(out, Excerpt{Source: i + 1, URL: p.URL, Text: ps.Text})
		}
	}
	return out
}

// ResearchStep is one layer of a research as it ran (contract.ts AiResearchStep).
type ResearchStep struct {
	Layer      string   `json:"layer"`
	Model      string   `json:"model"`
	Profile    string   `json:"profile"`
	Web        string   `json:"web"`
	TokensIn   int      `json:"tokens_in"`
	TokensOut  int      `json:"tokens_out"`
	Searches   int      `json:"searches"`
	Pages      []string `json:"pages"`
	Verdict    string   `json:"verdict"`
	Confidence string   `json:"confidence"`
	QuoteCheck string   `json:"quote_check"`
	Error      string   `json:"error,omitempty"`
	// ExcerptChars is the characters of excerpts the call carried (Web none: the excerpts only; provider or box: the web fallback).
	ExcerptChars int `json:"excerpt_chars"`
}

// ResearchAnswer is the answer of a research as findings reads it: Verdict is the answer as a reading of the line (Status affected,
// not_affected or unsure, or fixed when the AI named the fix; its bounds, line, quote, reason and the product it inferred from; Source
// is set by findings), URL the page of the quote ("" for the digest), QuoteCheck where the box found the quote (tool, digest, live,
// not_found, none) and QuotedText the text it was found in.
type ResearchAnswer struct {
	Verdict                    ProposeVerdict
	Confidence, Basis, Trap    string
	URL                        string
	QuoteCheck, QuotedText     string
	Mode, Layer, Note          string
	Model, Profile, ActivityID string
	Steps                      []ResearchStep
	TokensIn, TokensOut        int
	Fallback                   bool // a call with web tools ran
	// Fetch is what the box read for the research (set by findings): the pages, their bytes, and the excerpts' characters.
	Fetch ResearchFetch
}

// ResearchFetch is what the box read for one research: the reference pages read, their bytes as received, and the excerpts cut.
type ResearchFetch struct {
	Pages        int `json:"pages"`
	Bytes        int `json:"bytes"`
	ExcerptChars int `json:"excerpt_chars"`
}

// researchReader is the version of the research: a line read by an older one is researched again once (toResearch). 2: the box's
// excerpts first, the web only as a fallback.
const researchReader = 2

// The quote checks of a research (fnd_line_research.quote_check).
const (
	QuoteTool     = "tool"
	QuoteDigest   = "digest"
	QuoteLive     = "live"
	QuoteNotFound = "not_found"
	QuoteNone     = "none"
)

func quoteChecked(c string) bool { return c == QuoteTool || c == QuoteDigest || c == QuoteLive }

// LineResearch is one row of fnd_line_research: the research behind a reading.
type LineResearch struct {
	Layer      string         `json:"layer"`
	QuoteCheck string         `json:"quote_check"`
	Tokens     int            `json:"tokens"`
	Detail     ResearchDetail `json:"detail"`
}

// ResearchDetail is fnd_line_research.detail: the mode, the AI's own answer (before the box's checks of the reading), its confidence
// and the trap it checked, what the research could not do, and every layer.
type ResearchDetail struct {
	Mode       string         `json:"mode"`
	Verdict    string         `json:"verdict"`
	Confidence string         `json:"confidence"`
	Basis      string         `json:"basis"`
	FixedIn    string         `json:"fixed_in"`
	Trap       string         `json:"trap"`
	Note       string         `json:"note"`
	Steps      []ResearchStep `json:"steps"`
	// Reader is the research's version (researchReader); 0 for one before the excerpts.
	Reader   int           `json:"reader"`
	Fallback bool          `json:"fallback"`
	Fetch    ResearchFetch `json:"fetch"`
}

func lineResearchOf(a ResearchAnswer) LineResearch {
	layer := a.Layer
	if layer != "strong" {
		layer = "quick"
	}
	qc := a.QuoteCheck
	if !quoteChecked(qc) && qc != QuoteNone {
		qc = QuoteNotFound
	}
	steps := a.Steps
	if steps == nil {
		steps = []ResearchStep{}
	}
	for i := range steps {
		if steps[i].Pages == nil {
			steps[i].Pages = []string{}
		}
	}
	return LineResearch{Layer: layer, QuoteCheck: qc, Tokens: max(0, a.TokensIn+a.TokensOut), Detail: ResearchDetail{Mode: oneLine(a.Mode, 20),
		Verdict: oneLine(a.Verdict.Status, 20), Confidence: oneLine(a.Confidence, 10), Basis: oneLine(a.Basis, 10), FixedIn: oneLine(a.Verdict.FixedIn, 100),
		Trap: oneLine(a.Trap, 300), Note: oneLine(a.Note, 300), Steps: steps, Reader: researchReader, Fallback: a.Fallback, Fetch: a.Fetch}}
}

func storeResearch(ctx context.Context, tx *sql.Tx, key string, r LineResearch) error {
	b, err := json.Marshal(r.Detail)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_line_research (statement_key, layer, quote_check, tokens, detail) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (statement_key) DO UPDATE SET layer = excluded.layer, quote_check = excluded.quote_check, tokens = excluded.tokens, detail = excluded.detail`,
		key, r.Layer, r.QuoteCheck, r.Tokens, string(b)); err != nil {
		return fmt.Errorf("findings: storing a research: %w", err)
	}
	return nil
}

// researchColumn reads the research of a reading with it ("" when none), as one JSON object.
const researchColumn = `ifnull((SELECT json_object('layer', r.layer, 'quote_check', r.quote_check, 'tokens', r.tokens, 'detail', json(r.detail))
	FROM fnd_line_research r WHERE r.statement_key = fnd_line_statement.statement_key), '')`

func parseResearch(s string) *LineResearch {
	if s == "" {
		return nil
	}
	var r LineResearch
	if json.Unmarshal([]byte(s), &r) != nil {
		return nil
	}
	if r.Detail.Steps == nil {
		r.Detail.Steps = []ResearchStep{}
	}
	return &r
}

// researchDigest is what the box read for free about the CVE, for the research: who wrote the record and whether that is the vendor,
// the description and the vendor's solution, every row with where it comes from, and the references with their tags.
func researchDigest(cve string, rec CVERecordText, rows []string) string {
	var b strings.Builder
	b.WriteString(cve + "\n")
	vendorRow, cnaRow := false, false
	for _, r := range rec.Rows {
		vendorRow = vendorRow || r.VendorCNA
		cnaRow = cnaRow || r.Origin == "cna"
	}
	switch {
	case vendorRow:
		b.WriteString("Record writer: the vendor's own CNA (its rows are the vendor's word on its releases).\n")
	case cnaRow:
		b.WriteString("Record writer: a third party, not the vendor (its rows list what it tested; they never prove other releases unaffected).\n")
	}
	if !rec.Read {
		b.WriteString("Only NVD's copy of the record is held (the CNA's record was not read).\n")
	}
	if d := strings.TrimSpace(rec.Description); d != "" {
		b.WriteString("Description: " + clipBytes(d, 1500) + "\n")
	}
	if s := strings.TrimSpace(rec.Solution); s != "" {
		b.WriteString("Vendor's solution: " + clipBytes(s, 600) + "\n")
	}
	if w := strings.TrimSpace(rec.Workaround); w != "" {
		b.WriteString("Workaround: " + clipBytes(w, 400) + "\n")
	}
	for _, r := range rows {
		b.WriteString("Row: " + clipBytes(r, 300) + "\n")
	}
	for _, r := range rec.Rows {
		if r.DefaultStatus != "" && r.DefaultStatus != "unknown" {
			fmt.Fprintf(&b, "Default status of %s %s rows: %s\n", r.Vendor, r.Product, r.DefaultStatus)
		}
	}
	for i, r := range rec.Refs {
		if i == 25 {
			break
		}
		b.WriteString("Reference: " + clipBytes(r.URL, 300))
		if len(r.Tags) > 0 {
			b.WriteString(" [" + strings.Join(r.Tags, ", ") + "]")
		}
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String())
}

// platformsOf is the kinds of devices the units run on, as the research reads them: each device's kind and, when it names no device,
// its system; never a name, a host name or an address. At most 5.
func (s *Service) platformsOf(ctx context.Context, units []checkUnit) []string {
	var ids []string
	for _, u := range units {
		ids = append(ids, u.devs...)
	}
	views, err := s.cfg.Inventory.Assets(ctx, uniqueIDs(ids))
	if err != nil {
		return nil
	}
	var out []string
	for _, id := range slices.Sorted(mapsKeys(views)) {
		v := views[id]
		p := strings.TrimSpace(v.Kind)
		if d := strings.TrimSpace(v.Display); d != "" && d != v.Kind && !namesDevice(d, v) {
			p = strings.TrimSpace(p + ", " + d)
		}
		if p != "" && !slices.Contains(out, p) && len(out) < 5 {
			out = append(out, oneLine(p, 120))
		}
	}
	return out
}

// namesDevice says text carries the device's own name, host name or address.
func namesDevice(text string, v AssetView) bool {
	low := strings.ToLower(text)
	for _, n := range []string{v.Name, v.IP, v.ID} {
		if n != "" && n != NoIP && strings.Contains(low, strings.ToLower(n)) {
			return true
		}
	}
	return v.Hostname != nil && *v.Hostname != "" && strings.Contains(low, strings.ToLower(*v.Hostname))
}

// researchVerdict is the research's answer as a reading of the line: a quote found in what the box read itself is credited to where it
// was found (the reference page the box fetched, else the CVE record: Source 0), never to the page the AI cited; a quote its tools or a
// live fetch found is the cited page among the pages the box read, else a page of the research's own appended to pages; a "not affected" whose fix
// the quote or the text it was found in names is a fixed line.
func researchVerdict(a ResearchAnswer, pages []FetchedPage) (ProposeVerdict, []FetchedPage) {
	v := a.Verdict
	v.Index = 0
	// "not affected" because the installed release has the fix: a fixed line, so each version is placed against the fix (pastFix); an
	// "affected" keeps its bounds (the version inside them), and an inference never states a fix
	if v.Status == StatementNotAffected && v.InferredFrom == "" && a.Basis != BasisInferred && (v.FixedIn != "" || v.LastAffected != "") {
		if b := cmpNonEmpty(v.FixedIn, v.LastAffected); namesToken(v.Quote, b) || namesToken(a.QuotedText, b) {
			v.Status = StatementFixed
		}
	}
	if a.Basis == BasisInferred && v.InferredFrom == "" {
		v.InferredFrom = "a product sharing its code (the AI's inference)"
	}
	switch {
	case a.QuoteCheck == QuoteDigest:
		// found in what the box read itself: one of the reference pages it fetched (that page, whatever the AI cited), else the CVE
		// record as the box digested it, never the page the AI named
		for i, p := range pages {
			if p.Text != "" && p.Text == a.QuotedText {
				v.Source = i + 1
				return v, pages
			}
		}
		v.Source = 0
	case a.URL == "":
		v.Source = 0
	default:
		for i, p := range pages {
			if p.URL == a.URL {
				v.Source = i + 1
				return v, pages
			}
		}
		pages = append(slices.Clone(pages), FetchedPage{URL: a.URL, Status: "ok", Text: a.QuotedText})
		v.Source = len(pages)
	}
	return v, pages
}

// stillQuoted says a reading still stands on what the box reads now: its quote is in the record's text (a reading of the record) or on
// its cited page as the box fetched it this time (pages, else fetch reads it). A reading the box made from the page's text before
// research kept a hash of that text: unchanged text stands too.
func stillQuoted(st *LineStatement, pages []FetchedPage, record string, fetch func(string) (string, bool)) bool {
	if st.URL == "" {
		return st.Quote != "" && quoteFound(st.Quote, record)
	}
	text, ok := pageText(st, pages, record)
	if !ok && fetch != nil {
		text, ok = fetch(st.URL)
	}
	if !ok {
		return false
	}
	if st.Research == nil && pageHash(text) == st.PageHash {
		return true
	}
	return st.Quote != "" && (quoteFound(st.Quote, text) || normQuoteIn(st.Quote, text))
}

// normQuoteIn is the research's tolerant quote check (markup, typographic quotes, Markdown marks and letter case folded).
func normQuoteIn(quote, text string) bool {
	q := normQuote(quote)
	return len(q) >= 12 && strings.Contains(normQuote(text), q)
}

var quoteFold = strings.NewReplacer("‘", "'", "’", "'", "“", `"`, "”", `"`, "–", "-", "—", "-", " ", " ", "*", " ", "_", " ", "`", " ", "#", " ")

func normQuote(s string) string { return foldSpace(quoteFold.Replace(s)) }

// rehashStatement moves a reading that survived a re-read of the record to the record's new identity.
func rehashStatement(ctx context.Context, tx *sql.Tx, key, record string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE fnd_line_statement SET record_hash = ?, seen_at = ? WHERE statement_key = ?`, record, store.FormatTS(now), key); err != nil {
		return fmt.Errorf("findings: keeping a reading across a record re-read: %w", err)
	}
	return nil
}

// onPages says the reading's cited text is one the box read itself this time: the record, or one of its reference pages.
func onPages(st *LineStatement, pages []FetchedPage) bool {
	if st.URL == "" {
		return true
	}
	return slices.ContainsFunc(pages, func(p FetchedPage) bool { return p.URL == st.URL })
}

// ---- the review queue (P-12): the AI's "not affected" answers, which wait for a person ----

// ReviewFilter selects the rows of GET /findings/review.
type ReviewFilter struct {
	Device, Software, Q string
	Confidence          string // high, medium or low: the AI's own confidence ("" every one)
	Quote               string // checked: the box found the quote; unchecked: it did not ("" both)
}

// ReviewList is contract.ts ReviewList.
type ReviewList struct {
	Items     []PossibleRowJS `json:"items"`
	Total     int             `json:"total"`
	Exploited int             `json:"exploited"` // rows of the filter whose CVE is exploited: confirmed in bulk only when the request names them
}

// reviewable says the possible CVE is an AI "not affected" answer waiting for a person.
func reviewable(it PossibleItem) bool {
	return it.State == PossibleProposal && it.Check != nil && it.Check.DecidedBy == DecidedAI && it.Check.Verdict == VerdictNotAffected && it.Check.RejectedBy == ""
}

// aiConfidence is the AI's own confidence of the reading behind a check ("" for a reading made before research).
func aiConfidence(c *Check) string {
	if c == nil || c.Reading == nil || c.Reading.Research == nil {
		return ""
	}
	return c.Reading.Research.Detail.Confidence
}

// Review reads one page of the review queue: the AI's "not affected" answers (of one device, one software line, a confidence, an
// evidence class, a search), exploited CVEs first.
func (s *Service) Review(ctx context.Context, f ReviewFilter, p Page) (ReviewList, error) {
	out := ReviewList{Items: []PossibleRowJS{}}
	err := s.readTx(ctx, func(ctx context.Context) error {
		items, err := s.possibleItemsOf(ctx, f.Device, true)
		if err != nil {
			return err
		}
		rs := s.ReadState(ctx)
		var keep []PossibleItem
		for _, it := range items {
			switch {
			case !reviewable(it):
			case f.Software != "" && it.Question.SoftwareID != f.Software:
			case f.Confidence != "" && aiConfidence(it.Check) != f.Confidence:
			case f.Quote == "checked" && (it.Check.Reading == nil || !it.Check.Reading.QuoteFound):
			case f.Quote == "unchecked" && it.Check.Reading != nil && it.Check.Reading.QuoteFound:
			default:
				keep = append(keep, it)
			}
		}
		slices.SortStableFunc(keep, func(a, b PossibleItem) int { return -cmpBool(a.Exploited, b.Exploited) })
		var assets, lines, cves []string
		for _, it := range keep {
			assets, lines, cves = append(assets, it.Question.AssetID), append(lines, it.Question.SoftwareID), append(cves, it.CVE)
		}
		ref, err := s.refs(ctx, uniqueIDs(assets), uniqueIDs(nonEmpty(lines)), uniqueIDs(cves))
		if err != nil {
			return err
		}
		q := strings.ToLower(strings.TrimSpace(f.Q))
		var rows []PossibleRowJS
		for _, it := range keep {
			r := possibleRow(it, ref, rs)
			if q != "" && !possibleMatches(r, q) {
				continue
			}
			if it.Question.Detail.Review {
				if id, err := s.openAIFinding(ctx, it.Question, it.CVE); err != nil {
					return err
				} else if id != "" {
					r.Finding = &id
				}
			}
			if it.Exploited {
				out.Exploited++
			}
			rows = append(rows, r)
		}
		out.Total = len(rows)
		lo, hi := p.cut(len(rows))
		out.Items = append(out.Items, rows[lo:hi]...)
		return nil
	})
	return out, err
}

// ReviewSkip is one row a bulk confirmation left: not_waiting (no such AI answer waits: answered, rejected, or the evidence changed) or
// exploited (its CVE is exploited and the request did not name it).
type ReviewSkip struct {
	ID     string `json:"id"`
	CVE    string `json:"cve"`
	Reason string `json:"reason"`
}

// ReviewConfirmed is contract.ts ReviewConfirmed.
type ReviewConfirmed struct {
	Confirmed int          `json:"confirmed"`
	Skipped   []ReviewSkip `json:"skipped"`
}

// ErrReviewIDs is a bulk confirmation with no row or too many.
var ErrReviewIDs = &APIError{"invalid", 400, fmt.Sprintf("Tick from 1 to %d AI answers to confirm.", MaxBulk)}

// ConfirmReview confirms the AI's "not affected" answers of the questions ids in one transaction: each answers its question "not
// affected" as ConfirmProposal does (listed under Handled and Answered, reopenable). A row whose CVE is exploited is confirmed only
// when its CVE is in includeExploited (the person ticked it by name); an exploited list that cannot be read confirms nothing.
func (s *Service) ConfirmReview(ctx context.Context, ids, includeExploited []string, user string) (ReviewConfirmed, error) {
	out := ReviewConfirmed{Skipped: []ReviewSkip{}}
	if err := ValidUser(user); err != nil {
		return out, err
	}
	ids = uniqueIDs(ids)
	if len(ids) == 0 || len(ids) > MaxBulk {
		return out, ErrReviewIDs
	}
	items, err := s.possibleItemsOf(ctx, "", true) // fails closed when the exploited lists cannot be read
	if err != nil {
		return out, err
	}
	byID := map[string]PossibleItem{}
	for _, it := range items {
		if it.Question.CVE == it.CVE {
			byID[it.Question.ID] = it
		}
	}
	var confirm []string
	rematch := map[string]bool{} // devices whose AI finding a confirmation closes: matched again at once
	for _, id := range ids {
		it, ok := byID[id]
		switch {
		case !ok || !reviewable(it):
			out.Skipped = append(out.Skipped, ReviewSkip{ID: id, CVE: it.CVE, Reason: "not_waiting"})
		case it.Exploited && !slices.Contains(includeExploited, it.CVE):
			out.Skipped = append(out.Skipped, ReviewSkip{ID: id, CVE: it.CVE, Reason: "exploited"})
		default:
			confirm = append(confirm, id)
			if it.Question.Detail.Review {
				rematch[it.Question.AssetID] = true
			}
		}
	}
	before := len(out.Skipped)
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		out.Confirmed, out.Skipped = 0, out.Skipped[:before]
		// the exploited lists are read again inside the write that answers: a CVE listed since the read above is confirmed only when
		// named; a list that cannot be read confirms nothing
		exploited, err := s.exploitedSet(ctx)
		if err != nil {
			return err
		}
		unnamed := map[string]bool{}
		for c := range exploited {
			if !slices.Contains(includeExploited, c) {
				unnamed[c] = true
			}
		}
		for _, id := range confirm {
			if _, err := s.confirmOne(ctx, tx, id, user, now, emit, unnamed, false); err != nil {
				switch {
				case errors.Is(err, ErrNoProposal):
					out.Skipped = append(out.Skipped, ReviewSkip{ID: id, CVE: byID[id].CVE, Reason: "not_waiting"})
					continue
				case errors.Is(err, ErrProposalPerRow):
					out.Skipped = append(out.Skipped, ReviewSkip{ID: id, CVE: byID[id].CVE, Reason: "exploited"})
					continue
				}
				return err
			}
			out.Confirmed++
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	// the person's "not affected" ends the finding the older AI reading kept open: the match applies the answer now
	for _, d := range slices.Sorted(mapsKeys(rematch)) {
		s.stamps.drop(d)
		if _, err := s.OnMatchChanged(ctx, d); err != nil && !errors.Is(err, ErrUnknownAsset) {
			s.cfg.Log.WarnContext(ctx, "findings: matching a device after a confirmation failed", "device", d, "error", err)
		}
	}
	return out, nil
}

// openAIFinding is the open finding of the question's device, CVE and line ("" when none).
func (s *Service) openAIFinding(ctx context.Context, q Question, cve string) (string, error) {
	var id string
	err := s.rd(ctx).QueryRowContext(ctx, `SELECT id FROM fnd_finding WHERE asset_id = ? AND cve = ? AND ifnull(software_id, '') = ? AND state = 'open' LIMIT 1`,
		q.AssetID, cve, q.SoftwareID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// ErrNotResearchable is "Research deeper" on a possible CVE the box cannot research (no check identity, or not possible any more).
var ErrNotResearchable = &APIError{"not_found", 404, "This possible CVE cannot be researched: it was decided, or Vedette lacks the version it needs."}

// StartResearchDeeper queues the release line of one possible CVE (question id) in front of the research worker's queue, to be
// researched again with the strong layer now (CheckStatus follows it; a line already queued or being researched is not asked twice).
// The answer replaces the line's reading like any research.
func (s *Service) StartResearchDeeper(ctx context.Context, questionID, actor string) (CheckRun, error) {
	if err := ValidUser(actor); err != nil {
		return CheckRun{}, err
	}
	if _, err := s.CheckStatus(ctx); err != nil {
		return CheckRun{}, err
	}
	unit, err := s.deeperUnit(ctx, questionID)
	if err != nil {
		return CheckRun{}, err
	}
	s.push([]checkUnit{*unit}, actor)
	return s.queuedRun(1, actor), nil
}

// deeperUnit is the unit "Research deeper" researches for the possible CVE of question id: its evidence identity, marked deeper.
func (s *Service) deeperUnit(ctx context.Context, questionID string) (*checkUnit, error) {
	items, err := s.possibleItems(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		if it.Question.ID == questionID && it.Question.CVE == it.CVE && it.Question.CheckKey != "" && it.Question.Detail.Check != nil && checkable(it.Question) {
			return &checkUnit{key: it.Question.CheckKey, cve: it.CVE, id: *it.Question.Detail.Check, q: it.Question, devs: []string{it.Question.AssetID}, deeper: true}, nil
		}
	}
	return nil, ErrNotResearchable
}

// shownNames is the names the devices show the installed software by (QuestionDetail.Software), for the research: only a name that
// names the product's vendor or the first word of its name (so a name of the customer's own never leaves the box), each once, at most 5.
func shownNames(qs []Question, product string) []string {
	vendor, name, _ := strings.Cut(strings.ToLower(product), "|")
	words := strings.Fields(strings.NewReplacer("_", " ", "-", " ").Replace(name))
	var keys []string
	if v := strings.Fields(vendor); len(v) > 0 && len(v[0]) >= 3 {
		keys = append(keys, v[0])
	}
	if len(words) > 0 && len(words[0]) >= 3 {
		keys = append(keys, words[0])
	}
	var out []string
	for _, q := range qs {
		shown := oneLine(q.Detail.Software, 120)
		if shown == "" || slices.Contains(out, shown) || len(out) == 5 {
			continue
		}
		low := " " + strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				return unicode.ToLower(r)
			}
			return ' '
		}, shown) + " "
		if slices.ContainsFunc(keys, func(k string) bool { return strings.Contains(low, " "+k+" ") }) {
			out = append(out, shown)
		}
	}
	return out
}
