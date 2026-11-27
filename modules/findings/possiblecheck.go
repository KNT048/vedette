package findings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
)

// Checking possible findings, the app first. A person starts one check (POST /findings/possible/check); it runs in the background over
// the possible CVEs that have a check identity and no stored check, at most possibleCheckMax of them, one CVE at a time:
//
//  1. the box's own data already ran (the match pass made the question because it decided nothing);
//  2. the box fetches the CVE's reference pages (https, chosen by their tags) and reads them itself (readAdvisory): a CSAF advisory or
//     a vendor's plain-text ranges that decide the version are the box's own verdict (decided by advisory), applied by the next match
//     like any range data, with the sentence quoted;
//  3. only what that leaves undecided goes to the AI (PossibleChecker.Propose): its verdict is a proposal a person confirms or rejects,
//     rated confident (its quote is in the page word for word and names a range of the version's line) or likely (the rest); unsure
//     decides nothing and keeps the AI's reason.
//
// Each check is stored once per evidence identity (fnd_possible_check) with how it was decided, and the CVE's undecided reason and
// blocking evidence when it stays undecided. A check that failed (no answer, a budget, the provider) stores nothing.

// possibleCheckMax is the most evidence identities one check reads; possibleCheckTimeout bounds a whole check.
const (
	possibleCheckMax     = 40
	possibleCheckTimeout = 15 * time.Minute
	possibleCheckItems   = 10 // the most products of one CVE in one AI call
)

// PossibleChecker is what a check of possible findings needs from outside findings (the binary's adapter over feeds and the ai module).
// nil: no check (the AI module is off).
type PossibleChecker interface {
	// Ready is nil when a check can run; else an error a person can read (no AI profile, the skill off).
	Ready(ctx context.Context) error
	// Record is the CVE's description and its references as the catalogue holds them.
	Record(ctx context.Context, cve string) (CVERecordText, error)
	// Fetch reads public reference pages over HTTPS (the box's own requests, no AI).
	Fetch(ctx context.Context, urls []string) []FetchedPage
	// Propose asks the AI for the vendor's statement for each item's release line from the public text (one call, the explain-finding
	// job's profile and budget; actor SystemUser is the automatic reading, held to its daily number of reads).
	Propose(ctx context.Context, actor string, req ProposeRequest) (ProposeAnswer, error)
	// Budget is how the automatic reading stands: switched on or off in the AI settings, and whether its reads are used up for now.
	Budget(ctx context.Context) ReadBudget
}

// ReadBudget is how the automatic reading of advisories stands (the AI settings).
type ReadBudget struct {
	Auto    bool // it runs by itself after a match pass
	Reached bool // today's reads, or this month's tokens for background jobs, are used up
}

// CheckStop is a Propose error that stops the whole check (the AI unavailable, this month's budget reached): Reason is the sentence
// a person reads.
type CheckStop struct{ Reason string }

func (e *CheckStop) Error() string { return e.Reason }

// ItemRefused is a Propose error about the items of that one call only (a hook stopped its text, the answer was not usable): the check
// goes on with the next item, and the automatic reading leaves these items until RetryAfter has passed, so one item that cannot be read
// is never first again at every run. Reason is the sentence a person reads. Systemic is set when the provider's answer was not usable
// (outside the schema, cut off): that may be the model rather than the item, so such calls count toward aiFailStreak too; a hook's
// refusal is about the item's own text and does not.
type ItemRefused struct {
	Reason     string
	RetryAfter time.Duration
	Systemic   bool
}

func (e *ItemRefused) Error() string { return e.Reason }

// possibleRetry is how long the automatic reading leaves items whose call failed for a reason Propose did not name (the provider
// answered an error, the hooks could not finish in time): the next run after it reads them again. aiFailStreak such calls in a row, or
// answers that could not be used (ItemRefused Systemic), with no answer between, mean the AI is not answering at all: the run stops
// there instead of failing every item that is left. The identification of software keeps the same streak.
const (
	possibleRetry = time.Hour
	aiFailStreak  = 3
)

// CVERecordText is the public text of a CVE's record: its description, the CNA's solution, the affected rows of every product it names
// and its references.
type CVERecordText struct {
	Description string
	Solution    string // the CNA's solution text, "" when none
	Rows        []RecordRow
	Refs        []RefLink
}

// RecordRow is one affected row of a CVE record as a person reads it, with the product it is about (the record's words).
type RecordRow struct {
	Vendor, Product string
	Edition         string // the edition the row's CPE pins (sw_edition, "esr"), "" when none
	Text            string // "acme widget (edition esr): affected from 3.0 before 3.4.2 [nvd]"
}

// recordRowsMax is the most rows of the record one reading sends (the item's own product first).
const recordRowsMax = 40

// readRecordRows is the record's rows the AI reads for the product: its own rows first, then every other product's, at most recordRowsMax;
// the rows the match read for the question when the record gave none.
func readRecordRows(rec CVERecordText, product string, q Question) []string {
	if len(rec.Rows) == 0 {
		return q.undecidedRows()
	}
	vendor, name, _ := strings.Cut(product, "|")
	own := func(r RecordRow) bool {
		return productid.Norm(r.Vendor) == productid.Norm(vendor) && productid.Norm(r.Product) == productid.Norm(name)
	}
	var mine, others []string
	for _, r := range rec.Rows {
		if t := strings.TrimSpace(r.Text); t != "" {
			if own(r) {
				mine = append(mine, t)
			} else {
				others = append(others, t)
			}
		}
	}
	out := append(mine, others...)
	return out[:min(len(out), recordRowsMax)]
}

// ownRowOnLine says a row of the record about product names a release of release line ("115.13" or "115.13.0" for line 115): an inference
// from another product's line N stands only while the record says nothing of this product's own line N.
func ownRowOnLine(rec CVERecordText, product, line string) bool {
	if line == "" {
		return false
	}
	vendor, name, _ := strings.Cut(product, "|")
	for _, r := range rec.Rows {
		if productid.Norm(r.Vendor) != productid.Norm(vendor) || productid.Norm(r.Product) != productid.Norm(name) {
			continue
		}
		for _, tok := range reVersionToken.FindAllString(r.Text, -1) {
			if tok == line || dottedPrefix(line, tok) {
				return true
			}
		}
	}
	return false
}

// otherProductsRow is the product ("vendor product") of the record's row that quote is from, when that row is another product's and the
// quote is in no row of product, nor in the description or the solution: an answer relying on it reads another product's statement,
// so it is an inference whatever the answer says (its bounds are that product's releases). "" otherwise.
func otherProductsRow(rec CVERecordText, product, quote string) string {
	if quoteFound(quote, rec.Description) || quoteFound(quote, rec.Solution) {
		return ""
	}
	vendor, name, _ := strings.Cut(product, "|")
	from := ""
	for _, r := range rec.Rows {
		if !quoteFound(quote, r.Text) {
			continue
		}
		if productid.Norm(r.Vendor) == productid.Norm(vendor) && productid.Norm(r.Product) == productid.Norm(name) {
			return ""
		}
		if from == "" {
			from = strings.TrimSpace(r.Vendor + " " + r.Product)
		}
	}
	return from
}

// unpairedBound names the other product of the record a release of the answer belongs to, when the quote names another product of the
// record: a bound the answer gives, the "before X" on the version's own train the quote states (its fix), and the version or line the
// quote names are this product's only when, at every place the quote names them, the nearest product name before it is this product's
// ("fixed in Browser ESR 115.42 and Mail 140.17": 115.42 is the browser's). A name inside a longer one is the longer one's ("Mail" in
// "Mail Server", "Mail-Server" or "MailServer"); a name is this product's for the vendor's same product or its edition ("Browser
// ESR"). A bound the quote does not hold is not this product's either. "" when the quote names no other product of the record, or every
// release it pairs is this product's.
func unpairedBound(rec CVERecordText, id CheckID, v ProposeVerdict) string {
	quote := strings.ToLower(oneLine(v.Quote, 400))
	vendor, name, _ := strings.Cut(id.Product, "|")
	own := func(rv, rp string) bool {
		p, n := productid.Norm(rp), productid.Norm(name)
		return productid.Norm(rv) == productid.Norm(vendor) && (p == n || strings.HasPrefix(p, n) && releaseWord[p[len(n):]])
	}
	type named struct {
		start, end int
		own        bool
		label      string
	}
	var found []named
	add := func(rv, rp string) {
		words := strings.FieldsFunc(strings.ToLower(rp), func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') })
		if len(strings.Join(words, "")) < 2 {
			return
		}
		for i, w := range words {
			words[i] = regexp.QuoteMeta(w)
		}
		re := regexp.MustCompile(`(?:^|[^a-z0-9])(` + strings.Join(words, `[\s_.\-]{0,2}`) + `)(?:$|[^a-z0-9])`)
		for _, m := range re.FindAllStringSubmatchIndex(quote, -1) {
			found = append(found, named{start: m[2], end: m[3], own: own(rv, rp), label: strings.TrimSpace(rv + " " + rp)})
		}
	}
	add(vendor, name)
	for _, r := range rec.Rows {
		add(r.Vendor, r.Product)
	}
	var names []named // a name inside a longer name of the quote is that longer name's
	other := ""
	for _, n := range found {
		if slices.ContainsFunc(found, func(o named) bool { return o.start <= n.start && o.end >= n.end && o.end-o.start > n.end-n.start }) {
			continue
		}
		names = append(names, n)
		if !n.own && other == "" {
			other = n.label
		}
	}
	if other == "" {
		return ""
	}
	pairedOwn := func(at int) string { // "" when the nearest name before at is this product's, else the product it is paired with
		var near *named
		for i := range names {
			n := &names[i]
			if n.end > at {
				continue
			}
			if near == nil || n.start > near.start || n.start == near.start && n.end > near.end {
				near = n
			}
		}
		switch {
		case near == nil:
			return other
		case !near.own:
			return near.label
		}
		return ""
	}
	bounds := []string{v.Introduced, v.FixedIn, v.LastAffected}
	for _, m := range reBefore.FindAllStringSubmatch(v.Quote, -1) {
		if x := strings.TrimRight(m[1], "."); onFixTrain(x, id.Version) {
			bounds = append(bounds, x)
		}
	}
	for i, b := range append(bounds, id.Version, id.Line, v.Line) {
		b = strings.ToLower(strings.TrimSpace(b))
		if b == "" {
			continue
		}
		at := tokenIndexes(quote, b)
		if len(at) == 0 && i < len(bounds) {
			return other // a bound the quote does not hold
		}
		for _, a := range at {
			if p := pairedOwn(a); p != "" {
				return p
			}
		}
	}
	return ""
}

// tokenIndexes are the places text (lower case) names tok as a whole version (namesToken): not inside a longer version, a sentence's
// last period may follow it.
func tokenIndexes(text, tok string) []int {
	word := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' }
	var out []int
	for from := 0; tok != ""; {
		i := strings.Index(text[from:], tok)
		if i < 0 {
			break
		}
		at, end := from+i, from+i+len(tok)
		from = at + 1
		if at > 0 && (word(text[at-1]) || text[at-1] == '.') {
			continue
		}
		if end < len(text) && (word(text[end]) || text[end] == '.' && end+1 < len(text) && word(text[end+1])) {
			continue
		}
		out = append(out, at)
	}
	return out
}

// recordText is the text of the record the AI reads as data block 0 and its quotes are looked up in: the description, the solution and
// the rows, one per line.
func recordText(rec CVERecordText, rows []string) string {
	parts := []string{strings.TrimSpace(rec.Description)}
	if s := strings.TrimSpace(rec.Solution); s != "" {
		parts = append(parts, s)
	}
	parts = append(parts, rows...)
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

// RefLink is one reference of a CVE record with its tags ("Vendor Advisory", "Patch").
type RefLink struct {
	URL  string
	Tags []string
}

// FetchedPage is one reference page as the box read it (Status ok, failed or skipped, with a note).
type FetchedPage struct {
	URL, Title, Status, Note, Text string
	JSON                           bool
	// Vendor says the page is the vendor's own advisory: its reference is tagged vendor-advisory or it is on the vendor's host
	// (vendorHost). Only such a page may settle "not affected"; findings sets it from the CVE record.
	Vendor bool
	// Empty says the page answered but has no advisory text (emptyPages): fetching it again gives the same.
	Empty bool
}

// ProposeItem is one product version of a CVE the AI is asked about (no device data). Edition is the build's edition as a CPE
// sw_edition when the box knows it and the record's rows pin editions ("esr"), "" otherwise.
type ProposeItem struct {
	Index                                   int
	Vendor, Product, Version, Line, Edition string
}

// ProposeRequest is one AI call: the CVE's public record and pages, and the items.
type ProposeRequest struct {
	CVE, Description string
	Rows             []string
	Items            []ProposeItem
	Pages            []FetchedPage
}

// ProposeVerdict is the AI's answer for one item: the vendor's statement for the item's release line.
type ProposeVerdict struct {
	Index                             int
	Status                            string // affected, fixed, not_affected or unsure
	Introduced, FixedIn, LastAffected string // the bounds the AI read ("" when none)
	Line                              string // the release line as the statement names it
	Reason, Quote                     string
	Source                            int // 1-based page index, 0 for the record
	// InferredFrom names the other product of the record whose release line the answer infers this one's from ("" when the text states
	// it for this product): such an answer may only say "affected" (readingOfAnswer).
	InferredFrom string
}

// ProposeAnswer is the answer of one AI call.
type ProposeAnswer struct {
	Verdicts                   []ProposeVerdict
	Model, Profile, ActivityID string
}

// CheckRun is contract.ts PossibleCheckRun: how the last check stands.
type CheckRun struct {
	Running    bool    `json:"running"`
	Total      int     `json:"total"`
	Done       int     `json:"done"`
	Advisory   int     `json:"advisory"`  // decided by the box from a vendor's advisory
	Proposals  int     `json:"proposals"` // AI proposals made (a reading of an exploited CVE as not affected, which a person confirms)
	Readings   int     `json:"readings"`  // AI readings of a vendor's statement stored (one per release line)
	Undecided  int     `json:"undecided"` // checked, still undecided
	Failed     int     `json:"failed"`    // not checked: a fetch or AI call failed (asked again by the next check)
	Stopped    *string `json:"stopped"`   // why the check stopped before the end (a budget, the AI unavailable); nil otherwise
	By         string  `json:"by"`
	StartedAt  string  `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
}

// checkState is the service's one check at a time.
type checkState struct {
	mu     sync.Mutex
	run    *CheckRun
	unread map[string]time.Time // check keys whose pages could not be read, when (the next check tries again)
	// held is the check keys whose AI call was refused or failed, until when the automatic reading leaves them and why (a person's
	// check reads them at once)
	held map[string]heldItem
	// due is the lines a finding the AI's reading opened stands on whose reading is due again (the record changed, or the page was not
	// fetched for statementRecheck): they have no question, so the match notes them here for the next check (noteReadingDue).
	due map[string]checkUnit
}

// noteReadingDue notes that the reading behind the finding of question q is due again (called by the match).
func (s *Service) noteReadingDue(q Question) {
	if q.CheckKey == "" || q.Detail.Check == nil {
		return
	}
	s.check.mu.Lock()
	defer s.check.mu.Unlock()
	if s.check.due == nil {
		s.check.due = map[string]checkUnit{}
	}
	u, ok := s.check.due[q.CheckKey]
	if !ok {
		u = checkUnit{key: q.CheckKey, cve: q.CVE, id: *q.Detail.Check, q: q}
	}
	if !slices.Contains(u.devs, q.AssetID) {
		u.devs = append(u.devs, q.AssetID)
	}
	s.check.due[q.CheckKey] = u
}

// unitsToCheck is what a check reads: the checkable possible items, and the lines of findings the AI's reading opened whose reading is
// due again (taken: the next match notes them again if they are still due).
func (s *Service) unitsToCheck(ctx context.Context, items []PossibleItem) []checkUnit {
	units := checkUnits(items, s.scoresOf(ctx, items))
	s.check.mu.Lock()
	due := s.check.due
	s.check.due = nil
	s.check.mu.Unlock()
	have := map[string]bool{}
	for _, u := range units {
		have[u.key] = true
	}
	var extra []checkUnit
	for _, k := range slices.Sorted(mapsKeys(due)) {
		if !have[k] {
			extra = append(extra, due[k])
		}
	}
	slices.SortStableFunc(extra, func(a, b checkUnit) int { return strings.Compare(a.cve, b.cve) })
	return append(units, extra...) // a finding is open already: the possible CVEs come first
}

// unreadKeys is the check keys whose pages the last check could not read.
func (s *Service) unreadKeys() map[string]bool {
	s.check.mu.Lock()
	defer s.check.mu.Unlock()
	out := make(map[string]bool, len(s.check.unread))
	for k := range s.check.unread {
		out[k] = true
	}
	return out
}

func (s *Service) markUnread(keys []string, unread bool, now time.Time) {
	s.check.mu.Lock()
	defer s.check.mu.Unlock()
	if s.check.unread == nil {
		s.check.unread = map[string]time.Time{}
	}
	for _, k := range keys {
		if unread {
			s.check.unread[k] = now
		} else {
			delete(s.check.unread, k)
		}
	}
}

// heldItem is why the automatic reading leaves an item for now, and until when: kind is one of HeldReasons (what a person reads),
// reason the error of the call (the log's).
type heldItem struct {
	until  time.Time
	kind   string
	reason string
}

// Why the automatic reading leaves an item for now (Held.Reason), a closed list a person reads as a label (never the provider's words).
const (
	HeldHookRefused    = "hook_refused"    // a hook stopped the text of its call
	HeldAnswerUnusable = "answer_unusable" // the AI's answer was outside the format or cut off
	HeldAIFailed       = "ai_failed"       // the AI provider failed, or the hooks could not finish in time
)

// HeldReasons is the closed list of Held.Reason.
var HeldReasons = []string{HeldHookRefused, HeldAnswerUnusable, HeldAIFailed}

// Held is until when the automatic reading leaves an item, and why (one of HeldReasons).
type Held struct {
	Until  time.Time
	Reason string
}

// heldKind is the HeldReasons entry of a call's error.
func heldKind(err error) string {
	if refused := (*ItemRefused)(nil); errors.As(err, &refused) {
		if refused.Systemic {
			return HeldAnswerUnusable
		}
		return HeldHookRefused
	}
	return HeldAIFailed
}

// heldKeys is the check keys the automatic reading leaves at now, with until when and why.
func (s *Service) heldKeys(now time.Time) map[string]Held {
	s.check.mu.Lock()
	defer s.check.mu.Unlock()
	out := map[string]Held{}
	for k, h := range s.check.held {
		if now.Before(h.until) {
			out[k] = Held{Until: h.until, Reason: h.kind}
		}
	}
	return out
}

// hold notes the keys whose call was refused or failed (until the time given, kind one of HeldReasons), or clears them after an answer
// (zero until).
func (s *Service) hold(keys []string, until time.Time, kind, reason string) {
	s.check.mu.Lock()
	defer s.check.mu.Unlock()
	if s.check.held == nil {
		s.check.held = map[string]heldItem{}
	}
	for _, k := range keys {
		if until.IsZero() {
			delete(s.check.held, k)
		} else {
			s.check.held[k] = heldItem{until: until, kind: kind, reason: reason}
		}
	}
}

// ReadState is how the AI's reading stands now, as PossibleCause reads it.
func (s *Service) ReadState(ctx context.Context) ReadState {
	if s.cfg.Checker == nil || s.cfg.Checker.Ready(ctx) != nil {
		return ReadState{}
	}
	b := s.cfg.Checker.Budget(ctx)
	return ReadState{Ready: true, Auto: b.Auto, BudgetReached: b.Reached}
}

// The API errors of a check.
var (
	ErrCheckUnavailable = &APIError{"ai_unavailable", 409, "Checking possible findings needs the AI assistant with a profile for explaining findings (Settings, AI assistant)."}
	ErrCheckRunning     = &APIError{"check_running", 409, "A check of possible findings is running. Wait for it to finish."}
	ErrNothingToCheck   = &APIError{"nothing_to_check", 409, "Every possible finding was checked already; a new check runs when a version or a CVE record changes."}
	ErrNoProposal       = &APIError{"not_found", 404, "No such proposal: it was answered, rejected or the evidence changed."}
	ErrProposalPerRow   = &APIError{"invalid", 400, "An exploited CVE proposed not affected is confirmed one by one, after reading its sources."}
	ErrNeedsAdmin       = &APIError{"forbidden", 403, "Recording a CVE as affected on your word needs an administrator."}
)

// SetChecker sets the door a check of possible findings goes through (the binary sets it once while wiring, before serving).
func (s *Service) SetChecker(c PossibleChecker) { s.cfg.Checker = c }

// CheckStatus is how the last check stands (nil when none ran since the box started), with whether a check can run now.
func (s *Service) CheckStatus(ctx context.Context) (run *CheckRun, ready error) {
	s.check.mu.Lock()
	if s.check.run != nil {
		c := *s.check.run
		run = &c
	}
	s.check.mu.Unlock()
	if s.cfg.Checker == nil {
		return run, ErrCheckUnavailable
	}
	if err := s.cfg.Checker.Ready(ctx); err != nil {
		return run, &APIError{"ai_unavailable", 409, err.Error()}
	}
	return run, nil
}

// checkUnit is one evidence identity a check reads, with the items (devices) that share it.
type checkUnit struct {
	key  string
	cve  string
	id   CheckID
	q    Question // one of its questions (for the software's name and the undecided reason the match gave)
	devs []string
}

// StartPossibleCheck starts a check of the possible CVEs (of one device when device is set) and returns its first state. The check
// runs in the background; CheckStatus follows it.
func (s *Service) StartPossibleCheck(ctx context.Context, device, actor string) (CheckRun, error) {
	if err := ValidUser(actor); err != nil {
		return CheckRun{}, err
	}
	if _, err := s.CheckStatus(ctx); err != nil {
		return CheckRun{}, err
	}
	items, err := s.possibleItems(ctx, device)
	if err != nil {
		return CheckRun{}, err
	}
	units := s.unitsToCheck(ctx, items)
	if len(units) == 0 {
		return CheckRun{}, ErrNothingToCheck
	}
	if len(units) > possibleCheckMax {
		units = units[:possibleCheckMax]
	}
	s.check.mu.Lock()
	if s.check.run != nil && s.check.run.Running {
		s.check.mu.Unlock()
		return CheckRun{}, ErrCheckRunning
	}
	run := &CheckRun{Running: true, Total: len(units), By: actor, StartedAt: store.FormatTS(s.now())}
	s.check.run = run
	first := *run
	s.check.mu.Unlock()
	go func() {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), possibleCheckTimeout)
		defer cancel()
		s.runPossibleCheck(bg, units, actor)
	}()
	return first, nil
}

// possibleAutoMax is the most evidence identities one automatic reading takes; the AI settings' daily number of reads and this month's
// budget stop it earlier.
const possibleAutoMax = 200

// AutoRead starts the automatic reading of possible findings after a match pass, in the background: when a reading can run, the AI
// settings have it on and its reads for today are not used up, over every possible CVE that is due (exploited first, then the highest
// CVSS score), skipping those whose pages could not be read in the last day and those whose last call was refused or failed until their
// retry time (held). It returns whether a reading started; nothing happens while another check runs.
func (s *Service) AutoRead(ctx context.Context) bool {
	if s.cfg.Checker == nil || s.cfg.Checker.Ready(ctx) != nil {
		return false
	}
	if b := s.cfg.Checker.Budget(ctx); !b.Auto || b.Reached {
		return false
	}
	items, err := s.possibleItems(ctx, "")
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: reading possible findings for the automatic reading failed", "error", err)
		return false
	}
	now := s.now()
	s.check.mu.Lock()
	recent := func(k string) bool { at, ok := s.check.unread[k]; return ok && now.Sub(at) < 24*time.Hour }
	items = slices.DeleteFunc(items, func(it PossibleItem) bool { return recent(it.Question.CheckKey) })
	s.check.mu.Unlock()
	units := s.unitsToCheck(ctx, items)
	s.check.mu.Lock()
	units = slices.DeleteFunc(units, func(u checkUnit) bool { h, ok := s.check.held[u.key]; return ok && now.Before(h.until) })
	s.check.mu.Unlock()
	if len(units) == 0 {
		return false
	}
	if len(units) > possibleAutoMax {
		units = units[:possibleAutoMax]
	}
	s.check.mu.Lock()
	if s.check.run != nil && s.check.run.Running {
		s.check.mu.Unlock()
		return false
	}
	s.check.run = &CheckRun{Running: true, Total: len(units), By: SystemUser, StartedAt: store.FormatTS(now)}
	s.check.mu.Unlock()
	go func() {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), possibleCheckTimeout)
		defer cancel()
		s.runPossibleCheck(bg, units, SystemUser)
	}()
	return true
}

// scoresOf is the CVSS score of the items' CVEs (none when they cannot be read: the order then falls back to the CVE).
func (s *Service) scoresOf(ctx context.Context, items []PossibleItem) map[string]CVSS {
	var cves []string
	for _, it := range items {
		if it.Checkable() {
			cves = append(cves, it.CVE)
		}
	}
	scores, err := s.cfg.Feeds.CVSS(ctx, uniqueIDs(cves))
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: reading CVSS scores for a check failed", "error", err)
		return nil
	}
	return scores
}

// checkUnits groups the checkable possible items by evidence identity: exploited CVEs first, then the highest CVSS score, then by CVE.
func checkUnits(items []PossibleItem, scores map[string]CVSS) []checkUnit {
	by := map[string]int{}
	var out []checkUnit
	exploited := map[string]bool{}
	for _, it := range items {
		if !it.Checkable() || it.Question.Detail.Check == nil {
			continue
		}
		exploited[it.CVE] = exploited[it.CVE] || it.Exploited
		if i, ok := by[it.Question.CheckKey]; ok {
			out[i].devs = append(out[i].devs, it.Question.AssetID)
			continue
		}
		by[it.Question.CheckKey] = len(out)
		out = append(out, checkUnit{key: it.Question.CheckKey, cve: it.CVE, id: *it.Question.Detail.Check, q: it.Question, devs: []string{it.Question.AssetID}})
	}
	slices.SortStableFunc(out, func(a, b checkUnit) int {
		if exploited[a.cve] != exploited[b.cve] {
			if exploited[a.cve] {
				return -1
			}
			return 1
		}
		if sa, sb := scores[a.cve].Score, scores[b.cve].Score; sa != sb {
			if sa > sb {
				return -1
			}
			return 1
		}
		return strings.Compare(a.cve, b.cve)
	})
	return out
}

// runPossibleCheck checks the units CVE by CVE, stores each check, matches the devices again and writes one audit row.
func (s *Service) runPossibleCheck(ctx context.Context, units []checkUnit, actor string) {
	update := func(f func(r *CheckRun)) {
		s.check.mu.Lock()
		f(s.check.run)
		s.check.mu.Unlock()
	}
	devices := map[string]bool{}
	var stopped string
	streak := 0 // AI calls in a row that failed with no answer between (aiFailStreak)
	for i := 0; i < len(units); {
		j := i
		for j < len(units) && units[j].cve == units[i].cve {
			j++
		}
		group := units[i:j]
		i = j
		res := s.checkCVE(ctx, group, actor, &streak)
		failed, checks, readings := res.failed, res.checks, res.readings
		if len(checks) > 0 || len(readings) > 0 || len(res.seen) > 0 {
			if err := s.storeChecks(ctx, checks, readings, res.seen); err != nil {
				s.cfg.Log.WarnContext(ctx, "findings: storing checks of possible findings failed", "cve", group[0].cve, "error", err)
				failed, checks, readings = len(group), nil, nil
			}
		}
		for _, u := range group {
			for _, d := range u.devs {
				devices[d] = true
			}
		}
		if len(readings) > 0 { // a reading applies to every device on its line, not only to those this check looked at
			others, err := devicesOfCVE(ctx, s.rd(ctx), group[0].cve)
			if err != nil {
				s.cfg.Log.WarnContext(ctx, "findings: reading the devices of a CVE after a check failed", "cve", group[0].cve, "error", err)
			}
			for _, d := range others {
				devices[d] = true
			}
		}
		update(func(r *CheckRun) {
			r.Done += len(group)
			r.Failed += failed
			for _, c := range checks {
				switch {
				case c.DecidedBy == DecidedAdvisory:
					r.Advisory++
				case c.Verdict == VerdictUnsure:
					r.Undecided++
				default:
					r.Proposals++
				}
			}
			r.Readings += len(readings)
		})
		if res.stop != "" {
			stopped = res.stop
			break
		}
		if ctx.Err() != nil {
			stopped = "The check took longer than it may and stopped."
			break
		}
	}
	for _, d := range slices.Sorted(mapsKeys(devices)) { // what an advisory decided is applied by the match, the one detection writer
		s.stamps.drop(d)
		if _, err := s.OnMatchChanged(ctx, d); err != nil && !errors.Is(err, ErrUnknownAsset) {
			s.cfg.Log.WarnContext(ctx, "findings: matching a device after a check failed", "device", d, "error", err)
		}
	}
	var final CheckRun
	update(func(r *CheckRun) {
		r.Running = false
		at := store.FormatTS(s.now())
		r.FinishedAt = &at
		if stopped != "" {
			r.Stopped = &stopped
		}
		final = *r
	})
	detail := fmt.Sprintf("checked %d possible findings: %d decided from vendor advisories, %d release lines read by AI, %d still undecided, %d not checked",
		final.Done, final.Advisory, final.Readings, final.Undecided, final.Failed)
	if actor == SystemUser {
		detail = "automatic reading: " + detail
	}
	if stopped != "" {
		detail += "; stopped: " + stopped
	}
	if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: "findings.possible_checked", Target: "possible", Detail: clipBytes(detail, 500)})
	}); err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: auditing a check failed", "error", err)
	}
	s.gen.Add(1)
}

func mapsKeys[K comparable, V any](m map[K]V) func(func(K) bool) {
	return func(yield func(K) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// cveCheck is what the check of one CVE produced: checks of exact versions (the box's own reading, or undecided), the AI's readings of
// release lines, the readings whose page was fetched again and found unchanged, how many units were not checked, and why the run
// stops ("" when it goes on).
type cveCheck struct {
	checks   []Check
	readings []LineStatement
	seen     []string
	failed   int
	stop     string
}

// lineAsk is one release line of a CVE the AI is asked about, with the units (exact versions) on it.
type lineAsk struct {
	units []checkUnit
	last  *LineStatement // the newest stored reading of the line, nil when none
}

// checkCVE checks the units of one CVE: the pages first, then the AI, once per release line, for what they leave. stop is set when the
// run must stop (the AI unavailable, a budget reached, aiFailStreak failed calls in a row): what was decided so far is returned. streak
// is the run's count of AI calls in a row that failed for a reason Propose did not name or whose answer was not usable (ItemRefused
// Systemic), with no answer between: an answer sets it to 0, a call a hook refused leaves it, since it says nothing about the AI.
func (s *Service) checkCVE(ctx context.Context, group []checkUnit, actor string, streak *int) (res cveCheck) {
	cve := group[0].cve
	now := s.now()
	rec, err := s.cfg.Checker.Record(ctx, cve)
	if err != nil {
		res.failed = len(group)
		return res
	}
	urls := chooseRefs(rec.Refs, group[0].id.Product)
	var pages []FetchedPage
	if len(urls) > 0 {
		pages = s.cfg.Checker.Fetch(ctx, urls)
	}
	markVendorPages(pages, rec.Refs, group[0].id.Product)
	emptyPages(pages, cve, group)
	read := slices.ContainsFunc(pages, func(p FetchedPage) bool { return p.Status == "ok" })
	sources := make([]CheckSource, 0, len(pages))
	for _, p := range pages {
		sources = append(sources, CheckSource{URL: p.URL, Title: p.Title, Status: p.Status, Note: p.Note})
	}
	keys := make([]string, 0, len(group))
	for _, u := range group {
		keys = append(keys, u.key)
	}
	s.markUnread(keys, !read && len(urls) > 0 && slices.ContainsFunc(pages, func(p FetchedPage) bool { return !p.Empty }), now)
	var ask []checkUnit
	var unparsed = map[string]*Undecided{}
	for _, u := range group {
		v, ok, why := readAdvisory(pages, u.id, cve)
		if ok {
			c := Check{Key: u.key, CVE: cve, ID: u.id, DecidedBy: DecidedAdvisory, Verdict: v.verdict, Quote: v.quote, Sources: citeSource(sources, v.url),
				Reason: advisoryReason(v), CheckedBy: actor, CheckedAt: now}
			res.checks = append(res.checks, c)
			continue
		}
		unparsed[u.key] = why
		ask = append(ask, u)
	}
	if len(ask) == 0 {
		return res
	}
	// The AI reads the whole record (its description, solution and every product's rows) beside the pages; when no page could be read
	// (none referenced, a script-rendered shell, a refusal) it reads the record alone, as a person would. A record with no text and no
	// page read is not sent: nothing is stored, and the next check tries the pages again.
	rows := readRecordRows(rec, group[0].id.Product, group[0].q)
	recText := recordText(rec, rows)
	if !read && recText == "" {
		res.failed = len(ask)
		s.markUnread(keys, true, now)
		return res
	}
	okPages := slices.DeleteFunc(slices.Clone(pages), func(p FetchedPage) bool { return p.Status != "ok" })
	lines, err := s.linesToAsk(ctx, cve, ask)
	if err != nil {
		res.failed = len(ask)
		return res
	}
	// a line whose newest reading rests on the same record and on a page that reads the same now is not asked again: the fetch found it
	// unchanged (an unsure reading is asked again after statementRecheck; a rejected one never for the same page)
	asks := lines[:0]
	for _, l := range lines {
		unsureAgain := l.last != nil && l.last.RejectedBy == "" && l.last.Status == StatementUnsure && now.Sub(l.last.AskedAt) >= statementRecheck
		if st := l.last; st != nil && st.RecordHash == l.units[0].id.Record && !unsureAgain {
			if text, ok := pageText(st, okPages, recText); ok && pageHash(text) == st.PageHash {
				res.seen = append(res.seen, st.Key)
				continue
			}
		}
		asks = append(asks, l)
	}
	for start := 0; start < len(asks); start += possibleCheckItems {
		part := asks[start:min(start+possibleCheckItems, len(asks))]
		req := ProposeRequest{CVE: cve, Description: recordText(CVERecordText{Description: rec.Description, Solution: rec.Solution}, nil), Rows: rows, Pages: okPages}
		for k, l := range part {
			id := l.units[0].id
			vendor, product, _ := strings.Cut(id.Product, "|")
			var versions []string
			for _, u := range l.units {
				if !slices.Contains(versions, u.id.Release()) {
					versions = append(versions, u.id.Release())
				}
			}
			req.Items = append(req.Items, ProposeItem{Index: k, Vendor: vendor, Product: catalogueName(id.Product, product), Version: strings.Join(versions, ", "), Line: id.Line,
				Edition: edition(l.units[0].q)})
		}
		var keys []string
		for _, l := range part {
			for _, u := range l.units {
				keys = append(keys, u.key)
			}
		}
		ans, err := s.cfg.Checker.Propose(ctx, actor, req)
		if err != nil {
			n := 0
			for _, l := range asks[start:] {
				n += len(l.units)
			}
			var stopErr *CheckStop
			if errors.As(err, &stopErr) {
				res.failed += n
				res.stop = stopErr.Reason
				return res
			}
			// only this call's items: noted with the reason and a retry time, and the check goes on with the next item
			res.failed += len(keys)
			wait, why := possibleRetry, err.Error()
			if refused := (*ItemRefused)(nil); errors.As(err, &refused) {
				wait = max(refused.RetryAfter, possibleRetry)
				if refused.Systemic {
					*streak++
				}
			} else {
				*streak++
			}
			s.hold(keys, now.Add(wait), heldKind(err), why)
			s.cfg.Log.InfoContext(ctx, "findings: an AI reading of a possible CVE was not made", "cve", cve,
				"items", len(keys), "retry_after", wait.String(), "reason", clipBytes(why, 300))
			if *streak >= aiFailStreak { // the AI answers nothing at all: the run stops here, the items left wait for the next run
				res.failed += n - len(keys)
				res.stop = fmt.Sprintf("The AI failed on %d calls in a row (%s); the reading goes on at the next run.", *streak, why)
				return res
			}
			continue
		}
		*streak = 0
		s.hold(keys, time.Time{}, "", "")
		byIndex := map[int]ProposeVerdict{}
		for _, v := range ans.Verdicts {
			byIndex[v.Index] = v
		}
		for k, l := range part {
			v, ok := byIndex[k]
			if !ok {
				res.failed += len(l.units)
				continue
			}
			if v.InferredFrom == "" && (v.Source < 1 || v.Source > len(okPages)) {
				v.InferredFrom = otherProductsRow(rec, l.units[0].id.Product, v.Quote) // another product's row is that product's statement
			}
			if v.InferredFrom == "" {
				v.InferredFrom = unpairedBound(rec, l.units[0].id, v) // a release the sentence pairs with another product is that product's
			}
			st := readingOfAnswer(cve, l.units[0].id, v, okPages, recText, rec.Refs, ans, actor, now)
			if st.Status == StatementAffected && v.InferredFrom != "" && ownRowOnLine(rec, l.units[0].id.Product, st.StatedLine) {
				st.Status = StatementUnsure // the record has a row of this product on the line: its own row, not another product's, decides
				st.Reason = oneLine("The record has a row of this product on line "+st.StatedLine+", so another product's line decides nothing: "+st.Reason, 600)
			}
			if st.Basis == BasisStated && !namedWithThisProduct(st.Quote, ownNames(rec, l.units[0].id.Product), ownEditions(rec, l.units[0].id.Product, edition(l.units[0].q)), ownVendors(l.units[0].id.Product)) {
				st.Basis = BasisUnpaired // a version the quote does not pair with this product's own name: it may open, never settle or fix
			}
			res.readings = append(res.readings, st)
		}
	}
	return res
}

// edition is the build's edition as a CPE sw_edition the reading tells the AI (ProposeItem.Edition), "" when none.
func edition(q Question) string {
	if q.Detail.Attribute == AttrUnlistedLine {
		return mozillaESR // the edition is known, its line is what the rows do not list
	}
	return ""
}

// ownNames is how the record and the catalogue name the product (lower case, words joined by spaces): the product key's name, the
// catalogue's display name, product name and other names, and the product of the record's own rows.
func ownNames(rec CVERecordText, product string) []string {
	vendor, name, _ := strings.Cut(product, "|")
	var out []string
	add := func(n string) {
		n = strings.Join(strings.Fields(strings.ToLower(strings.ReplaceAll(n, "_", " "))), " ")
		if len(n) >= 2 && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	add(name)
	if p, ok := productid.ByKey(product); ok {
		add(p.Display)
		add(p.Product)
		for _, a := range p.Also { // the catalogue's other names of the product ("Synology|DSM")
			_, n, _ := strings.Cut(a, "|")
			add(n)
		}
	}
	for _, r := range rec.Rows {
		if productid.Norm(r.Vendor) == productid.Norm(vendor) && productid.Norm(r.Product) == productid.Norm(name) {
			add(r.Product)
		}
	}
	return out
}

// ownEditions is the edition words the record's own rows of the product pin, and the build's edition the box knows (lower case).
func ownEditions(rec CVERecordText, product, known string) []string {
	vendor, name, _ := strings.Cut(product, "|")
	var out []string
	for _, e := range append([]string{known}, func() []string {
		var es []string
		for _, r := range rec.Rows {
			if productid.Norm(r.Vendor) == productid.Norm(vendor) && productid.Norm(r.Product) == productid.Norm(name) {
				es = append(es, r.Edition)
			}
		}
		return es
	}()...) {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" && !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

// reVersionLike is any version-like token of a sentence (lower case), the token in group 1: one starting with a digit ("115", "115.42",
// "115.x", "8.6.5p1", "21.4r2-s3", a date "2026-01-15") or a short letter prefix with a dotted or dashed release ("v115.42", "r2-s3").
// Every value a reading may take as a bound, a line or a fix is one of these.
var reVersionLike = regexp.MustCompile(`(?:^|[^0-9a-z])([a-z]{1,3}[0-9]+(?:[.\-_][0-9a-z]+)+|[0-9][0-9a-z]*(?:[.\-_][0-9a-z]+)*)`)

// namedWithThisProduct says every version-like token in quote (reVersionLike: a whole number, a wildcard line or a date too) follows one
// of the product's own names (names), with only spaces, or one of its own edition words, between ("Mail 115.42", "Mail ESR 115.42"):
// only such a quote may settle "not affected" or give a fix. A CVE id is no version, and a number inside one of the product's own names
// ("Server 2019") is the name's. A quote with no version, a version after another name ("Mail Server 115.42", a name the record does not
// know) or after no name ("fixed in 115.42", "3 issues") is not.
func namedWithThisProduct(quote string, names, editions, vendors []string) bool {
	q := strings.ToLower(quote)
	if len(q) != len(quote) {
		return false // a quote whose case changes its length: positions would not line up with the original's words
	}
	var spans [][]int
	for _, m := range reVersionLike.FindAllStringSubmatchIndex(q, -1) {
		spans = append(spans, m[2:4])
	}
	if len(spans) == 0 {
		return false
	}
	// a name of this product ends p, and the word before it is the vendor's name, the start, punctuation or a lower-case word: a
	// capitalised other word makes it another product's name ("Thunder Mail")
	endsWithName := func(p string) bool {
		for _, n := range names {
			if !strings.HasSuffix(p, n) || len(p) > len(n) && isAlnum(p[len(p)-len(n)-1]) {
				continue
			}
			head := strings.TrimRight(p[:len(p)-len(n)], " \t")
			if head == "" || !isAlnum(head[len(head)-1]) {
				return true
			}
			k := len(head)
			for k > 0 && isAlnum(head[k-1]) {
				k--
			}
			w := head[k:]
			if slices.Contains(vendors, w) || quote[len(head)-len(w)] >= 'a' && quote[len(head)-len(w)] <= 'z' {
				return true
			}
		}
		return false
	}
	for _, sp := range spans {
		before := q[:sp[0]]
		if strings.HasSuffix(before, "cve-") || endsWithName(q[:sp[1]]) {
			continue // a CVE id, or a number of one of the product's own names
		}
		p := strings.TrimRight(before, " \t")
		if len(p) == len(before) {
			return false // no space before the version ("v115.42", "(115.42")
		}
		if endsWithName(p) {
			continue
		}
		ok := false
		for _, e := range editions {
			if !strings.HasSuffix(p, e) || len(p) > len(e) && isAlnum(p[len(p)-len(e)-1]) {
				continue
			}
			rest := p[:len(p)-len(e)]
			if r := strings.TrimRight(rest, " \t"); len(r) < len(rest) && endsWithName(r) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// linesToAsk groups the units by release line (product and line), with the newest stored reading of each line.
func (s *Service) linesToAsk(ctx context.Context, cve string, units []checkUnit) ([]lineAsk, error) {
	sts, err := statementsOf(ctx, s.rd(ctx), []string{cve})
	if err != nil {
		return nil, err
	}
	var out []lineAsk
	at := map[string]int{}
	for _, u := range units {
		k := u.id.Product + "\x1f" + u.id.Line
		if i, ok := at[k]; ok {
			out[i].units = append(out[i].units, u)
			continue
		}
		at[k] = len(out)
		r := readingFor(sts, cve, u.id)
		l := lineAsk{units: []checkUnit{u}, last: r.newest()}
		if l.last != nil && l.last.Line != u.id.Line {
			l.last = r.rejected // another line's reading that covers this one is not this line's own
		}
		out = append(out, l)
	}
	return out, nil
}

// pageText is the text a reading was read from as the box fetched it now: its page, or the CVE record; ok false when the page was not
// read this time.
func pageText(st *LineStatement, pages []FetchedPage, record string) (string, bool) {
	if st.URL == "" {
		return record, true
	}
	for _, p := range pages {
		if p.URL == st.URL {
			return p.Text, true
		}
	}
	return "", false
}

// readingOfAnswer is the AI's answer for one release line as the box keeps it: the quote looked up word for word in the text the box
// fetched (a page, or the record's text for source 0), a version bound kept only when the quote or the cited page names it, a "fixed"
// with no bound left unsure, and a page that is not about this CVE (it names neither the CVE nor an advisory the record references:
// aboutCVE) left unsure whatever the AI read in it. An answer inferred from another product's release line keeps no bound (they are
// the other product's) and stands only as "affected" with a quote naming a release of the item's line (namedByRelease) or the line
// itself; anything else it says is unsure.
func readingOfAnswer(cve string, id CheckID, v ProposeVerdict, pages []FetchedPage, record string, refs []RefLink, ans ProposeAnswer, actor string,
	now time.Time) LineStatement {
	cited := citedText(v.Source, pages, record)
	quote := oneLine(v.Quote, 400)
	st := LineStatement{CVE: cve, Product: id.Product, Line: id.Line, StatedLine: clipBytes(strings.TrimSpace(v.Line), 200),
		RecordHash: cmpNonEmpty(id.Record, recordHash("")), PageHash: pageHash(cited.text), Status: v.Status, Reason: oneLine(v.Reason, 600), Quote: quote,
		URL: cited.url, Host: hostOf(cited.url), QuoteFound: quote != "" && quoteFound(quote, cited.text),
		Model: cmpNonEmpty(ans.Model, "unknown"), Profile: cmpNonEmpty(ans.Profile, "unknown"), Activity: ans.ActivityID, AskedBy: actor, AskedAt: now, SeenAt: now,
		Basis: BasisStated}
	if v.Source >= 1 && v.Source <= len(pages) {
		st.VendorPage = pages[v.Source-1].Vendor
	}
	// a bound counts when the quote names it, or the cited page does (a tracker's "present-in" and "fixed-in" lines are two sentences);
	// only a bound the quote names may settle a version as not affected or become the fix (pastFix, fix)
	bound := func(b string) string {
		b = strings.TrimSpace(b)
		if len(b) > 100 || !namesToken(quote, b) && !namesToken(cited.text, b) {
			return ""
		}
		return b
	}
	st.Introduced, st.FixedIn, st.Last = bound(v.Introduced), bound(v.FixedIn), bound(v.LastAffected)
	switch st.Status {
	case StatementAffected, StatementNotAffected, StatementUnsure:
	case StatementFixed:
		if st.FixedIn == "" && st.Last == "" {
			st.Status = StatementUnsure // "fixed" in a release the text does not name decides nothing
		}
	default:
		st.Status = StatementUnsure
	}
	if from := oneLine(v.InferredFrom, 100); from != "" {
		st.Basis = BasisInferred
		st.Introduced, st.FixedIn, st.Last = "", "", "" // the bounds of another product are none of this one's
		st.Reason = oneLine("Inferred from "+from+": "+v.Reason, 600)
		switch {
		case st.Status == StatementNotAffected: // a person decides it, like every "not affected" the AI reads (a proposal)
		case st.Status != StatementAffected || !st.coversLine(id) && !st.namedByRelease(id):
			st.Status = StatementUnsure
			st.Reason = oneLine("An inference from "+from+" opens only from a quote that names a release of this line: "+v.Reason, 600)
		}
	}
	if cited.url != "" && st.Status != StatementUnsure && !aboutCVE(cited.text, cve, refs) {
		st.Status = StatementUnsure
		st.Reason = "The page the AI read names neither " + cve + " nor an advisory the CVE record references, so it decides nothing for this CVE."
	}
	st.Key = statementKey(cve, st.Product, st.Line, st.RecordHash, st.PageHash)
	return st
}

// catalogueName is the product's name as the catalogue writes it: never the software's name as the device or a person wrote it, which
// may carry the device's own name.
func catalogueName(key, product string) string {
	if p, ok := productid.ByKey(key); ok && p.Display != "" {
		return p.Display
	}
	return product
}

func cmpNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// emptyPages marks a page read whose text names neither the CVE nor a product of the group as not read and empty: it is no advisory of
// this CVE (a script-rendered portal's shell, "Loading … Refresh", names neither), and its text is not sent to the AI.
func emptyPages(pages []FetchedPage, cve string, group []checkUnit) {
	for i := range pages {
		p := &pages[i]
		if p.Status != "ok" {
			continue
		}
		if names, _ := cveMentions(p.Text, cve); names || slices.ContainsFunc(group, func(u checkUnit) bool { return mentionsProduct(p.Text, u.id) }) {
			continue
		}
		p.Status, p.Empty, p.Text = "failed", true, ""
		p.Note = "the page has no advisory text about this CVE (it may need a browser)"
	}
}

// markVendorPages marks the pages that are the vendor's own advisory (FetchedPage.Vendor): the reference is tagged vendor-advisory, or
// the page is on the vendor's host.
func markVendorPages(pages []FetchedPage, refs []RefLink, product string) {
	vendor, _, _ := strings.Cut(product, "|")
	for i := range pages {
		for _, r := range refs {
			if r.URL == pages[i].URL && slices.ContainsFunc(r.Tags, func(t string) bool { return refTag(t) == "vendor-advisory" }) {
				pages[i].Vendor = true
			}
		}
		if u, err := url.Parse(pages[i].URL); err == nil && vendorHost(u.Hostname(), vendor) {
			pages[i].Vendor = true
		}
	}
}

// vendorHost says host is the vendor's own: the label before its top-level domain (or before a country's second level, as in
// juniper.co.jp) is the vendor's name in letters and digits ("paloaltonetworks.com" for Palo Alto Networks). A host that carries the
// vendor's word elsewhere (juniper.example.com) is not.
func vendorHost(host, vendor string) bool {
	v := productid.Norm(vendor)
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(host), "."), ".")
	n := len(labels)
	if v == "" || n < 2 {
		return false
	}
	i := n - 2
	if n >= 3 && len(labels[n-1]) == 2 && slices.Contains([]string{"co", "com", "net", "org", "ac", "ne", "or", "gov"}, labels[n-2]) {
		i = n - 3
	}
	return productid.Norm(labels[i]) == v
}

// undecidedRows is the range rows the match read for the question, as text for the AI and the audit.
func (q Question) undecidedRows() []string {
	if q.Detail.Undecided == nil {
		return nil
	}
	return q.Detail.Undecided.Ranges
}

type citation struct{ text, url string }

// citedText is the text the AI's source number points at: a page (1-based) or the record (0).
func citedText(source int, pages []FetchedPage, record string) citation {
	if source >= 1 && source <= len(pages) {
		return citation{text: pages[source-1].Text, url: pages[source-1].URL}
	}
	return citation{text: record}
}

// citeSource marks the page a verdict's quote is from.
func citeSource(sources []CheckSource, url string) []CheckSource {
	out := slices.Clone(sources)
	for i := range out {
		if out[i].URL == url {
			out[i].Cited = true
		}
	}
	return out
}

func advisoryReason(v advisoryVerdict) string {
	if v.verdict == VerdictAffected {
		return "The vendor's advisory lists a range of releases that contains this version."
	}
	return "The vendor's advisory states the fixed release of this version's release line, and this version is at or past it."
}

// The tags of the references a check reads, in the order it reads them, in the catalogue's words (the CVE record's, which NVD's tags
// are stored in too); a page tagged exploit is never fetched.
var refTagOrder = []string{"vendor-advisory", "release-notes", "patch", "mitigation", "third-party-advisory"}

// refTag is a reference tag in the catalogue's words: lower case, words joined by dashes ("Vendor Advisory" is vendor-advisory).
func refTag(t string) string { return strings.ToLower(strings.Join(strings.Fields(t), "-")) }

// chooseRefs picks the references a check reads, best first: https only, by tag (refTagOrder; untagged after them), a host that names
// the product's vendor first among equals; never one tagged Exploit. At most five, of which the fetcher reads three.
func chooseRefs(refs []RefLink, product string) []string {
	vendor, _, _ := strings.Cut(strings.ToLower(product), "|")
	vendor = strings.Fields(vendor + " x")[0]
	type cand struct {
		url  string
		rank int
	}
	var cs []cand
	for _, r := range refs {
		if !strings.HasPrefix(strings.ToLower(r.URL), "https://") || slices.ContainsFunc(r.Tags, func(t string) bool { return refTag(t) == "exploit" }) {
			continue
		}
		rank := len(refTagOrder) * 2
		for i, t := range refTagOrder {
			if slices.ContainsFunc(r.Tags, func(x string) bool { return refTag(x) == t }) {
				rank = min(rank, i*2)
			}
		}
		host := strings.ToLower(strings.TrimPrefix(r.URL, "https://"))
		if h, _, ok := strings.Cut(host, "/"); ok {
			host = h
		}
		if vendor == "" || !strings.Contains(host, vendor) {
			rank++
		}
		cs = append(cs, cand{r.URL, rank})
	}
	slices.SortStableFunc(cs, func(a, b cand) int { return a.rank - b.rank })
	var out []string
	for _, c := range cs {
		if len(out) == 5 {
			break
		}
		out = append(out, c.url)
	}
	return out
}

// storeChecks stores the checks and readings of one CVE in one write: a key checked meanwhile keeps its first check; a reading found
// unchanged by a new fetch (seen) is touched.
func (s *Service) storeChecks(ctx context.Context, cs []Check, readings []LineStatement, seen []string) error {
	now := s.now()
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, c := range cs {
			if err := insertCheck(ctx, tx, c); err != nil {
				return err
			}
		}
		for _, st := range readings {
			if err := storeStatement(ctx, tx, st); err != nil {
				return err
			}
		}
		for _, k := range seen {
			if err := touchStatement(ctx, tx, k, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---- proposals ----

// ConfirmProposal is a person's "yes" to an AI proposal of one possible CVE (question id): affected records the finding, whose basis
// and confirmation come from who stated the version (never from the AI), with the AI's quote as its evidence; not affected answers the
// question "not affected" (listed under Answered, can be asked again). One audit row, the finding's history.
// admin says the person may record "affected" on their word (as answering affected); without it an affected proposal is 403.
func (s *Service) ConfirmProposal(ctx context.Context, questionID, user string, admin bool) (string, error) {
	if err := ValidUser(user); err != nil {
		return "", err
	}
	var found string
	err := s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		var err error
		found, err = s.confirmOne(ctx, tx, questionID, user, now, emit, nil, admin)
		return err
	})
	return found, err
}

// ConfirmProposals confirms every proposal of one class at once (of one device when device is set): verdict and confidence say the
// class. An exploited CVE proposed "not affected" is never among them (confirmed one by one). It answers how many it confirmed.
func (s *Service) ConfirmProposals(ctx context.Context, device, verdict, confidence, user string, admin bool) (int, error) {
	if err := ValidUser(user); err != nil {
		return 0, err
	}
	if verdict != VerdictAffected && verdict != VerdictNotAffected || confidence != ConfidenceConfident && confidence != ConfidenceLikely {
		return 0, &APIError{"invalid", 400, "Name the class: verdict affected or not_affected, confidence confident or likely."}
	}
	if verdict == VerdictAffected && !admin {
		return 0, ErrNeedsAdmin
	}
	items, err := s.possibleItems(ctx, device)
	if err != nil {
		return 0, err
	}
	var ids []string
	for _, it := range items {
		if it.Bulk() && it.Check.Verdict == verdict && it.Check.Confidence == confidence {
			ids = append(ids, it.Question.ID)
		}
	}
	if len(ids) > MaxBulk {
		ids = ids[:MaxBulk]
	}
	// read once, and fail closed: an exploited CVE proposed not affected is never confirmed in bulk, so a list that cannot be read
	// confirms nothing
	exploited, err := s.exploitedSet(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		n = 0
		for _, id := range ids {
			if _, err := s.confirmOne(ctx, tx, id, user, now, emit, exploited, admin); err != nil {
				if errors.Is(err, ErrNoProposal) {
					continue
				}
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// confirmOne confirms the proposal of one question inside a write. exploited is set when the confirmation is one of a bulk: an
// exploited CVE proposed not affected is then refused (ErrProposalPerRow).
func (s *Service) confirmOne(ctx context.Context, tx *sql.Tx, questionID, user string, now time.Time, emit func(string, any), exploited map[string]bool,
	admin bool) (string, error) {
	q, err := scanQuestion(tx.QueryRowContext(ctx, `SELECT `+questionColumns+` FROM fnd_question WHERE id = ?`, questionID))
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoProposal
	}
	if err != nil {
		return "", fmt.Errorf("findings: reading a question: %w", err)
	}
	if q.Answer != "" || q.CheckKey == "" || q.CVE == "" {
		return "", ErrNoProposal
	}
	cs, err := checksFor(ctx, tx, []Question{q})
	if err != nil {
		return "", err
	}
	c, ok := cs[q.CheckKey]
	if (!ok || !c.Settled() || c.Stale) && q.Detail.Check != nil { // the AI's reading of the line, as the lists show it
		rs, err := readingsFor(ctx, tx, []Question{q})
		if err != nil {
			return "", err
		}
		if r, okR := rs[q.CheckKey]; okR && r.applied != nil {
			c, ok = r.applied.asCheck(*q.Detail.Check), true
		}
	}
	if !ok || !c.Proposal() {
		return "", ErrNoProposal
	}
	if c.Verdict == VerdictAffected && !admin {
		return "", ErrNeedsAdmin
	}
	if exploited != nil && c.Verdict == VerdictNotAffected && exploited[q.CVE] {
		return "", ErrProposalPerRow
	}
	found := ""
	answer := AnswerNotAffected
	if c.Verdict == VerdictAffected {
		answer = AnswerAffected
		a, okA, err := s.cfg.Inventory.MatchInput(ctx, q.AssetID)
		if err != nil {
			return "", fmt.Errorf("findings: reading the device: %w", err)
		}
		if !okA {
			return "", ErrNoProposal
		}
		lines := deviceLines(a)
		// the CVE's entry as the match reads it (an exploited list's, or the catalogue's for a CVE on none): its fix and urgency
		vs, err := s.cfg.Feeds.MatchSet(ctx, NewMatchScope([]Asset{a}, []string{q.CVE}))
		if err != nil {
			return "", fmt.Errorf("findings: reading the catalogue: %w", err)
		}
		v := Vuln{CVE: q.CVE}
		if i := slices.IndexFunc(vs, func(x Vuln) bool { return x.CVE == q.CVE }); i >= 0 {
			v = vs[i]
		}
		d, okD := lineDetection(a, lines, q.SoftwareID, v, RangeAIConfirmed, Evidence{Summary: aiConfirmedNote(Question{AnsweredBy: user, Detail: q.Detail}, c), CheckedAt: now})
		if !okD {
			return "", ErrNoProposal
		}
		fs, err := queryFindings(ctx, tx, `asset_id = ? AND cve = ? AND ifnull(software_id, '') = ?`, q.AssetID, q.CVE, q.SoftwareID)
		if err != nil {
			return "", err
		}
		f, isNew := Finding{ID: store.NewID("f"), AssetID: q.AssetID, CVE: q.CVE}, true
		if len(fs) == 1 {
			f, isNew = fs[0], false
		}
		g, _, err := s.step(ctx, tx, f, isNew, Trigger{Kind: TrDetected, At: now, Detection: d}, emit)
		if err != nil {
			return "", err
		}
		found = g.ID
	}
	if _, err := tx.ExecContext(ctx, `UPDATE fnd_question SET answer = ?, answered_by = ?, answered_at = ? WHERE id = ?`, answer, user, store.FormatTS(now), q.ID); err != nil {
		return "", fmt.Errorf("findings: answering a question: %w", err)
	}
	detail := questionAuditDetail(q, "confirmed the AI proposal "+strings.ReplaceAll(c.Verdict, "_", " ")+" ("+c.Confidence+")")
	if c.Quote != "" {
		detail += ": \"" + oneLine(c.Quote, 200) + "\""
	}
	return found, s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "findings.proposal_confirmed", Target: q.ID, Detail: clipBytes(detail, 500)})
}

// RejectProposal is a person's "no" to an AI proposal or to the AI's reading of a vendor's statement (key: a check key or a reading's
// key). A proposal's check stays stored (it is not asked again) and is marked rejected, so the CVE is possible again on every device
// that shares it. A reading is marked rejected and stays stored, so the same page is never applied again: every device on its line is
// matched again at once, a finding it opened closes, and its CVE is possible again until a changed page or record is read. One audit
// row.
func (s *Service) RejectProposal(ctx context.Context, key, user string) error {
	if err := ValidUser(user); err != nil {
		return err
	}
	if !checkKeyRE.MatchString(key) {
		return ErrNoProposal
	}
	var devices []string
	err := s.write(ctx, func(tx *sql.Tx, now time.Time, _ func(string, any)) error {
		devices = nil
		res, err := tx.ExecContext(ctx, `UPDATE fnd_line_statement SET rejected_by = ?, rejected_at = ? WHERE statement_key = ? AND rejected_by IS NULL`,
			user, store.FormatTS(now), key)
		if err != nil {
			return fmt.Errorf("findings: rejecting a reading: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 1 {
			st, err := scanStatement(tx.QueryRowContext(ctx, `SELECT `+statementColumns+` FROM fnd_line_statement WHERE statement_key = ?`, key))
			if err != nil {
				return fmt.Errorf("findings: reading a reading: %w", err)
			}
			if devices, err = devicesOfCVE(ctx, tx, st.CVE); err != nil {
				return err
			}
			where := cmpNonEmpty(st.Host, "the CVE record")
			return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "findings.ai_reading_rejected", Target: key,
				Detail: clipBytes(fmt.Sprintf("%s on %s line %s: rejected the AI's reading of %s (%s)", st.CVE, st.Product, st.Line, where,
					strings.ReplaceAll(st.Status, "_", " ")), 500)})
		}
		res, err = tx.ExecContext(ctx, `UPDATE fnd_possible_check SET rejected_by = ?, rejected_at = ? WHERE check_key = ? AND decided_by = 'ai' AND verdict <> 'unsure'
			AND rejected_by IS NULL`, user, store.FormatTS(now), key)
		if err != nil {
			return fmt.Errorf("findings: rejecting a proposal: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNoProposal
		}
		cs, err := checksOf(ctx, tx, []string{key})
		if err != nil {
			return err
		}
		c := cs[key]
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "findings.proposal_rejected", Target: key,
			Detail: clipBytes(fmt.Sprintf("%s on %s %s: rejected the AI proposal %s", c.CVE, c.ID.Product, c.ID.Version, strings.ReplaceAll(c.Verdict, "_", " ")), 500)})
	})
	if err != nil {
		return err
	}
	for _, d := range devices { // the rejection applies to every device on the line now, through the match (the one detection writer)
		s.stamps.drop(d)
		if _, err := s.OnMatchChanged(ctx, d); err != nil && !errors.Is(err, ErrUnknownAsset) {
			s.cfg.Log.WarnContext(ctx, "findings: matching a device after a rejected reading failed", "device", d, "error", err)
		}
	}
	return nil
}

// devicesOfCVE is every device with a finding the AI's reading opened or a question about cve.
func devicesOfCVE(ctx context.Context, q querier, cve string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT asset_id FROM fnd_finding WHERE cve = ?1 AND range_origin = ?2 UNION SELECT asset_id FROM fnd_question WHERE cve = ?1
		ORDER BY 1`, cve, RangeAIRead)
	if err != nil {
		return nil, fmt.Errorf("findings: reading the devices of a CVE: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("findings: reading the devices of a CVE: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ownVendors is the vendor's name as the product key and the catalogue write it (lower case).
func ownVendors(product string) []string {
	vendor, _, _ := strings.Cut(product, "|")
	out := []string{strings.ToLower(strings.TrimSpace(vendor))}
	if p, ok := productid.ByKey(product); ok && p.Vendor != "" {
		out = append(out, strings.ToLower(strings.TrimSpace(p.Vendor)))
	}
	return out
}
