package findings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	// Propose asks the AI for a verdict per item from the public text (one call, the explain-finding job's profile and budget).
	Propose(ctx context.Context, actor string, req ProposeRequest) (ProposeAnswer, error)
}

// CheckStop is a Propose error that stops the whole check (the AI unavailable, this month's budget reached): Reason is the sentence
// a person reads.
type CheckStop struct{ Reason string }

func (e *CheckStop) Error() string { return e.Reason }

// CVERecordText is the public text of a CVE's record.
type CVERecordText struct {
	Description string
	Refs        []RefLink
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
}

// ProposeItem is one product version of a CVE the AI is asked about (no device data).
type ProposeItem struct {
	Index                          int
	Vendor, Product, Version, Line string
}

// ProposeRequest is one AI call: the CVE's public record and pages, and the items.
type ProposeRequest struct {
	CVE, Description string
	Rows             []string
	Items            []ProposeItem
	Pages            []FetchedPage
}

// ProposeVerdict is the AI's answer for one item.
type ProposeVerdict struct {
	Index                  int
	Verdict, Reason, Quote string
	Source                 int // 1-based page index, 0 for the record
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
	Proposals  int     `json:"proposals"` // AI proposals made
	Undecided  int     `json:"undecided"` // checked, still undecided
	Failed     int     `json:"failed"`    // not checked: a fetch or AI call failed (asked again by the next check)
	Stopped    *string `json:"stopped"`   // why the check stopped before the end (a budget, the AI unavailable); nil otherwise
	By         string  `json:"by"`
	StartedAt  string  `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
}

// checkState is the service's one check at a time.
type checkState struct {
	mu  sync.Mutex
	run *CheckRun
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
	units := checkUnits(items)
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

// checkUnits groups the checkable possible items by evidence identity: exploited CVEs first, then by CVE.
func checkUnits(items []PossibleItem) []checkUnit {
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
	for i := 0; i < len(units); {
		j := i
		for j < len(units) && units[j].cve == units[i].cve {
			j++
		}
		group := units[i:j]
		i = j
		checks, failed, stop := s.checkCVE(ctx, group, actor)
		if len(checks) > 0 {
			if err := s.storeChecks(ctx, checks); err != nil {
				s.cfg.Log.WarnContext(ctx, "findings: storing checks of possible findings failed", "cve", group[0].cve, "error", err)
				failed, checks = len(group), nil
			}
		}
		for _, u := range group {
			for _, d := range u.devs {
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
		})
		if stop != "" {
			stopped = stop
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
	detail := fmt.Sprintf("checked %d possible findings: %d decided from vendor advisories, %d AI proposals, %d still undecided, %d not checked",
		final.Done, final.Advisory, final.Proposals, final.Undecided, final.Failed)
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

// checkCVE checks the units of one CVE: the pages first, then the AI for what they leave. stop is set when the run must stop (the AI
// unavailable, a budget reached): the checks made so far are returned.
func (s *Service) checkCVE(ctx context.Context, group []checkUnit, actor string) (checks []Check, failed int, stop string) {
	cve := group[0].cve
	now := s.now()
	rec, err := s.cfg.Checker.Record(ctx, cve)
	if err != nil {
		return nil, len(group), ""
	}
	urls := chooseRefs(rec.Refs, group[0].id.Product)
	var pages []FetchedPage
	if len(urls) > 0 {
		pages = s.cfg.Checker.Fetch(ctx, urls)
	}
	read := slices.ContainsFunc(pages, func(p FetchedPage) bool { return p.Status == "ok" })
	sources := make([]CheckSource, 0, len(pages))
	for _, p := range pages {
		sources = append(sources, CheckSource{URL: p.URL, Title: p.Title, Status: p.Status, Note: p.Note})
	}
	var ask []checkUnit
	var unparsed = map[string]*Undecided{}
	for _, u := range group {
		v, ok, why := readAdvisory(pages, u.id, cve)
		if ok {
			c := Check{Key: u.key, CVE: cve, ID: u.id, DecidedBy: DecidedAdvisory, Verdict: v.verdict, Quote: v.quote, Sources: citeSource(sources, v.url),
				Reason: advisoryReason(v), CheckedBy: actor, CheckedAt: now}
			checks = append(checks, c)
			continue
		}
		unparsed[u.key] = why
		ask = append(ask, u)
	}
	if len(ask) == 0 {
		return checks, 0, ""
	}
	okPages := slices.DeleteFunc(slices.Clone(pages), func(p FetchedPage) bool { return p.Status != "ok" })
	for start := 0; start < len(ask); start += possibleCheckItems {
		part := ask[start:min(start+possibleCheckItems, len(ask))]
		req := ProposeRequest{CVE: cve, Description: rec.Description, Rows: part[0].q.undecidedRows(), Pages: okPages}
		for k, u := range part {
			vendor, product, _ := strings.Cut(u.id.Product, "|")
			req.Items = append(req.Items, ProposeItem{Index: k, Vendor: vendor, Product: catalogueName(u.id.Product, product), Version: u.id.Release(), Line: u.id.Line})
		}
		ans, err := s.cfg.Checker.Propose(ctx, actor, req)
		if err != nil {
			var stopErr *CheckStop
			if errors.As(err, &stopErr) {
				return checks, failed + len(ask) - start, stopErr.Reason
			}
			failed += len(part)
			continue
		}
		byIndex := map[int]ProposeVerdict{}
		for _, v := range ans.Verdicts {
			byIndex[v.Index] = v
		}
		for k, u := range part {
			v, ok := byIndex[k]
			if !ok {
				failed++
				continue
			}
			c := Check{Key: u.key, CVE: cve, ID: u.id, DecidedBy: DecidedAI, Verdict: v.Verdict, Reason: oneLine(v.Reason, 600), Quote: oneLine(v.Quote, 400),
				Model: cmpNonEmpty(ans.Model, "unknown"), Profile: cmpNonEmpty(ans.Profile, "unknown"), ActivityID: ans.ActivityID, CheckedBy: actor, CheckedAt: now}
			c.Sources = slices.Clone(sources)
			cited := citedText(v.Source, okPages, rec.Description)
			found := c.Quote != "" && quoteFound(c.Quote, cited.text)
			if found && cited.url != "" {
				c.Sources = citeSource(c.Sources, cited.url)
			}
			switch {
			case c.Verdict == VerdictUnsure:
				c.Undecided = cmpUndecided(unparsed[u.key], &Undecided{Reason: UndecidedAIUnsure})
				if !read {
					c.Undecided = noPageReason(len(urls))
				}
			case found && quoteNamesRange(c.Quote, u.id):
				c.Confidence = ConfidenceConfident
			default:
				c.Confidence = ConfidenceLikely
			}
			checks = append(checks, c)
		}
	}
	return checks, failed, ""
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

func cmpUndecided(a, b *Undecided) *Undecided {
	if a != nil {
		return a
	}
	return b
}

// noPageReason is the undecided reason of a CVE whose pages could not be read: none it may read, or none answered.
func noPageReason(urls int) *Undecided {
	if urls == 0 {
		return &Undecided{Reason: UndecidedNoReference}
	}
	return &Undecided{Reason: UndecidedFetchFailed}
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

// The tags of the references a check reads, in the order it reads them; a page tagged Exploit is never fetched.
var refTagOrder = []string{"Vendor Advisory", "Release Notes", "Patch", "Mitigation", "Third Party Advisory"}

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
		if !strings.HasPrefix(strings.ToLower(r.URL), "https://") || slices.ContainsFunc(r.Tags, func(t string) bool { return strings.EqualFold(t, "Exploit") }) {
			continue
		}
		rank := len(refTagOrder) * 2
		for i, t := range refTagOrder {
			if slices.ContainsFunc(r.Tags, func(x string) bool { return strings.EqualFold(x, t) }) {
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

// storeChecks stores the checks of one CVE in one write: a key checked meanwhile keeps its first check.
func (s *Service) storeChecks(ctx context.Context, cs []Check) error {
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, c := range cs {
			if _, err := insertCheck(ctx, tx, c); err != nil {
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
		found, err = s.confirmOne(ctx, tx, questionID, user, now, emit, false, admin)
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
	n := 0
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		n = 0
		for _, id := range ids {
			if _, err := s.confirmOne(ctx, tx, id, user, now, emit, true, admin); err != nil {
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

// confirmOne confirms the proposal of one question inside a write.
func (s *Service) confirmOne(ctx context.Context, tx *sql.Tx, questionID, user string, now time.Time, emit func(string, any), bulk, admin bool) (string, error) {
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
	cs, err := checksOf(ctx, tx, []string{q.CheckKey})
	if err != nil {
		return "", err
	}
	c, ok := cs[q.CheckKey]
	if !ok || !c.Proposal() {
		return "", ErrNoProposal
	}
	if c.Verdict == VerdictAffected && !admin {
		return "", ErrNeedsAdmin
	}
	if bulk && c.Verdict == VerdictNotAffected {
		if ex, err := s.exploitedSet(ctx); err == nil && ex[q.CVE] {
			return "", ErrProposalPerRow
		}
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
		v := Vuln{CVE: q.CVE}
		if vs, err := s.cfg.Feeds.Vulns(ctx); err == nil {
			for _, x := range vs {
				if x.CVE == q.CVE {
					v = x
				}
			}
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

// RejectProposal is a person's "no" to an AI proposal: the check of that evidence stays stored (it is not asked again) and is marked
// rejected, so the CVE is possible again on every device that shares it. One audit row.
func (s *Service) RejectProposal(ctx context.Context, key, user string) error {
	if err := ValidUser(user); err != nil {
		return err
	}
	if !checkKeyRE.MatchString(key) {
		return ErrNoProposal
	}
	return s.write(ctx, func(tx *sql.Tx, now time.Time, _ func(string, any)) error {
		res, err := tx.ExecContext(ctx, `UPDATE fnd_possible_check SET rejected_by = ?, rejected_at = ? WHERE check_key = ? AND decided_by = 'ai' AND verdict <> 'unsure'
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
}
