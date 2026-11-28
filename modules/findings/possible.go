package findings

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Possible findings. A CVE of software a device runs that Vedette cannot decide is a possible finding: an open question about one CVE
// (fnd_question), never a fnd_finding row, so it is never in the open totals, an alert, a report or Home's trend. It is counted apart,
// shown inside By device and By fix, and says machine-readably why it is undecided (QuestionDetail.Undecided). A finding of the same
// (device, CVE, line) always wins: the question is then not listed. A check of the CVE's advisories may settle it ("not affected" from
// the vendor's advisory: listed as settled, not counted) or propose a verdict (the AI's: a proposal a person confirms or rejects; the
// CVE stays possible meanwhile).

// The states of a possible row (PossibleRowJS.state).
const (
	PossibleOpen     = "possible" // undecided, unchecked or checked without a verdict, or a rejected proposal
	PossibleProposal = "proposal" // an AI proposal waiting for a person
	PossibleSettled  = "settled"  // the box settled it not affected from the vendor's advisory
)

// PossibleItem is one possible CVE of one line of one device.
type PossibleItem struct {
	Question  Question
	CVE       string
	Check     *Check // the check of its evidence; nil when none
	Exploited bool   // the CVE is on an exploited list
	State     string
	// Due says the AI's reading of the line is due (none yet, or an older one to read again): with Check, what Checkable reads.
	Due bool
	// Unread says the last check could read none of the CVE's pages (they failed; the next check tries again).
	Unread bool
	// Held says the automatic reading leaves it until a time, and why (its last AI call was refused or failed); nil when not held.
	Held *Held
	// OlderBuild says it is reported only for an older build (markOlderBuilds): listed and counted apart; nil otherwise.
	OlderBuild *OlderBuild
}

// DistroPending says the item waits for the distribution's word on its own package (cause distro_silent): it is listed and counted
// apart from the main possible list, like the older-build group, and the device badge leaves it out. It is never checked (checkable).
func (it PossibleItem) DistroPending() bool {
	u := it.Question.Detail.Undecided
	return it.State == PossibleOpen && u != nil && slices.Contains(distroSilentReasons, u.Reason)
}

// Checkable says the item can be checked now: its evidence has a check identity and no check of that evidence is stored (none, or
// only one made on older evidence of the CVE record, which applies until a new check replaces it, or one that stored only that no page
// could be read, from before the AI read the record when no page reads).
func (it PossibleItem) Checkable() bool {
	if it.Question.CheckKey == "" {
		return false
	}
	if it.Check != nil && it.Check.Reading != nil {
		return it.Due
	}
	return it.Check == nil || it.Check.Stale || it.Check.noPageRead()
}

// noPageRead says the check stored only that no reference page could be read (decided by structure, no_reference_page or fetch_failed).
func (c Check) noPageRead() bool {
	return c.DecidedBy == DecidedStructured && c.Verdict == VerdictUnsure && c.Undecided != nil &&
		(c.Undecided.Reason == UndecidedNoReference || c.Undecided.Reason == UndecidedFetchFailed)
}

// Bulk says a proposal may be confirmed together with others of its class: never an exploited CVE proposed "not affected" (a person
// confirms that one row by row).
func (it PossibleItem) Bulk() bool {
	return it.State == PossibleProposal && (!it.Exploited || it.Check.Verdict != VerdictNotAffected)
}

// possibleItems reads the possible CVEs of devices nobody ignored (of one device when device is set): every unanswered question about a
// CVE (each CVE of a version_needed question of a line), less those a finding of the same (device, CVE, line) has.
func (s *Service) possibleItems(ctx context.Context, device string) ([]PossibleItem, error) {
	qs, err := s.openQuestions(ctx, device)
	if err != nil {
		return nil, err
	}
	checks, err := checksFor(ctx, s.rd(ctx), qs)
	if err != nil {
		return nil, err
	}
	readings, err := readingsFor(ctx, s.rd(ctx), qs)
	if err != nil {
		return nil, err
	}
	had, err := s.findingKeys(ctx, device)
	if err != nil {
		return nil, err
	}
	exploited, err := s.exploitedSet(ctx)
	if err != nil {
		return nil, err
	}
	in := causeInputs{checks: checks, readings: readings, exploited: exploited, unread: s.unreadKeys(), held: s.heldKeys(s.now()), now: s.now()}
	var out []PossibleItem
	add := func(q Question, cve string) {
		if cve == "" || had[lineKey(cve, q.SoftwareID)] {
			return
		}
		out = append(out, possibleItemOf(q, cve, in))
	}
	for _, q := range qs {
		switch {
		case q.Kind == QuestionNothingToCheck:
		case q.CVE != "":
			add(q, q.CVE)
		default:
			for _, c := range q.Detail.CVEList {
				add(q, c)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b PossibleItem) int {
		return cmp.Or(cmp.Compare(a.Question.AssetID, b.Question.AssetID), cmp.Compare(a.Question.SoftwareID, b.Question.SoftwareID),
			-cmpBool(a.Exploited, b.Exploited), cmp.Compare(a.CVE, b.CVE))
	})
	return out, nil
}

// causeInputs is what the state and the cause of a possible CVE are read from: the checks and the AI's readings of the questions (by
// check key), the exploited list, the check keys whose pages the last check could not read, the AI's reading as it stands, and now.
// The lists (possibleItems) and the coverage of a match pass (pairStates) read a possible CVE the same way, through possibleItemOf and
// PossibleCause.
type causeInputs struct {
	checks    map[string]Check
	readings  map[string]lineReading
	exploited map[string]bool
	unread    map[string]bool
	held      map[string]Held // the check keys the automatic reading leaves for now (possible.go only; the coverage does not read it)
	rs        ReadState
	now       time.Time
}

// possibleItemOf is the possible CVE cve of question q as the lists show it: its check (the box's own reading of the vendor's advisory
// first, else the AI's reading of the line), and its state (settled, a proposal for a person, or open).
func possibleItemOf(q Question, cve string, in causeInputs) PossibleItem {
	it := PossibleItem{Question: q, CVE: cve, Exploited: in.exploited[cve], State: PossibleOpen}
	if q.CheckKey == "" || q.CVE != cve {
		return it
	}
	it.Unread = in.unread[q.CheckKey]
	if h, ok := in.held[q.CheckKey]; ok {
		it.Held = &h
	}
	c, ok := in.checks[q.CheckKey]
	r, read := in.readings[q.CheckKey]
	it.Due = q.Detail.Check != nil && (!read || r.due(*q.Detail.Check, in.now))
	switch {
	case ok && !c.Stale && c.Settled(): // the box's own reading of the vendor's advisory comes first
	case read && q.Detail.Check != nil && (r.applied != nil || r.rejected != nil):
		st := r.applied
		if st == nil {
			st = r.rejected
		}
		c, ok = st.asCheck(*q.Detail.Check), true
	}
	if !ok {
		return it
	}
	it.Check = &c
	switch {
	case c.Settled() && c.Verdict == VerdictNotAffected:
		it.State = PossibleSettled
	case c.Proposal():
		it.State = PossibleProposal
	}
	return it
}

func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

// findingKeys is the (CVE, line) of every finding, in any state, of a device (of every device when device is ""), but a finding the AI's
// reading opened and Vedette closed when the reading went (a person rejected it): its CVE is undecided again, so possible, never gone.
func (s *Service) findingKeys(ctx context.Context, device string) (map[string]bool, error) {
	rows, err := s.rd(ctx).QueryContext(ctx, `SELECT cve, ifnull(software_id, '') FROM fnd_finding WHERE (?1 = '' OR asset_id = ?1)
		AND NOT (range_origin = ?2 AND state = 'handled' AND ifnull(via, '') = ?3)`, device, RangeAIRead, string(ViaDataCorrected))
	if err != nil {
		return nil, fmt.Errorf("findings: reading findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var cve, sw string
		if err := rows.Scan(&cve, &sw); err != nil {
			return nil, fmt.Errorf("findings: reading findings: %w", err)
		}
		out[lineKey(cve, sw)] = true
	}
	return out, rows.Err()
}

// exploitedSet is the CVEs on an exploited list.
func (s *Service) exploitedSet(ctx context.Context) (map[string]bool, error) {
	vs, err := s.cfg.Feeds.Vulns(ctx)
	if err != nil {
		return nil, fmt.Errorf("findings: reading the exploited list: %w", err)
	}
	out := make(map[string]bool, len(vs))
	for _, v := range vs {
		out[v.CVE] = true
	}
	return out, nil
}

// PossibleCounts is contract.ts PossibleCounts: the possible CVEs (open and proposals) but those reported only for an older build and
// those waiting for the distribution, each group apart, the AI proposals waiting, the ones a check can still look at, and the ones the
// box settled from an advisory.
type PossibleCounts struct {
	Possible   int `json:"possible"`
	OlderBuild int `json:"older_build"` // reported only for an older build (OlderBuild), not in Possible
	// DistroPending: waiting for the distribution's word on its own package (DistroPending), not in Possible or its causes;
	// DistroPendingExploited how many of them are on an exploited list
	DistroPending          int            `json:"distro_pending"`
	DistroPendingExploited int            `json:"distro_pending_exploited"`
	Proposals              int            `json:"proposals"`
	Unchecked              int            `json:"unchecked"`
	Settled                int            `json:"settled"`
	Causes                 map[string]int `json:"causes"` // the possible CVEs of Possible by cause (PossibleCause), every cause of the list present
}

func countPossible(items []PossibleItem, rs ReadState) PossibleCounts {
	c := PossibleCounts{Causes: make(map[string]int, len(PossibleCauses))}
	for _, k := range PossibleCauses {
		c.Causes[k] = 0
	}
	for _, it := range items {
		switch it.State {
		case PossibleSettled:
			c.Settled++
			continue
		case PossibleProposal:
			c.Proposals++
		}
		if it.Checkable() {
			c.Unchecked++
		}
		if it.DistroPending() {
			c.DistroPending++
			if it.Exploited {
				c.DistroPendingExploited++
			}
			continue
		}
		if it.OlderBuild != nil {
			c.OlderBuild++
			continue
		}
		c.Possible++
		c.Causes[PossibleCause(it, rs)]++
	}
	return c
}

// possibleByDevice is how many possible CVEs (not settled) each device has, those reported only for an older build apart: the device
// badge's counts when nothing open is more urgent. Those waiting for the distribution are not counted (the badge leaves them out).
func possibleByDevice(items []PossibleItem) (main, older map[string]int) {
	main, older = map[string]int{}, map[string]int{}
	for _, it := range items {
		switch {
		case it.State == PossibleSettled, it.DistroPending():
		case it.OlderBuild != nil:
			older[it.Question.AssetID]++
		default:
			main[it.Question.AssetID]++
		}
	}
	return main, older
}

// PossibleFilter selects the rows of GET /findings/possible.
type PossibleFilter struct {
	Device string
	Q      string
	State  string // "" every row but the settled ones; possible, proposal or settled
}

// PossibleRowJS is contract.ts PossibleRow.
type PossibleRowJS struct {
	ID        string         `json:"id"` // the question
	CVE       string         `json:"cve"`
	Kind      string         `json:"kind"`
	Device    deviceRefJS    `json:"device"`
	Software  *softwareRefJS `json:"software"`
	Severity  *cveSeverityJS `json:"severity"`
	Exploited bool           `json:"exploited"`
	State     string         `json:"state"`
	Undecided *Undecided     `json:"undecided"`
	Line      *string        `json:"line"`
	Fixes     []string       `json:"fixes"`
	Check     *CheckJS       `json:"check"`
	Checkable bool           `json:"checkable"`
	Bulk      bool           `json:"bulk"`
	Cause     *string        `json:"cause"` // PossibleCause; null for a settled row
	Held      *HeldJS        `json:"held"`  // the automatic reading leaves it until a time; null when not held, settled, or that reading cannot run now
	// OlderBuild: reported only for an older build, listed apart (markOlderBuilds); null otherwise
	OlderBuild *OlderBuild `json:"older_build"`
}

// HeldJS is contract.ts PossibleHeld.
type HeldJS struct {
	Until  string `json:"until"`
	Reason string `json:"reason"` // one of HeldReasons
}

// CheckJS is contract.ts PossibleCheck: a check's verdict as the lists show it, with the pages it read.
type CheckJS struct {
	Key        string        `json:"key"`
	DecidedBy  string        `json:"decided_by"`
	Verdict    string        `json:"verdict"`
	Confidence *string       `json:"confidence"`
	Reason     string        `json:"reason"`
	Quote      string        `json:"quote"`
	Sources    []CheckSource `json:"sources"`
	Model      *string       `json:"model"`
	CheckedBy  string        `json:"checked_by"`
	CheckedAt  string        `json:"checked_at"`
	Rejected   bool          `json:"rejected"`
	Reading    *ReadingJS    `json:"reading"`
}

// ReadingJS is contract.ts AiReading: the AI's reading of the vendor's statement for a release line, as the box checked it.
type ReadingJS struct {
	Status       string  `json:"status"`
	Line         string  `json:"line"`
	StatedLine   *string `json:"stated_line"`
	Introduced   *string `json:"introduced"`
	FixedIn      *string `json:"fixed_in"`
	LastAffected *string `json:"last_affected"`
	Host         *string `json:"host"`
	VendorPage   bool    `json:"vendor_page"`
	QuoteFound   bool    `json:"quote_found"`
	// Research is how the customer's AI researched the line (P-12); null for a reading of the pages the box fetched.
	Research *LineResearch `json:"research"`
}

func readingJS(st *LineStatement) *ReadingJS {
	if st == nil {
		return nil
	}
	opt := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	return &ReadingJS{Status: st.Status, Line: st.Line, StatedLine: opt(st.StatedLine), Introduced: opt(st.Introduced), FixedIn: opt(st.FixedIn),
		LastAffected: opt(st.Last), Host: opt(st.Host), VendorPage: st.VendorPage, QuoteFound: st.QuoteFound, Research: st.Research}
}

func checkJS(c *Check) *CheckJS {
	if c == nil {
		return nil
	}
	out := &CheckJS{Key: c.Key, DecidedBy: c.DecidedBy, Verdict: c.Verdict, Reason: c.Reason, Quote: c.Quote, Sources: c.Sources, CheckedBy: c.CheckedBy,
		CheckedAt: store.FormatTS(c.CheckedAt), Rejected: c.RejectedBy != "", Reading: readingJS(c.Reading)}
	if out.Sources == nil {
		out.Sources = []CheckSource{}
	}
	if c.Confidence != "" {
		v := c.Confidence
		out.Confidence = &v
	}
	if c.Model != "" {
		v := c.Model
		out.Model = &v
	}
	return out
}

// PossibleList is contract.ts PossibleList.
type PossibleList struct {
	Items  []PossibleRowJS `json:"items"`
	Total  int             `json:"total"`
	Counts PossibleCounts  `json:"counts"`
}

// Possible reads one page of the possible CVEs (of one device, of a search, of one state), with the counts of the whole set of the
// device or of every device.
func (s *Service) Possible(ctx context.Context, f PossibleFilter, p Page) (PossibleList, error) {
	out := PossibleList{Items: []PossibleRowJS{}}
	err := s.readTx(ctx, func(ctx context.Context) error {
		items, err := s.possibleItems(ctx, f.Device)
		if err != nil {
			return err
		}
		rs := s.ReadState(ctx)
		s.markOlderBuilds(ctx, items, rs)
		out.Counts = countPossible(items, rs)
		var assets, lines, cves []string
		for _, it := range items {
			assets, lines, cves = append(assets, it.Question.AssetID), append(lines, it.Question.SoftwareID), append(cves, it.CVE)
		}
		ref, err := s.refs(ctx, uniqueIDs(assets), uniqueIDs(nonEmpty(lines)), uniqueIDs(cves))
		if err != nil {
			return err
		}
		q := strings.ToLower(strings.TrimSpace(f.Q))
		var rows []PossibleRowJS
		for _, it := range items {
			if f.State == "" && it.State == PossibleSettled || f.State != "" && it.State != f.State {
				continue
			}
			r := possibleRow(it, ref, rs)
			if q != "" && !possibleMatches(r, q) {
				continue
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

func nonEmpty(xs []string) []string {
	return slices.DeleteFunc(slices.Clone(xs), func(x string) bool { return x == "" })
}

func possibleRow(it PossibleItem, ref refs, rs ReadState) PossibleRowJS {
	q := it.Question
	r := PossibleRowJS{ID: q.ID, CVE: it.CVE, Kind: string(q.Kind), Device: deviceRef(ref.device(q.AssetID)), Exploited: it.Exploited, State: it.State,
		Undecided: q.Detail.Undecided, Fixes: q.Detail.Fixes, Check: checkJS(it.Check), Checkable: it.Checkable(), Bulk: it.Bulk(), OlderBuild: it.OlderBuild}
	if r.Fixes == nil {
		r.Fixes = []string{}
	}
	if c := PossibleCause(it, rs); c != "" {
		r.Cause = &c
		// it says when the automatic reading reads it again: only while that reading can run (otherwise the cause says what waits)
		if it.Held != nil && rs.Ready && rs.Auto && !rs.BudgetReached {
			r.Held = &HeldJS{Until: store.FormatTS(it.Held.Until), Reason: it.Held.Reason}
		}
	}
	if r.Undecided == nil {
		r.Undecided = &Undecided{Reason: UndecidedRangesDoNotCover}
	}
	if q.Detail.Line != "" {
		line := q.Detail.Line
		r.Line = &line
	}
	if l, ok := ref.lines[q.SoftwareID]; ok && q.SoftwareID != "" {
		sw := &softwareRefJS{ID: l.ID, Name: cmp.Or(q.Detail.Software, l.Display)}
		if v := cmp.Or(q.Detail.Version, l.Version); v != "" {
			sw.Version = &v
		}
		r.Software = sw
	}
	if c, ok := ref.scores[it.CVE]; ok {
		r.Severity = severityJS(&c)
	}
	return r
}

func possibleMatches(r PossibleRowJS, q string) bool {
	has := func(v string) bool { return v != "" && strings.Contains(strings.ToLower(v), q) }
	return has(r.CVE) || has(r.Device.Name) || r.Device.IP != nil && has(*r.Device.IP) || r.Software != nil && has(r.Software.Name)
}

// UndecidedAudit is one group of the undecided audit (GET /findings/possible/audit): a reason, how many possible CVEs carry it, and the
// distinct rows or advisory texts that blocked them, so the cases the box cannot decide can be grouped by phrasing.
type UndecidedAudit struct {
	Reason   string   `json:"reason"`
	Count    int      `json:"count"`
	Examples []string `json:"examples"` // distinct blocking rows or advisory snippets (with their address), at most 20
}

// PossibleAudit groups every possible CVE and every check that left one undecided by its undecided reason.
func (s *Service) PossibleAudit(ctx context.Context) ([]UndecidedAudit, error) {
	var out []UndecidedAudit
	err := s.readTx(ctx, func(ctx context.Context) error {
		items, err := s.possibleItems(ctx, "")
		if err != nil {
			return err
		}
		by := map[string]*UndecidedAudit{}
		for _, it := range items {
			if it.State == PossibleSettled {
				continue
			}
			u := it.Question.Detail.Undecided
			if it.Check != nil && it.Check.Undecided != nil {
				u = it.Check.Undecided // the check read further than the match did
			}
			if u == nil {
				continue
			}
			g := by[u.Reason]
			if g == nil {
				g = &UndecidedAudit{Reason: u.Reason, Examples: []string{}}
				by[u.Reason] = g
			}
			g.Count++
			ex := strings.Join(u.Ranges, "; ")
			if u.Text != "" {
				ex = u.URL + ": " + u.Text
			}
			if ex != "" && len(g.Examples) < 20 && !slices.Contains(g.Examples, ex) {
				g.Examples = append(g.Examples, ex)
			}
		}
		for _, g := range by {
			out = append(out, *g)
		}
		slices.SortFunc(out, func(a, b UndecidedAudit) int { return cmp.Or(b.Count-a.Count, cmp.Compare(a.Reason, b.Reason)) })
		return nil
	})
	if out == nil {
		out = []UndecidedAudit{}
	}
	return out, err
}
