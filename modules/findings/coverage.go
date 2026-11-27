package findings

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
)

// Decision coverage (M-14). Each match pass counts, for every (software line, CVE) the catalogue relates on the devices it matched,
// what decided it and, for what stays undecided, why: decided by the source whose data decided (the range-origin vocabulary of
// fnd_finding.range_origin, plus the platform list) as affected or not affected, or possible by its undecided reason (UndecidedReasons;
// an AI proposal waiting for a person is ai_proposal). A pair the matcher reached that ended as neither a finding, a question nor a
// proof is counted under a CoverageOther class: it is undecided and no one is told why, so its target is zero. Beside it, the identity coverage
// counts the software lines by how the box knows what product they are (CoverageIdentity*). The counts are of the readings the pass
// made: a device the pass found unchanged keeps the counts of its last full match. Each pass's sum is one row of fnd_coverage_run; the
// counting changes no finding or question.

// The identity methods of a software line.
const (
	IdentityStated    = "stated"    // its source states the product: a CPE (nmap, SNMP, the agent's OS) or the distribution's package
	IdentityCatalogue = "catalogue" // the product catalogue gives it CPE names (content/catalog/products)
	IdentityRecord    = "record"    // its own vendor and product name the product of a CVE record or NVD row it is matched to
	IdentityNone      = "none"      // nothing in the catalogue is matched to it
)

// IdentityMethods lists the identity methods, in the order the coverage shows them.
var IdentityMethods = []string{IdentityStated, IdentityCatalogue, IdentityRecord, IdentityNone}

// CoveragePlatformList is the source of a "not affected" the platform list decided (content/catalog/platform-limits.json): hand data.
const CoveragePlatformList = "platform_list"

// CoverageOther is the cause of a pair the matcher reached that is neither decided nor a possible finding with a reason the box gives.
// The coverage tells three such classes apart (CoverageOther* below, each starting with CoverageOther), so the unnamed share says where
// it comes from; CoverageOther alone is a question whose reason is none of UndecidedReasons.
const CoverageOther = "other"

// The unnamed classes: nobody is told why these pairs are undecided.
const (
	// CoverageOtherDistroSilent: a distribution's package whose distribution's data has no word on the CVE (only it may decide the
	// package: NVD's upstream ranges do not see its backported fixes), for no cause of DistroSilences (a release a person gave). Such a
	// pair with a cause is counted under it (distroSilence).
	CoverageOtherDistroSilent = "other_distro_silent"
	// CoverageOtherRecordUnread: the record or NVD's rows name the product, and the matcher read nothing it could compare (no bounded
	// range, a row shape it does not read).
	CoverageOtherRecordUnread = "other_record_unread"
	// CoverageOtherDropped: the matcher matched the product or needed a version, and neither a finding nor a question came of it (a
	// match on the name alone, an old entry, that is not on the could-not-check list).
	CoverageOtherDropped = "other_dropped"
)

// CoverageAIProposal is the cause of a possible finding whose AI proposal waits for a person.
const CoverageAIProposal = "ai_proposal"

// Coverage is the decision coverage of the last match pass.
type Coverage struct {
	At       time.Time        `json:"at"`
	Devices  int              `json:"devices"`  // devices the pass matched
	Lines    int              `json:"lines"`    // their software lines (and the network OS a device states without one)
	Pairs    int              `json:"pairs"`    // (line, CVE) the catalogue relates on them
	Decided  []CoverageSource `json:"decided"`  // by source, the most pairs first
	Possible []CoverageCause  `json:"possible"` // by cause, the most first
	Identity []CoverageMethod `json:"identity"` // by method, in IdentityMethods order
}

// CoverageSource is how many pairs one source decided, each way.
type CoverageSource struct {
	By          string `json:"by"`
	Affected    int    `json:"affected"`
	NotAffected int    `json:"not_affected"`
}

// CoverageCause is how many pairs stay undecided for one cause.
type CoverageCause struct {
	Cause string `json:"cause"`
	Count int    `json:"count"`
}

// CoverageMethod is how many software lines one identity method identifies.
type CoverageMethod struct {
	Method string `json:"method"`
	Lines  int    `json:"lines"`
}

// deviceCover is one device's counts.
type deviceCover struct {
	lines    int
	decided  map[string][2]int // source -> affected, not affected
	possible map[string]int
	identity map[string]int
}

// covers is the counts of each device the pass matched, by device id, and the sum of the last pass.
type covers struct {
	mu   sync.Mutex
	m    map[string]deviceCover
	last *Coverage
}

func (c *covers) set(id string, d deviceCover) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]deviceCover{}
	}
	c.m[id] = d
}

// pass keeps only the devices of live and stores their sum as the last pass's coverage.
func (c *covers) pass(live map[string]bool, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	maps.DeleteFunc(c.m, func(id string, _ deviceCover) bool { return !live[id] })
	out := Coverage{At: at, Decided: []CoverageSource{}, Possible: []CoverageCause{}, Identity: []CoverageMethod{}}
	decided, possible, identity := map[string][2]int{}, map[string]int{}, map[string]int{}
	for _, d := range c.m {
		out.Devices++
		out.Lines += d.lines
		for k, n := range d.decided {
			s := decided[k]
			decided[k] = [2]int{s[0] + n[0], s[1] + n[1]}
			out.Pairs += n[0] + n[1]
		}
		for k, n := range d.possible {
			possible[k] += n
			out.Pairs += n
		}
		for k, n := range d.identity {
			identity[k] += n
		}
	}
	for by, n := range decided {
		out.Decided = append(out.Decided, CoverageSource{By: by, Affected: n[0], NotAffected: n[1]})
	}
	slices.SortFunc(out.Decided, func(a, b CoverageSource) int {
		return cmp.Or((b.Affected+b.NotAffected)-(a.Affected+a.NotAffected), cmp.Compare(a.By, b.By))
	})
	for cause, n := range possible {
		out.Possible = append(out.Possible, CoverageCause{Cause: cause, Count: n})
	}
	slices.SortFunc(out.Possible, func(a, b CoverageCause) int { return cmp.Or(b.Count-a.Count, cmp.Compare(a.Cause, b.Cause)) })
	for _, m := range IdentityMethods {
		out.Identity = append(out.Identity, CoverageMethod{Method: m, Lines: identity[m]})
	}
	c.last = &out
}

// get is the last pass's coverage; false before the first pass.
func (c *covers) get() (Coverage, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		none := Coverage{Decided: []CoverageSource{}, Possible: []CoverageCause{}, Identity: []CoverageMethod{}}
		for _, m := range IdentityMethods {
			none.Identity = append(none.Identity, CoverageMethod{Method: m})
		}
		return none, false
	}
	return *c.last, true
}

// coverageKeep is how many passes fnd_coverage_run keeps (the newest).
const coverageKeep = 30

// Coverage is the decision coverage of the last match pass: the one this service ran, else the newest stored (a pass before the box
// restarted); false (every count 0) when there is none.
func (s *Service) Coverage(ctx context.Context) (Coverage, bool, error) {
	if c, ok := s.covers.get(); ok {
		return c, true, nil
	}
	none, _ := s.covers.get()
	var at, raw string
	err := s.rd(ctx).QueryRowContext(ctx, `SELECT ran_at, counts FROM fnd_coverage_run ORDER BY id DESC LIMIT 1`).Scan(&at, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return none, false, nil
	}
	if err != nil {
		return none, false, fmt.Errorf("findings: reading the last coverage: %w", err)
	}
	c := none
	t, err := parseTS(at)
	if err != nil || json.Unmarshal([]byte(raw), &c) != nil {
		return none, false, nil // an unreadable row: as if none (the next pass writes a new one)
	}
	c.At = t
	return c, true, nil
}

// storeCoverage records the coverage of a pass (fnd_coverage_run) and keeps the newest coverageKeep.
func (s *Service) storeCoverage(ctx context.Context) error {
	c, ok := s.covers.get()
	if !ok {
		return nil
	}
	at := c.At
	c.At = time.Time{}
	b, err := json.Marshal(struct {
		Coverage
		At struct{} `json:"at,omitzero"`
	}{Coverage: c})
	if err != nil {
		return fmt.Errorf("findings: coverage counts: %w", err)
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_coverage_run (ran_at, counts) VALUES (?, ?)`, store.FormatTS(at), string(b)); err != nil {
			return fmt.Errorf("findings: storing the coverage: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_coverage_run WHERE id NOT IN (SELECT id FROM fnd_coverage_run ORDER BY id DESC LIMIT ?)`, coverageKeep); err != nil {
			return fmt.Errorf("findings: pruning coverage runs: %w", err)
		}
		return nil
	})
}

// pairState is what decided one (line, CVE) pair, or why it is undecided.
type pairState struct {
	by       string // the deciding source; "" when undecided
	affected bool
	cause    string // undecided: why
}

// coverOf counts device dm.a's pairs and lines from the readings of its match (dm, every entry read) and its findings and questions as
// the pass's write left them (rows), with the checks of those questions (checks, by check key).
func coverOf(dm *devMatch, rows deviceRows, checks map[string]Check) deviceCover {
	state, linked := pairStates(dm, rows, checks)
	d := deviceCover{decided: map[string][2]int{}, possible: map[string]int{}, identity: map[string]int{}}
	for _, st := range state {
		switch {
		case st.by != "" && st.affected:
			n := d.decided[st.by]
			d.decided[st.by] = [2]int{n[0] + 1, n[1]}
		case st.by != "":
			n := d.decided[st.by]
			d.decided[st.by] = [2]int{n[0], n[1] + 1}
		default:
			d.possible[st.cause]++
		}
	}
	counted := map[string]bool{}
	for i, s := range dm.sws { // the first row of a line is its effective reading
		if s.ID == "" || counted[s.ID] {
			continue
		}
		counted[s.ID] = true
		d.lines++
		d.identity[identityOf(s, dm.infos[i], linked[storedLine(s.ID)])]++
	}
	return d
}

// pairStates is the state of every pair of device dm.a, by lineKey, and the lines (stored id) with a related pair.
func pairStates(dm *devMatch, rows deviceRows, checks map[string]Check) (map[string]pairState, map[string]bool) {
	related := map[string]string{}  // lineKey of every pair a row of the line reached -> its unnamed class, if nothing else decides it
	proofs := map[string]string{}   // lineKey -> the source of the proof of "not affected"
	ruledOut := map[string]string{} // lineKey -> the source of the rows that name another product (no proof)
	linked := map[string]bool{}     // stored line id -> the line has a related pair
	seen := make(map[string]bool, len(dm.vulns))
	for vi, v := range dm.vulns {
		if !ValidCVE(v.CVE) || seen[v.CVE] {
			continue
		}
		seen[v.CVE] = true
		e := dm.read(vi)
		k := 0 // the next proof of e.provedEach: they come in the order of the outNotAffected rows
		for _, o := range e.outs {
			s := dm.sws[o.row]
			line := storedLine(s.ID)
			key := lineKey(v.CVE, line)
			if related[key] == "" {
				related[key] = CoverageOtherDropped
			}
			linked[line] = true
			switch o.out {
			case outNotAffected:
				if k < len(e.provedEach) {
					if _, ok := proofs[key]; !ok {
						proofs[key] = proofBy(dm.a, s, dm.infos[o.row], v, e.provedEach[k])
					}
					k++
				}
			case outRuledOut:
				if _, ok := ruledOut[key]; !ok {
					ruledOut[key] = v.rangeOrigin()
				}
			}
		}
		// A row the entry's key or its rows name, that the matcher read and left with nothing (a record row it cannot read, a
		// distribution's package its data has no word on): the catalogue relates it all the same, undecided.
		reached := make(map[int]bool, len(e.outs))
		for _, o := range e.outs {
			reached[o.row] = true
		}
		cand := dm.namedRows[vi]
		ek := keyOf(v)
		if v.Vendor != "" || v.Product != "" {
			cand = dm.allRows
		}
		for _, i := range cand {
			s := dm.sws[i]
			if reached[i] || s.Guess || !keyedBy(dm.keys[i], ek) && (!dm.named[i][vi] || !recordNames(dm.infos[i], v)) {
				continue
			}
			line, class := storedLine(s.ID), CoverageOtherRecordUnread
			if in := dm.infos[i]; in.pkgBuilt() && !upstreamJudges(in, v) {
				if _, ok := distroVerdict(in, v); !ok { // only its distribution's word may decide it: why it has none (distroSilence)
					class = cmp.Or(distroSilence(in, v, dm.now), CoverageOtherDistroSilent)
				}
			}
			if key := lineKey(v.CVE, line); related[key] == "" {
				related[key] = class
			}
			linked[line] = true
		}
	}
	state := map[string]pairState{}
	for _, f := range rows.findings {
		if f.Detected {
			state[lineKey(f.CVE, f.SoftwareID)] = pairState{by: cmp.Or(f.RangeOrigin, RangeNVD), affected: true}
			linked[f.SoftwareID] = true
		}
	}
	ask := func(q Question, cve string) {
		key := lineKey(cve, q.SoftwareID)
		if _, ok := state[key]; ok || cve == "" {
			return
		}
		linked[q.SoftwareID] = true
		if q.Answer != "" {
			state[key] = pairState{by: RangePerson, affected: q.Answer == AnswerAffected}
			return
		}
		u := q.Detail.Undecided
		if c, ok := checks[q.CheckKey]; ok && q.CheckKey != "" && q.CVE == cve {
			switch {
			case c.Settled() && c.Verdict == VerdictNotAffected:
				state[key] = pairState{by: RangeAdvisory}
				return
			case c.Proposal():
				state[key] = pairState{cause: CoverageAIProposal}
				return
			case c.Undecided != nil:
				u = c.Undecided // the check read further than the match did
			}
		}
		cause := CoverageOther
		if u != nil && slices.Contains(UndecidedReasons, u.Reason) {
			cause = u.Reason
		}
		state[key] = pairState{cause: cause}
	}
	for _, q := range rows.questions {
		switch {
		case q.Kind == QuestionNothingToCheck:
		case q.CVE != "":
			ask(q, q.CVE)
		default:
			for _, c := range q.Detail.CVEList {
				ask(q, c)
			}
		}
	}
	for key, class := range related {
		if _, ok := state[key]; ok {
			continue
		}
		switch {
		case proofs[key] != "":
			state[key] = pairState{by: proofs[key]}
		case ruledOut[key] != "":
			state[key] = pairState{by: ruledOut[key]}
		default: // reached, and neither a finding, a question nor a proof
			state[key] = pairState{cause: class}
		}
	}
	return state, linked
}

// recordNames says a row of v names the product of the line read as in (its CPE, its name or an alias), whatever versions it gives.
func recordNames(in swInfo, v Vuln) bool {
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil {
			continue
		}
		if own, _ := appliesTo(c, in.cpe, in.hasCPE, in.ids); own {
			return true
		}
	}
	return false
}

// identityOf is how the box knows what product line s is: its source states it, the catalogue names it, or its own name reaches a
// record (linked: a pair of the line is related), else none.
func identityOf(s Software, in swInfo, linked bool) string {
	switch {
	case in.hasCPE || in.pkgBuilt():
		return IdentityStated
	case len(cpeAliases[identity{vendor: productid.Norm(s.Vendor), product: productid.Norm(s.Product)}]) > 0:
		return IdentityCatalogue
	case linked:
		return IdentityRecord
	}
	return IdentityNone
}

// proofBy is the source of a proof m that row s of device a is not affected by v, as resolve names the origin of a finding.
func proofBy(a Asset, s Software, in swInfo, v Vuln, m Match) string {
	switch {
	case m.pkgFixed:
		return RangeDistro
	case m.why != "":
		return CoveragePlatformList
	}
	if _, ok := distroVerdict(in, v); ok {
		return RangeDistro
	}
	if lineJudge(a, s, in, v).decides() {
		return RangeVendorLine
	}
	if r, ok := schemeJudge(a, s, in, v); ok && r.origin != "" {
		return r.origin
	}
	return v.rangeOrigin()
}

// rowOut is one row an entry reached and how (entryRead.outs).
type rowOut struct {
	row int
	out outcome
}
