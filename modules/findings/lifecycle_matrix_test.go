package findings

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The life cycle of one line's AI readings, as a matrix: every sequence of up to four events on one release line of a synthetic product
// (Quillfeather Mail 115.9.0) is played through the decision functions the box uses (lineStore, lineReject, readingFor, lineOutcome,
// verdictFor; the precedence of a person's answer as the match applies it), and the invariants are checked after every step:
//
//	I1 an open finding closes only by a person: a confirmed "not affected" (with the exploited tick when the CVE is exploited) or a rejected
//	   reading (stated record data is the matcher's, not the readings');
//	I2 an affected reading with a checked quote is never hidden or deleted by an AI reading or a re-read; while a person has not answered
//	   the line, it keeps a finding open;
//	I3 no AI output alone answers the line or settles it not affected;
//	I4 a rejection never rejects, or holds back, a reading of the opposite verdict for the version.

type lcEvent string

const (
	evAffected      lcEvent = "affected+quote"
	evAffectedNoQ   lcEvent = "affected-unchecked"
	evNotAffected   lcEvent = "not_affected+quote"
	evNotAffNoQ     lcEvent = "not_affected-unchecked"
	evFixedLater    lcEvent = "fixed-later+quote" // fixed in 115.12: the version is before the fix (affected)
	evFixedLaterNoQ lcEvent = "fixed-later-unchecked"
	evFixedOther    lcEvent = "fixed-other-bounds+quote" // fixed in 115.13: affected, other bounds
	evFixedPast     lcEvent = "fixed-past+quote"         // fixed in 115.5: the version has the fix (not affected)
	evUnsure        lcEvent = "unsure"
	evRejectNewest  lcEvent = "person-rejects-newest-reading"
	evRejectHolder  lcEvent = "person-rejects-the-finding's-reading"
	evConfirm       lcEvent = "person-confirms"
	evConfirmTick   lcEvent = "person-confirms-with-exploited-tick"
	evReopen        lcEvent = "person-reopens"
	evRereadKept    lcEvent = "record-reread-quote-kept"
	evRereadGone    lcEvent = "record-reread-quote-gone"
	evPageChanged   lcEvent = "cited-page-changed"
	evExploited     lcEvent = "exploited-flag-toggled"
)

var lcEvents = []lcEvent{evAffected, evAffectedNoQ, evNotAffected, evNotAffNoQ, evFixedLater, evFixedLaterNoQ, evFixedOther, evFixedPast, evUnsure,
	evRejectNewest, evRejectHolder, evConfirm, evConfirmTick, evReopen, evRereadKept, evRereadGone, evPageChanged, evExploited}

func (e lcEvent) ai() bool { return slices.Index(lcEvents, e) <= slices.Index(lcEvents, evUnsure) }

func (e lcEvent) person() bool {
	return e == evRejectNewest || e == evRejectHolder || e == evConfirm || e == evConfirmTick || e == evReopen
}

// lcState is the line: its readings newest first (as statementsOf reads them), whether a person answered "not affected", the CVE's
// exploited flag, the record and the cited page, and the clock.
type lcState struct {
	line      []LineStatement
	answered  bool
	exploited bool
	record    int
	page      int
	clock     int
	// what the last step left (the next step's "before"): the outcome and the live affected readings
	last string
	live []string
}

const lcProduct = "quillfeather|mail"

func (s lcState) id() CheckID {
	return CheckID{Product: lcProduct, Line: "115.9.0", Version: "115.9.0", Record: recordHash(fmt.Sprint("r", s.record))}
}

func (s lcState) clone() lcState {
	s.line = slices.Clone(s.line)
	s.live = slices.Clone(s.live)
	return s
}

func (s lcState) now() time.Time { return time.Date(2026, 11, 1, 0, 0, s.clock, 0, time.UTC) }

// reading is the reading an AI event stores: cited from the vendor's page as the box read it, keyed like the box keys it.
func (s lcState) reading(e lcEvent) LineStatement {
	st := LineStatement{CVE: cveQuill, Product: lcProduct, Line: "115.9.0", RecordHash: recordHash(fmt.Sprint("r", s.record)),
		PageHash: pageHash(fmt.Sprint("page", s.page)), URL: quillSA, Host: "quillfeather.example", Basis: BasisStated, Model: "m", Profile: "p",
		AskedBy: "system", AskedAt: s.now(), SeenAt: s.now(), Research: &LineResearch{Layer: "quick", QuoteCheck: QuoteDigest}}
	switch e {
	case evAffected, evAffectedNoQ:
		st.Status, st.Quote = StatementAffected, "Quillfeather Mail 115.9.0 is affected by this issue."
	case evNotAffected, evNotAffNoQ:
		st.Status, st.Quote = StatementNotAffected, "Quillfeather Mail 115.9.0 is not affected by this issue."
	case evFixedLater, evFixedLaterNoQ:
		st.Status, st.FixedIn, st.Quote = StatementFixed, "115.12", "The issue is fixed in Quillfeather Mail 115.12."
	case evFixedOther:
		st.Status, st.FixedIn, st.Quote = StatementFixed, "115.13", "The issue is fixed in Quillfeather Mail 115.13."
	case evFixedPast:
		st.Status, st.FixedIn, st.Quote = StatementFixed, "115.5", "Quillfeather Mail versions before 115.5 are affected; it is fixed in 115.5."
	case evUnsure:
		st.Status = StatementUnsure
	}
	st.QuoteFound = st.Quote != "" && e != evAffectedNoQ && e != evNotAffNoQ && e != evFixedLaterNoQ
	if !st.QuoteFound {
		st.Research.QuoteCheck = QuoteNotFound
	}
	st.Key = st.identity()
	return st
}

// store plays storeStatement: lineStore's deletes, then the upsert (a row of the same key a person rejected stays as it is).
func (s *lcState) store(st LineStatement) {
	drop := lineStore(s.line, st)
	s.line = slices.DeleteFunc(s.line, func(o LineStatement) bool { return slices.Contains(drop, o.Key) })
	if i := slices.IndexFunc(s.line, func(o LineStatement) bool { return o.Key == st.Key }); i >= 0 {
		if s.line[i].RejectedBy != "" {
			return
		}
		s.line = slices.Delete(s.line, i, i+1) // updated: its asked_at moves it first
	}
	s.line = append([]LineStatement{st}, s.line...)
}

// reject plays RejectProposal: the one reading is rejected; the resolution covers the others (coveredBy).
func (s *lcState) reject(r *LineStatement) {
	for i := range s.line {
		if r != nil && s.line[i].Key == r.Key && s.line[i].RejectedBy == "" {
			s.line[i].RejectedBy, s.line[i].RejectedAt = "ana@example.com", s.now()
		}
	}
}

// rejected says the resolution treats reading i as rejected (by a person, or covered by a person's rejection), and by which reading.
func (s lcState) rejected(says []string, i int) (bool, *LineStatement) {
	if s.line[i].RejectedBy != "" {
		return true, &s.line[i]
	}
	by := coveredBy(s.line, says, i)
	return by != nil, by
}

// outcome is what the match makes of the line: a person's answer first, then the readings (lineOutcome), else a proposal of the newest
// reading for a person, else still possible.
func (s lcState) outcome() (string, *LineStatement) {
	if s.answered {
		return "answered_not_affected", nil
	}
	r := readingFor(s.line, cveQuill, s.id())
	if by, review := lineOutcome(r, s.id()); by != nil {
		if review {
			return "finding+review", by
		}
		return "finding", by
	}
	if r.applied != nil && r.applied.verdictFor(s.id()) == VerdictNotAffected {
		return "proposal_not_affected", nil
	}
	return "possible", nil
}

func open(o string) bool { return strings.HasPrefix(o, "finding") }

// step plays one event on s and returns why an invariant broke ("" when none).
func (s *lcState) step(e lcEvent) string {
	s.clock++
	before, live := s.last, s.live
	if before == "" {
		before, live = "possible", nil
	}
	answered := s.answered
	id := s.id()
	switch e {
	case evRejectNewest, evRejectHolder:
		var r *LineStatement
		if e == evRejectNewest {
			r = readingFor(s.line, cveQuill, id).applied
		} else {
			_, r = s.outcome()
		}
		s.reject(r)
	case evConfirm, evConfirmTick:
		r := readingFor(s.line, cveQuill, id).applied
		if r != nil && r.verdictFor(id) == VerdictNotAffected && (!s.exploited || e == evConfirmTick) {
			s.answered = true
		}
	case evReopen:
		s.answered = false
	case evRereadKept:
		s.record++
		if r := readingFor(s.line, cveQuill, id).newest(); r != nil {
			for i := range s.line {
				if s.line[i].Key == r.Key {
					s.line[i].RecordHash = recordHash(fmt.Sprint("r", s.record))
				}
			}
		}
	case evRereadGone:
		s.record++
	case evPageChanged:
		s.page++
	case evExploited:
		s.exploited = !s.exploited
	default:
		s.store(s.reading(e))
	}
	// I4: every reading the resolution treats as rejected was rejected by a person, or says for the version what a reading a person
	// rejected says
	var now []string // the live affected readings after the step
	says := lineSays(s.line, cveQuill, id)
	for i, o := range s.line {
		rej, by := s.rejected(says, i)
		if rej && o.RejectedBy == "" {
			if bv := by.says(id); bv != says[i] {
				return fmt.Sprintf("I4: a rejected %s reading covers a reading that says %q", bv, says[i])
			}
		}
		if !rej && o.QuoteFound && says[i] == VerdictAffected {
			now = append(now, o.Key)
		}
	}
	after, _ := s.outcome()
	if e.ai() && s.line[0].asCheck(id).Settled() { // the readings before were checked when they were stored
		return "I3: an AI reading settles the line"
	}
	if !e.person() && s.answered != answered {
		return "I3: an AI output or a re-read changed a person's answer"
	}
	if open(before) && !open(after) && e != evConfirm && e != evConfirmTick && e != evRejectNewest && e != evRejectHolder {
		return fmt.Sprintf("I1: the finding closed on %s (%s -> %s)", e, before, after)
	}
	if open(before) && !open(after) && e == evConfirm && s.exploited {
		return "I1: an exploited CVE's finding closed without the tick"
	}
	if !e.person() && len(live) > 0 && len(now) == 0 {
		return fmt.Sprintf("I2: %s removed or hid every affected reading with a checked quote", e)
	}
	for _, k := range live { // gone only behind a newer reading stating the same with a checked quote (lineStore), never otherwise
		if !e.person() && !slices.Contains(now, k) && !slices.ContainsFunc(s.line, func(o LineStatement) bool { return o.Key == k }) &&
			(!e.ai() || !s.line[0].QuoteFound || s.line[0].says(id) != VerdictAffected) {
			return fmt.Sprintf("I2: %s removed an affected reading with a checked quote", e)
		}
	}
	if !s.answered && len(now) > 0 && !open(after) {
		return fmt.Sprintf("I2: an affected reading with a checked quote is hidden (%s)", after)
	}
	s.last, s.live = after, now
	return ""
}

func TestReadingLifeCycle_Matrix(t *testing.T) {
	t.Parallel()
	var probe lcState
	for e, want := range map[lcEvent]string{evAffected: VerdictAffected, evAffectedNoQ: "", evNotAffected: VerdictNotAffected, evFixedLater: VerdictAffected,
		evFixedOther: VerdictAffected, evFixedPast: VerdictNotAffected, evUnsure: ""} {
		if got := probe.reading(e).verdictFor(probe.id()); got != want {
			t.Fatalf("the event %s says %q for the version, want %q: the matrix would not test what it names", e, got, want)
		}
	}
	const depth = 4
	type result struct {
		sequences int
		failed    map[string]int
		first     []string
	}
	// one goroutine per first event: the sequences are independent, and the whole matrix stays well under a second
	results := make([]result, len(lcEvents))
	var wg sync.WaitGroup
	for i, e0 := range lcEvents {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := result{failed: map[string]int{}}
			var walk func(s lcState, path []lcEvent)
			walk = func(s lcState, path []lcEvent) {
				e := path[len(path)-1]
				res.sequences++
				if why := s.step(e); why != "" {
					class := why
					if i := strings.Index(why, " ("); i > 0 {
						class = why[:i]
					}
					if res.failed[class]++; res.failed[class] == 1 {
						res.first = append(res.first, fmt.Sprintf("%s\n    after %v", why, path))
					}
					return
				}
				if len(path) == depth {
					return
				}
				for _, e := range lcEvents {
					walk(s.clone(), append(slices.Clone(path), e))
				}
			}
			walk(lcState{}, []lcEvent{e0})
			results[i] = res
		}()
	}
	wg.Wait()
	sequences, failed, seen := 0, map[string]int{}, map[string]bool{}
	for _, r := range results {
		sequences += r.sequences
		for c, n := range r.failed {
			failed[c] += n
		}
		for _, f := range r.first {
			class, _, _ := strings.Cut(f, "\n")
			if i := strings.Index(class, " ("); i > 0 {
				class = class[:i]
			}
			if !seen[class] {
				seen[class] = true
				t.Errorf("%s", f)
			}
		}
	}
	t.Logf("%d event sequences of length 1 to %d", sequences, depth)
	for class, n := range failed {
		t.Logf("%d sequences: %s", n, class)
	}
}

// namesToken reads a version as a whole token exactly as the expression it replaced did (a faster reading, the same answers).
func TestNamesToken_SameAsTheExpression(t *testing.T) {
	t.Parallel()
	re := func(text, tok string) bool {
		return regexp.MustCompile(`(?:^|[^0-9a-z.])` + regexp.QuoteMeta(strings.ToLower(tok)) + `(?:$|[^0-9a-z.]|\.(?:$|[^0-9a-z]))`).MatchString(strings.ToLower(text))
	}
	texts := []string{"", "7.4.10", "7.4.1", "Fixed in 7.4.1.", "fixed in 7.4.1.x", "v7.4.1", "7.4.1-beta", "(7.4.1)", "7.4.1, 7.4.2", "a7.4.1", ".7.4.1",
		"7.4.1.", "7.4.1.5", "Mail 115.9.0 is affected", "115.9", "115", "Überall 7.4.1 ist", "x 7.4.17.4.1 y", "7.4.1R2", "7.4.1r", "7.4.1 7.4.1"}
	toks := []string{"7.4.1", "115", "115.9", "115.9.0", "7.4", "1", "R2", "7.4.1r"}
	for _, x := range texts {
		for _, k := range toks {
			if got, want := namesToken(x, k), re(x, k); got != want {
				t.Errorf("namesToken(%q, %q) = %v, the expression says %v", x, k, got, want)
			}
		}
	}
}
