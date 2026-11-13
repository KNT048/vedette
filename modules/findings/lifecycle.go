package findings

import (
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Status is the state of a finding.
type Status string

// The statuses of a finding (INV-2). Confirmed and suspected are open.
const (
	StatusConfirmed     Status = "confirmed"
	StatusSuspected     Status = "suspected"
	StatusMitigated     Status = "mitigated"
	StatusPatched       Status = "patched"
	StatusFalsePositive Status = "false_positive"
	StatusNotRelevant   Status = "not_relevant"
	// StatusRiskAccepted is closed by a person until Finding.AcceptedUntil; it reopens by itself after that day (D-498).
	StatusRiskAccepted Status = "risk_accepted"
)

// Open reports whether the finding still needs attention (confirmed, suspected).
func (s Status) Open() bool { return s == StatusConfirmed || s == StatusSuspected }

func (s Status) valid() bool {
	switch s {
	case StatusConfirmed, StatusSuspected, StatusMitigated, StatusPatched, StatusFalsePositive, StatusNotRelevant, StatusRiskAccepted:
		return true
	}
	return false
}

// Action is what a person can do from the finding page (POST /findings/{id}/status).
type Action string

// The actions of POST /findings/{id}/status (INV-3).
const (
	ActionPatched       Action = "patched"
	ActionMitigated     Action = "mitigated"
	ActionFalsePositive Action = "false_positive"
	ActionNotRelevant   Action = "not_relevant"
	ActionReopen        Action = "reopen"
	// ActionAcceptRisk needs a note and an until date (Finding.AcceptRisk, D-498).
	ActionAcceptRisk Action = "accept_risk"
)

const (
	// MaxNote is the longest note, counted in UTF-16 code units like the GUI.
	MaxNote = 500
	// MinReasonNote is the shortest note for false_positive, not_relevant and accept_risk.
	MinReasonNote = 3
	// MaxAcceptDays is how far ahead a risk can be accepted (D-498).
	MaxAcceptDays = 365
	// SystemUser is the history user for automatic events.
	SystemUser = "system"

	maxEvidenceField = 4096
	maxTemplate      = 128
)

// Finding is the lifecycle state of one (asset, cve) pair. The id, asset and
// cve live in the storage layer.
type Finding struct {
	Status         Status
	Severity       Severity
	Confidence     float64
	Basis          Basis
	Evidence       *Evidence
	ResolvedBy     string    // "" = none
	ResolvedAt     time.Time // zero = none
	ResolutionNote string    // "" = none
	// ResolutionReason is set only when Vedette closed the finding by itself (D-530): ReasonNotAffectedVersion. A
	// person's action, a reopen or a scan clears it.
	ResolutionReason string
	// AcceptedUntil is the last day (00:00 UTC) of a risk acceptance; set only while the status is risk_accepted (D-498).
	AcceptedUntil time.Time
}

// ReasonRiskExpired is the StatusChangedEvent reason of a finding whose risk acceptance ran out (D-498, INV-13).
const ReasonRiskExpired = "risk_acceptance_expired"

// dayOf is the UTC day of t, at 00:00.
func dayOf(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// FmtDay is how a day is written in history notes: "12 Feb 2027", like the GUI.
func FmtDay(t time.Time) string { return t.UTC().Format("2 Jan 2006") }

// ExpireAcceptance reopens a risk_accepted finding once its last day has passed (D-498, INV-13): to the open status a
// fresh match would give (confirmed with a scan basis, else suspected), with a history row by the system user that names
// who accepted it and until when. ok is false for anything else.
func (f Finding) ExpireAcceptance(now time.Time) (Finding, HistoryEntry, bool) {
	if f.Status != StatusRiskAccepted || !dayOf(now).After(f.AcceptedUntil) {
		return f, HistoryEntry{}, false
	}
	note := "Risk acceptance expired (accepted by " + f.ResolvedBy + " until " + FmtDay(f.AcceptedUntil) + ")."
	f.Status = StatusSuspected
	if f.Basis == BasisScan {
		f.Status = StatusConfirmed
	}
	f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason, f.AcceptedUntil = "", time.Time{}, "", "", time.Time{}
	return f, HistoryEntry{TS: now, User: SystemUser, Action: "reopened", Note: note}, true
}

// ReasonNotAffectedVersion closes a suspected finding whose version the matcher proved outside every range (D-530).
const ReasonNotAffectedVersion = "not_affected_version"

// AutoResolved reports whether Vedette closed the finding by itself (D-530): only such a finding reopens on a match.
func (f Finding) AutoResolved() bool {
	return f.Status == StatusNotRelevant && f.ResolutionReason == ReasonNotAffectedVersion
}

// AutoResolve closes a suspected finding (basis version or product) that the matcher proved not affected (D-530):
// not_relevant by the system user, with the matcher's sentence as note. ok is false for anything else: an open
// finding a scan confirmed, or a closed one, is never touched.
func (f Finding) AutoResolve(note string, now time.Time) (Finding, HistoryEntry, bool) {
	if f.Status != StatusSuspected || f.Basis == BasisScan {
		return f, HistoryEntry{}, false
	}
	note = clipRunes(note, MaxNote)
	f.Status, f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason, f.AcceptedUntil = StatusNotRelevant, SystemUser, now, note, ReasonNotAffectedVersion, time.Time{}
	return f, HistoryEntry{TS: now, User: SystemUser, Action: string(StatusNotRelevant), Note: note}, true
}

// reopenedByPerson reports whether a person reopened the finding after Vedette last closed it by itself (D-530,
// review M-b of #663): the person overruled the proof, so the matcher never closes it again. hist is oldest first.
func reopenedByPerson(hist []HistoryEntry) bool {
	reopened := false
	for i := len(hist) - 1; i >= 0; i-- {
		switch h := hist[i]; {
		case h.User == SystemUser && h.Action == string(StatusNotRelevant):
			return reopened
		case h.User != SystemUser && h.Action == "reopened":
			reopened = true
		}
	}
	return false
}

// ReopenOnMatch reopens a finding Vedette closed by itself when the matcher says the device matches again (D-530).
func (f Finding) ReopenOnMatch(now time.Time) (Finding, HistoryEntry, bool) {
	if !f.AutoResolved() {
		return f, HistoryEntry{}, false
	}
	f.Status, f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason = StatusSuspected, "", time.Time{}, "", ""
	return f, HistoryEntry{TS: now, User: SystemUser, Action: "matches_again",
		Note: "The device matches this entry again, so Vedette reopened it (it had closed it as not affected)."}, true
}

// clipRunes cuts s to at most n UTF-16 units (jsLen), on a character boundary.
func clipRunes(s string, n int) string {
	if jsLen(s) <= n {
		return s
	}
	out := []rune{}
	for _, r := range s {
		if jsLen(string(append(out, r))) > n-1 {
			break
		}
		out = append(out, r)
	}
	return string(out) + "…"
}

// HistoryEntry is one append-only row of fnd_finding_history.
type HistoryEntry struct {
	TS     time.Time
	User   string
	Action string // created, confirmed, rescanned, rescan_clear, no_longer_matches, matches_again, reopened, patched, mitigated, false_positive, not_relevant, risk_accepted
	Note   string
}

// Validate checks INV-2: valid status and basis, confidence in [0,1], confirmed
// only with basis scan plus evidence (template and checked_at), suspected only
// with basis version or product.
func (f Finding) Validate() error {
	if !f.Status.valid() {
		return fmt.Errorf("findings: validating finding: unknown status %q", f.Status)
	}
	if rank(f.Basis) == 0 {
		return fmt.Errorf("findings: validating finding: unknown basis %q", f.Basis)
	}
	if math.IsNaN(f.Confidence) || f.Confidence < 0 || f.Confidence > 1 {
		return fmt.Errorf("findings: validating finding: confidence %v outside [0,1]", f.Confidence)
	}
	if f.Status == StatusConfirmed {
		if f.Basis != BasisScan || f.Evidence == nil || f.Evidence.Template == "" || f.Evidence.CheckedAt.IsZero() {
			return fmt.Errorf("findings: validating finding: confirmed needs basis scan and evidence with template and checked_at")
		}
	}
	if f.Status == StatusSuspected && f.Basis == BasisScan {
		return fmt.Errorf("findings: validating finding: suspected cannot have basis scan")
	}
	if (f.Status == StatusRiskAccepted) == f.AcceptedUntil.IsZero() {
		return fmt.Errorf("findings: validating finding: an until date goes with risk_accepted and only with it")
	}
	return nil
}

// NewFinding builds the finding for a match: suspected, with the matcher's
// basis, confidence, severity and evidence, plus its "created" history row.
func NewFinding(m Match, now time.Time) (Finding, HistoryEntry) {
	ev := m.Evidence
	if ev.CheckedAt.IsZero() {
		ev.CheckedAt = now
	}
	note := "Matched product " + m.SoftwareDisplay
	if m.Basis == BasisVersion {
		note = "Matched version of " + m.SoftwareDisplay
	}
	return Finding{Status: StatusSuspected, Severity: m.Severity, Confidence: m.Confidence, Basis: m.Basis, Evidence: &ev},
		HistoryEntry{TS: now, User: SystemUser, Action: "created", Note: note}
}

// ApplyMatch merges a repeated match into an existing finding. Only an open
// finding changes; the basis never goes down, the status never changes and a
// closed finding is left alone. A stronger basis (product to version) brings the
// match's evidence and severity when it is higher (review H2: a ransomware CVE
// first matched by product becomes critical once its NVD ranges arrive). A
// finding matched by product only takes the matcher's product severity (medium,
// D-500) when it was graded higher before that rule (walk 3 W3-3): once, since
// it then equals the match.
func (f Finding) ApplyMatch(m Match) Finding {
	if !f.Status.Open() {
		return f
	}
	switch {
	case rank(m.Basis) > rank(f.Basis):
		ev := m.Evidence
		f.Basis, f.Evidence = m.Basis, &ev
		f.Confidence = math.Max(f.Confidence, m.Confidence)
		if sevRank(m.Severity) > sevRank(f.Severity) {
			f.Severity = m.Severity
		}
	case f.Basis == BasisProduct && m.Basis == BasisProduct && m.Severity != "" && sevRank(f.Severity) > sevRank(m.Severity):
		f.Severity = m.Severity
	}
	return f
}

// sevRank orders severities (unknown values lowest).
func sevRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// Apply performs a status action by a person (INV-3). Checks run in the order
// the API reports them: action, note length, note required, until, already open. On
// error the finding is unchanged. The note is trimmed and measured like the GUI
// does (JavaScript trim and UTF-16 length). accept_risk needs a date: use AcceptRisk.
func (f Finding) Apply(action Action, note, user string, now time.Time) (Finding, HistoryEntry, error) {
	return f.apply(action, note, user, time.Time{}, now)
}

// AcceptRisk closes the finding as risk_accepted until the end of the UTC day until (D-498): a note of at least
// MinReasonNote and a day from tomorrow to MaxAcceptDays ahead, with one day of slack on each side so a person's local
// "tomorrow" and "a year from today" always pass (ErrBadUntil otherwise).
func (f Finding) AcceptRisk(note, user string, until, now time.Time) (Finding, HistoryEntry, error) {
	return f.apply(ActionAcceptRisk, note, user, until, now)
}

// ValidUntil checks the until day of accept_risk against now (D-498): it must be set only with accept_risk, and fall
// between today and MaxAcceptDays+1 days ahead in UTC (tomorrow and MaxAcceptDays in any time zone).
func ValidUntil(action Action, until, now time.Time) error {
	if action != ActionAcceptRisk {
		if !until.IsZero() {
			return fmt.Errorf("findings: applying action %q with a date: %w", action, ErrBadUntil)
		}
		return nil
	}
	today := dayOf(now)
	if until.IsZero() || !until.Equal(dayOf(until)) || until.Before(today) || until.After(today.AddDate(0, 0, MaxAcceptDays+1)) {
		return fmt.Errorf("findings: accepting the risk until %s: %w", until.Format(time.DateOnly), ErrBadUntil)
	}
	return nil
}

func (f Finding) apply(action Action, note, user string, until, now time.Time) (Finding, HistoryEntry, error) {
	switch action {
	case ActionPatched, ActionMitigated, ActionFalsePositive, ActionNotRelevant, ActionReopen, ActionAcceptRisk:
	default:
		return f, HistoryEntry{}, fmt.Errorf("findings: applying action %q: %w", action, ErrBadAction)
	}
	note = jsTrim(note)
	n := jsLen(note)
	if n > MaxNote {
		return f, HistoryEntry{}, fmt.Errorf("findings: applying action %q: %w", action, ErrNoteTooLong)
	}
	if (action == ActionFalsePositive || action == ActionNotRelevant || action == ActionAcceptRisk) && n < MinReasonNote {
		return f, HistoryEntry{}, fmt.Errorf("findings: applying action %q: %w", action, ErrNoteRequired)
	}
	if err := ValidUntil(action, until, now); err != nil {
		return f, HistoryEntry{}, err
	}
	if action == ActionReopen {
		if f.Status.Open() {
			return f, HistoryEntry{}, fmt.Errorf("findings: applying action %q: %w", action, ErrAlreadyOpen)
		}
		f.Status = StatusSuspected
		if f.Basis == BasisScan {
			f.Status = StatusConfirmed
		}
		f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason, f.AcceptedUntil = "", time.Time{}, "", "", time.Time{}
		return f, HistoryEntry{TS: now, User: user, Action: "reopened", Note: note}, nil
	}
	f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason, f.AcceptedUntil = user, now, note, "", time.Time{}
	if action == ActionAcceptRisk {
		f.Status, f.AcceptedUntil = StatusRiskAccepted, until
		return f, HistoryEntry{TS: now, User: user, Action: string(StatusRiskAccepted), Note: note + " (until " + FmtDay(until) + ")"}, nil
	}
	f.Status = Status(action)
	return f, HistoryEntry{TS: now, User: user, Action: string(action), Note: note}, nil
}

// ScanOutcome is the result of a scan confirmation.
type ScanOutcome struct {
	Finding Finding
	History []HistoryEntry // 0 or 1 rows to append
	// Notify is true when findings.finding.status_changed must be emitted: the
	// status changed, or a person has to decide because the scan matched a
	// finding they closed (POST-2).
	Notify bool
}

// ConfirmFromScan applies a positive scan result (PRE-2: evidence has a
// template and time). Oversized evidence fields are truncated with a marker, not
// rejected, so a real confirmation is never lost. Open findings become
// confirmed with basis scan and confidence at least ConfScan.
//
// false_positive, not_relevant and risk_accepted are never reopened by a scan. The first time a
// scan template matches such a finding, its evidence is recorded (basis scan, a
// "rescanned" row) and Notify is true so a person can decide; the same template
// again changes nothing and does not notify. patched and mitigated become
// confirmed again with a "reopened" row because the flaw is still there ([ĐX],
// DATA_MODEL 5.2). Nothing is ever closed here.
func (f Finding) ConfirmFromScan(ev Evidence, now time.Time) (ScanOutcome, error) {
	if ev.Template == "" || len(ev.Template) > maxTemplate || ev.CheckedAt.IsZero() || !isText(ev.Template, ev.Summary, ev.Request, ev.Response) {
		return ScanOutcome{Finding: f}, fmt.Errorf("findings: confirming from scan: %w", ErrInvalidEvidence)
	}
	ev.Summary, ev.Request, ev.Response = truncate(ev.Summary), truncate(ev.Request), truncate(ev.Response)
	was := f.Status
	auto := f.AutoResolved() // closed by Vedette, not a person (D-530): a scan reopens it like patched
	closedByPerson := (was == StatusFalsePositive || was == StatusNotRelevant || was == StatusRiskAccepted) && !auto
	if closedByPerson && f.Basis == BasisScan && f.Evidence != nil && f.Evidence.Template == ev.Template {
		return ScanOutcome{Finding: f}, nil // this match was already signalled
	}
	f.Basis = BasisScan
	f.Confidence = math.Max(f.Confidence, ConfScan)
	f.Evidence = &ev
	h := HistoryEntry{TS: now, User: SystemUser, Action: "confirmed", Note: ev.Template}
	switch {
	case closedByPerson:
		h.Action, h.Note = "rescanned", "scan: "+ev.Template+" (kept as "+string(was)+")"
		return ScanOutcome{Finding: f, History: []HistoryEntry{h}, Notify: true}, nil
	case was == StatusConfirmed:
		h.Action = "rescanned"
	case was == StatusPatched, was == StatusMitigated, auto:
		h.Action, h.Note = "reopened", "scan: "+ev.Template
	}
	f.Status = StatusConfirmed
	f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason, f.AcceptedUntil = "", time.Time{}, "", "", time.Time{}
	return ScanOutcome{Finding: f, History: []HistoryEntry{h}, Notify: was != StatusConfirmed}, nil
}

const truncMarker = "...[truncated]"

// truncate caps an evidence field at maxEvidenceField bytes (marker included),
// cutting on a character boundary.
func truncate(s string) string {
	if len(s) <= maxEvidenceField {
		return s
	}
	cut := maxEvidenceField - len(truncMarker)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncMarker
}

// jsLen counts UTF-16 code units, like JavaScript's String.length, so the Go
// service and the GUI agree on the note limits.
func jsLen(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r >= 0x10000 {
			n++
		}
	}
	return n
}

// jsTrim trims what JavaScript's String.trim trims.
func jsTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) && r != 0x85 || r == 0xFEFF })
}

// ScanClear records that a rescan no longer matches. It never changes the
// status: nothing closes without a person (FORBID-2).
func ScanClear(now time.Time) HistoryEntry {
	return HistoryEntry{TS: now, User: SystemUser, Action: "rescan_clear"}
}

// isText reports whether every string is valid UTF-8 without NUL. Scan evidence comes from a probe's
// reply, so it is untrusted; SQLite JSON and the audit log both refuse such bytes.
func isText(ss ...string) bool {
	for _, s := range ss {
		if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
			return false
		}
	}
	return true
}
