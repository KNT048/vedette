package findings

import (
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/orgtime"
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
	// StatusRiskAccepted is closed by a person until Finding.AcceptedUntil; it reopens by itself after that day.
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
	// ActionAcceptRisk needs a note and an until date (Finding.AcceptRisk).
	ActionAcceptRisk Action = "accept_risk"
)

const (
	// MaxNote is the longest note, counted in UTF-16 code units like the GUI.
	MaxNote = 500
	// MinReasonNote is the shortest note for false_positive, not_relevant and accept_risk.
	MinReasonNote = 3
	// MaxAcceptDays is how far ahead a risk can be accepted.
	MaxAcceptDays = 365
	// SystemUser is the history user for automatic events.
	SystemUser = "system"

	maxHistoryNote   = 600 // the length of fnd_finding_history.note
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
	// ResolutionReason is set only when Vedette closed the finding by itself: ReasonNotAffectedVersion. A
	// person's action, a reopen or a scan clears it.
	ResolutionReason string
	// SoftwareID is the device's software row the matcher matched the finding on ("" until a match reaches it). ProvedVersion is, for a
	// finding closed by proof (ReasonNotAffectedVersion), the version or package release the matcher compared; "" for a closure that
	// compared none (name only, age, platform question, another platform).
	SoftwareID, ProvedVersion string
	// AcceptedUntil is the last day (00:00 UTC) of a risk acceptance; set only while the status is risk_accepted.
	AcceptedUntil time.Time
}

// ReasonRiskExpired is the StatusChangedEvent reason of a finding whose risk acceptance ran out (INV-13).
const ReasonRiskExpired = "acceptance_expired"

// AcceptanceEnds is when a risk accepted until the day until ends: once that day is over everywhere on Earth, at its end
// in UTC-12, which is the next day at 12:00 UTC. It is never early for anyone and at most about a day late for UTC+14.
func AcceptanceEnds(until time.Time) time.Time {
	return dayOf(until).AddDate(0, 0, 1).Add(12 * time.Hour)
}

// dayOf is the UTC day of t, at 00:00.
func dayOf(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// ActionConfirmUndone is the history action of Undo: it is not a person's reopen decision, so the matcher may close the finding
// again when the version proves it not affected.
const ActionConfirmUndone = "confirm_undone"

// Confirmed reports whether the finding rests on evidence the matcher never takes back: a scan's, or a person's.
func (f Finding) Confirmed() bool { return f.Basis == BasisScan || f.Basis == BasisPerson }

// ByDevice reports whether the finding is a version match on a version the device itself stated (its SNMP answer or its own
// agent) inside an affected range with an end (Evidence.Source): confirmed while that holds. Unlike Confirmed, the matcher re-judges
// it at every match: it goes back to suspected, or closes, when the stated version leaves the range.
func (f Finding) ByDevice() bool { return f.Basis == BasisVersion && f.Evidence.deviceStated() }

// ShownConfidence is the confidence every reader is given (the API's lists, page and export, the AI context, MCP): a finding
// whose evidence confirms it, a scan's or a person's (Confirmed) or the version the device itself reports (ByDevice), is never
// shown below a scan's confirmation (ConfScan), whatever its status (a confirmed finding later risk-accepted or mitigated
// keeps it); any other finding shows the stored value. The stored Confidence is not raised to ConfScan: when a person's
// confirmation is undone it shows what ConfirmByPerson left (at least ConfVersion), and when the device no longer reports an
// affected version, the match's value.
func (f Finding) ShownConfidence() float64 {
	// an open ByDevice finding is confirmed (SettleByDevice); a suspected one still carrying the device's evidence is not yet
	if f.Status == StatusConfirmed || f.Confirmed() || f.ByDevice() && f.Status != StatusSuspected {
		return math.Max(f.Confidence, ConfScan)
	}
	return f.Confidence
}

// OpenStatus is the open status the finding has when it is reopened: confirmed with a scan or person basis or a version the device
// stated, else suspected.
func (f Finding) OpenStatus() Status {
	if f.Confirmed() || f.ByDevice() {
		return StatusConfirmed
	}
	return StatusSuspected
}

// DeviceConfirmedNote is the history note of a finding the version the device reports confirmed (ByDevice); DeviceUnconfirmedNote
// that of one it no longer confirms.
const (
	DeviceConfirmedNote   = "Confirmed by the version the device reports."
	DeviceUnconfirmedNote = "The device no longer reports a version inside the affected range, so this is suspected again."
)

// SettleByDevice gives an open finding that rests on the matcher alone (basis version or product) the status its evidence gives:
// confirmed when the device itself stated a version inside the range (ByDevice), else suspected. A scan's or a person's confirmation
// and a closed finding are never touched. ok says the status changed; h is its history row by the system user: "confirmed" with
// DeviceConfirmedNote, or "confirm_undone" with DeviceUnconfirmedNote.
func (f Finding) SettleByDevice(now time.Time) (Finding, HistoryEntry, bool) {
	if !f.Status.Open() || f.Confirmed() {
		return f, HistoryEntry{}, false
	}
	to := f.OpenStatus()
	if to == f.Status {
		return f, HistoryEntry{}, false
	}
	f.Status = to
	if to == StatusConfirmed {
		f.Confidence = math.Max(f.Confidence, ConfVersion)
		return f, HistoryEntry{TS: now, User: SystemUser, Action: "confirmed", Note: DeviceConfirmedNote}, true
	}
	return f, HistoryEntry{TS: now, User: SystemUser, Action: ActionConfirmUndone, Note: DeviceUnconfirmedNote}, true
}

// ExpireAcceptance reopens a risk_accepted finding once AcceptanceEnds(its last day) (INV-13): to the open status a
// fresh match would give (confirmed with a scan basis, else suspected), with a history row by the system user that names
// who accepted it and until when. ok is false for anything else.
func (f Finding) ExpireAcceptance(now time.Time) (Finding, HistoryEntry, bool) {
	if f.Status != StatusRiskAccepted || now.Before(AcceptanceEnds(f.AcceptedUntil)) {
		return f, HistoryEntry{}, false
	}
	note := "Risk acceptance expired (accepted by " + f.ResolvedBy + " until " + orgtime.CalendarDay(f.AcceptedUntil) + ")."
	f.Status = f.OpenStatus()
	f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason, f.AcceptedUntil = "", time.Time{}, "", "", time.Time{}
	return f, HistoryEntry{TS: now, User: SystemUser, Action: "reopened", Note: note}, true
}

// ReasonNotAffectedVersion closes a suspected finding whose version the matcher proved outside every range.
const ReasonNotAffectedVersion = "not_affected_version"

// AutoResolved reports whether Vedette closed the finding by itself: only such a finding reopens on a match.
func (f Finding) AutoResolved() bool {
	return f.Status == StatusNotRelevant && f.ResolutionReason == ReasonNotAffectedVersion
}

// AutoResolve closes an open finding that the matcher proved not affected (the version is outside every range, or the software is
// not installed): a suspected one (basis version or product), one the version the device reports confirmed (ByDevice: a newer stated
// version takes it back), or one a person confirmed (basis person): a person's confirm only keeps the matcher from taking it back to
// suspected, it never outranks a newer version. A scan's confirmation is never closed here. It is closed not_relevant by the system
// user, with the matcher's sentence as note. ok is false for anything else: an open finding a scan confirmed, or a closed one, is
// never touched.
func (f Finding) AutoResolve(note string, now time.Time) (Finding, HistoryEntry, bool) {
	if !f.Status.Open() || f.Basis == BasisScan {
		return f, HistoryEntry{}, false
	}
	note = clipNote(note)
	f.Status, f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason, f.AcceptedUntil = StatusNotRelevant, SystemUser, now, note, ReasonNotAffectedVersion, time.Time{}
	f.ProvedVersion = ""
	return f, HistoryEntry{TS: now, User: SystemUser, Action: string(StatusNotRelevant), Note: note}, true
}

// ReasonFixedByUpdate is the resolution reason (and StatusChangedEvent reason) of a finding Vedette closed as patched because a later
// reading of the same software on the device has a version outside every affected range: the device got an update (FixedByUpdate).
const ReasonFixedByUpdate = "fixed_by_update"

// FixedByUpdateNote starts the note of a finding closed by FixedByUpdate.
const FixedByUpdateNote = "Fixed by an update:"

// PatchedByUpdate reports whether Vedette closed the finding as patched because the device's version moved out of the affected range.
// Like AutoResolved, only such a patched finding reopens on a match (the version went back into the range).
func (f Finding) PatchedByUpdate() bool {
	return f.Status == StatusPatched && f.ResolutionReason == ReasonFixedByUpdate
}

// FixedByUpdate closes an open finding the way AutoResolve does, but as patched: a version match whose software a later reading shows
// at a version outside every range (the caller decides that, fixedByUpdate). Status patched by the system user, reason
// ReasonFixedByUpdate, note the "Fixed by an update: …" sentence. ok is false for what AutoResolve leaves alone.
func (f Finding) FixedByUpdate(note string, now time.Time) (Finding, HistoryEntry, bool) {
	if !f.Status.Open() || f.Basis == BasisScan {
		return f, HistoryEntry{}, false
	}
	note = clipNote(note)
	f.Status, f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason, f.AcceptedUntil = StatusPatched, SystemUser, now, note, ReasonFixedByUpdate, time.Time{}
	f.ProvedVersion = ""
	return f, HistoryEntry{TS: now, User: SystemUser, Action: string(StatusPatched), Note: note}, true
}

// RelabelFixed turns a finding Vedette closed as not affected by a version proof (AutoResolved) into one patched by an update, for the
// one-time pass over findings closed before the rule existed (reclassifyPatched): status and reason change, the day it was closed
// stays (resolved_at: the day the update was seen), the note becomes the "Fixed by an update" sentence. ok is false for anything else.
func (f Finding) RelabelFixed(note string, now time.Time) (Finding, HistoryEntry, bool) {
	if !f.AutoResolved() || f.ResolvedBy != SystemUser {
		return f, HistoryEntry{}, false
	}
	note = clipNote(note)
	f.Status, f.ResolutionNote, f.ResolutionReason = StatusPatched, note, ReasonFixedByUpdate
	return f, HistoryEntry{TS: now, User: SystemUser, Action: string(StatusPatched), Note: note}, true
}

// SettleAsked gives a finding Vedette closed while waiting for a person's answer (AskedNote) the reason the answer proved:
// same status, the proof as its note and a history row. ok is false for any other finding.
func (f Finding) SettleAsked(note string, now time.Time) (Finding, HistoryEntry, bool) {
	if !f.AutoResolved() || f.ResolvedBy != SystemUser || !strings.HasPrefix(f.ResolutionNote, AskedNote) {
		return f, HistoryEntry{}, false
	}
	note = clipNote(note)
	f.ResolvedAt, f.ResolutionNote = now, note
	return f, HistoryEntry{TS: now, User: SystemUser, Action: string(StatusNotRelevant), Note: note}, true
}

// reopenedByPerson reports whether a person reopened the finding after Vedette last closed it by itself
// (#663): the person overruled the proof, so the matcher never closes it again. hist is oldest first.
func reopenedByPerson(hist []HistoryEntry) bool {
	reopened := false
	for i := len(hist) - 1; i >= 0; i-- {
		switch h := hist[i]; {
		case h.User == SystemUser && (h.Action == string(StatusNotRelevant) && !strings.HasPrefix(h.Note, IgnoredNote) || // the close of an ignored device is no proof
			h.Action == string(StatusPatched) && strings.HasPrefix(h.Note, FixedByUpdateNote)):
			return reopened
		case h.User != SystemUser && h.Action == "reopened":
			reopened = true
		}
	}
	return false
}

// ReopenOnMatch reopens a finding Vedette closed by itself when the matcher says the device matches again.
func (f Finding) ReopenOnMatch(now time.Time) (Finding, HistoryEntry, bool) {
	if !f.AutoResolved() && !f.PatchedByUpdate() {
		return f, HistoryEntry{}, false
	}
	note := "The device matches this entry again, so Vedette reopened it (it had closed it as not affected)."
	if f.PatchedByUpdate() { // the version went back inside the range: a rollback, or a reading of another install
		note = "The device matches this entry again, so Vedette reopened it (it had marked it fixed by an update; the version it reports now is inside the affected range)."
	}
	if strings.HasPrefix(f.ResolutionNote, AgedNote) { // Closed for its age; whatever brought it back (a version, a template, a new date), say only that it matches
		note = "The device matches this entry again, so Vedette reopened it (it had closed it as older than 12 months and matched by the product name only)."
	}
	if strings.HasPrefix(f.ResolutionNote, NameOnlyNote) { // Closed for want of version evidence; a later match compared one
		note = "The device matches this entry again, so Vedette reopened it (it had closed it because only the product name matched)."
	}
	if strings.HasPrefix(f.ResolutionNote, AskedNote) { // The answer says the device is affected
		note = "The answer about the device's system or package release says it is affected, so Vedette reopened it."
	}
	if strings.HasPrefix(f.ResolutionNote, NotInstalledNote) { // INV-6c: the person cleared "Not installed", or the source reads a new install
		note = "The device matches this entry again, so Vedette reopened it (it had closed it because a person said the software is not installed)."
	}
	f.Status, f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason = f.OpenStatus(), "", time.Time{}, "", ""
	return f, HistoryEntry{TS: now, User: SystemUser, Action: "matches_again", Note: note}, true
}

// IgnoredNote starts the note of an open finding Vedette closed because a person ignored its device (inventory INV-38).
// With status not_relevant, resolved_by system and no resolution reason it marks the findings Stop ignoring reopens: no other
// close writes it (a person's close has the person in resolved_by, Vedette's own proof has a reason).
const IgnoredNote = "Closed by Vedette: the device was ignored"

// ReasonDeviceIgnored and ReasonDeviceWatched are the StatusChangedEvent reasons of IgnoreClose and UnignoreReopen: notify
// sends nothing for either (a person just acted on the device).
const (
	ReasonDeviceIgnored = "device_ignored"
	ReasonDeviceWatched = "device_watched"
)

// ClosedForIgnore reports whether the finding is one IgnoreClose closed and nobody has touched since.
func (f Finding) ClosedForIgnore() bool {
	return f.Status == StatusNotRelevant && f.ResolvedBy == SystemUser && f.ResolutionReason == "" && strings.HasPrefix(f.ResolutionNote, IgnoredNote)
}

// IgnoreClose closes an open finding (suspected or confirmed) of a device a person ignored: not_relevant by the system
// user, the note naming the person. ok is false for a finding that is already closed: what a person settled (patched, mitigated,
// false positive, not relevant, risk accepted) and Vedette's own closes keep their status.
func (f Finding) IgnoreClose(by string, now time.Time) (Finding, HistoryEntry, bool) {
	if !f.Status.Open() {
		return f, HistoryEntry{}, false
	}
	note := IgnoredNote + "."
	if by != "" {
		note = clipNote(IgnoredNote + " by " + by + ".")
	}
	f.Status, f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason, f.AcceptedUntil = StatusNotRelevant, SystemUser, now, note, "", time.Time{}
	return f, HistoryEntry{TS: now, User: SystemUser, Action: string(StatusNotRelevant), Note: note}, true
}

// UnignoreReopen reopens a finding IgnoreClose closed, once a person stops ignoring the device: to the open status a fresh
// match would give (confirmed with a scan basis, else suspected), then the device is matched again as usual. ok is false for any
// other finding, so nothing a person decided is reopened.
func (f Finding) UnignoreReopen(by string, now time.Time) (Finding, HistoryEntry, bool) {
	if !f.ClosedForIgnore() {
		return f, HistoryEntry{}, false
	}
	note := "The device is watched again, so Vedette reopened this finding it had closed when the device was ignored."
	if by != "" {
		note = clipNote("The device is watched again (" + by + " stopped ignoring it), so Vedette reopened this finding it had closed when the device was ignored.")
	}
	f.Status = f.OpenStatus()
	f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason, f.AcceptedUntil = "", time.Time{}, "", "", time.Time{}
	return f, HistoryEntry{TS: now, User: SystemUser, Action: "reopened", Note: note}, true
}

// clipNote cuts a note to at most MaxNote UTF-16 units (jsLen), on a character boundary.
func clipNote(s string) string {
	n := MaxNote
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
	Action string // created, confirmed, confirm_undone, rescanned, rescan_clear, no_longer_matches, matches_again, reopened, patched, mitigated, false_positive, not_relevant, risk_accepted
	Note   string
}

// Validate checks INV-2: valid status and basis, confidence in [0,1], confirmed
// only with basis scan plus evidence (template and checked_at), basis person, or basis version on a version the device
// stated (ByDevice); suspected only with basis version or product.
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
		switch {
		case f.Basis == BasisPerson && f.Evidence != nil:
		case f.ByDevice():
		case f.Basis != BasisScan || f.Evidence == nil || f.Evidence.Template == "" || f.Evidence.CheckedAt.IsZero():
			return fmt.Errorf("findings: validating finding: confirmed needs basis scan (evidence with template and checked_at), basis person, or basis version on a version the device stated")
		}
	}
	if f.Status == StatusSuspected && f.Confirmed() {
		return fmt.Errorf("findings: validating finding: suspected cannot have basis %s", f.Basis)
	}
	if (f.Status == StatusRiskAccepted) == f.AcceptedUntil.IsZero() {
		return fmt.Errorf("findings: validating finding: an until date goes with risk_accepted and only with it")
	}
	return nil
}

// NewFinding builds the finding for a match: suspected, or confirmed when the device itself stated the version (ByDevice; the
// caller adds the "confirmed" row, SettleByDevice's), with the matcher's basis, confidence, severity and evidence, plus its
// "created" history row.
func NewFinding(m Match, now time.Time) (Finding, HistoryEntry) {
	ev := m.Evidence
	if ev.CheckedAt.IsZero() {
		ev.CheckedAt = now
	}
	note := "Matched product " + m.SoftwareDisplay
	if m.Basis == BasisVersion {
		note = "Matched version of " + m.SoftwareDisplay
	}
	f := Finding{Status: StatusSuspected, Severity: m.Severity, Confidence: m.Confidence, Basis: m.Basis, Evidence: &ev, SoftwareID: m.SoftwareID}
	f.Status = f.OpenStatus()
	return f, HistoryEntry{TS: now, User: SystemUser, Action: "created", Note: note}
}

// ApplyMatch merges a repeated match into an existing finding. Only an open
// finding changes; the basis never goes down, the status never changes (SettleByDevice
// then re-judges a finding the device's stated version confirms) and a
// closed finding is left alone. A stronger basis (product to version) brings the
// match's evidence and severity when it is higher (a ransomware CVE
// first matched by product becomes critical once its NVD ranges arrive). A
// finding matched by product only takes the matcher's product severity (medium)
// when it was graded higher before that rule: once, since
// it then equals the match. A match of the same basis (version or product, never
// scan, whose evidence is the template's) brings its evidence: the sentence
// says what the device runs now and in today's words (an agent row's
// finding written before says "only suspected" until then). A finding the agent
// detected whose new match is not the agent's takes the new sentence (no basis change).
func (f Finding) ApplyMatch(m Match) Finding {
	if m.SoftwareID != "" {
		f.SoftwareID = m.SoftwareID // whatever the status: where the finding rests, not its state
	}
	if !f.Status.Open() {
		return f
	}
	switch {
	case m.Basis == f.Basis && !f.Confirmed() && m.Evidence.Summary != "":
		ev := m.Evidence
		f.Evidence = &ev
	case !f.Confirmed() && f.Evidence != nil && (f.Evidence.Agent && !m.Evidence.Agent || f.Evidence.deviceStated() && !m.Evidence.deviceStated()) &&
		m.Evidence.Summary != "" && rank(m.Basis) <= rank(f.Basis):
		// The agent's row (or the device's stated version) is gone or no longer decides it: drop "Detected by the agent" and the
		// device's confirmation, and take the sentence of what matches now; the basis never goes down.
		ev := m.Evidence
		ev.AgentRow = ev.AgentRow && f.Basis == BasisProduct // It says what a product-only finding is; a version finding stays one (#801)
		f.Evidence = &ev
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

// AcceptRisk closes the finding as risk_accepted until the end of the UTC day until: a note of at least
// MinReasonNote and a day from tomorrow to MaxAcceptDays ahead, with one day of slack on each side so a person's local
// "tomorrow" and "a year from today" always pass (ErrBadUntil otherwise).
func (f Finding) AcceptRisk(note, user string, until, now time.Time) (Finding, HistoryEntry, error) {
	return f.apply(ActionAcceptRisk, note, user, until, now)
}

// ValidUntil checks the until day of accept_risk against now: it must be set only with accept_risk, and fall
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
		f.Status = f.OpenStatus()
		f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason, f.AcceptedUntil = "", time.Time{}, "", "", time.Time{}
		return f, HistoryEntry{TS: now, User: user, Action: "reopened", Note: note}, nil
	}
	f.ResolvedBy, f.ResolvedAt, f.ResolutionNote, f.ResolutionReason, f.AcceptedUntil = user, now, note, "", time.Time{}
	if action == ActionAcceptRisk {
		f.Status, f.AcceptedUntil = StatusRiskAccepted, until
		return f, HistoryEntry{TS: now, User: user, Action: string(StatusRiskAccepted), Note: note + " (until " + orgtime.CalendarDay(until) + ")"}, nil
	}
	f.Status = Status(action)
	return f, HistoryEntry{TS: now, User: user, Action: string(action), Note: note}, nil
}

// ConfirmByPerson confirms a suspected finding on a person's word (INV-2): status confirmed, basis person, the version
// evidence kept as it is (Evidence.Prior remembers the basis for Undo), a history row "Confirmed by <user>: <note>". The note is
// required (MinReasonNote). Anything but a suspected finding is refused (ErrNotSuspected), a scan's confirmation included.
func (f Finding) ConfirmByPerson(note, user string, now time.Time) (Finding, HistoryEntry, error) {
	note = jsTrim(note)
	n := jsLen(note)
	switch {
	case f.Status != StatusSuspected:
		return f, HistoryEntry{}, fmt.Errorf("findings: confirming a %s finding: %w", f.Status, ErrNotSuspected)
	case n > MaxNote:
		return f, HistoryEntry{}, fmt.Errorf("findings: confirming: %w", ErrNoteTooLong)
	case n < MinReasonNote:
		return f, HistoryEntry{}, fmt.Errorf("findings: confirming: %w", ErrConfirmNoteRequired)
	}
	ev := Evidence{CheckedAt: now}
	if f.Evidence != nil {
		ev = *f.Evidence
	}
	ev.Prior = f.Basis
	f.Status, f.Basis, f.Evidence = StatusConfirmed, BasisPerson, &ev
	f.Confidence = math.Max(f.Confidence, ConfVersion)
	line := "Confirmed by " + user + ": "
	if room := maxHistoryNote - utf8.RuneCountInString(line); utf8.RuneCountInString(note) > room { // a very long address leaves less room in the column
		note = string([]rune(note)[:max(room, 0)])
	}
	return f, HistoryEntry{TS: now, User: user, Action: "confirmed", Note: line + note}, nil
}

// UnconfirmByPerson is Undo: a finding a person confirmed (basis person, still confirmed) goes back to suspected with the basis it
// had, a history row "reopened" by the person. Anything else is refused (ErrNotConfirmedByHand): a scan's proof is not undone.
func (f Finding) UnconfirmByPerson(user string, now time.Time) (Finding, HistoryEntry, error) {
	if f.Status != StatusConfirmed || f.Basis != BasisPerson {
		return f, HistoryEntry{}, fmt.Errorf("findings: undoing a confirmation of a %s finding with basis %s: %w", f.Status, f.Basis, ErrNotConfirmedByHand)
	}
	prior := BasisVersion
	if f.Evidence != nil && (f.Evidence.Prior == BasisProduct || f.Evidence.Prior == BasisVersion) {
		prior = f.Evidence.Prior
	}
	ev := Evidence{CheckedAt: now}
	if f.Evidence != nil {
		ev = *f.Evidence
	}
	ev.Prior = ""
	f.Status, f.Basis, f.Evidence = StatusSuspected, prior, &ev
	return f, HistoryEntry{TS: now, User: user, Action: ActionConfirmUndone, Note: "Confirmation undone by " + user + ": back to suspected."}, nil
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
	auto := f.AutoResolved() // closed by Vedette, not a person: a scan reopens it like patched
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
