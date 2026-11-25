package findings

import (
	"math"
	"strings"
	"time"
)

// The older read model of a finding (Record, Status, HistoryEntry) and the older event payloads, projected from the findings model.
// The current endpoints, notify, the AI context, MCP, the reports and response still read them; each moves to findings.View as it is
// rebuilt, and this file goes with the last of them. Nothing here is stored: every value comes from a Finding and its events.

// Status is the older status of a finding: the state, resolution and verification in one word.
type Status string

// The older statuses. Confirmed and suspected are open.
const (
	StatusConfirmed     Status = "confirmed"
	StatusSuspected     Status = "suspected"
	StatusMitigated     Status = "mitigated"
	StatusPatched       Status = "patched"
	StatusFalsePositive Status = "false_positive"
	StatusNotRelevant   Status = "not_relevant"
	StatusRiskAccepted  Status = "risk_accepted"
)

// Open reports whether the status is an open one (confirmed, suspected).
func (s Status) Open() bool { return s == StatusConfirmed || s == StatusSuspected }

// LegacyStatus is the older status of f.
func LegacyStatus(f Finding) Status {
	switch {
	case f.State == StateOpen && f.Confirmed():
		return StatusConfirmed
	case f.State == StateOpen:
		return StatusSuspected
	case f.Resolution == ResolutionAccepted:
		return StatusRiskAccepted
	}
	return Status(f.Resolution)
}

// The older resolution reasons (Record.ResolutionReason): what Vedette closed by itself.
const (
	ReasonNotAffectedVersion = "not_affected_version" // no longer detected while nothing on the device changed
	ReasonFixedByUpdate      = "fixed_by_update"      // patched: the version moved, the software went, the distribution fixed it, a safe check came back clear
	ReasonRiskExpired        = "acceptance_expired"   // StatusChangedEvent: an accepted risk reached its last day
)

// HistoryEntry is one event as the older history shows it.
type HistoryEntry struct {
	TS     time.Time
	User   string
	Action string // created, confirmed, confirm_undone, no_longer_matches, matches_again, reopened, patched, mitigated, false_positive, not_relevant, risk_accepted, urgency_changed, fix_changed
	Note   string
}

// Record is a finding in the older read model.
type Record struct {
	ID, AssetID, CVE string
	Status           Status
	Severity         Severity // the CVSS band of the CVE (medium while it has no score)
	Confidence       float64
	Basis            Basis
	Evidence         *Evidence
	ResolvedBy       string
	ResolvedAt       time.Time
	ResolutionNote   string
	ResolutionReason string
	SoftwareID       string
	ProvedVersion    string    // via version_moved: the version installed now
	AcceptedUntil    time.Time // the last day of an accepted risk
	FirstSeen        time.Time
	LastSeen         time.Time
	History          []HistoryEntry
	Row              Finding // the finding itself
}

// ByDevice reports whether the version the device itself reports confirms the finding.
func (r Record) ByDevice() bool { return r.Row.Verified == VerifiedDevice }

// ShownConfidence is the confidence every older reader is given: a confirmed finding never below a safe check's.
func (r Record) ShownConfidence() float64 {
	if r.Row.Confirmed() {
		return math.Max(r.Confidence, ConfScan)
	}
	return r.Confidence
}

// record projects f and its events (oldest first) into the older read model; band is the CVSS band of the CVE ("" when none).
func record(f Finding, evs []Event, band Severity) Record {
	r := Record{ID: f.ID, AssetID: f.AssetID, CVE: f.CVE, Status: LegacyStatus(f), Severity: band, Evidence: f.Evidence,
		ResolvedBy: f.ResolvedBy, ResolvedAt: f.ResolvedAt, ResolutionNote: f.Note, SoftwareID: f.SoftwareID, AcceptedUntil: f.AcceptedUntil,
		FirstSeen: f.FirstSeen, LastSeen: f.LastSeen, Row: f}
	if r.Severity == "" { // not scored yet
		r.Severity = SeverityMedium
	}
	switch {
	case f.Verified == VerifiedScan || f.Basis == DetectScan:
		r.Basis, r.Confidence = BasisScan, ConfScan
	case f.Verified == VerifiedPerson && f.proofHolds(): // a person's own Confirm (not the version they entered: a version match)
		r.Basis, r.Confidence = BasisPerson, ConfVersion
	default:
		r.Basis, r.Confidence = BasisVersion, ConfVersion
	}
	if f.State == StateHandled && f.Via != ViaPerson {
		r.ResolutionReason = ReasonNotAffectedVersion
		if f.Via.Credit() {
			r.ResolutionReason = ReasonFixedByUpdate
		}
		if r.ResolutionNote == "" {
			r.ResolutionNote = handledSentence(f)
		}
	}
	r.ProvedVersion = f.ToVersion
	for _, e := range evs {
		r.History = append(r.History, historyEntry(e))
	}
	return r
}

// handledSentence says, from the stored fields, how Vedette handled a finding.
func handledSentence(f Finding) string {
	switch f.Via {
	case ViaVersionMoved:
		if f.ResolvedBy != "" && f.ResolvedBy != SystemUser { // a person changed the version they had entered
			return "Patched by " + f.ResolvedBy + ": version changed " + f.FromVersion + " → " + f.ToVersion + "."
		}
		return "Patched by Vedette: version moved " + f.FromVersion + " → " + f.ToVersion + "."
	case ViaSoftwareRemoved:
		return "Patched by Vedette: the software was removed."
	case ViaDistroFixed:
		return "Patched by Vedette: the distribution fixed the installed package."
	case ViaScanClear:
		return "Patched by Vedette: a safe check that had matched came back clear."
	case ViaNotInstalled:
		return "Not relevant: " + f.ResolvedBy + " said the software is not installed."
	case ViaDataCorrected:
		return "Not relevant: Vedette corrected its match; nothing on the device changed."
	}
	return ""
}

// historyEntry is one event in the older history vocabulary.
func historyEntry(e Event) HistoryEntry {
	h := HistoryEntry{TS: e.TS, User: e.Actor, Action: string(e.Kind), Note: e.Detail.Note}
	switch e.Kind {
	case EvUnconfirmed:
		h.Action = "confirm_undone"
	case EvHandled:
		h.Action = string(e.Detail.Resolution)
		if e.Detail.Resolution == ResolutionAccepted {
			h.Action = string(StatusRiskAccepted)
			h.Note += " (until " + e.Detail.AcceptedUntil + ")"
		}
		if e.Detail.Via != ViaPerson && h.Note == "" {
			h.Note = handledSentence(Finding{Via: e.Detail.Via, FromVersion: e.Detail.FromVersion, ToVersion: e.Detail.ToVersion, ResolvedBy: e.Actor})
		}
	case EvReopened:
		if e.Detail.Why == WhyDetectedAgain || e.Detail.Why == WhyStillDetected {
			h.Action = "matches_again"
		}
		if e.Detail.Why == WhyStillDetected {
			h.Note = "Still detected after it was marked patched (reading of " + e.Detail.ReadingAt + ")."
		}
		if e.Detail.Why == WhyDetectedAgain && e.Detail.By != "" {
			h.Note = "The version was set back by " + e.Detail.By + "."
		}
	case EvAcceptanceExpire:
		h.Action = "reopened"
		h.Note = "Risk acceptance expired (accepted by " + e.Detail.From + " until " + e.Detail.AcceptedUntil + ")."
	case EvNoLongerDetected:
		h.Action = "no_longer_matches"
	case EvRedetected:
		h.Action = "matches_again"
	case EvUrgencyChanged:
		if e.Detail.Layer >= UrgencyUnderAttack && e.Detail.Layer <= UrgencyUpdate {
			h.Note = "Now: " + StatusName(e.Detail.Layer) + "."
		}
	case EvFixChanged:
		h.Note = fixChangeNote(e.Detail.To)
	}
	return h
}

// fixChangeNote says the fix a fix_changed event moved to, from its fix key (FixKey: "<product>|<kind>|<version>"), in the words the
// fix is shown with elsewhere; "" when the key cannot be read.
func fixChangeNote(key string) string {
	parts := strings.Split(key, "|")
	if len(parts) < 3 {
		return ""
	}
	kind, version := FixKind(parts[len(parts)-2]), parts[len(parts)-1]
	switch {
	case kind == FixNoneYet:
		return "Now: no fix from the vendor yet."
	case version == "" || kind == FixUnknown:
		return "Now: Vedette's data names no fixed release."
	case kind == FixDistroUpdate:
		return "Now: install the distribution's package " + version + " or later."
	case kind == FixOSUpdate:
		return "Now: install the operating system update to build " + version + " or later."
	case kind == FixFeatureUpdate:
		return "Now: move to " + version + ", a release that has the fix."
	case kind == FixRestart: // the fixed kernel is installed already: nothing to install, the device must run it
		return "Now: restart the device to run the installed " + version + "."
	}
	return "Now: update to " + version + " or later."
}

// legacyEvent is the older status_changed payload of one transition, or ok false when the older status did not change and no person
// has to know. A safe check that confirms a finding a person closed as false positive, not relevant or accepted is told with From
// equal to To (someone has to decide).
func legacyEvent(before, after Finding, evs []Event) (StatusChangedEvent, bool) {
	from, to := LegacyStatus(before), LegacyStatus(after)
	e := StatusChangedEvent{FindingID: after.ID, From: from, To: to}
	for _, ev := range evs {
		switch {
		case ev.Kind == EvAcceptanceExpire:
			e.Reason, e.AcceptedBy, e.AcceptedUntil = ReasonRiskExpired, ev.Detail.From, ev.Detail.AcceptedUntil
		case ev.Kind == EvReopened && ev.Actor == SystemUser && ev.Detail.Why == WhyStillDetected:
			e.Reason = ReasonStillDetected
		case ev.Kind == EvReopened && ev.Actor == SystemUser:
			e.Reason = ReasonMatchesAgain
		case ev.Kind == EvHandled && ev.Detail.Via != ViaPerson && e.Reason == "":
			e.Reason = ReasonNotAffectedVersion
			if ev.Detail.Via.Credit() {
				e.Reason = ReasonFixedByUpdate
			}
		case ev.Kind == EvConfirmed && ev.Actor == SystemUser && after.Verified == VerifiedDevice && e.Reason == "":
			e.Reason = ReasonDeviceVersion
		}
	}
	if from != to {
		return e, true
	}
	scanned := after.Verified == VerifiedScan && before.Verified != VerifiedScan
	if scanned && after.State == StateHandled && after.Via == ViaPerson &&
		(after.Resolution == ResolutionFalsePositive || after.Resolution == ResolutionNotRelevant || after.Resolution == ResolutionAccepted) {
		return e, true
	}
	return e, false
}

// bandOf is the older severity of a CVSS score: its band.
func bandOf(c CVSS) Severity {
	switch {
	case c.Score >= 9:
		return SeverityCritical
	case c.Score >= 7:
		return SeverityHigh
	case c.Score >= 4:
		return SeverityMedium
	case c.Score > 0:
		return "low"
	}
	return "info"
}
