package findings

import (
	"fmt"
	"regexp"
	"time"
)

// The findings model: one row of fnd_finding per (device, CVE, software line) that was affected at some time, with three separate
// facts. Detection (Detected .. Evidence) says whether and how the current data shows the device affected; only the match pass and
// the safe checks write it. Handling (State .. ToVersion) says what was done about it, by whom and how; only Transition changes it.
// Urgency (Urgency, UrgencyAt) says why it matters now; only the urgency pass writes it.

// State is the structural state of a finding: open (it needs attention) or handled (a person or Vedette settled it).
type State string

// The states of a finding.
const (
	StateOpen    State = "open"
	StateHandled State = "handled"
)

// Resolution is how a handled finding was settled.
type Resolution string

// The resolutions of a handled finding.
const (
	ResolutionPatched       Resolution = "patched"        // the fixed version is installed, or the software is gone
	ResolutionMitigated     Resolution = "mitigated"      // a workaround is in place; the flaw is still in the software
	ResolutionAccepted      Resolution = "accepted"       // a person lives with it until AcceptedUntil
	ResolutionFalsePositive Resolution = "false_positive" // the match was wrong
	ResolutionNotRelevant   Resolution = "not_relevant"   // it does not apply to this device
)

// Resolutions lists every resolution, in the order the handle dialog offers them.
var Resolutions = []Resolution{ResolutionPatched, ResolutionMitigated, ResolutionAccepted, ResolutionNotRelevant, ResolutionFalsePositive}

// Valid reports whether r is one of the resolutions.
func (r Resolution) Valid() bool {
	switch r {
	case ResolutionPatched, ResolutionMitigated, ResolutionAccepted, ResolutionFalsePositive, ResolutionNotRelevant:
		return true
	}
	return false
}

// Via is how a finding was handled: by a person, or the way the flaw went away on its own. An open vocabulary (stored as text).
type Via string

// The ways a finding is handled.
const (
	ViaPerson Via = "person" // a person marked it
	// ViaVersionMoved: the software line moved past the affected version (FromVersion, ToVersion). Patch credit.
	ViaVersionMoved Via = "version_moved"
	// ViaSoftwareRemoved: the software line is gone from the device. Patch credit.
	ViaSoftwareRemoved Via = "software_removed"
	// ViaDistroFixed: the distribution now says the installed package release is fixed. Patch credit.
	ViaDistroFixed Via = "distro_fixed"
	// ViaScanClear: a safe check that had matched came back clear. Patch credit.
	ViaScanClear Via = "scan_clear"
	// ViaDataCorrected: no longer detected while nothing on the device changed (range data changed, a person corrected a wrong
	// version, a platform answer): Vedette corrected its match. Never patch credit.
	ViaDataCorrected Via = "data_corrected"
	// ViaNotInstalled: a person said the software is not installed on the device.
	ViaNotInstalled Via = "not_installed"
)

// Vias lists every way a finding is handled (the stored vocabulary; a test lists every value Transition writes).
var Vias = []Via{ViaPerson, ViaVersionMoved, ViaSoftwareRemoved, ViaDistroFixed, ViaScanClear, ViaDataCorrected, ViaNotInstalled}

// Valid reports whether v is one of the ways.
func (v Via) Valid() bool { return validWord(string(v)) && containsVia(v) }

func containsVia(v Via) bool {
	for _, x := range Vias {
		if x == v {
			return true
		}
	}
	return false
}

// Credit reports whether the way is patch credit: the flaw went away because something changed on the device.
func (v Via) Credit() bool {
	switch v {
	case ViaVersionMoved, ViaSoftwareRemoved, ViaDistroFixed, ViaScanClear:
		return true
	}
	return false
}

// Verified is how sure Vedette is that the device is affected.
type Verified string

// The verification levels, weakest first.
const (
	VerifiedNo     Verified = "no"     // not confirmed yet: a version read from a banner, a person's statement, a package list read by name
	VerifiedPerson Verified = "person" // a person confirmed it on their own word
	VerifiedDevice Verified = "device" // the device itself reports the affected version (its agent, its SNMP answer)
	VerifiedScan   Verified = "scan"   // a safe check confirmed it
)

func (v Verified) rank() int {
	switch v {
	case VerifiedPerson:
		return 1
	case VerifiedDevice:
		return 2
	case VerifiedScan:
		return 3
	}
	return 0
}

// Valid reports whether v is a verification level.
func (v Verified) Valid() bool { return v == VerifiedNo || v.rank() > 0 }

// sticky reports whether the level is a proof the match pass never takes back: a safe check's or a person's word. A device's own
// report is judged again at every match.
func (v Verified) sticky() bool { return v == VerifiedScan || v == VerifiedPerson }

// DetectionBasis is what a detection rests on (fnd_finding.basis). An open vocabulary.
type DetectionBasis string

// The bases of a detection.
const (
	DetectScan          DetectionBasis = "scan"           // a safe check
	DetectDeviceVersion DetectionBasis = "device_version" // a version the device itself reports (its agent, its SNMP answer)
	DetectPackage       DetectionBasis = "package"        // a distribution package release
	DetectBannerVersion DetectionBasis = "banner_version" // a version read from a network banner
	DetectStatement     DetectionBasis = "statement"      // a version a person typed for the device
	DetectPerson        DetectionBasis = "person"         // a person said it is affected
)

// DetectionBases lists every basis.
var DetectionBases = []DetectionBasis{DetectScan, DetectDeviceVersion, DetectPackage, DetectBannerVersion, DetectStatement, DetectPerson}

// Valid reports whether b is one of the bases.
func (b DetectionBasis) Valid() bool {
	for _, x := range DetectionBases {
		if x == b {
			return true
		}
	}
	return false
}

// The origins of the affected range a detection used (fnd_finding.range_origin). An open vocabulary.
const (
	RangeNVD    = "nvd"
	RangeCNA    = "cna"
	RangeADP    = "adp"
	RangeDistro = "distro"
	RangeScan   = "scan"
)

// FixKind is the kind of the fix of a finding. An open vocabulary.
type FixKind string

// The kinds of fix.
const (
	FixUpdate        FixKind = "update"         // install FixVersion of the software or later
	FixDistroUpdate  FixKind = "distro_update"  // install the distribution's package release FixVersion or later
	FixOSUpdate      FixKind = "os_update"      // install the operating system update FixRef (a KB) or build FixVersion
	FixFeatureUpdate FixKind = "feature_update" // no update of this release fixes it: move to release FixVersion
	FixNoneYet       FixKind = "none_yet"       // the vendor has no fix yet (FixRef: the advisory)
	FixUnknown       FixKind = "unknown"        // no fix data
)

// Announced is the one rule of what findings tells the alert path about: only a finding at an urgency above "update recommended" (a
// CVE on an exploited list until the urgency pass rates it). A finding of a CVE on no list is never announced, whatever creates or
// changes it: the match pass, a safe check, a person.
func Announced(f Finding) bool { return f.Urgency >= 1 && f.Urgency < UrgencyUpdate }

// joinsList reports whether a step makes an open finding announced that was not (its CVE joined an exploited list since the finding
// was made): the caller announces it once, as a new exploited match, and the step sends no other notice for it. A handled finding
// stays silent whatever its urgency.
func joinsList(before, after Finding) bool {
	return after.Open() && !Announced(before) && Announced(after)
}

// Fix is the fix of a finding as the match pass stores it.
type Fix struct {
	Kind    FixKind
	Version string // "" = none
	Ref     string // "" = none
}

// FixKey is the "By fix" group of a fix of product productKey: the same key on every device the same fix applies to; never empty.
func FixKey(productKey string, f Fix) string {
	k := f.Kind
	if k == "" {
		k = FixUnknown
	}
	if productKey == "" {
		productKey = "unknown"
	}
	return clipBytes(productKey+"|"+string(k)+"|"+f.Version, 400)
}

// Finding is one row of fnd_finding.
type Finding struct {
	ID, AssetID, CVE string
	SoftwareID       string // "" = NULL: a safe-check hit on a device with no line for the product

	// A. detection
	Detected       bool
	Basis          DetectionBasis
	Verified       Verified
	RangeOrigin    string
	MatchedVersion string // the version (or package release) the match compared; "" = none
	Fix            Fix
	FixKey         string
	Evidence       *Evidence // display only

	// B. handling
	State         State
	Resolution    Resolution // "" while open
	Via           Via        // "" while open
	ResolvedBy    string     // a person, or SystemUser
	ResolvedAt    time.Time
	Note          string
	AcceptedUntil time.Time // the last day (00:00 UTC) of an acceptance; zero otherwise
	FromVersion   string    // via version_moved
	ToVersion     string    // via version_moved

	// C. urgency
	Urgency   int // 1..5
	UrgencyAt time.Time

	FirstSeen, LastSeen, UpdatedAt time.Time
}

// Open reports whether the finding needs attention.
func (f Finding) Open() bool { return f.State == StateOpen }

// Confirmed reports whether the finding is confirmed (by the device, a safe check or a person).
func (f Finding) Confirmed() bool { return f.Verified != VerifiedNo && f.Verified != "" }

// Validate checks the invariants of one row (and the vocabularies): open exactly when no resolution; a handled
// row has a resolution, a way, who and when; accepted exactly with a last day; version_moved exactly with two different versions.
func (f Finding) Validate() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("findings: finding %s: "+format, append([]any{f.ID}, args...)...)
	}
	switch {
	case !f.Basis.Valid():
		return bad("unknown basis %q", f.Basis)
	case !f.Verified.Valid():
		return bad("unknown verification %q", f.Verified)
	case !validWord(f.RangeOrigin):
		return bad("bad range origin %q", f.RangeOrigin)
	case !validWord(string(f.Fix.Kind)):
		return bad("bad fix kind %q", f.Fix.Kind)
	case f.FixKey == "":
		return bad("no fix key")
	case f.Urgency < 1 || f.Urgency > 5:
		return bad("urgency %d outside 1..5", f.Urgency)
	}
	switch f.State {
	case StateOpen:
		if f.Resolution != "" || f.Via != "" || f.ResolvedBy != "" || !f.ResolvedAt.IsZero() {
			return bad("open with a handling")
		}
	case StateHandled:
		if !f.Resolution.Valid() || !f.Via.Valid() || f.ResolvedBy == "" || f.ResolvedAt.IsZero() {
			return bad("handled without resolution, way, who or when")
		}
	default:
		return bad("unknown state %q", f.State)
	}
	if (f.Resolution == ResolutionAccepted) == f.AcceptedUntil.IsZero() {
		return bad("a last day goes with accepted and only with it")
	}
	if moved := f.Via == ViaVersionMoved; moved != (f.FromVersion != "" && f.ToVersion != "" && f.FromVersion != f.ToVersion) ||
		!moved && (f.FromVersion != "" || f.ToVersion != "") {
		return bad("versions go with version_moved and only with it, and they differ")
	}
	return nil
}

// EventKind is the kind of a fnd_finding_event row. An open vocabulary.
type EventKind string

// The kinds of finding event.
const (
	EvCreated          EventKind = "created"
	EvConfirmed        EventKind = "confirmed"
	EvUnconfirmed      EventKind = "unconfirmed"
	EvHandled          EventKind = "handled"
	EvReopened         EventKind = "reopened"
	EvUrgencyChanged   EventKind = "urgency_changed"
	EvFixChanged       EventKind = "fix_changed"
	EvRedetected       EventKind = "redetected"
	EvNoLongerDetected EventKind = "no_longer_detected"
	EvAcceptanceExpire EventKind = "acceptance_expired"
)

// EventKinds lists every kind.
var EventKinds = []EventKind{EvCreated, EvConfirmed, EvUnconfirmed, EvHandled, EvReopened, EvUrgencyChanged, EvFixChanged, EvRedetected,
	EvNoLongerDetected, EvAcceptanceExpire}

// Why a finding is open again (EventDetail.Why of a reopened event).
const (
	WhyStillDetected     = "still_detected"     // a person marked it patched and a newer reading still shows the affected version
	WhyDetectedAgain     = "detected_again"     // it came back after Vedette closed it
	WhyAcceptanceExpired = "acceptance_expired" // the accepted risk reached its last day
	WhyPerson            = "person"             // a person reopened it
)

// Event is one row of fnd_finding_event.
type Event struct {
	ID        int64
	FindingID string
	TS        time.Time
	Actor     string // SystemUser or the person
	Kind      EventKind
	Detail    EventDetail
}

// EventDetail is the JSON of fnd_finding_event.detail: the structured facts of the change, for display.
type EventDetail struct {
	Resolution    Resolution `json:"resolution,omitempty"`
	Via           Via        `json:"via,omitempty"`
	Note          string     `json:"note,omitempty"`
	AcceptedUntil string     `json:"accepted_until,omitempty"` // YYYY-MM-DD
	FromVersion   string     `json:"from_version,omitempty"`
	ToVersion     string     `json:"to_version,omitempty"`
	Why           string     `json:"why,omitempty"`        // reopened: WhyStillDetected, WhyDetectedAgain, WhyAcceptanceExpired, WhyPerson
	ReadingAt     string     `json:"reading_at,omitempty"` // reopened still_detected: the time of the reading that still detects it
	Layer         int        `json:"layer,omitempty"`      // urgency_changed: the new layer
	From          string     `json:"from,omitempty"`       // confirmed, unconfirmed: the verification before; fix_changed: the fix key before
	To            string     `json:"to,omitempty"`         // confirmed, unconfirmed: the verification after; fix_changed: the fix key after
}

// QuestionKind is the kind of a fnd_question row. An open vocabulary.
type QuestionKind string

// The kinds of question.
const (
	QuestionVersionNeeded  QuestionKind = "version_needed"  // the software line has no version Vedette can read
	QuestionPlatform       QuestionKind = "platform"        // the CVE affects only some platforms and nothing says which this is
	QuestionPackageRelease QuestionKind = "package_release" // the distribution's package release decides
	QuestionNotComparable  QuestionKind = "not_comparable"  // the version cannot be compared with the affected ranges
	QuestionNoRangeData    QuestionKind = "no_range_data"   // the CVE names the product but gives no affected versions
)

// QuestionKinds lists every kind.
var QuestionKinds = []QuestionKind{QuestionVersionNeeded, QuestionPlatform, QuestionPackageRelease, QuestionNotComparable, QuestionNoRangeData}

// Question is one row of fnd_question.
type Question struct {
	ID, AssetID string
	SoftwareID  string // "" = none
	CVE         string // "" = it decides several CVEs (Cves of them)
	Kind        QuestionKind
	Detail      QuestionDetail
	Cves        int
	AskedAt     time.Time
	Answer      string // "" = not answered
	AnsweredBy  string
	AnsweredAt  time.Time
}

// QuestionDetail is the JSON of fnd_question.detail, for display.
type QuestionDetail struct {
	Software   string   `json:"software,omitempty"`    // the software line's name as the device page shows it
	Version    string   `json:"version,omitempty"`     // the version read, when there is one
	Source     string   `json:"source,omitempty"`      // who read it
	Reason     string   `json:"reason,omitempty"`      // the matcher's reason (UncheckedReason)
	NVDPending bool     `json:"nvd_pending,omitempty"` // no range data while NVD has not answered yet
	Choice     string   `json:"choice,omitempty"`      // a package release a person gave that is no release of the distribution
	CVEList    []string `json:"cve_list,omitempty"`    // version_needed: the CVEs that wait, worst first
}

// key is the question's identity on its device (the unique index).
func (q Question) key() string {
	return q.SoftwareID + "\x1f" + q.CVE + "\x1f" + string(q.Kind)
}

var wordRE = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

// validWord is the shape check of the open vocabularies.
func validWord(s string) bool { return wordRE.MatchString(s) }

// clipBytes cuts s to at most n bytes, on a character boundary.
func clipBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
