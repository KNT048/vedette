package findings

import (
	"fmt"
	"reflect"
	"time"
)

// TriggerKind is what happened to a finding.
type TriggerKind string

// The triggers of Transition.
const (
	// TrDetected: the match pass, or a safe check, detects the flaw on the finding's software line now (Trigger.Detection).
	TrDetected TriggerKind = "detected"
	// TrGone: the data no longer detects it (Trigger.Via says how it went away; FromVersion and ToVersion for version_moved).
	TrGone TriggerKind = "gone"
	// TrHandle: a person marks it handled (Trigger.Resolution, Note, Until for accepted).
	TrHandle TriggerKind = "handle"
	// TrReopen: a person opens a handled finding again (their handling was a mistake).
	TrReopen TriggerKind = "reopen"
	// TrVerify: a person confirms a finding that is not confirmed yet, on their own word (Trigger.Note says what makes them sure).
	TrVerify TriggerKind = "verify"
	// TrUnverify: a person takes back their own confirmation.
	TrUnverify TriggerKind = "unverify"
	// TrTick: time passes (an accepted risk reaches the end of its last day).
	TrTick TriggerKind = "tick"
	// TrUrgency: the urgency pass sets the layer (Trigger.Layer).
	TrUrgency TriggerKind = "urgency"
)

// TriggerKinds lists every trigger.
var TriggerKinds = []TriggerKind{TrDetected, TrGone, TrHandle, TrReopen, TrVerify, TrUnverify, TrTick, TrUrgency}

// Trigger is one input of Transition.
type Trigger struct {
	Kind TriggerKind
	At   time.Time // when it happened (the pass, the person's action, the clock)
	// Actor is the person of handle, reopen, verify and unverify, of gone via not_installed (who said the software is not
	// installed) and of gone via version_moved on a person's entry (who changed the version); "" means SystemUser.
	Actor string

	Detection Detection // TrDetected

	Via                    Via // TrGone
	FromVersion, ToVersion string
	// Corrected (TrGone, data_corrected): what the line reads now is a person's correction of what a source reads. It closes a finding
	// a person confirmed (a person's newer word about the device, like "not installed"); a safe check's proof still holds against it.
	Corrected bool

	Resolution Resolution // TrHandle
	Note       string     // TrHandle, TrReopen, TrVerify; TrGone: Vedette's reason from the match's proof (shown as the closing note)
	Until      time.Time  // TrHandle accepted: the last day

	Layer int // TrUrgency
}

// Detection is what the match pass, or a safe check, found for one (device, CVE, software line).
type Detection struct {
	SoftwareID     string // "" only for a safe-check hit on a device with no line for the product
	Basis          DetectionBasis
	Verified       Verified // what the data proves now: no, device or scan (never person)
	RangeOrigin    string
	MatchedVersion string
	ProductKey     string // the software line's product, for the fix key
	Fix            Fix
	Evidence       *Evidence
	// ReadAt is when the source read the version the match compared (zero: unknown). A finding a person marked patched reopens only
	// on a reading known to be newer than their mark.
	ReadAt time.Time
	// Urgency is the layer a new finding starts with until the urgency pass sets it (0: 5, update recommended).
	Urgency int
	// SetBy is the person whose version entry the match compared ("" for a source's reading): a finding a version move closed that
	// this detection opens on another version says who set the version back.
	SetBy string
}

// Transition is the one function that changes the handling of a finding. It is total: every finding (new: State
// "") and every trigger has a defined outcome, which is the finding after the trigger, the events to append (oldest first) and an
// error for a person's action that does not apply (the finding is then returned unchanged). The rules:
//
//   - detected on a new pair: created, open; confirmed too when the data proves it.
//   - detected on an existing finding: the detection columns follow the data, the basis is the newest detection's (a safe check's or a
//     person's confirmation stays as the proof, never taken back by a weaker one; a finding on no line takes the line it is found
//     on); a finding Vedette had closed opens again (detected_again), except that a banner or a person's statement does not overrule a
//     clear safe check; a finding a person marked patched opens again when a reading newer than their mark still detects it
//     (still_detected); mitigated, accepted, false positive and not relevant hold.
//   - gone (an edge: only a finding detected until now): an open finding is handled by Vedette, patched when something changed on
//     the device (version_moved, software_removed, distro_fixed, scan_clear), not relevant when only the data changed
//     (data_corrected) or a person said the software is not installed (not_installed). A mitigation or an accepted risk gives way to
//     patch credit (the flaw is gone). A person's patched, false positive and not relevant hold. A safe check's proof or a person's
//     confirmation is not undone by range data (data_corrected, distro_fixed, also a question the match asks instead), only by a
//     newer reading of the device or a person's "not installed" (a person's version correction also undoes a person's confirmation); a
//     clear safe check does not credit a flaw the device's own reading
//     still shows.
//   - handle, reopen, verify, unverify: a person's word, checked like the API reports it. Marking a finding the way Vedette already
//     closed it takes it over with the person's note, except Vedette's patch credit, which stays (the person's note is an event).
//   - tick: an accepted risk whose last day is over opens again while detected, else Vedette closes it as corrected.
//   - urgency: the layer, with an event when it changes.
func Transition(f Finding, t Trigger) (Finding, []Event, error) {
	if t.At.IsZero() {
		return f, nil, fmt.Errorf("findings: transition %s without a time", t.Kind)
	}
	now := t.At.UTC().Truncate(time.Millisecond)
	tr := transition{before: f, f: f, now: now, actor: t.Actor}
	if tr.actor == "" {
		tr.actor = SystemUser
	}
	var err error
	switch t.Kind {
	case TrDetected:
		err = tr.detected(t.Detection)
	case TrGone:
		err = tr.gone(t)
	case TrHandle:
		err = tr.handle(t)
	case TrReopen:
		err = tr.reopen(t)
	case TrVerify:
		err = tr.verify(t)
	case TrUnverify:
		err = tr.unverify()
	case TrTick:
		tr.tick()
	case TrUrgency:
		err = tr.urgency(t.Layer)
	default:
		err = fmt.Errorf("findings: unknown trigger %q", t.Kind)
	}
	if err != nil {
		return f, nil, err
	}
	if tr.f.State == "" { // nothing happened to a pair that has no row
		return f, nil, nil
	}
	if !sameFinding(f, tr.f) {
		tr.f.UpdatedAt = now
	}
	if err := tr.f.Validate(); err != nil {
		return f, nil, err
	}
	return tr.f, tr.events, nil
}

type transition struct {
	before, f Finding
	now       time.Time
	actor     string
	events    []Event
}

func (t *transition) emit(actor string, kind EventKind, d EventDetail) {
	t.events = append(t.events, Event{FindingID: t.f.ID, TS: t.now, Actor: actor, Kind: kind, Detail: d})
}

// open clears the handling.
func (t *transition) open() {
	f := &t.f
	f.State, f.Resolution, f.Via, f.ResolvedBy, f.ResolvedAt, f.Note, f.AcceptedUntil, f.FromVersion, f.ToVersion =
		StateOpen, "", "", "", time.Time{}, "", time.Time{}, "", ""
}

// close sets the handling.
func (t *transition) close(res Resolution, via Via, by, note string, until time.Time, from, to string) {
	f := &t.f
	f.State, f.Resolution, f.Via, f.ResolvedBy, f.ResolvedAt, f.Note, f.AcceptedUntil, f.FromVersion, f.ToVersion =
		StateHandled, res, via, by, t.now, note, until, from, to
	d := EventDetail{Resolution: res, Via: via, Note: note, FromVersion: from, ToVersion: to}
	if !until.IsZero() {
		d.AcceptedUntil = until.Format(time.DateOnly)
	}
	t.emit(by, EvHandled, d)
}

func (t *transition) detected(d Detection) error {
	if !d.Basis.Valid() || !d.Verified.Valid() || d.Verified == VerifiedPerson {
		return fmt.Errorf("findings: detection with basis %q and verification %q", d.Basis, d.Verified)
	}
	if d.RangeOrigin == "" {
		d.RangeOrigin = RangeNVD
	}
	if d.Fix.Kind == "" {
		d.Fix.Kind = FixUnknown
	}
	read := d.ReadAt.UTC().Truncate(time.Millisecond) // zero: not known, so never newer than a person's mark
	f := &t.f
	if f.State == "" { // a new pair
		f.SoftwareID = d.SoftwareID
		f.Detected, f.Basis, f.Verified, f.RangeOrigin, f.MatchedVersion, f.Fix, f.FixKey, f.Evidence =
			true, d.Basis, d.Verified, d.RangeOrigin, d.MatchedVersion, d.Fix, FixKey(d.ProductKey, d.Fix), d.Evidence
		f.Urgency, f.UrgencyAt = d.Urgency, t.now
		if f.Urgency < 1 || f.Urgency > 5 {
			f.Urgency = 5
		}
		f.FirstSeen, f.LastSeen = t.now, t.now
		t.open()
		t.emit(SystemUser, EvCreated, EventDetail{})
		if f.Confirmed() {
			t.emit(SystemUser, EvConfirmed, EventDetail{From: string(VerifiedNo), To: string(f.Verified)})
		}
		return nil
	}
	was := t.before
	if f.SoftwareID == "" && d.SoftwareID != "" {
		f.SoftwareID = d.SoftwareID // a finding on no line takes the line the flaw is now found on
	}
	// A safe check's or a person's confirmation is never taken back by weaker data; a stronger proof replaces it.
	// The basis is what the newest detection rests on; a safe check's or a person's confirmation stays as the proof, never as the
	// basis: it is evidence of the version it saw, and a newer reading of the device decides what follows.
	f.Basis = d.Basis
	if !was.Verified.sticky() || was.Verified.rank() <= d.Verified.rank() {
		f.Verified = d.Verified
	}
	f.RangeOrigin = d.RangeOrigin
	daily := t.now.Sub(was.LastSeen) >= lastSeenStep
	if daily || !sameEvidence(f.Evidence, d.Evidence) { // the times of the reading and of the check move with the daily step
		f.Evidence = d.Evidence
	}
	if d.MatchedVersion != "" || d.Basis != DetectScan { // a safe check that saw no version keeps the version matched before
		f.MatchedVersion = d.MatchedVersion
	}
	switch key := FixKey(d.ProductKey, d.Fix); {
	case d.ProductKey == "" && d.Fix == Fix{Kind: FixUnknown}: // the detection brings no fix data (a safe check): the fix stays
	case key != was.FixKey:
		t.emit(SystemUser, EvFixChanged, EventDetail{From: was.FixKey, To: key})
		f.Fix, f.FixKey = d.Fix, key
	default:
		f.Fix = d.Fix
	}
	// A detection never lowers the urgency (the urgency pass owns it); one that rates the flaw more urgent than stored raises it: a
	// CVE that joined an exploited list after its finding was made.
	if d.Urgency >= 1 && d.Urgency < f.Urgency {
		f.Urgency, f.UrgencyAt = d.Urgency, t.now
		t.emit(SystemUser, EvUrgencyChanged, EventDetail{Layer: d.Urgency})
	}
	f.Detected = true
	if daily || !sameFinding(*f, was) && t.now.After(f.LastSeen) {
		f.LastSeen = t.now // a pass that changes nothing writes nothing: last seen moves once a day, or with a change
	}
	switch {
	case f.Verified.rank() > was.Verified.rank(): // confirmed, or confirmed by a stronger proof
		t.emit(SystemUser, EvConfirmed, EventDetail{From: string(was.Verified), To: string(f.Verified)})
	case was.Confirmed() && !f.Confirmed():
		t.emit(SystemUser, EvUnconfirmed, EventDetail{From: string(was.Verified), To: string(f.Verified)})
	}
	switch {
	case was.State == StateOpen:
		if !was.Detected {
			t.emit(SystemUser, EvRedetected, EventDetail{})
		}
	case was.Via == ViaPerson && was.Resolution == ResolutionPatched:
		if read.After(was.ResolvedAt) { // a reading taken after the person's mark still shows the flaw
			t.open()
			t.emit(SystemUser, EvReopened, EventDetail{Why: WhyStillDetected, ReadingAt: read.Format(tsLayout)})
		}
	case was.Via == ViaPerson: // mitigated, accepted, false positive and not relevant hold while detected
	case was.Via == ViaScanClear && (d.Basis == DetectBannerVersion || d.Basis == DetectStatement):
		// a banner or a person's statement does not overrule a clear safe check; the device's own reading or another check does
	default: // Vedette closed it, a person's version change closed it, or a person said the software is not installed: detected again
		by := "" // a person is named only when their entry took the version back from the one it had moved to
		if was.Via == ViaVersionMoved && d.MatchedVersion != was.ToVersion {
			by = d.SetBy
		}
		t.open()
		t.emit(SystemUser, EvReopened, EventDetail{Why: WhyDetectedAgain, By: by})
	}
	return nil
}

func (t *transition) gone(tr Trigger) error {
	via, from, to := tr.Via, tr.FromVersion, tr.ToVersion
	if !via.Valid() || via == ViaPerson {
		return fmt.Errorf("findings: no longer detected via %q", via)
	}
	f := &t.f
	if f.State == "" || !f.Detected { // no row, or already not detected: only the edge changes anything
		return nil
	}
	if via == ViaVersionMoved && (from == "" || to == "" || from == to) {
		via = ViaDataCorrected // no version change to credit
	}
	if f.Verified.sticky() && (via == ViaDataCorrected || via == ViaDistroFixed) && (f.Verified != VerifiedPerson || !tr.Corrected) {
		// range data (or a question the match asks instead) does not undo what a safe check proved or a person confirmed; a newer
		// reading of the device does (version_moved, removed), and a person's "not installed" or version correction
		return nil
	}
	if via == ViaScanClear && (f.Basis == DetectDeviceVersion || f.Basis == DetectPackage) {
		return nil // a clear safe check does not credit a flaw the device's own reading still shows
	}
	if via != ViaVersionMoved {
		from, to = "", ""
	}
	by := SystemUser
	if via == ViaNotInstalled || via == ViaVersionMoved && t.actor != SystemUser {
		by = t.actor // a person said the software is not installed, or changed the version they had entered: theirs, not Vedette's
	}
	f.Detected = false
	res := ResolutionNotRelevant
	if via.Credit() {
		res = ResolutionPatched
	}
	note := "" // Vedette's own reason, when the match's proof gives one (the distribution's fixed release); never for a person's close
	if by == SystemUser {
		note = tr.Note
	}
	switch was := t.before; {
	case was.State == StateOpen:
		t.close(res, via, by, note, time.Time{}, from, to)
	case was.Via == ViaPerson && (was.Resolution == ResolutionMitigated || was.Resolution == ResolutionAccepted) && via.Credit():
		t.close(res, via, by, note, time.Time{}, from, to) // the flaw is gone: the workaround or the accepted risk no longer matters
	default:
		t.emit(SystemUser, EvNoLongerDetected, EventDetail{Via: via, FromVersion: from, ToVersion: to})
	}
	return nil
}

func (t *transition) handle(tr Trigger) error {
	if t.f.State == "" {
		return fmt.Errorf("findings: handling a finding: %w", ErrNotFound)
	}
	if !tr.Resolution.Valid() {
		return fmt.Errorf("findings: handling as %q: %w", tr.Resolution, ErrBadAction)
	}
	if err := ValidUser(t.actor); err != nil {
		return err
	}
	note, err := personNote(tr.Note, tr.Resolution == ResolutionFalsePositive || tr.Resolution == ResolutionNotRelevant || tr.Resolution == ResolutionAccepted)
	if err != nil {
		return fmt.Errorf("findings: handling as %s: %w", tr.Resolution, err)
	}
	var until time.Time
	if tr.Resolution == ResolutionAccepted {
		if err := validUntil(tr.Until, t.now); err != nil {
			return err
		}
		until = dayOf(tr.Until)
	} else if !tr.Until.IsZero() {
		return fmt.Errorf("findings: handling as %s with a date: %w", tr.Resolution, ErrBadUntil)
	}
	was := t.before
	if was.State == StateHandled && was.Resolution == tr.Resolution && was.AcceptedUntil.Equal(until) {
		switch {
		case was.Via == ViaPerson:
			return nil // already handled this way
		case was.Via.Credit():
			// Vedette already credited the patch: the credit stays, and a note the person wrote is kept in the history
			if note != "" {
				t.emit(t.actor, EvHandled, EventDetail{Resolution: tr.Resolution, Via: ViaPerson, Note: note})
			}
			return nil
		}
		// Vedette closed it the same way without credit: the person's handling takes it over, with their note
	}
	t.close(tr.Resolution, ViaPerson, t.actor, note, until, "", "")
	return nil
}

func (t *transition) reopen(tr Trigger) error {
	if t.f.State == "" {
		return fmt.Errorf("findings: reopening a finding: %w", ErrNotFound)
	}
	if err := ValidUser(t.actor); err != nil {
		return err
	}
	note, err := personNote(tr.Note, false)
	if err != nil {
		return fmt.Errorf("findings: reopening: %w", err)
	}
	if t.f.State == StateOpen {
		return fmt.Errorf("findings: reopening: %w", ErrAlreadyOpen)
	}
	t.open()
	t.emit(t.actor, EvReopened, EventDetail{Why: WhyPerson, Note: note})
	return nil
}

func (t *transition) verify(tr Trigger) error {
	if t.f.State == "" {
		return fmt.Errorf("findings: confirming a finding: %w", ErrNotFound)
	}
	if err := ValidUser(t.actor); err != nil {
		return err
	}
	if t.f.State != StateOpen || t.f.Confirmed() {
		return fmt.Errorf("findings: confirming a %s finding verified %s: %w", t.f.State, t.f.Verified, ErrNotSuspected)
	}
	note := jsTrim(tr.Note)
	switch n := jsLen(note); {
	case n > MaxNote:
		return fmt.Errorf("findings: confirming: %w", ErrNoteTooLong)
	case n < MinReasonNote:
		return fmt.Errorf("findings: confirming: %w", ErrConfirmNoteRequired)
	}
	t.f.Verified = VerifiedPerson
	t.emit(t.actor, EvConfirmed, EventDetail{From: string(VerifiedNo), To: string(VerifiedPerson), Note: note})
	return nil
}

func (t *transition) unverify() error {
	if t.f.State == "" {
		return fmt.Errorf("findings: undoing a confirmation: %w", ErrNotFound)
	}
	if err := ValidUser(t.actor); err != nil {
		return err
	}
	if t.f.Verified != VerifiedPerson {
		return fmt.Errorf("findings: undoing a confirmation of a finding verified %s: %w", t.f.Verified, ErrNotConfirmedByHand)
	}
	t.f.Verified = VerifiedNo
	t.emit(t.actor, EvUnconfirmed, EventDetail{From: string(VerifiedPerson), To: string(VerifiedNo)})
	return nil
}

func (t *transition) tick() {
	was := t.before
	if was.State != StateHandled || was.Resolution != ResolutionAccepted || t.now.Before(AcceptanceEnds(was.AcceptedUntil)) {
		return
	}
	d := EventDetail{AcceptedUntil: was.AcceptedUntil.Format(time.DateOnly), From: was.ResolvedBy}
	if was.Detected {
		t.open()
		t.emit(SystemUser, EvAcceptanceExpire, d)
		return
	}
	t.emit(SystemUser, EvAcceptanceExpire, d)
	t.close(ResolutionNotRelevant, ViaDataCorrected, SystemUser, "", time.Time{}, "", "") // nothing detects it any more
}

func (t *transition) urgency(layer int) error {
	if layer < 1 || layer > 5 {
		return fmt.Errorf("findings: urgency layer %d outside 1..5", layer)
	}
	if t.f.State == "" || t.f.Urgency == layer {
		return nil
	}
	t.f.Urgency, t.f.UrgencyAt = layer, t.now
	t.emit(SystemUser, EvUrgencyChanged, EventDetail{Layer: layer})
	return nil
}

// personNote trims and measures a person's note like the GUI does (JavaScript trim and UTF-16 length).
func personNote(note string, required bool) (string, error) {
	note = jsTrim(note)
	n := jsLen(note)
	switch {
	case n > MaxNote:
		return "", ErrNoteTooLong
	case required && n < MinReasonNote:
		return "", ErrNoteRequired
	}
	return note, nil
}

// lastSeenStep is how far last_seen may lag behind the pass that detected a finding again when nothing else changed: the hourly pass
// rewrites no row that did not change.
const lastSeenStep = 24 * time.Hour

// sameEvidence reports whether two evidences say the same, the times of the reading and of the comparison aside (a source that
// reads the same version again changes nothing the finding says).
func sameEvidence(a, b *Evidence) bool {
	if a == nil || b == nil {
		return a == b
	}
	x, y := *a, *b
	x.CheckedAt, y.CheckedAt = time.Time{}, time.Time{}
	if x.Read != nil && y.Read != nil {
		rx, ry := *x.Read, *y.Read
		rx.At, ry.At = time.Time{}, time.Time{}
		x.Read, y.Read = &rx, &ry
	}
	return reflect.DeepEqual(x, y)
}

// sameFinding reports whether two rows are equal but for UpdatedAt.
func sameFinding(a, b Finding) bool {
	a.UpdatedAt, b.UpdatedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(a, b)
}
