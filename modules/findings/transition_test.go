package findings

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

// The states a finding can be in, as the table test starts them. Marks are an hour before t0; a reading at t0 is newer than them.
func transitionStates() map[string]Finding {
	mark := t0.Add(-time.Hour)
	base := Finding{ID: "f-1", AssetID: "a-1", CVE: "CVE-2026-0001", SoftwareID: "s-1", Detected: true, Basis: DetectBannerVersion, Verified: VerifiedNo,
		RangeOrigin: RangeNVD, MatchedVersion: "1.0", Fix: Fix{Kind: FixUnknown}, FixKey: FixKey("acme|app", Fix{Kind: FixUnknown}), State: StateOpen,
		Urgency: 2, UrgencyAt: mark, FirstSeen: mark, LastSeen: mark, UpdatedAt: mark}
	by := func(f Finding, res Resolution, via Via, who string) Finding {
		f.State, f.Resolution, f.Via, f.ResolvedBy, f.ResolvedAt = StateHandled, res, via, who, mark
		return f
	}
	undetected := func(f Finding) Finding { f.Detected = false; return f }
	accepted := func(until time.Time, detected bool) Finding {
		f := by(base, ResolutionAccepted, ViaPerson, "anna@example.com")
		f.AcceptedUntil, f.Note, f.Detected = until, "maintenance window", detected
		return f
	}
	scan, personVerified := base, base
	scan.Basis, scan.Verified = DetectScan, VerifiedScan
	personVerified.Verified = VerifiedPerson
	moved := undetected(by(base, ResolutionPatched, ViaVersionMoved, SystemUser))
	moved.FromVersion, moved.ToVersion = "1.0", "2.0"
	return map[string]Finding{
		"new":                          {ID: "f-1", AssetID: "a-1", CVE: "CVE-2026-0001"},
		"open":                         base,
		"open, not detected":           undetected(base),
		"open, safe check":             scan,
		"open, confirmed by a person":  personVerified,
		"patched by a person":          by(base, ResolutionPatched, ViaPerson, "anna@example.com"),
		"mitigated":                    by(base, ResolutionMitigated, ViaPerson, "anna@example.com"),
		"accepted":                     accepted(dayOf(t0).AddDate(0, 0, 10), true),
		"accepted, last day over":      accepted(dayOf(t0).AddDate(0, 0, -2), true),
		"accepted, over, not detected": accepted(dayOf(t0).AddDate(0, 0, -2), false),
		"false positive":               by(base, ResolutionFalsePositive, ViaPerson, "anna@example.com"),
		"not relevant (person)":        by(base, ResolutionNotRelevant, ViaPerson, "anna@example.com"),
		"patched, version moved":       moved,
		"patched, safe check clear":    undetected(by(scan, ResolutionPatched, ViaScanClear, SystemUser)),
		"not relevant, corrected":      undetected(by(base, ResolutionNotRelevant, ViaDataCorrected, SystemUser)),
		"not relevant, not installed":  undetected(by(base, ResolutionNotRelevant, ViaNotInstalled, "anna@example.com")),
	}
}

// The triggers of the table test, all at t0.
func transitionTriggers() map[string]Trigger {
	det := func(basis DetectionBasis, v Verified, read time.Time) Trigger {
		return Trigger{Kind: TrDetected, At: t0, Detection: Detection{SoftwareID: "s-1", Basis: basis, Verified: v, MatchedVersion: "1.0", ProductKey: "acme|app", ReadAt: read, Urgency: 2}}
	}
	gone := func(via Via, from, to string) Trigger {
		return Trigger{Kind: TrGone, At: t0, Via: via, FromVersion: from, ToVersion: to, Actor: map[bool]string{true: "bob@example.com"}[via == ViaNotInstalled]}
	}
	handle := func(r Resolution, note string) Trigger {
		t := Trigger{Kind: TrHandle, At: t0, Actor: "bob@example.com", Resolution: r, Note: note}
		if r == ResolutionAccepted {
			t.Until = dayOf(t0).AddDate(0, 0, 30)
		}
		return t
	}
	return map[string]Trigger{
		"detected, new reading":       det(DetectBannerVersion, VerifiedNo, t0),
		"detected, old reading":       det(DetectBannerVersion, VerifiedNo, t0.Add(-2*time.Hour)),
		"detected by the device":      det(DetectDeviceVersion, VerifiedDevice, t0),
		"detected by a safe check":    det(DetectScan, VerifiedScan, t0),
		"gone, version moved":         gone(ViaVersionMoved, "1.0", "2.0"),
		"gone, version moved nowhere": gone(ViaVersionMoved, "1.0", "1.0"),
		"gone, software removed":      gone(ViaSoftwareRemoved, "", ""),
		"gone, distro fixed":          gone(ViaDistroFixed, "", ""),
		"gone, safe check clear":      gone(ViaScanClear, "", ""),
		"gone, data corrected":        gone(ViaDataCorrected, "", ""),
		"gone, not installed":         gone(ViaNotInstalled, "", ""),
		"handle patched":              handle(ResolutionPatched, ""),
		"handle mitigated":            handle(ResolutionMitigated, ""),
		"handle accepted":             handle(ResolutionAccepted, "until the upgrade"),
		"handle false positive":       handle(ResolutionFalsePositive, "lab box"),
		"handle not relevant":         handle(ResolutionNotRelevant, "not exposed"),
		"handle without a note":       handle(ResolutionFalsePositive, " "),
		"reopen":                      {Kind: TrReopen, At: t0, Actor: "bob@example.com"},
		"verify":                      {Kind: TrVerify, At: t0, Actor: "bob@example.com", Note: "I tried it"},
		"unverify":                    {Kind: TrUnverify, At: t0, Actor: "bob@example.com"},
		"tick":                        {Kind: TrTick, At: t0},
		"urgency 3":                   {Kind: TrUrgency, At: t0, Layer: 3},
	}
}

// transitionOutcome is the table's short form of a transition: the state (with resolution and way when handled, "!" when not detected), then
// the kinds of the events; "none" when the pair has no row; "err:<code>" for a refused action.
func transitionOutcome(before Finding, t Trigger) string {
	f, evs, err := Transition(before, t)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			return "err:" + ae.Code
		}
		return "err:" + err.Error()
	}
	if f.State == "" {
		return "none"
	}
	s := string(f.State)
	if f.State == StateHandled {
		s += "/" + string(f.Resolution) + "/" + string(f.Via)
	}
	if !f.Detected {
		s += "!"
	}
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, string(e.Kind))
	}
	return strings.TrimSpace(s + " " + strings.Join(kinds, ","))
}

// Every state against every trigger: the whole of the state machine in one table. A row for every pair, so a new
// state or trigger fails here until its outcome is written down.
func TestTransition_EveryStateAndTrigger(t *testing.T) {
	t.Parallel()
	want := transitionTable()
	states, triggers := transitionStates(), transitionTriggers()
	for sn, st := range states {
		for tn, tr := range triggers {
			w, ok := want[sn][tn]
			if !ok {
				t.Errorf("no outcome written for %q × %q (got %q)", sn, tn, transitionOutcome(st, tr))
				continue
			}
			if got := transitionOutcome(st, tr); got != w {
				t.Errorf("%q × %q = %q, want %q", sn, tn, got, w)
			}
		}
	}
	for sn, row := range want {
		if _, ok := states[sn]; !ok {
			t.Errorf("table row %q has no state", sn)
		}
		for tn := range row {
			if _, ok := triggers[tn]; !ok {
				t.Errorf("table cell %q × %q has no trigger", sn, tn)
			}
		}
	}
	for _, k := range TriggerKinds { // every kind of trigger is in the table
		if !slices.ContainsFunc(mapValues(triggers), func(tr Trigger) bool { return tr.Kind == k }) {
			t.Errorf("trigger kind %s is not in the table", k)
		}
	}
}

func mapValues[K comparable, V any](m map[K]V) []V {
	out := make([]V, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// The handling invariants hold after any sequence of triggers from any state: open exactly when there is no resolution; every handled row has a
// way, who and when; a version move names two different versions. And every value written is in its vocabulary.
func TestTransition_InvariantsHoldForAnySequence(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // a seeded sequence of test cases, not a secret
	states, triggers := mapValues(transitionStates()), mapValues(transitionTriggers())
	// random detections and moves too, not only the table's
	vias := Vias[1:]
	for range 20000 {
		f := states[rng.IntN(len(states))]
		at := t0
		for range 1 + rng.IntN(12) {
			at = at.Add(time.Duration(rng.IntN(72)) * time.Hour)
			var tr Trigger
			switch rng.IntN(3) {
			case 0:
				tr = triggers[rng.IntN(len(triggers))]
			case 1:
				tr = Trigger{Kind: TrGone, Via: vias[rng.IntN(len(vias))], FromVersion: []string{"", "1.0", "2.0"}[rng.IntN(3)], ToVersion: []string{"", "1.0", "2.0"}[rng.IntN(3)]}
			default:
				tr = Trigger{Kind: TrDetected, Detection: Detection{SoftwareID: "s-1", Basis: DetectionBases[rng.IntN(len(DetectionBases)-1)],
					Verified: []Verified{VerifiedNo, VerifiedDevice, VerifiedScan}[rng.IntN(3)], ReadAt: at.Add(-time.Duration(rng.IntN(48)) * time.Hour)}}
				if tr.Detection.Verified == VerifiedScan {
					tr.Detection.Basis = DetectScan
				}
			}
			tr.At = at
			g, evs, err := Transition(f, tr)
			if err != nil {
				if !sameFinding(g, f) {
					t.Fatalf("a refused trigger changed the finding: %+v", tr)
				}
				continue
			}
			if g.State == "" {
				continue
			}
			if err := g.Validate(); err != nil {
				t.Fatalf("after %+v from %+v: %v", tr, f, err)
			}
			if g.State == StateHandled && (g.Via == "" || g.ResolvedBy == "" || g.ResolvedAt.IsZero()) {
				t.Fatalf("handled without how, who or when: %+v", g)
			}
			if (g.State == StateOpen) != (g.Resolution == "") {
				t.Fatalf("state and resolution disagree: %+v", g)
			}
			if g.Via == ViaVersionMoved && (g.FromVersion == "" || g.ToVersion == "" || g.FromVersion == g.ToVersion) {
				t.Fatalf("a version move without two versions: %+v", g)
			}
			for _, e := range evs {
				if !slices.Contains(EventKinds, e.Kind) || e.Actor == "" || !e.TS.Equal(at.UTC().Truncate(time.Millisecond)) {
					t.Fatalf("event %+v", e)
				}
			}
			f = g
		}
	}
}

// A trigger that changes nothing writes nothing: the same detection twice, the same handling twice, a tick before the last day.
func TestTransition_RepeatsAreQuiet(t *testing.T) {
	t.Parallel()
	for sn, st := range transitionStates() {
		for tn, tr := range transitionTriggers() {
			f, _, err := Transition(st, tr)
			if err != nil || f.State == "" {
				continue
			}
			tr.At = tr.At.Add(time.Minute)
			if tr.Kind == TrDetected {
				tr.Detection.ReadAt = time.Time{} // the same reading again, not a newer one
			}
			if tr.Kind == TrReopen || tr.Kind == TrVerify || tr.Kind == TrUnverify {
				continue // refused the second time (already open, already confirmed, nothing to undo)
			}
			if _, evs, err := Transition(f, tr); err == nil && len(evs) > 0 {
				t.Errorf("%q × %q twice: the second wrote %v", sn, tn, evs)
			}
		}
	}
}

func ExampleTransition() {
	f := Finding{ID: "f-1", AssetID: "a-1", CVE: "CVE-2026-0001"}
	f, evs, _ := Transition(f, Trigger{Kind: TrDetected, At: t0, Detection: Detection{SoftwareID: "s-1", Basis: DetectDeviceVersion, Verified: VerifiedDevice, MatchedVersion: "6.24"}})
	fmt.Println(f.State, f.Verified, len(evs))
	f, _, _ = Transition(f, Trigger{Kind: TrGone, At: t0.Add(time.Hour), Via: ViaVersionMoved, FromVersion: "6.24", ToVersion: "7.23"})
	fmt.Println(f.State, f.Resolution, f.Via, f.ResolvedBy, f.FromVersion, "→", f.ToVersion)
	// Output:
	// open device 2
	// handled patched version_moved system 6.24 → 7.23
}
