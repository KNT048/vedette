package findings

import (
	"cmp"
	"slices"
	"strings"
)

// GateState is the gate's decision on one (installation, CVE) pair.
type GateState uint8

// The decisions of the gate. The zero value is undecided: nothing closes by default.
const (
	GateUndecided GateState = iota
	GateAffected
	GateNotAffected
)

var gateStateNames = [...]string{"undecided", "affected", "not_affected"}

func (s GateState) String() string {
	if int(s) < len(gateStateNames) {
		return gateStateNames[s]
	}
	return "unknown"
}

// Decision is the gate's answer: its state, the proof it rests on (affected or not affected), the cause of an undecided answer, and
// the evidence it weighed (in a fixed order, whatever order it was given in).
type Decision struct {
	State      GateState
	By         *Proof
	Cause      GateCause
	Considered []Proof
	Blockers   []Blocker
}

// Gate decides CVE cve on installation in from the statements ev and the blockers bl (exploited: the CVE is on an exploited list).
// In order: (1) an affected statement whose scope contains the installation decides affected, and one that may contain it (Unknown)
// leaves the pair undecided; (2) a blocker leaves it undecided; (3) a not-affected statement closes only when its scope contains the
// installation (Scope.Contains is Yes) and its kind is one its format can state for this CVE (allowedProof); (4) anything else is
// undecided with a named cause. The answer does not depend on the order of ev or bl.
func Gate(cve string, in Installation, ev []Proof, bl []Blocker, exploited bool) Decision {
	if slices.ContainsFunc(bl, func(b Blocker) bool { return b.CVE != "" && b.CVE != cve }) {
		bl = slices.DeleteFunc(slices.Clone(bl), func(b Blocker) bool { return b.CVE != "" && b.CVE != cve })
	}
	d := Decision{Considered: sortedProofs(ev), Blockers: sortedBlockers(bl)}
	var affected, closing []*Proof
	var causes []GateCause
	conflict := false
	for i := range d.Considered {
		p := &d.Considered[i]
		if p.CVE != "" && p.CVE != cve {
			continue
		}
		t, c := p.Scope.Contains(in)
		switch p.Says {
		case SaysAffected:
			switch t {
			case Yes:
				affected = append(affected, p)
			case Unknown:
				conflict = true
			}
		case SaysNotAffected:
			if t != Yes {
				causes = append(causes, c)
				continue
			}
			if ok, c := allowedProof(*p, exploited); !ok {
				causes = append(causes, c)
				continue
			}
			closing = append(closing, p)
		}
	}
	switch {
	case len(affected) > 0:
		d.State, d.By = GateAffected, affected[0]
	case conflict:
		d.Cause = CauseConflict
	case len(d.Blockers) > 0:
		cs := make([]GateCause, len(d.Blockers))
		for i, b := range d.Blockers {
			cs[i] = b.Cause
		}
		d.Cause = cmp.Or(firstCause(cs), CauseRecordClash)
	case len(closing) > 0:
		d.State, d.By = GateNotAffected, closing[0]
	default:
		d.Cause = cmp.Or(firstCause(causes), CauseNoProof)
	}
	return d
}

// kindFormats is which formats can state each kind of not-affected proof (the allowed-kind table). A kind a format is not listed for
// never closes: an NVD CPE configuration never states "unaffected" (vulnerable=false is the environment), a range start proves an
// introduction only where the standard says so (OSV's introduced), and only a person's answer is a person's proof.
var kindFormats = map[ProofKind][]Format{
	ProofFixedAt:           {FormatCVE5, FormatNVDCPE, FormatOSV, FormatCSAF, FormatOpenVEX, FormatDistroTracker, FormatMSRelease, FormatLineSource},
	ProofStatedUnaffected:  {FormatCVE5, FormatCSAF, FormatOpenVEX, FormatDistroTracker, FormatLineSource},
	ProofBeforeIntroduced:  {FormatOSV, FormatCVE5},
	ProofOtherPlatform:     {FormatCVE5, FormatCSAF, FormatOpenVEX, FormatDistroTracker, FormatLineSource},
	ProofOtherHardware:     {FormatCVE5, FormatCSAF, FormatOpenVEX, FormatLineSource},
	ProofPersonNotAffected: {FormatPerson},
}

// allowedProof says whether not-affected proof p may close a pair: its format is a declared one that can state its kind, its version
// set has the shape the kind needs, and the kind is not an inference for an exploited CVE.
func allowedProof(p Proof, exploited bool) (bool, GateCause) {
	f, vs := p.Src.Format, p.Scope.Versions
	if !f.known() || !slices.Contains(kindFormats[p.Kind], f) {
		return false, CauseKindNotAllowed
	}
	// an exact or range list says what is not listed only where the source says unlisted versions are not affected
	if vs.AllExceptListed && f != FormatOSV && (f != FormatCVE5 || !p.Src.DefaultUnaffected) {
		return false, CauseKindNotAllowed
	}
	switch p.Kind {
	case ProofFixedAt: // a fix: spans that start at the fixed release
		if vs.Every || vs.AllExceptListed || len(vs.Exact) > 0 || len(vs.Ranges) == 0 {
			return false, CauseKindNotAllowed
		}
		for _, r := range vs.Ranges {
			if r.From == "" || f == FormatNVDCPE && r.FromExcl { // NVD: only a range's excluded end is a fixed release
				return false, CauseKindNotAllowed
			}
		}
	case ProofBeforeIntroduced: // versions below the first affected release, stated by the format's own semantics
		if f == FormatCVE5 && !p.Src.DefaultUnaffected || vs.Every || len(vs.Exact) > 0 || len(vs.Ranges) == 0 {
			return false, CauseKindNotAllowed
		}
		for _, r := range vs.Ranges {
			if r.From != "" || r.To == "" {
				return false, CauseKindNotAllowed
			}
		}
	case ProofOtherPlatform:
		if pl := p.Scope.Platform; pl.Any || len(pl.OS)+len(pl.Arch) == 0 {
			return false, CauseKindNotAllowed
		}
	case ProofOtherHardware:
		if pl := p.Scope.Platform; pl.Any || len(pl.Hardware) == 0 {
			return false, CauseKindNotAllowed
		}
	}
	if exploited && (p.Kind == ProofBeforeIntroduced || p.Kind == ProofOtherHardware) {
		return false, CauseExploitedKind
	}
	return true, ""
}

// sortedProofs is a copy of ev in a fixed order (by kind, direction, format, producer, reference, quote), so that the decision and the
// proof it names do not depend on the order the producers ran in.
func sortedProofs(ev []Proof) []Proof {
	if len(ev) == 0 {
		return nil
	}
	out := slices.Clone(ev)
	slices.SortStableFunc(out, func(a, b Proof) int {
		return cmp.Or(cmp.Compare(a.Says, b.Says), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Src.Format, b.Src.Format),
			strings.Compare(a.Producer, b.Producer), strings.Compare(a.Src.Ref, b.Src.Ref), strings.Compare(a.Quote, b.Quote),
			strings.Compare(a.Note, b.Note))
	})
	return out
}

func sortedBlockers(bl []Blocker) []Blocker {
	if len(bl) == 0 {
		return nil
	}
	out := slices.Clone(bl)
	slices.SortStableFunc(out, func(a, b Blocker) int {
		return cmp.Or(strings.Compare(string(a.Cause), string(b.Cause)), strings.Compare(a.Producer, b.Producer), strings.Compare(a.CVE, b.CVE))
	})
	return out
}
