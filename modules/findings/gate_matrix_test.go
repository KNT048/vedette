package findings

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
)

// Layer A of the closing gate's scenario matrix: Gate alone, on generated cases, against an oracle written from the gate's published
// rules as truth tables (which versions, builds, products and platforms each scope speaks for; which kinds each format can state),
// never from gate.go or proof.go. Invariants:
//   I1 Gate = not affected only where the oracle says not affected (and otherwise the two agree, except the soft count below);
//   I2 nothing outside the declared formats closes, and no declared format is a model's reading;
//   I3 every undecided answer names a cause;
//   I4 adding an affected statement or a blocker never closes, removing a not-affected proof never closes;
//   I5 a proof about one installation never closes another;
//   I6 the order of the evidence does not change the answer.
// Soft count: the oracle closes and Gate does not (stricter than the tables): logged, never a failure.

// tv is the oracle's truth value.
type tv uint8

const (
	tN tv = iota
	tY
	tU
)

// and is the oracle's conjunction: a No anywhere is No, else an Unknown is Unknown.
func and(ts ...tv) tv {
	out := tY
	for _, t := range ts {
		if t == tN {
			return tN
		}
		if t == tU {
			out = tU
		}
	}
	return out
}

const mCVE = "CVE-2026-0001"

var mProduct = ProductRef{Vendor: "acme", Product: "widget"}

// The version sets of the matrix.
var mVersionSets = [7]VersionSet{
	{Every: true}, // 0 every version
	{Scheme: SchemeGeneric, Ranges: []Span{{From: "2.0", To: "3.0"}}},      // 1 fixed on line 2
	{Scheme: SchemeGeneric, Ranges: []Span{{From: "2.0"}}},                 // 2 fixed from 2.0 on
	{Scheme: SchemeGeneric, Ranges: []Span{{To: "1.0"}}},                   // 3 below 1.0
	{Scheme: SchemeGeneric, Exact: []string{"1.5", "2.5"}},                 // 4 two exact versions
	{Scheme: SchemeGeneric, Exact: []string{"1.5"}, AllExceptListed: true}, // 5 every version but 1.5
	{Every: true, Lines: []string{"2"}},                                    // 6 every version of line 2
}

// The installations' versions: value, scheme and release line.
var mShapes = [12]struct {
	scheme, raw, line string
}{
	{SchemeGeneric, "0.9", "0"}, {SchemeGeneric, "1.0", "1"}, {SchemeGeneric, "1.5", "1"}, {SchemeGeneric, "2.0", "2"},
	{SchemeGeneric, "2.5", "2"}, {SchemeGeneric, "2.9.9", "2"}, {SchemeGeneric, "3.0", "3"}, {SchemeGeneric, "4.1", "4"},
	{SchemeGeneric, "", ""}, {SchemeGeneric, "abc", ""}, {SchemeDeb, "2.5", "2"}, {SchemeGeneric, "2.5", ""},
}

// oVersion: does version set i contain shape j (by hand, from the sets' meaning).
var oVersion = [7][12]tv{
	//  0.9 1.0 1.5 2.0 2.5 2.9.9 3.0 4.1  ""  abc  deb nolin
	{tY, tY, tY, tY, tY, tY, tY, tY, tY, tY, tY, tY}, // every
	{tN, tN, tN, tY, tY, tY, tN, tN, tU, tU, tU, tY}, // [2.0, 3.0)
	{tN, tN, tN, tY, tY, tY, tY, tY, tU, tU, tU, tY}, // [2.0, ∞)
	{tY, tN, tN, tN, tN, tN, tN, tN, tU, tU, tU, tN}, // (-∞, 1.0)
	{tN, tN, tY, tN, tY, tN, tN, tN, tU, tU, tU, tY}, // 1.5, 2.5
	{tY, tY, tN, tY, tY, tY, tY, tY, tU, tU, tU, tY}, // all but 1.5
	{tN, tN, tN, tY, tY, tY, tN, tN, tU, tU, tY, tU}, // line 2
}

// oExact99: does the set {9.9} (an affected statement about another version) contain shape j.
var oExact99 = [12]tv{tN, tN, tN, tN, tN, tN, tN, tN, tU, tU, tU, tN}

var mScopeOrigins = [6]OriginSet{
	{Any: true},
	{Upstream: true},
	{Builds: []Origin{{Kind: OriginDistro, Distro: "debian", Release: "12"}}},
	{Builds: []Origin{{Kind: OriginDistro, Distro: "ubuntu", Release: "24.04"}}},
	{Builds: []Origin{{Kind: OriginDistro, Distro: "ubuntu", Release: "24.04", Pocket: "esm"}}},
	{Builds: []Origin{{Kind: OriginDistro, Distro: "debian", Release: "12"}, {Kind: OriginDistro, Distro: "ubuntu", Release: "24.04"}}},
}

var mInstallOrigins = [5]Origin{
	{Kind: OriginUpstream},
	{Kind: OriginDistro, Distro: "debian", Release: "12"},
	{Kind: OriginDistro, Distro: "ubuntu", Release: "24.04"},
	{Kind: OriginDistro, Distro: "ubuntu", Release: "24.04", Pocket: "esm"},
	{},
}

// oOrigin: does scope origin i speak for installation origin j.
var oOrigin = [6][5]tv{
	// up  deb12 u2404 u2404esm unknown
	{tY, tY, tY, tY, tY}, // any
	{tY, tN, tN, tN, tU}, // upstream
	{tN, tY, tN, tN, tU}, // debian 12
	{tN, tN, tY, tN, tU}, // ubuntu 24.04 main archive
	{tN, tN, tN, tY, tU}, // ubuntu 24.04 Pro pocket
	{tN, tY, tY, tN, tU}, // debian 12 or ubuntu 24.04
}

// The evidence kinds of the matrix: the six not-affected kinds, an affected statement, none.
const (
	mkFixed = iota
	mkStated
	mkBefore
	mkPlatform
	mkHardware
	mkPerson
	mkAffected
	mkNone
	mKinds
)

var mKindOf = [6]ProofKind{ProofFixedAt, ProofStatedUnaffected, ProofBeforeIntroduced, ProofOtherPlatform, ProofOtherHardware, ProofPersonNotAffected}

// mNaturalFormat is the format each kind is stated in for the full product.
var mNaturalFormat = [6]Format{FormatCVE5, FormatCVE5, FormatOSV, FormatCVE5, FormatCVE5, FormatPerson}

// oShape: may kind k (in its natural format, CVE5 without defaultStatus) close with version set i (the allowed-kind table: a fix is a
// span that starts at it; an introduction is a span that ends at it; "all but the listed" only where the source says so).
var oShape = [6][7]bool{
	// every  [2,3) [2,∞) (-∞,1) exact allbut line2
	{false, true, true, false, false, false, false},  // fixed at
	{true, true, true, true, true, false, true},      // stated unaffected
	{false, false, false, true, false, false, false}, // before introduced (OSV)
	{true, true, true, true, true, false, true},      // other platform
	{true, true, true, true, true, false, true},      // other hardware
	{true, true, true, true, true, false, true},      // person
}

// oFormatKind: can format f state kind k at all (independent of the version set), from the standards: NVD CPE states only affected
// ranges and their fixed ends; MS release data only fixes; OSV fixes and introductions; a CVE record also states unaffected versions,
// platforms and hardware; CSAF and OpenVEX states and products; a distribution tracker fixes, not-affected packages and architectures; a
// line source fixes, unaffected lines, platforms and hardware; a person only their own answer.
var oFormatKind = map[Format][6]bool{
	//                   fixed stated before platform hardware person
	FormatCVE5:          {true, true, true, true, true, false},
	FormatNVDCPE:        {true, false, false, false, false, false},
	FormatOSV:           {true, false, true, false, false, false},
	FormatCSAF:          {true, true, false, true, true, false},
	FormatOpenVEX:       {true, true, false, true, true, false},
	FormatDistroTracker: {true, true, false, true, false, false},
	FormatMSRelease:     {true, false, false, false, false, false},
	FormatLineSource:    {true, true, false, true, true, false},
	FormatPerson:        {false, false, false, false, false, true},
}

var mPlatform = Platform{OS: "linux", Arch: "x86_64", Hardware: "srx300"}

// platformOf is the scope platform each kind is stated with in the full product.
func platformOf(k int) PlatformSet {
	switch k {
	case mkPlatform:
		return PlatformSet{Arch: []string{"arm64"}, Except: true}
	case mkHardware:
		return PlatformSet{Hardware: []string{"mx480"}, Except: true}
	}
	return PlatformSet{Any: true}
}

func mProof(k int, f Format, sc Scope) Proof {
	if k == mkAffected {
		return Proof{Kind: ProofFixedAt, CVE: mCVE, Src: ProofSource{Format: FormatCVE5, Ref: "affected"}, Scope: sc, Says: SaysAffected, Producer: "matrix"}
	}
	return Proof{Kind: mKindOf[k], CVE: mCVE, Src: ProofSource{Format: f, Ref: "main"}, Scope: sc, Says: SaysNotAffected, Producer: "matrix"}
}

// mCase is one generated case and the oracle's answer.
type mCase struct {
	name      func() string // built only when a case fails
	in        Installation
	ev        []Proof
	bl        []Blocker
	exploited bool
	want      GateState
}

// matrixRun checks every invariant on one case and counts it.
type matrixRun struct {
	t                   *testing.T
	cases, soft, closed int
	failed              int
}

func (r *matrixRun) check(c mCase) {
	r.cases++
	d := Gate(mCVE, c.in, c.ev, c.bl, c.exploited)
	fail := func(format string, args ...any) {
		r.failed++
		if r.failed <= 20 {
			r.t.Errorf("%s: "+format, append([]any{c.name()}, args...)...)
		}
	}
	switch {
	case d.State == c.want:
	case c.want == GateNotAffected && d.State == GateUndecided:
		r.soft++
	default:
		fail("I1: gate %s (%s), oracle %s", d.State, d.Cause, c.want)
	}
	if d.State == GateNotAffected {
		r.closed++
		if d.By == nil || d.By.Says != SaysNotAffected {
			fail("I1: closed without a not-affected proof")
		}
	}
	if d.State == GateUndecided && d.Cause == "" { // I3
		fail("I3: undecided without a cause")
	}
	// I4: an affected statement that covers everything, or a blocker, never closes; a not-affected proof taken away never closes
	every := Proof{Kind: ProofFixedAt, CVE: mCVE, Src: ProofSource{Format: FormatCVE5, Ref: "zz"}, Says: SaysAffected, Producer: "zz",
		Scope: Scope{Product: mProduct, Origin: OriginSet{Any: true}, Versions: VersionSet{Every: true}, Platform: PlatformSet{Any: true}}}
	if Gate(mCVE, c.in, append(slices.Clip(c.ev), every), c.bl, c.exploited).State == GateNotAffected {
		fail("I4: closed with an affected statement added")
	}
	if Gate(mCVE, c.in, c.ev, append(slices.Clip(c.bl), Blocker{CVE: mCVE, Cause: CauseLostRow}), c.exploited).State == GateNotAffected {
		fail("I4: closed with a blocker added")
	}
	for i, p := range c.ev {
		if p.Says != SaysNotAffected {
			continue
		}
		less := slices.Delete(slices.Clone(c.ev), i, i+1)
		if Gate(mCVE, c.in, less, c.bl, c.exploited).State == GateNotAffected && d.State != GateNotAffected {
			fail("I4: closed once a not-affected proof was taken away")
		}
	}
	// I6: the evidence in reverse order
	rev, revb := slices.Clone(c.ev), slices.Clone(c.bl)
	slices.Reverse(rev)
	slices.Reverse(revb)
	if e := Gate(mCVE, c.in, rev, revb, c.exploited); e.State != d.State || e.Cause != d.Cause || !reflect.DeepEqual(e.By, d.By) {
		fail("I6: reversed evidence gives %s (%s), not %s (%s)", e.State, e.Cause, d.State, d.Cause)
	}
}

// pairs is every (i, x) of i in [0, n) and x in xs, as an iterator of two values.
func pairs(n int, xs []int) func(yield func(int, int) bool) {
	return func(yield func(int, int) bool) {
		for i := range n {
			for _, x := range xs {
				if !yield(i, x) {
					return
				}
			}
		}
	}
}

func mInstall(io int, sh int) Installation {
	s := mShapes[sh]
	return Installation{Device: "d", Line: "l", InstallKey: "A", Product: []ProductRef{mProduct}, Origin: mInstallOrigins[io],
		Version: VersionValue{Scheme: s.scheme, Raw: s.raw}, ReleaseLine: s.line, Platform: mPlatform}
}

// oracle is the oracle's answer from the containment of the main proof (cont), the evidence kind, whether the kind may close (allowed),
// whether an affected statement contains the installation (affY), may contain it (affU), and whether a blocker applies.
func oracle(kind int, cont tv, allowed, affY, affU, blocked bool) GateState {
	switch {
	case affY || kind == mkAffected && cont == tY:
		return GateAffected
	case affU || kind == mkAffected && cont == tU, blocked:
		return GateUndecided
	case kind < mkAffected && allowed && cont == tY:
		return GateNotAffected
	}
	return GateUndecided
}

func TestGateMatrix_LayerA(t *testing.T) {
	t.Parallel()
	r := &matrixRun{t: t}
	// Full product: version set × scope origin × installation origin × version shape × kind × opposing evidence.
	for vs := range mVersionSets {
		for so := range mScopeOrigins {
			for io := range mInstallOrigins {
				for sh := range mShapes {
					in := mInstall(io, sh)
					cont := and(oOrigin[so][io], oVersion[vs][sh])
					for k := range mKinds {
						var main []Proof
						allowed := false
						if k != mkNone {
							f := FormatCVE5
							if k < mkAffected {
								f, allowed = mNaturalFormat[k], oShape[k][vs]
							}
							main = []Proof{mProof(k, f, Scope{Product: mProduct, Origin: mScopeOrigins[so], Versions: mVersionSets[vs], Platform: platformOf(k)})}
						}
						for op := range 4 {
							ev, bl := slices.Clone(main), []Blocker(nil)
							affY, affU, blocked := false, false, false
							switch op {
							case 1: // an affected statement about every version
								ev = append(ev, Proof{Kind: ProofFixedAt, CVE: mCVE, Src: ProofSource{Format: FormatNVDCPE, Ref: "every"}, Says: SaysAffected, Producer: "op",
									Scope: Scope{Product: mProduct, Origin: OriginSet{Any: true}, Versions: VersionSet{Every: true}, Platform: PlatformSet{Any: true}}})
								affY = true
							case 2: // an affected statement about another exact version
								ev = append(ev, Proof{Kind: ProofFixedAt, CVE: mCVE, Src: ProofSource{Format: FormatNVDCPE, Ref: "9.9"}, Says: SaysAffected, Producer: "op",
									Scope: Scope{Product: mProduct, Origin: OriginSet{Any: true}, Versions: VersionSet{Scheme: SchemeGeneric, Exact: []string{"9.9"}}, Platform: PlatformSet{Any: true}}})
								affY, affU = oExact99[sh] == tY, oExact99[sh] == tU
							case 3:
								bl, blocked = []Blocker{{CVE: mCVE, Cause: CauseLostRow, Producer: "op"}}, true
							}
							r.check(mCase{name: func() string { return fmt.Sprintf("full vs%d so%d io%d sh%d k%d op%d", vs, so, io, sh, k, op) }, in: in, ev: ev, bl: bl,
								want: oracle(k, cont, allowed, affY, affU, blocked)})
						}
					}
				}
			}
		}
	}
	full := r.cases
	// Pairwise: format × kind × version set × exploited × the CVE record's defaultStatus, on upstream 2.5 (shape 4) and 0.9 (shape 0,
	// below every start: what a before-introduced span contains), plus formats that are not declared (I2).
	formats := []Format{FormatCVE5, FormatNVDCPE, FormatOSV, FormatCSAF, FormatOpenVEX, FormatDistroTracker, FormatMSRelease, FormatLineSource, FormatPerson, 0, 200}
	for _, f := range formats {
		for k, sh := range pairs(len(mKindOf), []int{4, 0}) {
			for vs := range mVersionSets {
				for _, exploited := range []bool{false, true} {
					for _, def := range []bool{false, true} {
						p := mProof(k, f, Scope{Product: mProduct, Origin: OriginSet{Upstream: true}, Versions: mVersionSets[vs], Platform: platformOf(k)})
						p.Src.DefaultUnaffected = def
						shape := oShape[k][vs]
						switch {
						case vs == 5: // all but the listed: OSV, or a CVE record whose default is unaffected
							shape = (k != mkFixed && k != mkBefore) && (f == FormatOSV || f == FormatCVE5 && def)
						case k == mkBefore && f == FormatCVE5:
							shape = shape && def
						}
						allowed := shape && oFormatKind[f][k] && (!exploited || k != mkBefore && k != mkHardware)
						r.check(mCase{name: func() string {
							return fmt.Sprintf("format %s k%d vs%d sh%d exploited=%v default=%v", f, k, vs, sh, exploited, def)
						}, in: mInstall(0, sh),
							ev: []Proof{p}, exploited: exploited, want: oracle(k, oVersion[vs][sh], allowed, false, false, false)})
					}
				}
			}
		}
	}
	// Pairwise: platform. Installation platforms × scope platforms × kinds that read it.
	installs := []Platform{mPlatform, {OS: "linux", Hardware: "srx300"}, {OS: "linux", Arch: "x86_64"}, {OS: "linux", Arch: "arm64", Hardware: "srx300"}, {OS: "linux", Arch: "x86_64", Hardware: "mx480"}}
	scopes := []PlatformSet{{Any: true}, {Arch: []string{"arm64"}, Except: true}, {Hardware: []string{"mx480"}, Except: true}, {Arch: []string{"x86_64"}}, {OS: []string{"windows"}}, {}}
	oPlatform := [6][5]tv{
		// full noarch nohw arm64 mx480
		{tY, tY, tY, tY, tY}, // any
		{tY, tU, tY, tN, tY}, // all but arm64
		{tY, tY, tU, tY, tN}, // all but mx480
		{tY, tU, tY, tN, tY}, // x86_64 only
		{tN, tN, tN, tN, tN}, // windows only
		{tU, tU, tU, tU, tU}, // no platform named: says nothing
	}
	oPlatformShape := map[int][6]bool{ // may the kind close with this scope platform
		mkStated:   {true, true, true, true, true, true},
		mkPlatform: {false, true, false, true, true, false},
		mkHardware: {false, false, true, false, false, false},
	}
	for si, sp := range scopes {
		for ii, ip := range installs {
			for _, k := range []int{mkStated, mkPlatform, mkHardware} {
				in := mInstall(0, 4)
				in.Platform = ip
				p := mProof(k, FormatCVE5, Scope{Product: mProduct, Origin: OriginSet{Upstream: true}, Versions: VersionSet{Every: true}, Platform: sp})
				r.check(mCase{name: func() string { return fmt.Sprintf("platform s%d i%d k%d", si, ii, k) }, in: in, ev: []Proof{p},
					want: oracle(k, oPlatform[si][ii], oPlatformShape[k][si], false, false, false)})
			}
		}
	}
	// Pairwise: product. The installation's names × the proof's product.
	inProducts := [][]ProductRef{{mProduct}, {{"acme", "widget pro"}, mProduct}, {{"other", "thing"}}, nil}
	scProducts := []ProductRef{mProduct, {"ACME", "Widget"}, {}}
	oProduct := [3][4]tv{{tY, tY, tN, tU}, {tY, tY, tN, tU}, {tU, tU, tU, tU}}
	for si, sp := range scProducts {
		for ii, ip := range inProducts {
			for k := range mKindOf {
				in := mInstall(0, 4)
				in.Product = ip
				p := mProof(k, mNaturalFormat[k], Scope{Product: sp, Origin: OriginSet{Upstream: true}, Versions: mVersionSets[1], Platform: platformOf(k)})
				r.check(mCase{name: func() string { return fmt.Sprintf("product s%d i%d k%d", si, ii, k) }, in: in, ev: []Proof{p},
					want: oracle(k, and(oProduct[si][ii], oVersion[1][4]), oShape[k][1], false, false, false)})
			}
		}
	}
	// Pairwise: sibling installations (I5): a proof pinned to installation A never closes B.
	for _, pin := range []string{"", "A", "B"} {
		for _, key := range []string{"A", "B"} {
			for k := range mKindOf {
				in := mInstall(0, 4)
				in.InstallKey = key
				p := mProof(k, mNaturalFormat[k], Scope{Product: mProduct, Origin: OriginSet{Upstream: true}, Versions: mVersionSets[1], Platform: platformOf(k), Install: pin})
				own := tY
				if pin != "" && pin != key {
					own = tN
				}
				c := mCase{name: func() string { return fmt.Sprintf("sibling pin=%q key=%s k%d", pin, key, k) }, in: in, ev: []Proof{p},
					want: oracle(k, and(own, oVersion[1][4]), oShape[k][1], false, false, false)}
				r.check(c)
				if own == tN && Gate(mCVE, in, c.ev, nil, false).State == GateNotAffected {
					t.Errorf("I5: %s closed", c.name())
				}
			}
		}
	}
	blockerCauses := [...]GateCause{CauseLostRow, CauseRowUnread, CauseDistroTriage, CauseRecordClash}
	// Pairwise: other opposing evidence (each blocker cause, a blocker, an affected and a not-affected statement about another CVE, a
	// second not-affected proof that does not contain the version) × kind × version set × shape, on upstream.
	for op := range 7 {
		for k := range mKinds {
			for vs := range mVersionSets {
				for sh := range mShapes {
					in := mInstall(0, sh)
					var ev []Proof
					allowed := false
					if k != mkNone {
						f := FormatCVE5
						if k < mkAffected {
							f, allowed = mNaturalFormat[k], oShape[k][vs]
						}
						ev = []Proof{mProof(k, f, Scope{Product: mProduct, Origin: OriginSet{Upstream: true}, Versions: mVersionSets[vs], Platform: platformOf(k)})}
					}
					var bl []Blocker
					blocked := false
					switch op {
					case 0, 1, 2, 3:
						bl, blocked = []Blocker{{CVE: mCVE, Cause: blockerCauses[op%len(blockerCauses)]}}, true
					case 4: // a blocker of another CVE
						bl = []Blocker{{CVE: "CVE-2026-0002", Cause: CauseLostRow}}
					case 5: // statements about another CVE, either way
						ev = append(ev, Proof{Kind: ProofFixedAt, CVE: "CVE-2026-0002", Src: ProofSource{Format: FormatCVE5, Ref: "o1"}, Says: SaysAffected, Producer: "op",
							Scope: Scope{Product: mProduct, Origin: OriginSet{Any: true}, Versions: VersionSet{Every: true}, Platform: PlatformSet{Any: true}}},
							Proof{Kind: ProofStatedUnaffected, CVE: "CVE-2026-0002", Src: ProofSource{Format: FormatCVE5, Ref: "o2"}, Says: SaysNotAffected, Producer: "op",
								Scope: Scope{Product: mProduct, Origin: OriginSet{Any: true}, Versions: VersionSet{Every: true}, Platform: PlatformSet{Any: true}}})
					case 6: // a person's answer about another version
						ev = append(ev, Proof{Kind: ProofPersonNotAffected, CVE: mCVE, Src: ProofSource{Format: FormatPerson, Ref: "p"}, Says: SaysNotAffected, Producer: "op",
							Scope: Scope{Product: mProduct, Origin: OriginSet{Any: true}, Versions: VersionSet{Scheme: SchemeGeneric, Exact: []string{"9.9"}}, Platform: PlatformSet{Any: true}}})
					}
					r.check(mCase{name: func() string { return fmt.Sprintf("opposing op%d k%d vs%d sh%d", op, k, vs, sh) }, in: in, ev: ev, bl: bl,
						want: oracle(k, and(oOrigin[1][0], oVersion[vs][sh]), allowed, false, false, blocked)})
				}
			}
		}
	}
	t.Logf("cases %d (full product %d), closed %d, soft count (oracle closes, gate does not) %d", r.cases, full, r.closed, r.soft)
	if full != 7*6*5*12*8*4 {
		t.Errorf("full product has %d cases, want %d", full, 7*6*5*12*8*4)
	}
}

// TestGate_NoModelFormat: the declared formats are the published standards and a person; none is a model's reading (I2).
func TestGate_NoModelFormat(t *testing.T) {
	t.Parallel()
	for f := Format(0); f < 255; f++ {
		if !f.known() {
			continue
		}
		switch f.String() {
		case "cve5", "nvd_cpe", "osv", "csaf", "openvex", "distro_tracker", "ms_release", "line_source", "person":
		default:
			t.Errorf("format %d (%s) is not one of the published standards or a person", f, f)
		}
	}
}

// A scope's versions are read strictly: a build or revision tail the order ignores (CompareVersions) does not make two versions equal,
// so a fix at one build never contains an earlier build of the same release.
func TestGate_VersionTailsReadStrictly(t *testing.T) {
	t.Parallel()
	in := mInstall(0, 4)
	for _, c := range []struct {
		name    string
		install string
		vs      VersionSet
		kind    ProofKind
	}{
		{"fixed at a later build of the release", "13.1-48.47", VersionSet{Scheme: SchemeGeneric, Ranges: []Span{{From: "13.1-49.15"}}}, ProofFixedAt},
		{"stated unaffected for another build", "7.0.0 build 1300", VersionSet{Scheme: SchemeGeneric, Exact: []string{"7.0.0 build 1234"}}, ProofStatedUnaffected},
		{"fixed at a build, installation states no build", "13.1", VersionSet{Scheme: SchemeGeneric, Ranges: []Span{{From: "13.1-49.15"}}}, ProofFixedAt},
	} {
		in.Version = VersionValue{Scheme: SchemeGeneric, Raw: c.install}
		p := Proof{Kind: c.kind, CVE: mCVE, Src: ProofSource{Format: FormatCVE5, Ref: "r"}, Says: SaysNotAffected,
			Scope: Scope{Product: mProduct, Origin: OriginSet{Upstream: true}, Versions: c.vs, Platform: PlatformSet{Any: true}}}
		if d := Gate(mCVE, in, []Proof{p}, nil, false); d.State == GateNotAffected {
			t.Errorf("%s: %s closed", c.name, c.install)
		}
	}
}

// A before-introduced proof is a span below the introduction: "every version but those below it" states the opposite and never
// closes as an introduction, in any format.
func TestGate_BeforeIntroducedIsASpanBelowTheIntroduction(t *testing.T) {
	t.Parallel()
	in := mInstall(0, 4) // upstream 2.5
	for _, f := range []Format{FormatOSV, FormatCVE5} {
		p := Proof{Kind: ProofBeforeIntroduced, CVE: mCVE, Src: ProofSource{Format: f, Ref: "r", DefaultUnaffected: true}, Says: SaysNotAffected,
			Scope: Scope{Product: mProduct, Origin: OriginSet{Upstream: true}, Platform: PlatformSet{Any: true},
				Versions: VersionSet{Scheme: SchemeGeneric, Ranges: []Span{{To: "1.0"}}, AllExceptListed: true}}}
		if d := Gate(mCVE, in, []Proof{p}, nil, false); d.State == GateNotAffected {
			t.Errorf("%s: 2.5 closed as older than an introduction at 1.0", f)
		}
	}
}

// A statement with no direction is neither proof nor conflict: it never closes.
func TestGate_StatementWithoutDirectionNeverCloses(t *testing.T) {
	t.Parallel()
	p := mProof(mkStated, FormatCVE5, Scope{Product: mProduct, Origin: OriginSet{Any: true}, Versions: VersionSet{Every: true}, Platform: PlatformSet{Any: true}})
	p.Says = 0
	if d := Gate(mCVE, mInstall(0, 4), []Proof{p}, nil, false); d.State != GateUndecided || d.Cause != CauseNoProof {
		t.Errorf("gate %s (%s), want undecided (%s)", d.State, d.Cause, CauseNoProof)
	}
}

// "Every version but those listed" with nothing listed is not a statement about any version: it never closes.
func TestGate_AllButNothingListedNeverCloses(t *testing.T) {
	t.Parallel()
	p := mProof(mkStated, FormatCVE5, Scope{Product: mProduct, Origin: OriginSet{Any: true}, Platform: PlatformSet{Any: true},
		Versions: VersionSet{Scheme: SchemeGeneric, AllExceptListed: true}})
	p.Src.DefaultUnaffected = true
	if d := Gate(mCVE, mInstall(0, 4), []Proof{p}, nil, false); d.State == GateNotAffected {
		t.Errorf("closed by an all-but-listed statement that lists nothing")
	}
}
