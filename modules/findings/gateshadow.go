package findings

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// The closing gate in shadow. Each step of the matcher that ends a pair as "not affected" (outNotAffected) or "ruled out"
// (outRuledOut) also says what the gate would read from it (gateShadow): the proofs the step's data states, with their scope, and the
// blockers. The coverage of a pass and the closing of a finding that went away ask Gate with them and record its answer beside their
// own (pairState.gate, covers.gate: in memory only). Nothing here changes a finding, a question or a count of the coverage.

// The producers: the matcher step a shadow comes from.
const (
	prodDistroFixed      = "distro_fixed"          // the distribution's fixed package release
	prodDistroNot        = "distro_not_affected"   // the distribution's word that its package is not affected
	prodPlatformFixed    = "platform_distro_fixed" // the platform list's step that reads the distribution's fix
	prodPlatformList     = "platform_list"         // the platform list (hand data)
	prodEdgeLegacy       = "edge_legacy"           // an Edge Legacy CVE on Chromium Edge (an identity rule)
	prodLineFixed        = "line_fixed"            // a vendor's line statement: fixed, last affected or introduced
	prodLineUnaffected   = "line_unaffected"       // a vendor's line statement: the line is not affected
	prodLineConvention   = "line_convention"       // a line source's convention for lines it does not list
	prodSchemeFixed      = "scheme_fixed"          // the vendor's rows read in its scheme: past the fix of the train
	prodSchemeBefore     = "scheme_before"         // older than the first release the rows list
	prodSchemeStated     = "scheme_stated"         // the vendor's statements of unaffected releases
	prodSchemeElsewhere  = "scheme_elsewhere"      // listed only on other hardware
	prodRanges           = "ranges"                // NVD's or the CVE record's ranges, row by row
	prodPastRecordFix    = "past_record_fix"       // past a fix a partial record states for the train
	prodOSList           = "os_list"               // NVD lists only other releases of the device's OS
	prodWindowsRelease   = "windows_release"       // the Windows release's own monthly update data
	prodWindowsSibling   = "windows_sibling"       // read with the rows of another Windows release on the same build
	prodEveryReading     = "every_reading"         // every reading of the record gave the verdict
	prodOtherSeries      = "other_series"          // the exploited list names other Juniper series
	prodOthersOnly       = "others_only"           // NVD lists other products only
	prodRuledOutNoProof  = "ruled_out_no_proof"    // outside every row with nothing that proves it
	prodGoneNoLine       = "gone_no_line"          // a finding on no line that is not detected any more
	gateWouldIdentity    = "identity"              // the step is an identity rule: not a decision about this product
	gateWouldExit        = "exit"                  // a finding that went away for a reason other than data (removed, not installed)
	gateWouldHeld        = "held"                  // a finding the gate would keep: still listed, with its cause
	gateWouldNotAffected = "not_affected"
)

// gateShadow is what the gate reads from one matcher step: the producer, the proofs and blockers, and what the step established about
// the installation (product names the identity rules matched to the line, the release line and the version as the step's source
// numbers them).
type gateShadow struct {
	producer string
	proofs   []Proof
	blockers []Blocker
	identity bool
	products []ProductRef
	line     string
	ver      string
}

// ShadowGate switches the closing gate's shadow on or off for the next passes: with it on, each closing step records what the gate
// would read from it, and the pass keeps the gate's answers in memory beside its counts (for measurement runs; nothing reads them to
// decide). Off by default, and then no shadow work is done.
func (s *Service) ShadowGate(on bool) { s.gateShadow.Store(on) }

// shadowGate makes every row of the device match record the gate's shadow.
func (d *devMatch) shadowGate() {
	for i := range d.infos {
		d.infos[i].shadow = true
	}
	for _, r := range d.own {
		if r != nil {
			r.info.shadow = true
		}
	}
}

// The shadows of the steps that state nothing are the same for every pair.
var stopShadows = func() map[string]*gateShadow {
	m := map[string]*gateShadow{}
	for _, p := range []string{prodOtherSeries, prodPlatformList, prodOthersOnly, prodRuledOutNoProof, prodOSList, prodWindowsSibling, prodEveryReading} {
		m[p] = &gateShadow{producer: p}
	}
	m[prodEdgeLegacy] = &gateShadow{producer: prodEdgeLegacy, identity: true}
	return m
}()

// shadowStop is a step the gate takes no proof from: whatever it decides, the gate leaves the pair undecided (no_proof). nil when the
// row records no shadow.
func shadowStop(in swInfo, producer string) *gateShadow {
	if !in.shadow {
		return nil
	}
	return stopShadows[producer]
}

// shadowIdentity is a step that is an identity rule (not a decision about this product); nil when the row records no shadow.
func shadowIdentity(in swInfo, producer string) *gateShadow {
	if !in.shadow {
		return nil
	}
	return stopShadows[producer]
}

// distroID is the distribution whose data judges a packaged row and the device's release as it names it ("" when none).
func distroID(in swInfo) (string, string) {
	if in.pkgDistro == nil {
		return "", ""
	}
	return in.pkgDistro.id, in.pkgRel
}

func distroScheme(distro string) string {
	if distro == "alpine" {
		return SchemeAPK
	}
	return SchemeDeb
}

// shadowDistro is the distribution's answer d (fixed release or not affected) as a proof: the package of the distribution's own build
// of the release (and pocket) it speaks for.
func shadowDistro(in swInfo, v Vuln, d distroAnswer) *gateShadow {
	if !in.shadow {
		return nil
	}
	distro, _ := distroID(in)
	b := Origin{Kind: OriginDistro, Distro: distro, Release: cmp.Or(d.from, d.release)}
	if d.pro {
		b.Pocket = "esm"
	}
	p := Proof{CVE: v.CVE, Says: SaysNotAffected, Src: ProofSource{Format: FormatDistroTracker, Publisher: d.name, Ref: DistroSource(d.name)},
		Scope: Scope{Product: ProductRef{Vendor: distro, Product: d.pkg}, Origin: OriginSet{Builds: []Origin{b}}, Platform: PlatformSet{Any: true}}}
	if d.kind == distroNotAffected {
		p.Kind, p.Producer, p.Scope.Versions = ProofStatedUnaffected, prodDistroNot, VersionSet{Every: true}
	} else {
		p.Kind, p.Producer = ProofFixedAt, prodDistroFixed
		p.Scope.Versions = VersionSet{Scheme: distroScheme(distro), Ranges: []Span{{From: d.fixed}}}
	}
	return &gateShadow{producer: p.Producer, proofs: []Proof{p}}
}

// ownProduct is the first name the line is identified by (never one an AI chose); zero when none.
func ownProduct(in swInfo) ProductRef {
	for _, id := range in.ids {
		if !id.ai {
			return ProductRef{Vendor: id.vendor, Product: id.product}
		}
	}
	return ProductRef{}
}

// asRead is a proof whose version scope is the installation's version as the step read it (its own check of the version is taken as
// it is: the producer's own scope is not modelled yet), for the product the line is identified by, upstream builds only.
func asRead(producer string, k ProofKind, f Format, v Vuln, in swInfo, ver string) Proof {
	vs := VersionSet{Scheme: SchemeGeneric, Ranges: []Span{{From: ver, To: ver, ToIncl: true}}}
	switch k {
	case ProofBeforeIntroduced:
		vs.Ranges = []Span{{To: ver, ToIncl: true}}
	case ProofStatedUnaffected, ProofOtherHardware, ProofOtherPlatform:
		vs = VersionSet{Every: true}
	}
	return Proof{Kind: k, CVE: v.CVE, Says: SaysNotAffected, Producer: producer, Src: ProofSource{Format: f},
		Scope: Scope{Product: ownProduct(in), Origin: OriginSet{Upstream: true}, Versions: vs, Platform: PlatformSet{Any: true}}}
}

// rowsFormat is the format of v's rows: NVD's CPE configurations, or the CNA's CVE record.
func rowsFormat(origin string) Format {
	if origin == RangeNVD || origin == "" {
		return FormatNVDCPE
	}
	return FormatCVE5
}

// shadowPlatformFixed is the platform list's distribution step: the distribution's fix, taken as read.
func shadowPlatformFixed(v Vuln, in swInfo) *gateShadow {
	if !in.shadow {
		return nil
	}
	distro, rel := distroID(in)
	ver := cmp.Or(strings.TrimSpace(in.pkgVer), strings.TrimSpace(in.personPkg))
	p := asRead(prodPlatformFixed, ProofFixedAt, FormatDistroTracker, v, in, ver)
	p.Scope.Versions.Scheme = distroScheme(distro)
	p.Scope.Origin = OriginSet{Builds: []Origin{{Kind: OriginDistro, Distro: distro, Release: rel}}}
	return &gateShadow{producer: prodPlatformFixed, proofs: []Proof{p}}
}

// shadowSchemed is the vendor's own verdict: a release-line statement (lr, when it decides) or the vendor's rows read in its scheme.
func shadowSchemed(v Vuln, in swInfo, lr lineRead, sr schemeRead) *gateShadow {
	if !in.shadow {
		return nil
	}
	if lr.decides() {
		return shadowLine(v, in, lr)
	}
	f := rowsFormat(sr.origin)
	switch {
	case sr.before != nil:
		return &gateShadow{producer: prodSchemeBefore, proofs: []Proof{asRead(prodSchemeBefore, ProofBeforeIntroduced, f, v, in, in.ver)}}
	case len(sr.elsewhere) > 0:
		p := asRead(prodSchemeElsewhere, ProofOtherHardware, f, v, in, in.ver)
		p.Scope.Platform = PlatformSet{Hardware: sr.elsewhere, Except: true}
		return &gateShadow{producer: prodSchemeElsewhere, proofs: []Proof{p}}
	case sr.stated:
		return &gateShadow{producer: prodSchemeStated, proofs: []Proof{asRead(prodSchemeStated, ProofStatedUnaffected, f, v, in, in.ver)}}
	}
	return &gateShadow{producer: prodSchemeFixed, proofs: []Proof{asRead(prodSchemeFixed, ProofFixedAt, f, v, in, in.ver)}}
}

// shadowLine is a vendor's release-line statement as a proof about the line it names: a fix, a last affected release or an
// introduction on that line, or the line stated not affected. A convention for lines the source does not list states nothing.
func shadowLine(v Vuln, in swInfo, lr lineRead) *gateShadow {
	g := &gateShadow{line: lr.line, ver: lr.ver}
	if p := ownProduct(in); !p.zero() {
		g.products = []ProductRef{p}
	}
	base := Proof{CVE: v.CVE, Says: SaysNotAffected, Src: ProofSource{Format: FormatLineSource, Ref: lr.cover.Ref},
		Scope: Scope{Product: ownProduct(in), Origin: OriginSet{Upstream: true}, Platform: PlatformSet{Any: true}}}
	switch {
	case lr.convention:
		g.producer = prodLineConvention
		return g
	case lr.verdict == lineUnaffected:
		g.producer = prodLineUnaffected
		base.Kind, base.Scope.Versions = ProofStatedUnaffected, VersionSet{Every: true, Lines: []string{lr.line}}
	default:
		g.producer = prodLineFixed
		vs := VersionSet{Scheme: SchemeGeneric, Lines: []string{lr.line}}
		switch {
		case lr.row.Introduced != "" && (VersionRange{EndExcl: lr.row.Introduced}).Contains(lr.ver) == Yes:
			base.Kind, vs.Ranges = ProofBeforeIntroduced, []Span{{To: lr.row.Introduced}}
		case lr.row.Fixed != "":
			base.Kind, vs.Ranges = ProofFixedAt, []Span{{From: lr.row.Fixed}}
		default:
			base.Kind, vs.Ranges = ProofFixedAt, []Span{{From: lr.row.LastAffected, FromExcl: true}}
		}
		base.Scope.Versions = vs
	}
	base.Producer = g.producer
	g.proofs = []Proof{base}
	return g
}

// shadowRanges is a "not affected" from the ranges of judgeRanges' last step: the OS release list, a Windows release's own data or a
// sibling release's, every reading of the record, a partial record's fix, or the rows themselves (rangeProofs).
func shadowRanges(in swInfo, v Vuln, key []identity, proof proofKind, via, agreed bool) *gateShadow {
	switch {
	case !in.shadow:
		return nil
	case agreed:
		return shadowStop(in, prodEveryReading)
	case proof == proofOS:
		return shadowStop(in, prodOSList)
	case proof == proofRelease:
		return &gateShadow{producer: prodWindowsRelease, proofs: []Proof{asRead(prodWindowsRelease, ProofFixedAt, FormatMSRelease, v, in, in.ver)}}
	case via:
		return shadowStop(in, prodWindowsSibling)
	case v.RangesFrom == RangesCVEOrgPartial:
		return &gateShadow{producer: prodPastRecordFix, proofs: []Proof{asRead(prodPastRecordFix, ProofFixedAt, FormatCVE5, v, in, in.ver)}}
	}
	return rangeProofs(in, v, key)
}

// rangeProofs reads v's rows that name the line (its own names, or the exploited list's key) one by one. Each row's affected span is
// an affected statement; a row's end is a fix (an excluded end) or a last affected release (an included end) on its line: the fix holds
// up to the next row's start, and past the last row only when the rows are one line of releases (no two rows start on different
// release lines); a record that lists every affected version (VendorList) states every other version not affected. A row of a product
// only the exploited list's key names is a statement about that product, not about the line's. A row the reader lost blocks.
func rangeProofs(in swInfo, v Vuln, key []identity) *gateShadow {
	g := &gateShadow{producer: prodRanges}
	f := FormatNVDCPE
	if v.RangesFrom != "" {
		f = FormatCVE5
	}
	type row struct {
		af  Affected
		ref ProductRef
	}
	var rows []row
	starts := map[ProductRef][]string{} // the starts and exact versions of each product's rows
	lines := map[ProductRef]map[string]bool{}
	sib := siblingsOf(&v)
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA {
			continue
		}
		own, byKey, _ := entryFor(c, in, key)
		if !own && !byKey {
			continue
		}
		if _, ok := in.install.judge(c, in.cpe, in.hasCPE, sib); !ok { // a row of another edition, system or architecture
			continue
		}
		vn, _ := c.Vendor.Literal()
		pn, _ := c.Product.Literal()
		ref := ProductRef{Vendor: vn, Product: pn}
		if own {
			g.products = append(g.products, ref)
		}
		if af.Lost {
			g.blockers = append(g.blockers, Blocker{CVE: v.CVE, Cause: CauseLostRow, Producer: prodRanges})
		}
		rows = append(rows, row{af, ref})
		r := af.Range
		for _, st := range []string{r.StartIncl, r.StartExcl} {
			if st != "" && st != "0" {
				starts[ref] = append(starts[ref], st)
				if lines[ref] == nil {
					lines[ref] = map[string]bool{}
				}
				lines[ref][lineOfVersion(st)] = true
			}
		}
		if ver, ok := c.Version.Literal(); ok && r.IsZero() && ver != "" && ver != "*" && ver != "-" {
			starts[ref] = append(starts[ref], ver)
		}
	}
	listed := map[ProductRef]*VersionSet{} // a complete list's affected versions, per product
	everyListed := map[ProductRef]bool{}   // a complete list that lists every version: nothing else is stated
	for _, x := range rows {
		r, ref := x.af.Range, x.ref
		src := ProofSource{Format: f, Publisher: cmp.Or(v.rangeOrigin(), RangeNVD), Ref: x.af.CPE, DefaultUnaffected: x.af.VendorList}
		base := Scope{Product: ref, Origin: OriginSet{Upstream: true}, Platform: PlatformSet{Any: true}}
		aff := Proof{Kind: ProofFixedAt, CVE: v.CVE, Src: src, Says: SaysAffected, Producer: prodRanges, Scope: base}
		var span *Span
		switch {
		case r.IsZero():
			c, _ := x.af.cpe()
			if ver, ok := c.Version.Literal(); ok && ver != "" && ver != "*" && ver != "-" {
				aff.Scope.Versions = VersionSet{Scheme: SchemeGeneric, Exact: []string{ver}}
			} else {
				aff.Scope.Versions = VersionSet{Every: true}
			}
		default:
			sp := Span{From: cmp.Or(r.StartIncl, r.StartExcl), FromExcl: r.StartIncl == "" && r.StartExcl != "", To: cmp.Or(r.EndExcl, r.EndIncl), ToIncl: r.EndExcl == "" && r.EndIncl != ""}
			if sp.From == "0" {
				sp.From = ""
			}
			span = &sp
			aff.Scope.Versions = VersionSet{Scheme: SchemeGeneric, Ranges: []Span{sp}}
		}
		g.proofs = append(g.proofs, aff)
		if x.af.VendorList {
			if aff.Scope.Versions.Every {
				everyListed[ref] = true
			}
			if listed[ref] == nil {
				listed[ref] = &VersionSet{Scheme: SchemeGeneric, AllExceptListed: true}
			}
			listed[ref].Ranges = append(listed[ref].Ranges, aff.Scope.Versions.Ranges...)
			listed[ref].Exact = append(listed[ref].Exact, aff.Scope.Versions.Exact...)
		}
		if span == nil || span.To == "" || x.af.AffectedOnly {
			continue
		}
		fix := Proof{Kind: ProofFixedAt, CVE: v.CVE, Src: src, Says: SaysNotAffected, Producer: prodRanges, Scope: base}
		fix.Scope.Versions = VersionSet{Scheme: SchemeGeneric, Ranges: []Span{{From: span.To, FromExcl: span.ToIncl, To: nextStart(span.To, starts[ref], len(lines[ref]) > 1)}}}
		g.proofs = append(g.proofs, fix)
	}
	for ref, l := range listed {
		if everyListed[ref] {
			continue
		}
		g.proofs = append(g.proofs, Proof{Kind: ProofStatedUnaffected, CVE: v.CVE, Says: SaysNotAffected, Producer: prodRanges,
			Src:   ProofSource{Format: FormatCVE5, Publisher: cmp.Or(v.rangeOrigin(), RangeCNA), DefaultUnaffected: true},
			Scope: Scope{Product: ref, Origin: OriginSet{Upstream: true}, Versions: *l, Platform: PlatformSet{Any: true}}})
	}
	return g
}

// nextStart is where a fix at end stops holding: the lowest start or listed version of the product's rows above it; past every row,
// nowhere when the rows are one line of releases, else at the next release line (branched).
func nextStart(end string, starts []string, branched bool) string {
	next := ""
	for _, st := range starts {
		if c, ok := CompareVersions(st, end); ok && c > 0 {
			if next == "" {
				next = st
			} else if c2, ok := CompareVersions(st, next); ok && c2 < 0 {
				next = st
			}
		}
	}
	if next != "" || !branched {
		return next
	}
	return nextLine(end)
}

// lineOfVersion is the release line of a version as its first two numbers ("2.4" of "2.4.58"), or its first number alone.
func lineOfVersion(ver string) string {
	nums := leadingNumbers(ver, 2)
	switch len(nums) {
	case 0:
		return ver
	case 1:
		return strconv.FormatUint(nums[0], 10)
	}
	return fmt.Sprintf("%d.%d", nums[0], nums[1])
}

// nextLine is the first release of the line after ver's ("2.5" after "2.4.58"); ver itself when it has no number (an empty span).
func nextLine(ver string) string {
	nums := leadingNumbers(ver, 2)
	switch len(nums) {
	case 0:
		return ver
	case 1:
		return strconv.FormatUint(nums[0]+1, 10)
	}
	return fmt.Sprintf("%d.%d", nums[0], nums[1]+1)
}

// leadingNumbers is up to n dot-separated numbers ver starts with.
func leadingNumbers(ver string, n int) []uint64 {
	var out []uint64
	for _, part := range strings.SplitN(strings.TrimPrefix(strings.ToLower(ver), "v"), ".", n+1) {
		end := 0
		for end < len(part) && isDigit(part[end]) {
			end++
		}
		if end == 0 || len(out) == n {
			break
		}
		x, err := strconv.ParseUint(part[:end], 10, 64)
		if err != nil {
			break
		}
		out = append(out, x)
		if end < len(part) {
			break
		}
	}
	return out
}

// installationOf is the line of row s (read as in) as the gate reads it, with what the steps in gs established about it.
func installationOf(a Asset, s Software, in swInfo, gs []*gateShadow) Installation {
	line := storedLine(s.ID)
	out := Installation{Device: a.ID, Line: line, InstallKey: line, Origin: Origin{Kind: OriginUpstream},
		Version: VersionValue{Scheme: SchemeGeneric, Raw: strings.TrimSpace(in.ver)}}
	for _, id := range in.ids {
		if !id.ai {
			out.Product = append(out.Product, ProductRef{Vendor: id.vendor, Product: id.product})
		}
	}
	if in.pkgBuilt() {
		distro, rel := distroID(in)
		out.Origin = Origin{}
		if distro != "" {
			out.Origin = Origin{Kind: OriginDistro, Distro: distro, Release: rel}
			if strings.Contains(in.pkgVer, "esm") {
				out.Origin.Pocket = "esm"
			}
		}
		out.Version = VersionValue{Scheme: distroScheme(distro), Raw: cmp.Or(strings.TrimSpace(in.pkgVer), strings.TrimSpace(in.personPkg))}
		if in.pkgSrc != "" {
			out.Product = append(out.Product, ProductRef{Vendor: distro, Product: securitySource(distro, in.pkgSrc)})
		}
	}
	for _, g := range gs {
		out.Product = append(out.Product, g.products...)
		if g.line != "" && out.ReleaseLine == "" {
			out.ReleaseLine = g.line
		}
		if g.ver != "" {
			out.Version = VersionValue{Scheme: SchemeGeneric, Raw: g.ver}
		}
	}
	return out
}

// gateWould is the gate's answer from the steps gs that decided one pair today ("" when none recorded one): its state (or
// gateWouldIdentity), cause and the producer of the first step.
func gateWould(a Asset, s Software, in swInfo, v Vuln, gs []*gateShadow) (would string, cause GateCause, producer string) {
	if len(gs) == 0 {
		return "", "", ""
	}
	if gs[0].identity {
		return gateWouldIdentity, CauseIdentityRule, gs[0].producer
	}
	var ev []Proof
	var bl []Blocker
	for _, g := range gs {
		ev = append(ev, g.proofs...)
		bl = append(bl, g.blockers...)
	}
	d := Gate(v.CVE, installationOf(a, s, in, gs), ev, bl, v.listed())
	return d.State.String(), d.Cause, gs[0].producer
}

// gateCount is how many pairs decided "not affected" (or ruled out) by one source through one step the closing gate would answer one
// way, in shadow: would is the gate's answer (not_affected, undecided, affected, identity), cause its cause when undecided.
type gateCount struct {
	by, producer, would, cause string
	exploited                  bool
	n                          int
}

// gateGone is the closing gate's answer in shadow for a finding a pass closed because the match no longer detects it: via is how it
// closed today; would is exit (a change on the device or a person's word: removed, not installed, identity rejected, or a version
// moved to one the gate proves not affected), not_affected (the gate closes it too), held (the gate would keep it listed, with
// cause) or identity (an identity rule decided).
type gateGone struct {
	device, line, cve, via, would, cause, producer string
	exploited                                      bool
}

// gateReport is a pass's answers of the closing gate in shadow: per group of pairs, and per finding closed as gone.
type gateReport struct {
	would []gateCount
	gone  []gateGone
}

// gateShadowReport is the last pass's gateReport (empty before the first pass). In memory only: never stored or served.
func (s *Service) gateShadowReport() gateReport {
	s.covers.mu.Lock()
	defer s.covers.mu.Unlock()
	return s.covers.gate
}

// sortedGateCounts is the counts of m, the most pairs first.
func sortedGateCounts(m map[gateCount]int) []gateCount {
	out := make([]gateCount, 0, len(m))
	for k, n := range m {
		k.n = n
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b gateCount) int {
		return cmp.Or(cmp.Compare(b.n, a.n), strings.Compare(a.producer, b.producer), strings.Compare(a.would, b.would),
			strings.Compare(a.cause, b.cause), strings.Compare(a.by, b.by), cmp.Compare(exploitedRank(b.exploited), exploitedRank(a.exploited))) // exploited first
	})
	return out
}

func exploitedRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// gateGoneMax bounds the closures a pass keeps in memory for the shadow.
const gateGoneMax = 500

// gateGoneOf is the gate's answer for finding f of device a that closed as gone through via (rejected: a person rejected its
// identity), from the proof of its pair the match made (p, when ok).
func gateGoneOf(a Asset, lines map[string]line, vulns []Vuln, f Finding, via Via, rejected bool, p Match, ok bool) gateGone {
	v := Vuln{CVE: f.CVE}
	for _, x := range vulns {
		if x.CVE == f.CVE {
			v = x
			break
		}
	}
	g := gateGone{device: a.ID, line: f.SoftwareID, cve: f.CVE, via: string(via), exploited: v.listed()}
	if via == ViaNotInstalled || via == ViaSoftwareRemoved || rejected {
		g.would = gateWouldExit
		return g
	}
	l, found := lines[f.SoftwareID]
	if !found {
		g.would, g.cause, g.producer = gateWouldHeld, string(CauseNoProof), prodGoneNoLine
		return g
	}
	var steps []*gateShadow
	if ok && p.gate != nil {
		steps = []*gateShadow{p.gate}
	}
	would, cause, producer := gateWould(a, l.sw, swInfoOn(l.sw, a), v, steps)
	g.producer, g.cause = producer, string(cause)
	switch {
	case would == GateNotAffected.String() && via == ViaVersionMoved:
		g.would = gateWouldExit
	case would == GateNotAffected.String():
		g.would = gateWouldNotAffected
	case would == gateWouldIdentity:
		g.would = gateWouldIdentity
	default:
		g.would, g.cause = gateWouldHeld, string(cmp.Or(cause, CauseNoProof))
	}
	return g
}

// recordGone keeps g for the pass's coverage (one per device, line and CVE; at most gateGoneMax).
func (c *covers) recordGone(g gateGone) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gone == nil {
		c.gone = map[string]gateGone{}
	}
	k := g.device + "\x1f" + g.line + "\x1f" + g.cve
	if _, ok := c.gone[k]; ok || len(c.gone) < gateGoneMax {
		c.gone[k] = g
	}
}

// takeGone is the closures recorded since the last pass, in a fixed order; the record starts again. Called with c.mu held.
func (c *covers) takeGone() []gateGone {
	out := slices.SortedFunc(maps.Values(c.gone), func(a, b gateGone) int {
		return cmp.Or(strings.Compare(a.device, b.device), strings.Compare(a.line, b.line), strings.Compare(a.cve, b.cve))
	})
	c.gone = nil
	return out
}
