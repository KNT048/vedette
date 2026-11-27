package findings

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
)

// Vendor rows. A vendor that states its affected and fixed releases in its own notation (VMware's ESXi builds per update, Citrix's
// NetScaler builds per release line, the kernel's fixed release per stable branch) is read through the version scheme of the product
// (core/versionscheme, declared in the product catalogue): the device's version is placed in its release train and compared with
// the vendor's fixed release of that train, the way the vendor's own advisory reads (and Tenable's per-advisory checks do). When the
// vendor's rows name the device's release line and the scheme places the device's version, the vendor's word decides, before NVD's
// generic ranges (which list ESXi's releases one by one and miss the patch releases between them). Otherwise the generic comparison
// decides, as before. Nothing is guessed: a version the scheme cannot place leaves the decision to the generic comparison.

// schemeRead is what the vendor's rows say about one software line.
type schemeRead struct {
	installed versionscheme.Version
	verdict   versionscheme.Verdict
	stated    bool // not affected by what the vendor states (a range it says is unaffected, its model-limited ranges): vendorStatements
	// before is set when the version is older than the first release the vendor lists as affected (olderThanEveryStart): not affected,
	// the flaw came in with that release. nil otherwise.
	before  *versionscheme.Version
	origin  string // who stated the rows (RangeCNA, RangeADP)
	vendor  string // the product's vendor as the catalogue names it ("VMware")
	product string // the product as the catalogue names it ("VMware ESXi")
}

// buildRE reads the build a device states beside its version ("VMware ESXi 8.0 Update 3 (build 24022510)").
var buildRE = regexp.MustCompile(`\(build ([0-9]{5,9})\)`)

// statedBuild is the build the line's own reading states ("VMware ESXi 8.0 Update 3 (build 24022510)": the device's statement keeps it
// in the line's name), "" when none. Only the line is read, never the device's OS line, so every reader of a row (the matcher, the fix,
// Reachability, which has no device) places it the same way.
func statedBuild(s Software) string {
	if m := buildRE.FindStringSubmatch(s.Display); m != nil {
		return m[1]
	}
	return ""
}

// schemedSpans is the spans of v's vendor rows that name the line's product, with the product's scheme; nil when none. A
// distribution's package is never read by a vendor scheme (the distribution's own data decides it), nor a row a distribution may
// have built on a device that runs one (an Ubuntu kernel reports 6.8.0 while it carries fixes of later stable releases).
// The vendor's rows that only support "not affected" (SchemedRange.Unaffected, ModelOnly) are not among them: vendorRows gives those.
func schemedSpans(a Asset, s Software, in swInfo, v Vuln) (*versionscheme.Scheme, []versionscheme.Span, string, productid.Product) {
	scheme, spans, origin, p, _ := vendorRows(a, s, in, v)
	return scheme, spans, origin, p
}

// statements are the vendor's rows of one product that only support "not affected": the ranges it states unaffected and its affected
// ranges limited to some models, with their scheme and origin.
type statements struct {
	scheme             *versionscheme.Scheme
	unaffected, models []versionscheme.Span
	origin             string
}

// vendorRows is schemedSpans with the vendor's statements of the same product (statements).
func vendorRows(a Asset, s Software, in swInfo, v Vuln) (*versionscheme.Scheme, []versionscheme.Span, string, productid.Product, statements) {
	if len(v.Schemed) == 0 && len(v.Affected) == 0 || in.pkgBuilt() || distroBuilt(in) && linuxDistro(cmpOr(a.OS, in.osName)) != "" {
		return nil, nil, "", productid.Product{}, statements{}
	}
	if len(v.Schemed) == 0 && !oracleNamed(v) { // the common case: nothing a scheme reads, no product lookup
		return nil, nil, "", productid.Product{}, statements{}
	}
	p, ok := productid.ResolveStored(s.Vendor, s.Product, s.Display, s.CPE)
	if !ok || p.Scheme == "" {
		return nil, nil, "", productid.Product{}, statements{}
	}
	var spans []versionscheme.Span
	var scheme *versionscheme.Scheme
	var st statements
	origin := ""
	for _, r := range v.Schemed {
		if r.Product != p.Key || r.Scheme == nil || r.Scheme.Name != p.Scheme || fipsWithoutTheWord(r) {
			continue
		}
		if r.Unaffected || r.ModelOnly {
			if r.Unaffected {
				st.unaffected = append(st.unaffected, r.Span)
			} else {
				st.models = append(st.models, r.Span)
			}
			if st.scheme = r.Scheme; st.origin == "" || r.Origin == RangeCNA {
				st.origin = r.Origin
			}
			continue
		}
		spans, scheme = append(spans, r.Span), r.Scheme
		if origin == "" || r.Origin == RangeCNA {
			origin = r.Origin
		}
	}
	if p.Scheme == versionscheme.Java.Name {
		if tr := oracleTrains(v); len(tr) > 0 && scheme == nil {
			spans, scheme, origin = tr, versionscheme.Java, v.rangeOrigin()
		}
	}
	return scheme, spans, origin, p, st
}

// javaOneRelease says a Java version names one release of a train: an update of Java 8 or earlier ("1.8.0_411"), or a version of three
// numbers from Java 9 on ("17.0.11"); "11.0" or "1.8.0" names only the train.
func javaOneRelease(ver string) bool {
	if strings.HasPrefix(ver, "1.") {
		return strings.Contains(ver, "_")
	}
	return strings.Count(ver, ".") >= 2
}

// oracleNamed says an NVD row of v names Oracle's Java SE (cpe:2.3:a:oracle:jdk or jre), read without parsing the whole name.
func oracleNamed(v Vuln) bool {
	return slices.ContainsFunc(v.Affected, func(af Affected) bool {
		return strings.Contains(af.CPE, ":oracle:jdk:") || strings.Contains(af.CPE, ":oracle:jre:")
	})
}

// oracleTrains reads Oracle's way of stating Java SE's affected versions: its critical patch update lists the newest affected release
// of each supported train ("Oracle Java SE: 8u411, 17.0.11, 21.0.3"), which NVD writes as exact versions
// (cpe:2.3:a:oracle:jdk:17.0.11, cpe:2.3:a:oracle:jre:1.8.0:update411). Every earlier release of a listed train is affected too, so
// each listed release is the span from the start of its train to it, included; a train Oracle does not list is not read here.
func oracleTrains(v Vuln) []versionscheme.Span {
	var out []versionscheme.Span
	for _, af := range v.Affected {
		if !af.Range.IsZero() {
			continue
		}
		c, err := af.cpe()
		if err != nil {
			continue
		}
		vn, okV := c.Vendor.Literal()
		pn, okP := c.Product.Literal()
		ver, okVer := c.Version.Literal()
		if !okV || !okP || !okVer || productid.Norm(vn) != "oracle" || pn != "jdk" && pn != "jre" {
			continue
		}
		if upd, ok := c.Update.Literal(); ok && strings.HasPrefix(upd, "update") && strings.HasPrefix(ver, "1.") {
			ver += "_" + strings.TrimPrefix(strings.TrimPrefix(upd, "update_"), "update")
		}
		end, ok := versionscheme.Java.Parse(ver)
		if !ok || end.LineStart || !javaOneRelease(ver) {
			continue // "11.0" names the train, not its newest affected release
		}
		start := versionscheme.Version{Line: end.Line, Variant: end.Variant, LineStart: true, Train: end.Train, Label: end.Train, Display: end.Train}
		out = append(out, versionscheme.Span{Start: &start, End: &end, EndIncl: true})
	}
	return out
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// schemeJudge reads the vendor's rows of v for software line s of device a: ok is true when they name the line's product, the scheme
// places the line's version (with the build the device states) and the rows name its release line, and the verdict is not "not
// comparable". The verdict is then the vendor's: affected (with the fixed release of the device's train, when the vendor states one)
// or not affected.
func schemeJudge(a Asset, s Software, in swInfo, v Vuln) (schemeRead, bool) {
	scheme, spans, origin, p, st := vendorRows(a, s, in, v)
	read := scheme
	if read == nil {
		read = st.scheme
	}
	if read == nil {
		return schemeRead{}, false
	}
	installed, ok := read.Installed(in.ver, statedBuild(s))
	if !ok {
		return schemeRead{}, false
	}
	out := schemeRead{installed: installed, origin: origin, vendor: p.Vendor, product: cmpOr(p.Display, s.Display)}
	if scheme != nil && namesLine(spans, installed) {
		verdict := versionscheme.Judge(installed, spans)
		switch {
		case verdict.State == versionscheme.Affected:
			out.verdict = verdict
			return out, true
		case verdict.State == versionscheme.NotAffected && endsInTrain(spans, installed) && !inside(installed, st.models):
			out.verdict = verdict
			return out, true
		}
		// not comparable, or "not affected" by release order only (the vendor's rows are silent on the device's own train: VMware's
		// U3 row missing while NVD lists 8.0 update_3; on a disagreement the affected side wins, so NVD's ranges decide), or inside a
		// model-limited range: only the vendor's statements below may still say "not affected"
	}
	if scheme != nil && !namesLine(spans, installed) && !inside(installed, st.models) {
		if first, ok := olderThanEveryStart(installed, spans); ok && !nvdCovers(in, v) {
			out.verdict, out.before = versionscheme.Verdict{State: versionscheme.NotAffected}, first
			return out, true
		}
	}
	if notAffectedByStatements(installed, spans, st) && !nvdCovers(in, v) {
		out.verdict, out.stated, out.origin = versionscheme.Verdict{State: versionscheme.NotAffected}, true, cmpOr(st.origin, origin)
		return out, true
	}
	return schemeRead{}, false
}

// notAffectedByStatements says the vendor's statements prove installed not affected: it is inside a range the vendor states
// unaffected (for every device: feeds keeps no other) and inside none of the vendor's affected ranges, of every device or of some models; or it is outside
// every affected range, in a train one of them ends in, when some are model-limited (the vendor's word on the train, as schemeJudge
// reads its rows). Never "affected": a model-limited range does not say this device's model has the flaw.
// schemeJudge reads it only when no NVD row covers the version (nvdCovers).
func notAffectedByStatements(installed versionscheme.Version, spans []versionscheme.Span, st statements) bool {
	if inside(installed, spans) || inside(installed, st.models) {
		return false
	}
	if inside(installed, st.unaffected) {
		return true
	}
	if len(st.models) == 0 {
		return false
	}
	all := append(slices.Clone(spans), st.models...)
	return namesLine(all, installed) && endsInTrain(all, installed) && versionscheme.Judge(installed, all).State == versionscheme.NotAffected
}

// olderThanEveryStart says the version is older than the first release every one of the vendor's affected ranges starts at, and that
// first release is one inside its branch (Juniper's "23.2 versions from 23.2R2-S1 before 23.2R2-S5"): the vendor states where the flaw
// came in, so an older release is not affected. It returns that first release. Not when a range has no start ("all versions before
// 21.4R3-S9" reaches every older release: affected), when a start does not compare with the version (another variant), or when the
// first start is the start or first release of a branch ("24.2 before 24.2R2-S3"): a vendor lists only the branches it supports, so
// silence about an older branch is no statement (the line stays a question, olderLine).
func olderThanEveryStart(installed versionscheme.Version, spans []versionscheme.Span) (*versionscheme.Version, bool) {
	if len(spans) == 0 {
		return nil, false
	}
	var first *versionscheme.Version
	for _, sp := range spans {
		if sp.Start == nil {
			return nil, false
		}
		c, ok := versionscheme.Compare(installed, *sp.Start)
		if !ok || c >= 0 {
			return nil, false
		}
		if first == nil {
			first = sp.Start
		} else if c, ok := versionscheme.Compare(*sp.Start, *first); ok && c < 0 {
			first = sp.Start
		}
	}
	if branchStart(*first) {
		return nil, false
	}
	return first, true
}

// branchStart says a range start is the start of a release branch or its first release ("24.2", "24.2R1", ESXi "8.0"), not a
// release inside the branch where a flaw came in ("23.2R2-S1").
func branchStart(v versionscheme.Version) bool {
	if v.LineStart {
		return true
	}
	if v.Rank != 0 || len(v.Build) == 0 {
		return v.Rank == 0 && len(v.Build) == 0
	}
	if v.Build[0] > 1 {
		return false
	}
	for _, b := range v.Build[1:] {
		if b != 0 {
			return false
		}
	}
	return true
}

// nvdCovers says one of NVD's affected rows (a range or an exact release) covers the line's version (decide: Yes). On a
// disagreement the affected side wins: the vendor's statements never close what NVD lists as affected, NVD's rows decide it.
func nvdCovers(in swInfo, v Vuln) bool {
	t, _, _, _ := decide(in, v, keyIDs(v))
	return t == Yes
}

// inside says installed is inside one of spans, each read alone (versionscheme.Judge on one span: its bounds, in release order).
func inside(installed versionscheme.Version, spans []versionscheme.Span) bool {
	return slices.ContainsFunc(spans, func(sp versionscheme.Span) bool {
		return versionscheme.Judge(installed, []versionscheme.Span{sp}).State == versionscheme.Affected
	})
}

// fipsWithoutTheWord says a NetScaler row ends at a plain 13.1 build of the 37 series ("13.1 lessThan 13.1-37.235"): Citrix's FIPS and
// NDcPP builds of 13.1 are that series (13.1-37.235 FIPS), while the plain line left it in 2022, so a recent row written so is the
// FIPS build without its word. Neither line can be told from it: the row is left out (versionscheme.Conflicts covers the case where a
// plain row of the same CVE ends elsewhere in 13.1), so it names no fix and decides nothing; NVD's ranges decide.
func fipsWithoutTheWord(r SchemedRange) bool {
	e := r.Span.End
	return r.Scheme.Name == versionscheme.NetScaler.Name && e != nil && e.Variant == "" && len(e.Line) == 2 && e.Line[0] == 13 && e.Line[1] == 1 &&
		len(e.Build) > 0 && e.Build[0] == 37
}

// endsInTrain says a span ends in v's own release train: the vendor states the fixed release of that very train, so a release past it
// is not affected by the vendor's word.
func endsInTrain(spans []versionscheme.Span, v versionscheme.Version) bool {
	return slices.ContainsFunc(spans, func(sp versionscheme.Span) bool {
		return sp.End != nil && !sp.End.LineStart && sp.End.Variant == v.Variant && sp.End.Train == v.Train
	})
}

// namesLine says a span starts or ends in the release line of v (same numbers, same variant), or has no start and ends in a later
// line ("0 lessThan 21.2R3-S9" covers 20.4): the vendor speaks about that line, so its silence about a train of it means "not
// affected". A line no span reaches is left to the generic comparison.
func namesLine(spans []versionscheme.Span, v versionscheme.Version) bool {
	same := func(x *versionscheme.Version) bool {
		if x == nil || x.Variant != v.Variant || len(x.Line) != len(v.Line) {
			return false
		}
		for i := range x.Line {
			if x.Line[i] != v.Line[i] {
				return false
			}
		}
		return true
	}
	before := func(end *versionscheme.Version) bool { // a range from the first release on reaches the earlier lines too
		if end == nil || end.Variant != v.Variant {
			return false
		}
		for i := range min(len(end.Line), len(v.Line)) {
			if v.Line[i] != end.Line[i] {
				return v.Line[i] < end.Line[i]
			}
		}
		return false
	}
	for _, sp := range spans {
		if same(sp.Start) || same(sp.End) || sp.Start == nil && before(sp.End) {
			return true
		}
	}
	return false
}

// schemeNames says v's vendor rows decide the line (schemeJudge reads them for its version): the match pass reads the entry for the
// row, as it does a row NVD's list names (viaNVD). Rows a scheme cannot place the line's version in leave the row to NVD's list.
func schemeNames(a Asset, s Software, in swInfo, v Vuln) bool {
	_, ok := schemeJudge(a, s, in, v)
	return ok
}

// schemeDecision is judge's reading of the vendor's rows: the tri-state, the range to name in the evidence (its end is the vendor's
// fixed release of the device's train), and the note of a proof.
func schemeDecision(a Asset, v Vuln, r schemeRead) (Tri, VersionRange, string) {
	release := releaseName(r.installed)
	who := clean(r.vendor)
	if who == "" {
		who = "The vendor"
	}
	switch r.verdict.State {
	case versionscheme.Affected:
		var within VersionRange
		if r.verdict.Fix != nil {
			within.EndExcl = releaseName(*r.verdict.Fix)
		}
		return Yes, within, ""
	case versionscheme.NotAffected:
		if r.before != nil {
			return No, VersionRange{}, fmt.Sprintf("Not affected: %s lists the releases of %s that have %s starting from %s, and %s runs %s %s, older than the first affected release the vendor lists (%s). Vedette closed this by itself and reopens it if a later match says the device is affected.",
				who, clean(r.product), v.CVE, clean(releaseName(*r.before)), clean(a.Name), clean(r.product), clean(release), clean(releaseName(*r.before)))
		}
		if r.stated {
			return No, VersionRange{}, fmt.Sprintf("Not affected: %s states which releases of %s have %s, and %s runs %s %s, which is not one of them. Vedette closed this by itself and reopens it if a later match says the device is affected.",
				who, clean(r.product), v.CVE, clean(a.Name), clean(r.product), clean(release))
		}
		return No, VersionRange{}, fmt.Sprintf("Not affected: %s states the fixed release of each release train for %s, and %s runs %s %s, which is not affected. Vedette closed this by itself and reopens it if a later match says the device is affected.",
			who, v.CVE, clean(a.Name), clean(r.product), clean(release))
	}
	return Unknown, VersionRange{}, ""
}

// releaseName is a release as the vendor names it, with its build when the name does not say it ("8.0 U3d (build 24585383)").
func releaseName(v versionscheme.Version) string {
	if v.Display != "" {
		return v.Display
	}
	return v.Label
}

// selfStated says the row is a device's own statement of its firmware through its management interface (an ESXi host's API, an
// iLO's page): the device's word with its exact build, not a version guessed from a banner (core/observe.SelfStatedBasis).
func selfStated(s Software) bool {
	return s.Source == "nmap" && !s.Guess && observe.SelfStatedBasis(strings.TrimSpace(s.Display)) != ""
}

// schemeAffectedNote is the evidence of a finding the vendor's rows decide: the release the device runs and the vendor's fixed release
// of its train ("esx01 runs VMware ESXi 8.0 U2 (build 22380479). VMware fixed CVE-2025-22225 in 8.0 U2d (build 24585300) for this
// release train; ...").
func schemeAffectedNote(a Asset, s Software, in swInfo, v Vuln, within VersionRange) string {
	r, _ := schemeJudge(a, s, in, v)
	who := clean(r.vendor)
	if who == "" {
		who = "The vendor"
	}
	runs := fmt.Sprintf("%s runs %s %s", clean(a.Name), clean(r.product), clean(releaseName(r.installed)))
	if s.Source == "agent" {
		runs = fmt.Sprintf("The agent on %s reports %s %s installed", clean(a.Name), clean(r.product), clean(releaseName(r.installed)))
	}
	if within.EndExcl == "" {
		return fmt.Sprintf("%s. %s lists this release as affected by %s and states no fixed release for it yet"+suspectedClause, runs, who, v.CVE)
	}
	if f := r.verdict.Fix; f != nil && f.Train != r.installed.Train { // the nearest fix is in a later train: this train has none
		return fmt.Sprintf("%s. %s lists no fixed release of %s for this device's release train (%s); the nearest fixed release is %s, in release train %s, so this device has the flaw until it moves to that release or a later one.",
			runs, who, v.CVE, clean(r.installed.Train), clean(within.EndExcl), clean(f.Train))
	}
	return fmt.Sprintf("%s. %s fixed %s in %s for this release train, so this device has the flaw until it installs that release or a later one.", runs, who, v.CVE, clean(within.EndExcl))
}
