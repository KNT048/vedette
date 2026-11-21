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
	origin    string // who stated the rows (RangeCNA, RangeADP)
	vendor    string // the product's vendor as the catalogue names it ("VMware")
	product   string // the product as the catalogue names it ("VMware ESXi")
}

// buildRE reads the build a device states beside its version ("VMware ESXi 8.0 Update 3 (build 24022510)").
var buildRE = regexp.MustCompile(`\(build ([0-9]{5,9})\)`)

// statedBuild is the build of the line: the one its own reading states (the device's statement keeps it in the line's name), else the
// one the device's OS line states; "" when none.
func statedBuild(a Asset, s Software) string {
	if m := buildRE.FindStringSubmatch(s.Display); m != nil {
		return m[1]
	}
	if m := buildRE.FindStringSubmatch(a.OS); m != nil {
		return m[1]
	}
	return ""
}

// schemedSpans is the spans of v's vendor rows that name the line's product, with the product's scheme; nil when none. A
// distribution's package is never read by a vendor scheme (the distribution's own data decides it), nor a row a distribution may
// have built on a device that runs one (an Ubuntu kernel reports 6.8.0 while it carries fixes of later stable releases).
func schemedSpans(a Asset, s Software, in swInfo, v Vuln) (*versionscheme.Scheme, []versionscheme.Span, string, productid.Product) {
	if len(v.Schemed) == 0 && len(v.Affected) == 0 || in.pkgBuilt() || distroBuilt(in) && linuxDistro(cmpOr(a.OS, in.osName)) != "" {
		return nil, nil, "", productid.Product{}
	}
	if len(v.Schemed) == 0 && !oracleNamed(v) { // the common case: nothing a scheme reads, no product lookup
		return nil, nil, "", productid.Product{}
	}
	p, ok := productid.ResolveStored(s.Vendor, s.Product, s.Display, s.CPE)
	if !ok || p.Scheme == "" {
		return nil, nil, "", productid.Product{}
	}
	var spans []versionscheme.Span
	var scheme *versionscheme.Scheme
	origin := ""
	for _, r := range v.Schemed {
		if r.Product != p.Key || r.Scheme == nil || r.Scheme.Name != p.Scheme {
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
	return scheme, spans, origin, p
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
	scheme, spans, origin, p := schemedSpans(a, s, in, v)
	if scheme == nil {
		return schemeRead{}, false
	}
	installed, ok := scheme.Installed(in.ver, statedBuild(a, s))
	if !ok || !namesLine(spans, installed) {
		return schemeRead{}, false
	}
	verdict := versionscheme.Judge(installed, spans)
	if verdict.State == versionscheme.NotComparable {
		return schemeRead{}, false
	}
	return schemeRead{installed: installed, verdict: verdict, origin: origin, vendor: p.Vendor, product: cmpOr(p.Display, s.Display)}, true
}

// namesLine says a span starts or ends in the release line of v (same numbers, same variant): the vendor speaks about that line, so
// its silence about a train of it means "not affected". A line no span names is left to the generic comparison.
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
	for _, sp := range spans {
		if same(sp.Start) || same(sp.End) {
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
func schemeDecision(a Asset, s Software, in swInfo, v Vuln, r schemeRead) (Tri, VersionRange, string) {
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
	return s.Source == "nmap" && observe.SelfStatedBasis(strings.TrimSpace(s.Display)) != ""
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
		return fmt.Sprintf("%s. %s lists this release as affected by %s and states no fixed release for it yet; no scan has confirmed it yet, so this is only suspected.", runs, who, v.CVE)
	}
	return fmt.Sprintf("%s. %s fixed %s in %s for this release train, so this device has the flaw until it installs that release or a later one.", runs, who, v.CVE, clean(within.EndExcl))
}
