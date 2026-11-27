package findings

import (
	"slices"
	"strings"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
)

// UncheckedReason says why an exploited CVE of software the device has could not be checked (#910 phase 1, contract.ts
// UncheckedReason). Precedence, first that applies: no NVD data, no NVD versions, NVD names other products, versions that do not
// compare.
type UncheckedReason string

// The four reasons, in precedence order (contract.ts UncheckedReason), then the two of a platform-limited CVE only a person's answer
// decides (MatchResult.Asked), which come from the platform rules, not uncheckedReason.
const (
	UncheckedNoNVDData     UncheckedReason = "no_nvd_data"     // NVD has no CPE configuration for the CVE yet (audit class 1)
	UncheckedNoNVDVersions UncheckedReason = "no_nvd_versions" // NVD names products but no affected version (audit class 2)
	UncheckedNotNamed      UncheckedReason = "not_named"       // NVD's list names none of the row's names (audit class 5, "3k")
	UncheckedNotComparable UncheckedReason = "not_comparable"  // the row's version cannot be compared with NVD's
	// UncheckedPlatformUnknown: the CVE affects only some platforms or builds and nothing says which this row is.
	UncheckedPlatformUnknown UncheckedReason = "platform_unknown"
	// UncheckedPackageUnknown: the platform is the one of the distribution's fixed list, and the package release is not known.
	UncheckedPackageUnknown UncheckedReason = "package_unknown"
)

// Unchecked is one exploited CVE of one software row of the device that gave no finding, no "add the version" item and no
// proof either way (#910 phase 1, MatchResult.Unchecked).
type Unchecked struct {
	CVE        string
	SoftwareID string // osSoftwareID for the network OS a device states without a software row (NotComparable)
	Software   string // the row's display, as on the device page
	Version    string // the row's version as stored, "" when none
	Source     string // Software.Source: "manual" lets a person retype the version (action add_version)
	Reason     UncheckedReason
	// Answer: package_unknown only, the release a person gave that Vedette could not read as one; "" otherwise.
	Answer string
	// NVDPending: no_nvd_data while NVD has not answered for the CVE (Vuln.NVDAnswered false: a new box, the NVD feed off or failing):
	// Vedette is waiting for NVD's data, NVD has not said it has none (review r2 M1 of #939).
	NVDPending bool
	// Listed: no_nvd_versions only, the entries that name the row give versions, just none that decides this one (only exact versions,
	// only a start, or a partial CVE.org list); false when they give none (explainUnchecked). The question then says so, never "gives
	// no affected versions".
	Listed bool
	// Line is set when the vendor's own rows (Vuln.Schemed) name fixed releases only on release lines later than the row's and say
	// nothing about the row's own line ("7.2.1" of DSM 7.2.1-69057-5): the row's release line, and fixes the fixed releases those rows
	// state (olderLine). Such rows of one line are one question (QuestionOlderLine). "" otherwise.
	Line  string
	fixes []versionscheme.Version
	// Attribute: not_comparable only, the build attribute NVD pins that decides it and the box could not derive (blockingAttribute):
	// AttrEdition, AttrArchitecture or AttrPlatform, or AttrUnlistedLine for a Mozilla ESR line the CVE's ESR rows do not list. The
	// question then asks for it, not for the version. "" otherwise.
	Attribute string
	// undecided is the machine-readable reason no verdict was reached and the rows that were read (explainUnchecked); nil before it.
	undecided *Undecided
}

// explainUnchecked adds to each unchecked row with no version data its question needs (no_nvd_data, no_nvd_versions) what the reason
// alone does not say: whether the entries naming the row list versions of it at all (Listed), and whether the vendor's own rows name
// fixes only on later release lines than the row's (Line, olderLine); and to a not_comparable row the build attribute that decides it
// when that, not the version, is what is missing (Attribute). Only the device's rows are read (the network OS a device states
// without a row is not: its versions do not order).
func (d *devMatch) explainUnchecked(us []Unchecked, vulns []Vuln) {
	if len(us) == 0 {
		return
	}
	row := make(map[string]int, len(d.sws))
	for i, s := range d.sws {
		if _, ok := row[s.ID]; !ok { // the first row of an id is its effective reading
			row[s.ID] = i
		}
	}
	byCVE := make(map[string]Vuln, len(vulns))
	for _, v := range vulns {
		if _, ok := byCVE[v.CVE]; !ok {
			byCVE[v.CVE] = v
		}
	}
	for k := range us {
		u := &us[k]
		i, okR := row[u.SoftwareID]
		v, okV := byCVE[u.CVE]
		if !okR || !okV {
			u.undecided = undecidedOf(*u, nil)
			continue
		}
		s, in := d.sws[i], d.infos[i]
		if d.own != nil && d.own[i] != nil { // a row the AI identified is unchecked only as its own names read it (aiGuard)
			in = d.own[i].info
		}
		own := rowEntries(s, in, v)
		switch u.Reason {
		case UncheckedNotComparable:
			u.Attribute = blockingAttribute(in, v, keyIDs(v))
		case UncheckedNoNVDData, UncheckedNoNVDVersions:
			if u.Reason == UncheckedNoNVDVersions {
				u.Listed = slices.ContainsFunc(own, versionEvidence)
			}
			u.Line, u.fixes = olderLine(d.a, s, in, v)
		}
		u.undecided = undecidedOf(*u, own)
		switch {
		case u.undecided.Reason == UndecidedExactOnly && olderThanEveryExact(own, in.ver):
			u.undecided.Reason = UndecidedEOLUnlisted
		case u.undecided.Reason == UndecidedSchemeMismatch && !notationDiffers(own, in.ver) && !winVersionRE.MatchString(strings.TrimSpace(in.ver)):
			// the version reads and is written as the rows are: a row that does not compare is the record's, and typing the version
			// again changes nothing (a Windows build keeps its label: its release, not its notation, is read there)
			u.undecided.Reason = UndecidedRangesDoNotCover
		}
	}
}

// undecidedOf is the machine-readable reason of an unchecked row, with the rows of the CVE that name it (own) as they were read.
func undecidedOf(u Unchecked, own []Affected) *Undecided {
	out := &Undecided{}
	switch {
	case u.Reason == UncheckedPlatformUnknown:
		out.Reason = UndecidedPlatform
	case u.Reason == UncheckedPackageUnknown:
		out.Reason = UndecidedPackage
	case u.Reason == UncheckedNotComparable && u.Attribute != "":
		out.Reason = UndecidedAttribute
	case u.Reason == UncheckedNotComparable:
		out.Reason = UndecidedSchemeMismatch
	case u.NVDPending:
		out.Reason = UndecidedNVDPending
	case u.Line != "":
		out.Reason = UndecidedBranchOnly
	case u.Reason == UncheckedNotNamed:
		out.Reason = UndecidedNotNamed
	case !u.Listed:
		out.Reason = UndecidedNoRanges
	case !slices.ContainsFunc(own, func(af Affected) bool { return !af.Range.IsZero() }):
		out.Reason = UndecidedExactOnly
	default:
		out.Reason = UndecidedRangesDoNotCover
	}
	for _, af := range own {
		if len(out.Ranges) == undecidedRows {
			break
		}
		out.Ranges = append(out.Ranges, rowText(af))
	}
	return out
}

// notationDiffers says the version and the rows naming the line (own) are written in two notations: the version does not read, a row
// is in another scheme (schemeClash: "2016" against "16.0.1"), or a bound is of the version's own train. Only then is the CVE's
// undecided reason the version's notation; a bound of another train or a word is the record's own literal, which typing the version
// again does not change.
func notationDiffers(own []Affected, ver string) bool {
	if !versionKnown(ver) {
		return true
	}
	for _, af := range own {
		r := af.Range
		if c, err := af.cpe(); err == nil && r.IsZero() {
			if lit, ok := c.Version.Literal(); ok {
				r = VersionRange{StartIncl: lit, EndIncl: lit}
			}
		}
		if schemeClash(r, ver) {
			return true
		}
		for _, b := range []string{r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl} {
			if b == "" {
				continue
			}
			if sameTrain(ver, b, b) {
				return true // a bound of the version's own train, which may be the same release written another way ("1.9.17p2.1")
			}
		}
	}
	return false
}

// rowText is one row of a CVE's list as an audit reads it: its CPE and its bounds ("cpe:2.3:o:juniper:junos:15.1:r1:… [, )").
func rowText(af Affected) string {
	r := af.Range
	if r.IsZero() {
		return af.CPE
	}
	start, end := "[", ")"
	lo, hi := r.StartIncl, r.EndExcl
	if r.StartExcl != "" {
		start, lo = "(", r.StartExcl
	}
	if r.EndIncl != "" {
		end, hi = "]", r.EndIncl
	}
	return af.CPE + " " + start + lo + ", " + hi + end
}

// olderThanEveryExact says every exact release the rows list is of a later release line than ver (NVD lists only supported lines; an
// end-of-life line is often not evaluated). False when a row does not place against the version.
func olderThanEveryExact(own []Affected, ver string) bool {
	if len(own) == 0 {
		return false
	}
	for _, af := range own {
		c, err := af.cpe()
		if err != nil {
			return false
		}
		lit, ok := c.Version.Literal()
		if !ok {
			return false
		}
		o, ok := lineOrder(c, lit, ver) // < 0: the version's line is older than the listed release's
		if !ok || o >= 0 {
			return false
		}
	}
	return true
}

// olderLine says the vendor's own rows of v for the row's product (Vuln.Schemed: Synology's fixed DSM releases, VMware's ESXi builds)
// name only release lines later than the row's: line is the row's release line as the scheme names it ("7.2.1") and fixes the fixed
// releases the rows state. "" when there are no such rows, the scheme does not place the row's version, a row reaches the row's line
// (the vendor speaks about it: schemeJudge decides), or a row does not start on a later line. The vendor then says nothing about the
// row's line: a fix on a later line shows neither that this one is affected nor that it is not (a vendor fixes an older line for
// selected flaws only, in other advisories), so there is no verdict and the row stays a question, which says so. It decides nothing.
func olderLine(a Asset, s Software, in swInfo, v Vuln) (string, []versionscheme.Version) {
	if len(v.Schemed) == 0 {
		return "", nil
	}
	scheme, spans, _, _ := schemedSpans(a, s, in, v)
	if scheme == nil || len(spans) == 0 {
		return "", nil
	}
	installed, ok := scheme.Installed(in.ver, statedBuild(s))
	if !ok || installed.LineStart || namesLine(spans, installed) {
		return "", nil
	}
	here := versionscheme.LineStart(installed)
	var fixes []versionscheme.Version
	for _, sp := range spans {
		if sp.Start == nil { // a span from the first release on reaches every earlier line (namesLine): it ends on an earlier one here
			return "", nil
		}
		if c, ok := versionscheme.Compare(here, versionscheme.LineStart(*sp.Start)); !ok || c >= 0 {
			return "", nil
		}
		if e := sp.End; e != nil && !sp.EndIncl && !e.LineStart && len(e.Build) > 0 { // not a line's empty row ("7.3.1" before "7.3.1")
			fixes = append(fixes, *e)
		}
	}
	return here.Label, fixes
}

// newestPerLine is the newest of fixes on each release line, oldest line first, as people read them ("7.3.2-86009 Update 5").
func newestPerLine(fixes []versionscheme.Version) []string {
	var best []versionscheme.Version
	for _, f := range fixes {
		i := slices.IndexFunc(best, func(b versionscheme.Version) bool {
			c, ok := versionscheme.Compare(versionscheme.LineStart(b), versionscheme.LineStart(f))
			return ok && c == 0
		})
		switch {
		case i < 0:
			best = append(best, f)
		default:
			if c, ok := versionscheme.Compare(f, best[i]); ok && c > 0 {
				best[i] = f
			}
		}
	}
	slices.SortStableFunc(best, func(x, y versionscheme.Version) int {
		c, _ := versionscheme.Compare(x, y)
		return c
	})
	out := make([]string, len(best))
	for i, b := range best {
		out[i] = b.Display
	}
	return out
}

// uncheckedRow says whether row s, read against v with outcome out (matchOne), is one the device has but Vedette could not check,
// and why. Only two kinds of rows count, so the list never names an entry for software the device does not have:
//   - a row CISA's key names (keyedTo, never a vendor's "Multiple Products": there NVD's list of other products says it is not this
//     one) whose match is a No that proves nothing: NVD's ranges are for the entry's name, not for the row's;
//   - a row only NVD's list names (#910, viaNVD) by its own CPE, name or alias (rowEntries: for a Windows release row its own
//     release, not a sibling), with a version given, that gave neither a version match with a fix nor a proof: NVD lists only
//     exact versions, no end or no version, or the version does not compare. Not a row whose distribution decides (its own
//     word, or none, as for an Android entry that also lists the Linux kernel), not an Edge Legacy row, not a Juniper model CISA
//     leaves out.
//
// Nor does a row whose version the matcher never compares with the entry: a CVE on no exploited list against a version read from the
// network (a banner, the passive sensor; offListReading). Answering a question about the ranges would change nothing there, so it
// is not asked; the version is compared once the device's agent reports it or a person confirms it.
//
// Neither kind counts when NVD names the row only at exact versions older than its own, or of other release lines than its own and
// not all of them newer (newerThanListed): NVD's list enumerates the affected releases and does not name this one at all, so it is no
// candidate (not a verdict: nothing closes, nothing is "not affected").
//
// A product match the age rule drops and the network OS a device states without an order (NotComparable) are listed by
// MatchAsset itself.
func uncheckedRow(a Asset, s Software, in swInfo, v Vuln, named bool, m Match, out outcome) (UncheckedReason, bool) {
	switch {
	case out == outRuledOut: // only a keyed row is ruled out (viaNVD says nothing instead)
		// a vendor's "Multiple Products" reaches every row of the vendor by its key: only one NVD's list names counts (r1 L4)
		if m.Evidence.Summary != "" || isMultiProduct(v.Product) && len(rowEntries(s, in, v)) == 0 {
			return "", false
		}
	case out == outNone && named && in.given: // cheapest tests first: this runs for every row NVD's vendors may name
		if !v.listed() && !offListReading(s, in, v) { // matchOne never compares this row with a CVE on no list: no answer changes that
			return "", false
		}
		if edgeLegacyRow(s, in) || distroBuilt(in) || keyedTo(s, v) { // a keyed row with no outcome: its distribution decided
			return "", false
		}
		if _, ok := distroVerdict(in, v); ok {
			return "", false
		}
		if _, o := otherSeries(a.Model, v); o || len(rowEntries(s, in, v)) == 0 {
			return "", false
		}
	default:
		return "", false
	}
	if newerThanListed(rowEntries(s, in, v), in.ver) {
		return "", false
	}
	return uncheckedReason(s, in, v, false)
}

// newerThanListed says every entry of own (the entries of NVD's list that name the row, rowEntries) is one exact version, with no
// range, that the row's version is later than (laterThan) or that is of another release line (lineOrder), and the row is not older
// than every one of them: Java 8 Update 491 for CVE-2023-41993, which NVD lists for Java at "1.8.0 update401" only; SQL Server 2022
// (16.0.1000.6) for CVE-2012-1856, listed for SQL Server 2000 to 2008; Java 8 Update 491 for CVE-2025-21587, listed at 8u441 and at
// releases of Java 11, 17 and 21; Junos 21.3R3 for a CVE listed at releases of 21.2, 21.4 and 22.2. NVD's configuration enumerates
// those versions, not the row's, so the row is not a candidate. A release line older than every listed one stays a candidate: vendors
// often do not evaluate end-of-life lines (Juniper's advisories say so; Oracle lists supported releases only), so Junos 15.1R7.9 or
// Java 7 Update 401 against such a list is still asked. An older version of a listed line stays one too: an exact list is often the
// last affected update of each line (Oracle's "8u77 and earlier", NVD's 8.0 GA entry for an ESXi flaw fixed in 8.0 Update 3d), and so
// does any entry with a range, any version or a version that does not read.
func newerThanListed(own []Affected, ver string) bool {
	if len(own) == 0 || !versionKnown(ver) {
		return false
	}
	anchored := false // an entry the row is later than, or of an older line than the row's: the row is not older than every one
	for _, af := range own {
		c, err := af.cpe()
		if err != nil || !af.Range.IsZero() {
			return false
		}
		lit, ok := c.Version.Literal()
		if !ok {
			return false
		}
		if laterThan(c, lit, ver) {
			anchored = true
			continue
		}
		o, ok := lineOrder(c, lit, ver)
		if !ok || o == 0 {
			return false
		}
		anchored = anchored || o > 0
	}
	return anchored
}

// uncheckedReason is the reason of an unchecked row, first that applies:
//   - no_nvd_data: Vedette has no NVD entry for it: NVD answered with none, or has not answered yet (#939:
//     a new exploited CVE matched by name is listed at once; this replaces #920's "no row before NVD answered");
//   - no_nvd_versions: no entry gives a version (audit class 2);
//   - not_comparable: a Windows row of a build core/winrel does not know, when NVD lists Windows rows (winUnknownBuild);
//   - not_named: none names the row (audit class 5 and "3k", and #919's nvd_other_product);
//   - no_nvd_versions: those that name it give no version, or no range that decides (only exact versions, only a start, or a
//     partial CVE.org list);
//   - not_comparable: an entry naming it has a range with an end and the row's version did not compare with it, or the row is a
//     network OS whose version has no order (scheme): only then can typing the version as the vendor writes it help. When the
//     version scheme the catalogue declares for the product reads the version as written (Junos "15.1R7.9", schemeReads), typing it
//     again changes nothing: it is no_nvd_versions instead (the entries name the product, none decides this release), which a
//     person answers per CVE.
func uncheckedReason(s Software, in swInfo, v Vuln, scheme bool) (UncheckedReason, bool) {
	if len(v.Affected) == 0 { // before NVD answered too: Vedette has no NVD data for it yet, and says so at once (review r1 H2 of #939)
		return UncheckedNoNVDData, true
	}
	if !slices.ContainsFunc(v.Affected, versionEvidence) {
		return UncheckedNoNVDVersions, true
	}
	if _, ok := winUnknownBuild(s, in); ok && slices.ContainsFunc(v.Affected, func(af Affected) bool { // NVD lists Windows, and the build is not in the table
		c, err := af.cpe()
		return err == nil && winNamesWindows(c)
	}) {
		return UncheckedNotComparable, true
	}
	own := rowEntries(s, in, v)
	switch {
	case len(own) == 0:
		return UncheckedNotNamed, true
	case !slices.ContainsFunc(own, versionEvidence):
		return UncheckedNoNVDVersions, true
	case scheme || !versionKnown(in.ver):
		if schemeReads(s, in) {
			return UncheckedNoNVDVersions, true // see below
		}
		return UncheckedNotComparable, true
	case v.RangesFrom == RangesCVEOrgPartial || !slices.ContainsFunc(own, func(af Affected) bool { return endBound(af.Range) }):
		return UncheckedNoNVDVersions, true
	case schemeReads(s, in): // a range with an end did not decide a release the product's scheme reads: none of the entries decides it
		return UncheckedNoNVDVersions, true
	}
	return UncheckedNotComparable, true
}

// schemeReads says the version scheme the catalogue declares for the row's product reads its version as the vendor writes it.
func schemeReads(s Software, in swInfo) bool {
	p, ok := productid.ResolveStored(s.Vendor, s.Product, s.Display, s.CPE)
	if !ok || p.Scheme == "" || !versionGiven(in.ver) {
		return false
	}
	sc, ok := versionscheme.Lookup(p.Scheme)
	if !ok {
		return false
	}
	_, ok = sc.Installed(in.ver, statedBuild(s))
	return ok
}

// versionEvidence says whether an NVD entry gives a version: a range bound, or a version in its CPE.
func versionEvidence(af Affected) bool {
	if r := af.Range; r.StartIncl != "" || r.StartExcl != "" || r.EndIncl != "" || r.EndExcl != "" {
		return true
	}
	c, err := af.cpe()
	if err != nil {
		return false
	}
	_, ok := c.Version.Literal()
	return ok
}

// rowEntries are the entries of NVD's list for v that name the row itself (its CPE, name or alias, appliesTo), leaving out, for a
// Chromium-based Edge, the Edge Legacy entries: microsoft:edge with no version or one below 79, or, for a CVE published
// before the Chromium-based Edge, microsoft:edge with no version given at all (CVE-2017-0037 "Edge and Internet Explorer").
func rowEntries(s Software, in swInfo, v Vuln) []Affected {
	chromium := false
	if n, ok := edgeMajor(in.ver); ok && n >= chromiumEdgeFirst && productid.Norm(s.Vendor) == "microsoft" && strings.HasPrefix(productid.Norm(s.Product), "edge") {
		chromium = true
	}
	var out []Affected
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil {
			continue
		}
		if own, _ := appliesTo(c, in.cpe, in.hasCPE, in.ids); !own || chromium && edgeLegacyOf(c, af, v) || naVersionApart(c, in.ver, v.Affected) {
			continue
		}
		out = append(out, af)
	}
	return out
}

func uncheckedOf(s Software, v Vuln, r UncheckedReason) Unchecked {
	return Unchecked{CVE: v.CVE, SoftwareID: s.ID, Software: clean(s.Display), Version: clean(s.Version), Source: s.Source, Reason: r,
		NVDPending: r == UncheckedNoNVDData && !v.NVDAnswered}
}

// UncheckedQuestion is contract.ts UncheckedQuestion: the question of a platform-limited CVE and the answers that settle it.
// Every answer is a correction of inventory (INV-41), so the next match decides.
type UncheckedQuestion struct {
	Text string `json:"text"`
	// Error says the last answer could not be read ("Vedette could not read the release you entered …"), nil otherwise.
	Error   *string           `json:"error,omitempty"`
	Command *string           `json:"command"` // what to run on the device to read the answer ("apk info -e -v openssh-server"), nil when none
	Answers []UncheckedAnswer `json:"answers"`
}

// UncheckedAnswer is one answer: OS set → one click sets the device's OS to it (PATCH /inventory/devices/{asset_id} {os}); Ask holds "os" →
// the person types the OS (same call); Ask "pkg_version" → the person types the package release of the row (PATCH
// /inventory/devices/{asset_id}/software/{software_id} {pkg_version}).
type UncheckedAnswer struct {
	Label string   `json:"label"`
	OS    *string  `json:"os,omitempty"`
	Ask   []string `json:"ask,omitempty"` // "os", "pkg_version": what the person types (both for "Another system")
}

// edgeLegacyOf says an NVD entry is about Edge Legacy (rowEntries).
func edgeLegacyOf(c CPE, af Affected, v Vuln) bool {
	if edgeLegacyEntry(c, af.Range) {
		return true
	}
	p, _ := c.Product.Literal()
	pre := !v.Published.IsZero() && v.Published.Before(chromiumEdgeGA) || v.Published.IsZero() && cveYear(v.CVE) > 0 && cveYear(v.CVE) < 2020
	return productid.Norm(p) == "edge" && !versionEvidence(af) && pre
}
