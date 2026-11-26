package findings

import (
	"cmp"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/core/productid"
)

// Install attributes. NVD's CPE names a build of a product with the attributes after the version: sw_edition ("esr", "lts", "-"),
// target_sw (the platform: "windows", "macos") and target_hw (the architecture: "x64", "x86"). A software line rarely states them,
// and an attribute the line does not state lowers a match to "cannot be compared" (pinnedAttrs, #906): Thunderbird 115.9.0 inside
// "esr before 140.13.0", SQL Server 2022 RTM inside a range pinned to x64. Most of the time the box already holds the evidence: the
// name the device reports ("Microsoft SQL Server 2022 (64-bit)"), the version's shape (Mozilla numbers ESR builds M.N.x), the
// platform the device's own agent reports. installOf derives the attributes from that evidence, in one place for every product, and
// judge applies them to an NVD row before the version is compared:
//   - a row whose attribute the derived one satisfies is read as if it did not pin it (the version decides);
//   - a row whose attribute names another build than the derived one does not apply to the line (it is about another build: No);
//   - anything not derivable stays pinned, so #906's protection holds where nothing is known.
//
// A derived attribute is evidence of the device, never a person's word. The table of product rules is installRules.

// installAttrs is what the box derived about how one software line was built. "" is not known.
type installAttrs struct {
	edition  string // mozillaESR or mozillaPlain (Mozilla Firefox and Thunderbird)
	esrLine  uint64 // edition mozillaESR: the ESR line (major) of the build, 0 when not read
	phases   bool   // the product's sw_edition values name release phases of one code line, not builds (Node.js "-" and "lts")
	platform string // the device's OS family (osFamilies): "windows", "macos", "linux"
	arch     string // "x64", "x86", "arm64"
	// what says so, for the evidence: "Mozilla numbers ESR builds M.N.x", "its name says 64-bit"
	editionWhy, platformWhy, archWhy string
}

// The editions Mozilla builds Firefox and Thunderbird in, as NVD writes them in sw_edition.
const (
	mozillaESR   = "esr"
	mozillaPlain = "-"
)

// installRule is what one product's own release practice says about its builds.
type installRule struct {
	ids []identity // the inventory identities (productid.Norm) of the product
	// edition derives the sw_edition from the line's name and version ("" when the evidence does not say) and says why.
	edition func(display, ver string) (string, string)
	// phases: the product's sw_edition values name release phases, not builds.
	phases bool
	// arch is the only architecture the product ships in from release floor on (its first version number), or floorYear on for a
	// release year a person typed, "" for none.
	arch             string
	floor, floorYear uint64
	// source is where the rule comes from.
	source string
}

// installRules are the products whose release practice says which build a line is.
var installRules = []installRule{
	{
		ids: []identity{{vendor: "mozilla", product: "firefox"}, {vendor: "mozilla", product: "thunderbird"}}, edition: mozillaEdition,
		source: "https://whattrainisitnow.com/calendar/ and https://wiki.mozilla.org/Release_Management/ESR_Landing_Process (ESR builds are M.N.x, N >= 1; releases M.0 and M.0.x)",
	},
	{
		ids: []identity{{vendor: "nodejs", product: "nodejs"}}, phases: true,
		source: "https://nodejs.org/en/about/previous-releases (an even major is Current, then LTS, under one version line)",
	},
	{
		ids: []identity{{vendor: "microsoft", product: "sqlserver"}}, arch: "x64", floor: 13, floorYear: 2016,
		source: "https://learn.microsoft.com/en-us/sql/sql-server/install/hardware-and-software-requirements-for-installing-sql-server-2022 (SQL Server 2016, version 13, and later run on x64 processors only)",
	},
}

// mozillaESRMajors are the majors Mozilla released as an Extended Support Release (Firefox and Thunderbird share them), from
// https://whattrainisitnow.com/release/?version=esr and the ESR ranges NVD writes ("esr 153.0 before 153.4.0").
var mozillaESRMajors = []uint64{10, 17, 24, 31, 38, 45, 52, 60, 68, 78, 91, 102, 115, 128, 140, 153}

// mozillaESRGap: Mozilla makes every 12th or 13th major an ESR. A major this far past the newest one mozillaESRMajors lists may be an
// ESR the table does not list yet, so its M.0 builds are not called plain.
const mozillaESRGap = 12

var esrWord = regexp.MustCompile(`(?i)\besr\b|\d(esr)\b`)

// mozillaEdition is the edition of a Firefox or Thunderbird line: ESR when its name or version says so ("Mozilla Firefox ESR",
// "115.9.0esr") or its version is an ESR build's (M.N.x with N >= 1 on an ESR major from 24 on, when ESR numbering began: 115.9.0,
// 140.17.0), plain for M.0 or M.0.x on a major that is no ESR (160.0, 146.0.1), and "" for M.0.x on an ESR major (128.0 shipped as
// both) or anything else.
func mozillaEdition(display, ver string) (string, string) {
	if esrWord.MatchString(display) || esrWord.MatchString(ver) {
		return mozillaESR, "its name says ESR"
	}
	pv, ok := parseVersion(ver)
	if !ok || isPlaceholder(ver) || pv.q.class != 0 || len(pv.rel) < 2 || len(pv.rel) > 3 {
		return "", ""
	}
	major, minor := pv.rel[0], pv.rel[1]
	esrMajor := slices.Contains(mozillaESRMajors, major)
	switch {
	case minor >= 1 && esrMajor && major >= 24:
		return mozillaESR, fmt.Sprintf("Mozilla numbers only ESR builds %d.N.x with N of 1 or more", major)
	case minor == 0 && !esrMajor && major < mozillaESRMajors[len(mozillaESRMajors)-1]+mozillaESRGap && major >= 5:
		return mozillaPlain, fmt.Sprintf("Mozilla made no ESR of %d, so it is the normal release", major)
	}
	return "", ""
}

var (
	arch64Word = regexp.MustCompile(`(?i)\b(x64|x86[-_]64|amd64|win64|64-bit|64 bit)\b`)
	arch32Word = regexp.MustCompile(`(?i)\b(x86|i[3-6]86|win32|32-bit|32 bit)\b`)
	armWord    = regexp.MustCompile(`(?i)\b(arm64|aarch64)\b`)
)

// archOfName is the architecture a line's name states ("Microsoft SQL Server 2022 (64-bit)", "Notepad++ (32-bit x86)"), "" when it
// states none or more than one.
func archOfName(display string) string {
	var found []string
	if arch64Word.MatchString(display) {
		found = append(found, "x64")
	}
	if arch32Word.MatchString(arch64Word.ReplaceAllString(display, "")) { // "x86_64" is not x86
		found = append(found, "x86")
	}
	if armWord.MatchString(display) {
		found = append(found, "arm64")
	}
	if len(found) != 1 {
		return ""
	}
	return found[0]
}

// deviceArch is the architecture of the device's own operating system, as its agent reports it on the Windows release row
// ("cpe:2.3:o:microsoft:windows_11_26h2:…:x64:*", agent-intake), "" when no row says.
func deviceArch(a Asset) string {
	for _, s := range a.Software {
		c, err := ParseCPE(s.CPE)
		if err != nil || c.Part.Value != "o" {
			continue
		}
		if t, ok := c.TargetHW.Literal(); ok && c.TargetHW.Kind == Value {
			return normArch(t)
		}
	}
	return ""
}

// normArch is NVD's architecture word in one spelling ("aarch64" is arm64), "" for a word that names no architecture.
func normArch(t string) string {
	switch t = strings.ToLower(t); t {
	case "x64", "x86_64", "amd64":
		return "x64"
	case "x86", "i386", "i686":
		return "x86"
	case "arm64", "aarch64":
		return "arm64"
	case "itanium", "ia64":
		return "itanium"
	}
	return ""
}

// osFamilies maps NVD's target_sw words that name an operating system to its family; other words ("wordpress", "node.js") name a
// host application, not a platform, and are never judged here.
var osFamilies = map[string]string{
	"windows": "windows", "macos": "macos", "mac_os_x": "macos", "mac_os": "macos", "linux": "linux",
	"iphone_os": "ios", "ipados": "ios", "ios": "ios", "android": "android",
}

// familyOf is the OS family of the platform the device's own software inventory states for the line (platformOS), "" when unknown.
func familyOf(osText string) string {
	ids := platformsIn(osText)
	fam := ""
	for _, id := range ids {
		f := id
		switch id {
		case "alpine", "ubuntu", "debian", "rhel", "suse":
			f = "linux"
		case "windows", "macos":
		default:
			continue
		}
		if fam != "" && fam != f {
			return ""
		}
		fam = f
	}
	return fam
}

// installOf derives the install attributes of line s of device a from evidence the box holds. The line's own CPE wins for an attribute
// it states (judge reads it first).
func installOf(s Software, a Asset) installAttrs {
	var at installAttrs
	ids := []identity{{vendor: productid.Norm(s.Vendor), product: productid.Norm(s.Product)}}
	ver := s.Version
	for _, r := range installRules {
		if !slices.ContainsFunc(r.ids, func(i identity) bool { return slices.Contains(ids, i) }) {
			continue
		}
		if r.edition != nil {
			at.edition, at.editionWhy = r.edition(s.Display, ver)
			if pv, ok := parseVersion(ver); ok && at.edition == mozillaESR && len(pv.rel) > 0 {
				at.esrLine = pv.rel[0]
			}
		}
		at.phases = at.phases || r.phases
		if r.arch != "" && atLeastMajor(ver, r.floor, r.floorYear) {
			at.arch, at.archWhy = r.arch, "the product ships for "+r.arch+" only from that release on"
		}
	}
	if n := archOfName(s.Display); n != "" {
		at.arch, at.archWhy = n, "its name says "+n // the name the device reports wins over the product's rule
	}
	if at.arch == "" && deviceArch(a) == "x86" {
		// a 32-bit system runs only 32-bit programs; a 64-bit one runs both, so it says nothing
		at.arch, at.archWhy = "x86", "the device runs a 32-bit system"
	}
	if os := platformOS(s, a); os != "" {
		if at.platform = familyOf(os); at.platform != "" {
			at.platformWhy = "the device runs " + clean(os)
		}
	}
	return at
}

// atLeastMajor says whether the first number of ver is at least floor for a build (16.0.1000.6), or at least floorYear for a release
// year a person typed (2022; 2014 is not SQL Server 2016's version 13 or later).
func atLeastMajor(ver string, floor, floorYear uint64) bool {
	head, _, _ := strings.Cut(strings.TrimSpace(ver), ".")
	n, err := strconv.ParseUint(head, 10, 64)
	if err != nil {
		return false
	}
	if n >= 1990 { // a release year
		return floorYear != 0 && n >= floorYear
	}
	return n >= floor
}

// Indexes of the attributes after the version in CPE.fields.
const (
	attrEdition   = 5
	attrSWEdition = 7
	attrTargetSW  = 8
	attrTargetHW  = 9
)

// siblings are the values each attribute takes in the rows of one CVE, by product: what NVD's "-" stands beside. It is read from
// the CVE's rows once, on first use.
type siblings struct {
	v    *Vuln
	done bool
	by   map[string]*[11]map[string]bool
	// esrLines: by product, the ESR lines (start and end majors) each of its "esr" rows spans; a row with no start reaches every older
	// line, one with no end every newer one. A product with no "esr" row is absent.
	esrLines map[string][][2]uint64
}

func siblingsOf(v *Vuln) *siblings { return &siblings{v: v} }

// of is the values each attribute takes in the rows that name the product of c.
func (s *siblings) of(c CPE) [11]map[string]bool {
	if s == nil || s.v == nil {
		return [11]map[string]bool{}
	}
	if !s.done {
		s.by, s.done = s.read(), true
	}
	if m := s.by[c.Vendor.Value+":"+c.Product.Value]; m != nil {
		return *m
	}
	return [11]map[string]bool{}
}

// esrLineUnlisted says the CVE has "esr" rows of c's product and none of them spans ESR line line: Mozilla lists supported ESR lines
// only, so an end-of-life one (older than every listed line, or between them) is absent whether or not its code has the flaw. False
// when the product has no "esr" row: then no supported ESR is affected and the flaw is in code newer than every ESR line.
func (s *siblings) esrLineUnlisted(c CPE, line uint64) bool {
	if s == nil || s.v == nil || line == 0 {
		return false
	}
	s.of(c)
	spans, ok := s.esrLines[c.Vendor.Value+":"+c.Product.Value]
	return ok && !slices.ContainsFunc(spans, func(sp [2]uint64) bool { return sp[0] <= line && line <= sp[1] })
}

func (s *siblings) read() map[string]*[11]map[string]bool {
	out := map[string]*[11]map[string]bool{}
	s.esrLines = map[string][][2]uint64{}
	major := func(v string, none uint64) uint64 {
		if pv, ok := parseVersion(v); ok && len(pv.rel) > 0 {
			return pv.rel[0]
		}
		return none
	}
	for _, af := range s.v.Affected {
		c, err := af.cpe()
		if err != nil {
			continue
		}
		k := c.Vendor.Value + ":" + c.Product.Value
		if lit, _ := c.fields()[attrSWEdition].Literal(); c.fields()[attrSWEdition].Kind == Value && strings.EqualFold(lit, mozillaESR) {
			from := major(cmp.Or(af.Range.StartIncl, af.Range.StartExcl), 0)
			to := major(cmp.Or(af.Range.EndExcl, af.Range.EndIncl), math.MaxUint64)
			if exact, ok := c.Version.Literal(); ok && c.Version.Kind == Value && af.Range.IsZero() {
				from, to = major(exact, 0), major(exact, math.MaxUint64) // one ESR build (140.9.0 esr): its line only
			}
			s.esrLines[k] = append(s.esrLines[k], [2]uint64{from, to})
		}
		if out[k] == nil {
			out[k] = &[11]map[string]bool{}
		}
		f := c.fields()
		for i := attrEdition; i < len(f); i++ {
			if f[i].Kind == Value {
				if out[k][i] == nil {
					out[k][i] = map[string]bool{}
				}
				lit, _ := f[i].Literal()
				out[k][i][strings.ToLower(lit)] = true
			}
		}
	}
	return out
}

// judge reads NVD row c for a line with the derived attributes at: c with every attribute they satisfy set to ANY, and ok false when
// an attribute names another build than the line's (the row does not apply). An attribute the line's own CPE states is left to
// pinnedAttrs. sib gives the values the other rows of c's product take (siblingsOf), for NVD's "-" in a platform attribute.
func (at installAttrs) judge(c CPE, sw CPE, hasSW bool, sib *siblings) (CPE, bool) {
	f := c.fields()
	var sf [11]*Attr
	if hasSW {
		sf = sw.fields()
	}
	stated := func(i int) bool { return hasSW && sf[i].Kind != Any }
	// sw_edition
	if a := f[attrSWEdition]; a.Kind != Any && !stated(attrSWEdition) {
		lit, _ := a.Literal()
		switch {
		case at.phases && (a.Kind == NA || strings.EqualFold(lit, "lts")):
			*a = Attr{Kind: Any}
		case at.edition != "":
			val := mozillaPlain
			if a.Kind == Value {
				val = strings.ToLower(lit)
			}
			switch {
			case val != mozillaESR && val != mozillaPlain:
			case val == mozillaPlain && at.edition == mozillaESR && sib.esrLineUnlisted(c, at.esrLine):
				// an ESR line no ESR row spans (end-of-life): their silence about it is no proof, so the plain row stays pinned
			case val != at.edition:
				return c, false
			default:
				*a = Attr{Kind: Any}
			}
		}
	}
	// target_sw and target_hw
	for _, p := range []struct {
		i    int
		have string
		word func(string) string
	}{
		{attrTargetSW, at.platform, func(s string) string { return osFamilies[strings.ToLower(s)] }},
		{attrTargetHW, at.arch, normArch},
	} {
		a := f[p.i]
		if a.Kind == Any || stated(p.i) {
			continue
		}
		if a.Kind == Value {
			lit, ok := a.Literal()
			w := ""
			if ok {
				w = p.word(lit)
			}
			switch {
			case w == "" || p.have == "": // a host application, or nothing known: left pinned
			case w == p.have:
				*a = Attr{Kind: Any}
			default:
				return c, false
			}
			continue
		}
		// NA: the build for no named platform. With no other row of the product naming one, it is every build ("-" alone, as Visual
		// Studio Code's rows write it); beside named ones (Office's "-" and "macos") it is the build for none of them.
		named := sib.of(c)[p.i]
		if len(named) == 0 {
			*a = Attr{Kind: Any}
			continue
		}
		words := map[string]bool{}
		known := true
		for n := range named {
			w := p.word(n)
			known = known && w != ""
			words[w] = true
		}
		switch {
		case !known || p.have == "": // beside a word that names no platform ("vmware"), or nothing known: left pinned
		case words[p.have]:
			return c, false
		default:
			*a = Attr{Kind: Any}
		}
	}
	return c, true
}

// eval is evalAffected of NVD row c for the line, after its install attributes judged the row (judge): a row about another build is No.
func (in swInfo) eval(c CPE, r VersionRange, ver string, sib *siblings) (Tri, VersionRange) {
	c, ok := in.install.judge(c, in.cpe, in.hasCPE, sib)
	if !ok {
		return No, r
	}
	return evalAffected(c, r, ver, in.cpe, in.hasCPE)
}

// swInfoOn is newSWInfo for line s of device a, with the install attributes the box derives for it (installOf).
func swInfoOn(s Software, a Asset) swInfo {
	in := newSWInfo(s, a.OS)
	in.install = installOf(s, a)
	return in
}

// installClause says, for the evidence of a decision, which build NVD's rows were read for when the line's derived attributes decided
// which rows apply: the rows that name the range a finding rests on (within), or, for "not affected" (within nil), the rows about
// another build that were set aside. "" when no derived attribute took part.
func (in swInfo) installClause(v Vuln, key []identity, within *VersionRange) string {
	at := in.install
	if at == (installAttrs{}) {
		return ""
	}
	sib := siblingsOf(&v)
	used := map[int]bool{}
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA {
			continue
		}
		if own, _, _ := entryFor(c, in, key); !own {
			continue
		}
		j, ok := at.judge(c, in.cpe, in.hasCPE, sib)
		if within != nil && (!ok || af.Range != *within) || within == nil && ok {
			continue
		}
		f, g := c.fields(), j.fields()
		for _, i := range []int{attrSWEdition, attrTargetSW, attrTargetHW} {
			if within == nil && f[i].Kind != Any || within != nil && f[i].Kind != Any && g[i].Kind == Any {
				used[i] = true
			}
		}
	}
	var says []string
	if used[attrSWEdition] {
		switch {
		case at.phases:
			says = append(says, "LTS and Current are phases of one release line, so the version decides")
		case at.edition == mozillaESR:
			says = append(says, "this is the ESR edition ("+at.editionWhy+")")
		case at.edition == mozillaPlain:
			says = append(says, "this is the normal release, not ESR ("+at.editionWhy+")")
		}
	}
	if used[attrTargetSW] && at.platformWhy != "" {
		says = append(says, at.platformWhy)
	}
	if used[attrTargetHW] && at.archWhy != "" {
		says = append(says, "this is the "+at.arch+" build ("+at.archWhy+")")
	}
	return strings.Join(says, "; ")
}

// withInstall is a finding's evidence sentence with the build it was read for (installClause), before the "only suspected" clause
// that evidenceForStatus drops once the finding is confirmed.
func withInstall(summary, build string) string {
	if build == "" {
		return summary
	}
	if head, ok := strings.CutSuffix(summary, suspectedClause); ok {
		return head + "; read for this build: " + build + suspectedClause
	}
	return strings.TrimSuffix(summary, ".") + ". Read for this build: " + build + "."
}

// The build attributes a not_comparable question can ask for (Unchecked.Attribute).
const (
	AttrEdition      = "edition"      // sw_edition or edition: "ESR or the normal release?"
	AttrArchitecture = "architecture" // target_hw: "the 64-bit build?"
	AttrPlatform     = "platform"     // target_sw: "which system?"
	// AttrUnlistedLine: the build is a Mozilla ESR of a line the CVE's ESR rows do not list (end of life, esrLineUnlisted): the
	// edition is known, whether that line is affected is not.
	AttrUnlistedLine = "unlisted_line"
)

// blockingAttribute is the build attribute that keeps v undecided on the line: a row of the line's own product, judged with what the
// box derived (judge), still pins an attribute the line does not state, and the version is inside that row's range once the pin is set
// aside, so the attribute, not the version, decides. The edition comes first, then the architecture, then the platform. "" when no
// such row exists: typing the version as the vendor writes it is then the question.
func blockingAttribute(in swInfo, v Vuln, key []identity) string {
	if !versionKnown(in.ver) {
		return ""
	}
	sib := siblingsOf(&v)
	found := map[string]bool{}
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind == NA {
			continue
		}
		if own, _, _ := entryFor(c, in, key); !own {
			continue
		}
		j, ok := in.install.judge(c, in.cpe, in.hasCPE, sib)
		if !ok {
			continue
		}
		if t, _ := evalAffected(stripPins(j), af.Range, in.ver, in.cpe, in.hasCPE); t != Yes {
			continue
		}
		f := j.fields()
		var sf [11]*Attr
		if in.hasCPE {
			sf = in.cpe.fields()
		}
		for i, name := range map[int]string{attrEdition: AttrEdition, attrSWEdition: AttrEdition, attrTargetHW: AttrArchitecture, attrTargetSW: AttrPlatform} {
			if f[i].Kind != Any && (!in.hasCPE || !attrMatch(*f[i], *sf[i])) {
				if i == attrSWEdition && in.install.edition == mozillaESR && sib.esrLineUnlisted(c, in.install.esrLine) {
					name = AttrUnlistedLine // the plain row judge kept pinned: the edition is known, the line is not listed
				}
				found[name] = true
			}
		}
	}
	for _, a := range []string{AttrUnlistedLine, AttrEdition, AttrArchitecture, AttrPlatform} {
		if found[a] {
			return a
		}
	}
	return ""
}
