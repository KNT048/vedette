package findings

import (
	"cmp"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/knt048/vedette/core/productid"
)

// Vendor version schemes the NVD data uses besides plain dotted numbers. Each rule only turns a
// comparison into Unknown or into a No that is certain; none of them guesses "affected".

// officeMajors maps the edition names NVD gives Microsoft Office and its apps ("cpe:...:microsoft:office:2010")
// to the internal major version a computer reports (16.0.17928.20114 is Office 2016, 2019, 2021, 2024 or
// Microsoft 365: they all report 16). The Mac editions 2004, 2008 and 2011 reported 11, 12 and 14; Office 2016
// for Mac reported 15 and later 16. Sources: Microsoft Learn, "Update history for Office 2016/2019/2021/2024"
// and "Office for Mac release history".
var officeMajors = map[string][]uint64{
	"2000": {9}, "xp": {10}, "2002": {10}, "2003": {11}, "2004": {11}, "2007": {12}, "2008": {12},
	"2010": {14}, "2011": {14}, "2013": {15}, "2016": {15, 16}, "2019": {16}, "2021": {16}, "2024": {16},
}

// officeApps are the NVD products that are part of the Office suite and share its version numbers.
var officeApps = map[string]bool{
	"office": true, "word": true, "excel": true, "powerpoint": true, "outlook": true, "access": true, "publisher": true,
	"onenote": true, "officepowerpoint": true,
}

// officeEdition decides an exact Office edition configuration ("office:2010") against the software version.
// An edition typed by a person ("2016", "xp") must be that edition (another one is No; the same one is Yes, or
// Unknown when the configuration pins a service pack). A version a computer reports ("16.0.17928.20114", or
// "365") is compared by internal major: another major is No, the same major is Unknown (one major covers several
// editions). ok is false when the rule does not apply (not Office, not an edition name, another kind of version).
func officeEdition(c CPE, r VersionRange, exact bool, ver string) (Tri, bool) {
	if !exact {
		return Unknown, false
	}
	v, okV := c.Vendor.Literal()
	p, okP := c.Product.Literal()
	if !okV || !okP || productid.Norm(v) != "microsoft" || !officeApps[productid.Norm(p)] {
		return Unknown, false
	}
	majors, ok := officeMajors[strings.ToLower(r.StartIncl)]
	if !ok {
		return Unknown, false
	}
	if tok := strings.ToLower(strings.TrimSpace(ver)); officeMajors[tok] != nil { // the person typed an edition ("2016", "xp")
		switch {
		case tok != strings.ToLower(r.StartIncl):
			return No, true
		case c.Update.Kind != Any:
			return Unknown, true // "2010" does not say which service pack
		}
		return Yes, true
	}
	var major uint64
	if strings.TrimSpace(ver) == "365" { // "Microsoft 365 Apps", as the catalog hint suggests typing: it reports 16
		major = 16
	} else if pv, ok := parseVersion(ver); ok && len(pv.rel) >= 2 && pv.rel[0] >= 9 && pv.rel[0] <= 16 {
		major = pv.rel[0]
	} else {
		return Unknown, false
	}
	for _, m := range majors {
		if major == m {
			return Unknown, true
		}
	}
	return No, true
}

// sqlServerMajors maps the release names NVD gives SQL Server ("cpe:...:microsoft:sql_server:2014:sp3") to the major of
// the builds a computer reports (12.0.6024.0 is SQL Server 2014; 2008 R2 is 10.50, so 2008 and 2008 R2 share 10). One
// release per major, unlike Office. Source: Microsoft Learn, "Latest updates and version history for SQL Server"
// (https://support.microsoft.com/servicing/sql/kb321185-download-and-install-latest-updates).
var sqlServerMajors = map[string]uint64{"2000": 8, "2005": 9, "2008": 10, "2012": 11, "2014": 12, "2016": 13, "2017": 14, "2019": 15,
	"2022": 16, "2025": 17}

// sqlServerProducts are the releases NVD names as products of their own with build versions (microsoft:sql_server_2016 …
// _2025, NVD's CPE dictionary, 2026-11-17), the aliases of Microsoft|SQL Server in content/catalog/products. sql_server_2000/2005/2008
// write the release in the version ("sql_server_2008:r2:sp1") and are neither.
var sqlServerProducts = map[string]bool{"2016": true, "2017": true, "2019": true, "2022": true, "2025": true}

// sqlServerRelease reads the two ways NVD names a SQL Server release against the software version:
//   - an exact release configuration of microsoft:sql_server ("sql_server:2014:sp3"), as officeEdition does for Office: a release
//     typed by a person ("2014") must be that release; a build a computer reports ("16.0.4135.4") is compared by major: another
//     major is No (SQL Server 2022 is not SQL Server 2014), the same major is Unknown (the build does not say which service pack);
//   - a configuration of a release's own product (microsoft:sql_server_2016 … _2025, aliases of Microsoft|SQL Server in
//     content/catalog/products) with build ranges: a typed release other than that product's is No, the same one Unknown (a year is not a build);
//     a build of the product's major written with a service-pack minor ("13.2.5026.0", how SQL Server 2016 SP2's programs
//     read) is Unknown, since NVD writes those builds as 13.0.x; any other build is left to the ranges.
//
// It never answers Yes for a build. A No here is one entry's: decide still lets a Yes or Unknown of any other entry of the CVE win.
// ok is false when the rule does not apply.
func sqlServerRelease(c CPE, r VersionRange, exact bool, ver string) (Tri, bool) {
	v, okV := c.Vendor.Literal()
	p, okP := c.Product.Literal()
	if !okV || !okP || productid.Norm(v) != "microsoft" {
		return Unknown, false
	}
	var rel string // the release the configuration names
	product := false
	switch np := productid.Norm(p); {
	case np == "sqlserver" && exact:
		rel = strings.ToLower(r.StartIncl)
	case strings.HasPrefix(np, "sqlserver") && sqlServerProducts[strings.TrimPrefix(np, "sqlserver")]:
		rel, product = strings.TrimPrefix(np, "sqlserver"), true
	}
	major, ok := sqlServerMajors[rel]
	if !ok {
		return Unknown, false
	}
	if tok := strings.ToLower(strings.TrimSpace(ver)); sqlServerMajors[tok] != 0 { // the person typed a release
		switch {
		case tok != rel:
			return No, true
		case product || c.Update.Kind != Any:
			return Unknown, true // "2016" is not a build of the ranges; "2014" does not say which service pack
		}
		return Yes, true
	}
	pv, ok := parseVersion(ver)
	if !ok || len(pv.rel) < 3 || pv.rel[0] < 8 || pv.rel[0] > 17 {
		return Unknown, false
	}
	switch {
	case product && pv.rel[0] == major && pv.rel[1] != 0:
		return Unknown, true // a service pack's "13.2.5026.0" against NVD's 13.0.x ranges
	case product:
		return Unknown, false // the ranges decide
	case pv.rel[0] != major:
		return No, true
	}
	return Unknown, true
}

// schemeClash reports whether the range and the version are written in two different schemes, so that ordering
// them means nothing: one side starts with a year or a build-sized number (2016, 1607) and the other with a small
// one (16.0.1, 10.0.14393). Unparseable sides are left to the ordinary comparison (it answers Unknown).
func schemeClash(r VersionRange, ver string) bool {
	sv, ok := parseVersion(ver)
	if !ok {
		return false
	}
	for _, b := range []string{r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl} {
		if b == "" {
			continue
		}
		bv, ok := parseVersion(b)
		if ok && (bv.rel[0] >= 1000) != (sv.rel[0] >= 1000) {
			return true
		}
	}
	return false
}

// osPatterns turn the operating system inventory folds from osquery ("Ubuntu 26.04.1 LTS", "Debian GNU/Linux 12
// (bookworm)") into the NVD product and version of that release. NVD names an Ubuntu release by year.month
// ("ubuntu_linux:20.04"), so the point release of "20.04.6 LTS" is left out: it is still 20.04 (review M1).
var osPatterns = []struct {
	re *regexp.Regexp
	id identity
}{
	{regexp.MustCompile(`(?i)^ubuntu\s+(\d+\.\d+)`), identity{vendor: "canonical", product: "ubuntulinux"}},
	{regexp.MustCompile(`(?i)^debian(?:\s+gnu/linux)?\s+(\d+(?:\.\d+)?)`), identity{vendor: "debian", product: "debianlinux"}},
}

func osIdentity(os string) (identity, string) {
	for _, p := range osPatterns {
		if m := p.re.FindStringSubmatch(strings.TrimSpace(os)); m != nil {
			return p.id, m[1]
		}
	}
	return identity{}, ""
}

// distroVendors publish operating-system releases; an NVD entry of theirs with part "o" names a release, not a program.
var distroVendors = map[string]bool{"canonical": true, "debian": true, "redhat": true, "fedoraproject": true, "opensuse": true, "suse": true}

// distroRelease reports whether configuration c names a release of an operating-system distribution
// ("o:canonical:ubuntu_linux:22.04"), not a program.
func distroRelease(c CPE) bool {
	cv, ok := c.Vendor.Literal()
	return ok && c.Part.Kind == Value && c.Part.Value == "o" && distroVendors[productid.Norm(cv)]
}

// osRulesOut reports whether an entry whose configurations are ALL operating-system releases (CVE-2021-3493 lists
// only Ubuntu releases before 20.10 for a kernel bug) rules the device out: it lists releases of the device's own
// distribution and its release is outside every one of them. An entry that lists only another distribution's
// releases says nothing about this device (Unknown, review M1). These entries only ever rule out, never prove (the
// program's version is what proves).
func osRulesOut(v Vuln, in swInfo) bool {
	if len(v.Affected) == 0 {
		return false
	}
	own := false
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil || c.Part.Kind != Value || c.Part.Value != "o" {
			return false
		}
		cv, okV := c.Vendor.Literal()
		cp, okP := c.Product.Literal()
		if !okV || !okP || !distroVendors[productid.Norm(cv)] {
			return false
		}
		if !in.os.matches(productid.Norm(cv), productid.Norm(cp)) {
			continue // another distribution's release
		}
		own = true
		if t, _ := evalAffected(c, af.Range, in.osVer, CPE{}, false); t != No {
			return false
		}
	}
	return own
}

// sameVersionText reports whether an exact configuration version and the software version are the same text,
// ignoring case and surrounding space ("15.2(4)M3" and "15.2(4)m3"). A placeholder is never the same.
func sameVersionText(cfg, ver string) bool {
	ver = strings.TrimSpace(ver)
	return ver != "" && len(ver) <= maxVersionLen && !isPlaceholder(ver) && strings.EqualFold(strings.TrimSpace(cfg), ver)
}

// laterThan says the software version ver is certainly later than lit, the one version an exact NVD configuration c names (no
// range), in the scheme the vendor writes it: a SQL Server build against NVD's release name (16.0.1000.6 is SQL Server 2022, later
// than "sql_server:2008"), Java SE before 9 by line and update (javaRelease), any other by laterRelease. Office editions, Junos and
// everything that does not read are never later: "later" only takes a row off the "could not be checked" list (newerThanListed),
// so it must be certain, and it is never a verdict about the flaw.
func laterThan(c CPE, lit, ver string) bool {
	if isJunos(c) {
		return false
	}
	if _, ok := officeEdition(c, VersionRange{StartIncl: lit, EndIncl: lit}, true, ver); ok {
		return false
	}
	if later, ok := sqlServerLater(c, lit, ver); ok {
		return later
	}
	if el, eu, java, ok := javaEntry(c, lit); java { // Java's "1.8.0" is never compared as a number with "8.0.4910.10"
		rl, ru, rok := javaRelease(ver)
		return ok && rok && (rl > el || rl == el && ru > eu)
	}
	return laterRelease(lit, ver)
}

// lineOrder compares the release line of the software version ver with that of lit, the one version an exact NVD configuration c
// names (no range), in a notation whose lines are known: a Junos release ("15.1R7.9" against "junos:24.4:r1", by its release numbers)
// or Java SE (8 Update 491, "8.0.4910.10", against "jre:11.0.26" or "jre:1.7.0:update401"). It is negative when ver's line is older,
// 0 for the same line, positive when newer; ok is false for every other notation: "8.0.600" against Java's "1.8.0" or an ESXi update
// against NVD's "esxi:8.0" share no notation a line can be read from without guessing. Like laterThan it only takes a row off the
// "could not be checked" list (newerThanListed), never a verdict about the flaw.
func lineOrder(c CPE, lit, ver string) (int, bool) {
	if isJunos(c) { // the release numbers only: a train of the same release (an X train beside R) is not certain to be apart
		jv, okV := junosParse(ver)
		e, okE := junosRelOf(lit)
		if !okV || !okE {
			return 0, false
		}
		return junosRelCmp(jv, e), true
	}
	rl, _, rok := javaRelease(ver)
	if !rok {
		return 0, false
	}
	if el, _, java, ok := javaEntry(c, lit); java {
		return cmp.Compare(rl, el), ok
	}
	v, okV := c.Vendor.Literal()
	p, okP := c.Product.Literal()
	if !okV || !okP || productid.Norm(v) != "oracle" || productid.Norm(p) != "jre" && productid.Norm(p) != "jdk" {
		return 0, false
	}
	el, _, ok := javaRelease(lit) // Java 9 on: "11.0.26", "24"
	if !ok {
		return 0, false
	}
	return cmp.Compare(rl, el), true
}

// leadingRE is the release numbers a version starts with and what follows them: "7.2.1" and "-69057-5" of DSM's "7.2.1-69057-5",
// "8.0.3" and " build-24022510", "6.6.1" and "p1". What follows never starts with a digit, a dot and a digit, or a colon (an epoch,
// "1:9.6p1", is not a release number).
var leadingRE = regexp.MustCompile(`^(\d{1,9}(?:\.\d{1,9}){0,7})((?:[^\d.:]|\.[^\d]).*)?$`)

// leadingRelease is the release numbers a version starts with (leadingRE).
func leadingRelease(s string) ([]uint64, bool) {
	m := leadingRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return nil, false
	}
	var nums []uint64
	for _, p := range strings.Split(m[1], ".") {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, false
		}
		nums = append(nums, n)
	}
	return nums, true
}

// laterRelease is laterThan for a product no scheme rule reads (review r1 H1 of #970). NVD often names a release line by its first
// numbers ("esxi:8.0" with the update in the CPE, "vcenter_server:6.7", "solaris:11", "internet_explorer:11") while the computer
// reports the whole number ("8.0.3", "6.7.0.44000", "11.4", "11.0.26100.1"): a version is later only when its release numbers, as
// many as NVD wrote, are higher (9.0.1 after 8.0; 8.0.3 is inside 8.0). Only the release numbers each side starts with are compared:
// what follows them (an update, edition or other qualifier NVD pins, "esxi:6.5:update1"; a build or patch suffix, DSM's "4.3-3810",
// OpenSSH's "9.6p1", "8.0.3 build-24022510") is a step inside that release, so it never makes a version later than a higher release
// number nor earlier than a lower one: 8.0.3 is later than esxi:6.5:update1 and DSM 7.2.1-69057-5 than 4.3-3810, while 8.0.3 is not
// later than esxi:8.0:update_3 (the same release numbers). Never later: a version that does not start with a release number ("v7.2",
// "r28.3.9", an epoch), a release named by its year or a build-sized number ("2016" of Exchange or ColdFusion against a typed
// "2019"), and two ways of writing versions (schemeClash).
func laterRelease(lit, ver string) bool {
	ln, okL := leadingRelease(lit)
	rn, okR := leadingRelease(ver)
	if !okL || !okR || ln[0] >= 1000 || schemeClash(VersionRange{StartIncl: joinRelease(ln)}, joinRelease(rn)) {
		return false
	}
	for i, n := range ln {
		var r uint64
		if i < len(rn) {
			r = rn[i]
		}
		if r != n {
			return r > n
		}
	}
	return false // the same release, or a version inside it
}

// joinRelease writes release numbers back as a dotted version.
func joinRelease(nums []uint64) string {
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = strconv.FormatUint(n, 10)
	}
	return strings.Join(parts, ".")
}

// sqlServerLater is laterThan for an exact release configuration of microsoft:sql_server ("sql_server:2008:sp3"): a build a
// computer reports or a release a person typed is later when its major is higher. ok is false when the rule does not apply.
func sqlServerLater(c CPE, lit, ver string) (later, ok bool) {
	v, okV := c.Vendor.Literal()
	p, okP := c.Product.Literal()
	major, okM := sqlServerMajors[strings.ToLower(lit)]
	if !okV || !okP || !okM || productid.Norm(v) != "microsoft" || productid.Norm(p) != "sqlserver" {
		return false, false
	}
	if m := sqlServerMajors[strings.ToLower(strings.TrimSpace(ver))]; m != 0 {
		return m > major, true
	}
	pv, okR := parseVersion(ver)
	return okR && len(pv.rel) >= 3 && pv.rel[0] >= 8 && pv.rel[0] <= 17 && pv.rel[0] > major, true
}

// javaEntryRE is how NVD names a Java SE release in the "1.x" scheme: "1.8.0" or "1.8" (the update in the CPE's update, "update401",
// "update_111"), "1.4.2_25", and "1.9.0" for Java 9.
var javaEntryRE = regexp.MustCompile(`^1\.([1-9])(?:\.\d+)?(?:_(\d+))?$`)

// javaUpdateRE is NVD's update of a Java SE release: "update401", "update_401", "update32_b31" (a build of update 32).
var javaUpdateRE = regexp.MustCompile(`^update_?(\d+)(?:_b\d+)?$`)

// javaEntry reads an exact NVD configuration of Oracle's JRE or JDK written in the "1.x" scheme: java is true for those, and ok when
// the line and update read. An update of ANY is every update of the line: update is then the highest there is, so only a later line
// is later.
func javaEntry(c CPE, lit string) (line, update uint64, java, ok bool) {
	v, okV := c.Vendor.Literal()
	p, okP := c.Product.Literal()
	if !okV || !okP || productid.Norm(v) != "oracle" || productid.Norm(p) != "jre" && productid.Norm(p) != "jdk" || !strings.HasPrefix(lit, "1.") {
		return 0, 0, false, false
	}
	m := javaEntryRE.FindStringSubmatch(lit)
	if m == nil {
		return 0, 0, true, false
	}
	line, _ = strconv.ParseUint(m[1], 10, 64)
	switch u, okU := c.Update.Literal(); {
	case m[2] != "":
		update, _ = strconv.ParseUint(m[2], 10, 64)
	case c.Update.Kind == NA:
		update = 0 // "1.7.0:-": the release itself
	case okU && javaUpdateRE.MatchString(strings.ToLower(u)):
		update, _ = strconv.ParseUint(javaUpdateRE.FindStringSubmatch(strings.ToLower(u))[1], 10, 64)
	case c.Update.Kind == Any:
		update = math.MaxUint64 // every update of the line
	default:
		return 0, 0, true, false
	}
	return line, update, true, true
}

// javaWinRE is the version Windows' list of programs gives Java SE 5 to 8: "8.0.4910.10" is Java 8 Update 491 (the update times
// ten, then the build), "6.0.450" Java 6 Update 45.
var javaWinRE = regexp.MustCompile(`^([5-8])\.0\.(\d+)(?:\.\d+)?$`)

// javaUnderscoreRE is the version Java SE 5 to 8 reports itself ("java -version"): "1.8.0_491".
var javaUnderscoreRE = regexp.MustCompile(`^1\.([5-8])\.0_(\d+)(?:-b\d+)?$`)

// javaRelease reads a Java SE version as its line and update: "8.0.4910.10" and "1.8.0_491" are line 8 update 491; "17.0.10" is
// line 17 (from Java 9 on the version is the release, later than every update of an earlier line).
func javaRelease(ver string) (line, update uint64, ok bool) {
	ver = strings.TrimSpace(ver)
	if m := javaWinRE.FindStringSubmatch(ver); m != nil {
		line, _ = strconv.ParseUint(m[1], 10, 64)
		u, _ := strconv.ParseUint(m[2], 10, 64)
		return line, u / 10, true
	}
	if m := javaUnderscoreRE.FindStringSubmatch(ver); m != nil {
		line, _ = strconv.ParseUint(m[1], 10, 64)
		u, _ := strconv.ParseUint(m[2], 10, 64)
		return line, u, true
	}
	if pv, ok := parseVersion(ver); ok && pv.rel[0] >= 9 && pv.rel[0] < 1000 {
		return pv.rel[0], 0, true
	}
	return 0, 0, false
}
