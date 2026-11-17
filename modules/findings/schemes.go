package findings

import (
	"regexp"
	"strings"
)

// Vendor version schemes the NVD data uses besides plain dotted numbers (D-500). Each rule only turns a
// comparison into Unknown or into a No that is certain; none of them guesses "affected".

// officeMajors maps the edition names NVD gives Microsoft Office and its apps ("cpe:...:microsoft:office:2010")
// to the internal major version a computer reports (16.0.17928.20114 is Office 2016, 2019, 2021, 2024 or
// Microsoft 365: they all report 16). The Mac editions 2004, 2008 and 2011 reported 11, 12 and 14; Office 2016
// for Mac reported 15 and later 16. Sources: Microsoft Learn, "Update history for Office 2016/2019/2021/2024"
// and "Office for Mac release history"; the list is in docs/decisions/D-500.md.
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
	if !okV || !okP || norm(v) != "microsoft" || !officeApps[norm(p)] {
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
// (https://support.microsoft.com/servicing/sql/kb321185-download-and-install-latest-updates); D-606.
var sqlServerMajors = map[string]uint64{"2000": 8, "2005": 9, "2008": 10, "2012": 11, "2014": 12, "2016": 13, "2017": 14, "2019": 15,
	"2022": 16, "2025": 17}

// sqlServerProducts are the releases NVD names as products of their own with build versions (microsoft:sql_server_2016 …
// _2025, NVD's CPE dictionary, 2026-11-17), the aliases of Microsoft|SQL Server in nvd-cpe.json. sql_server_2000/2005/2008
// write the release in the version ("sql_server_2008:r2:sp1") and are neither.
var sqlServerProducts = map[string]bool{"2016": true, "2017": true, "2019": true, "2022": true, "2025": true}

// sqlServerRelease reads the two ways NVD names a SQL Server release against the software version (D-606):
//   - an exact release configuration of microsoft:sql_server ("sql_server:2014:sp3"), as officeEdition does for Office: a release
//     typed by a person ("2014") must be that release; a build a computer reports ("16.0.4135.4") is compared by major: another
//     major is No (SQL Server 2022 is not SQL Server 2014), the same major is Unknown (the build does not say which service pack);
//   - a configuration of a release's own product (microsoft:sql_server_2016 … _2025, aliases of Microsoft|SQL Server in
//     nvd-cpe.json) with build ranges: a typed release other than that product's is No, the same one Unknown (a year is not a build);
//     a build of the product's major written with a service-pack minor ("13.2.5026.0", how SQL Server 2016 SP2's programs
//     read) is Unknown, since NVD writes those builds as 13.0.x; any other build is left to the ranges.
//
// It never answers Yes for a build. A No here is one entry's: decide still lets a Yes or Unknown of any other entry of the CVE win.
// ok is false when the rule does not apply.
func sqlServerRelease(c CPE, r VersionRange, exact bool, ver string) (Tri, bool) {
	v, okV := c.Vendor.Literal()
	p, okP := c.Product.Literal()
	if !okV || !okP || norm(v) != "microsoft" {
		return Unknown, false
	}
	var rel string // the release the configuration names
	product := false
	switch np := norm(p); {
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
	return ok && c.Part.Kind == Value && c.Part.Value == "o" && distroVendors[norm(cv)]
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
		if !okV || !okP || !distroVendors[norm(cv)] {
			return false
		}
		if !in.os.matches(norm(cv), norm(cp)) {
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
