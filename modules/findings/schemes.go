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
		c, err := ParseCPE(af.CPE)
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
