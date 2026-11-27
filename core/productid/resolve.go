package productid

import (
	"regexp"
	"strconv"
	"strings"
)

// Source says what kind of name Resolve reads.
type Source string

// The sources of a name.
const (
	// Linux is a package name of a package database (deb, rpm, apk, pacman): the binary's name, or its source package's.
	Linux Source = "linux"
	// Windows is a program's display name in Windows' list of installed programs; vendor is its publisher.
	Windows Source = "windows"
	// CPE is a CPE a scan printed (nmap's "cpe:/a:igor_sysoev:nginx:1.18.0", or a CPE 2.3 string a device stated).
	CPE Source = "cpe"
)

const maxName = 400 // a longer name is not read

// Resolve finds the product of a name. name is the package name (Linux), the program's display name (Windows) or unused (CPE);
// vendor is the publisher; cpe a CPE 2.2 URI or 2.3 string (CPE). ok is false when the catalogue names no product, except for a
// CPE, which is a product of its own when the catalogue does not list it. A row the inventory stored is read with ResolveStored.
func Resolve(src Source, name, vendor, cpe string) (Product, bool) {
	if len(name) > maxName || len(vendor) > maxName || len(cpe) > maxName {
		return Product{}, false
	}
	switch src {
	case Linux:
		return resolveLinux(name)
	case Windows:
		return resolveWindows(name)
	case CPE:
		return resolveCPE(cpe, "", "")
	}
	return Product{}, false
}

func resolveLinux(name string) (Product, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if l, ok := cat.linux[n]; ok {
		p := withPatterns(l.e, name)
		p.Upstream = l.upstream
		return p, true
	}
	if e := longestPrefix(cat.linuxPrefix, n); e != nil {
		return withPatterns(e, name), true
	}
	return byPattern(name)
}

func resolveWindows(name string) (Product, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if e, ok := cat.windows[n]; ok {
		return withPatterns(e, name), true
	}
	if e := longestPrefix(cat.winPrefix, n); e != nil {
		return withPatterns(e, name), true
	}
	return byPattern(name)
}

// resolveCPE is the product of a CPE: the catalogue's product that lists it (an NVD name or the name nmap prints), else a product
// of its own named by it.
func resolveCPE(cpe, vendor, product string) (Product, bool) {
	base := cpeBase(cpe)
	if base == "" {
		return Product{}, false
	}
	if e, ok := cat.byCPE[base]; ok {
		return e.p, true
	}
	f := strings.SplitN(base, ":", 3)
	if vendor == "" || product == "" {
		vendor, product = strings.ReplaceAll(f[1], "_", " "), strings.ReplaceAll(f[2], "_", " ")
	}
	k := Key(vendor, product)
	return Product{Display: strings.TrimSpace(vendor + " " + product), Vendor: vendor, Product: product, Key: k, KEV: []string{k},
		CPEs: []CPEName{{Part: f[0], Vendor: f[1], Product: f[2]}}}, true
}

// ResolveStored is the product of a software row as the inventory keeps it: vendor, product, the name shown (display) and maybe a
// CPE. Every rule is tried: the CPE when the catalogue lists it, the vendor and product (or another name of the product, or one of
// its NVD names), the shown name and the product as a program name, the product as a package name when the row is a package
// (vendor and product the same name), and last the CPE as a product of its own.
func ResolveStored(vendor, product, display, cpe string) (Product, bool) {
	if len(vendor) > maxName || len(product) > maxName || len(display) > maxName || len(cpe) > maxName {
		return Product{}, false
	}
	if cpe != "" {
		if p, ok := resolveCPE(cpe, "", ""); ok && p.ID != "" {
			return p, true
		}
	}
	if e, ok := cat.byIdentity[NormKey(vendor, product)]; ok {
		p := withPatterns(e, display)
		if base := cpeBase(cpe); !p.HasCPE() && base != "" { // a product the catalogue knows by name only, named by the row's own CPE
			f := strings.SplitN(base, ":", 3)
			p.CPEs = []CPEName{{Part: f[0], Vendor: f[1], Product: f[2]}}
		}
		return p, true
	}
	for _, n := range []string{display, product} {
		if p, ok := resolveWindows(n); ok && n != "" {
			return p, true
		}
	}
	// A package name is read only for a row that is a package: one the agent keeps under its own name (vendor and product are the
	// package's name). A program "Code" by Claris or "Veeam Agent" by Veeam Software is not the package "code" or "veeam".
	if vendor == "" || Norm(vendor) == Norm(product) {
		if p, ok := resolveLinux(product); ok {
			return p, true
		}
	}
	if cpe != "" {
		return resolveCPE(cpe, vendor, product)
	}
	return Product{}, false
}

func longestPrefix(rows []prefixRow, name string) *entry {
	var best *entry
	bestLen := 0
	for _, r := range rows {
		if len(r.prefix) > bestLen && strings.HasPrefix(name, r.prefix) {
			best, bestLen = r.e, len(r.prefix)
		}
	}
	return best
}

// byPattern is the first product, in catalogue order, one of whose name patterns the name matches.
func byPattern(name string) (Product, bool) {
	for _, e := range cat.entries {
		for _, pt := range e.patterns {
			if m := pt.re.FindStringSubmatchIndex(name); m != nil {
				return applied(e, pt, name, m), true
			}
		}
	}
	return Product{}, false
}

// withPatterns is the product a table named, with the distribution and version its own patterns read in the name.
func withPatterns(e *entry, name string) Product {
	for _, pt := range e.patterns {
		if m := pt.re.FindStringSubmatchIndex(name); m != nil {
			return applied(e, pt, name, m)
		}
	}
	return e.p
}

func applied(e *entry, pt pattern, name string, m []int) Product {
	p := e.p
	p.Distribution = pt.distribution
	switch pt.version {
	case "":
	case "-":
		p.VersionNotOwn = true
	default:
		v := string(pt.re.ExpandString(nil, pt.version, name, m))
		if versionRE.MatchString(v) {
			p.Version, p.VersionNotOwn = v, true
		}
	}
	return p
}

// versionRE is a release a name may state: digits first, then digits, letters, '.', '_' and '+'.
var versionRE = regexp.MustCompile(`^\d[0-9A-Za-z._+]{0,39}$`)

// cpeBase is "part:vendor:product" (lower case) of a CPE 2.2 URI or CPE 2.3 string; "" when it is neither.
func cpeBase(cpe string) string {
	c := strings.ToLower(strings.TrimSpace(cpe))
	var f []string
	if rest, ok := strings.CutPrefix(c, "cpe:2.3:"); ok {
		f = strings.SplitN(rest, ":", 4)
	} else if rest, ok := strings.CutPrefix(c, "cpe:/"); ok {
		f = strings.SplitN(rest, ":", 4)
	}
	if len(f) < 3 || f[0] != "a" && f[0] != "o" && f[0] != "h" || f[1] == "" || f[2] == "" || f[1] == "*" || f[2] == "*" {
		return ""
	}
	return f[0] + ":" + strings.ReplaceAll(f[1], `\`, "") + ":" + strings.ReplaceAll(f[2], `\`, "")
}

// Line is the release train of version under the product's train rule: "" for a product without trains or a version that does not
// say it. Java's "1.8.0_491" and Windows' "8.0.4910.10" are train "8", "21.0.7" train "21"; .NET's "8.0.19" is "8.0" (major.minor).
// The line comes from the version only, never from an install path.
func (p Product) Line(version string) string {
	if p.Trains == TrainsNone {
		return ""
	}
	nums := leadingNumbers(version)
	if p.Scheme == "java" && len(nums) >= 2 && nums[0] == "1" {
		nums = nums[1:] // "1.8.0_491" is Java 8
	}
	switch {
	case p.Trains == TrainsMajor && len(nums) >= 1:
		return nums[0]
	case p.Trains == TrainsMajorMinor && len(nums) >= 2:
		return nums[0] + "." + nums[1]
	}
	return ""
}

// Canonical is version in the vendor's own notation: the rewrite of the first VersionMap row whose expression matches it, else the
// version as reported ("8.0.4910.10" -> "1.8.0_491" for Java on Windows). Read before Line by the matcher's line verdicts.
func (p Product) Canonical(version string) string {
	v := strings.TrimSpace(version)
	for _, m := range p.VersionMap {
		if sub := m.re.FindStringSubmatchIndex(v); sub != nil {
			return string(m.re.ExpandString(nil, m.to, v, sub))
		}
	}
	return v
}

// leadingNumbers is the dotted numbers a version starts with ("8.0.19-1ubuntu1" -> 8, 0, 19), without leading zeros.
func leadingNumbers(v string) []string {
	var out []string
	for part := range strings.SplitSeq(strings.TrimSpace(v), ".") {
		end := 0
		for end < len(part) && part[end] >= '0' && part[end] <= '9' {
			end++
		}
		if end == 0 || end > 9 {
			break
		}
		n, _ := strconv.Atoi(part[:end])
		out = append(out, strconv.Itoa(n))
		if end < len(part) {
			break
		}
	}
	return out
}
