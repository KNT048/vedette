package findings

import (
	"cmp"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Juniper Junos OS (W1-32, D-510). A Junos version is a release ("15.1"), a release type and number ("R7": the 7th
// maintenance release; "F6": feature release), an optional service release ("-S5") and a build ("R7.9": build 9 of
// R7, which is still R7). The "X" trains ("12.3X48-D105", "15.1X49-D200") are special releases of their own, with
// maintenance releases "D". NVD writes them as version and update: "junos:15.1:r7", "junos:21.4:r3-s5",
// "junos:12.3x48:d105", and its ranges end at a plain release ("before 20.4"). The generic reader takes "R7.9" for
// Ivanti's "R2.4" (a release of its own) and cannot read an X train, so a Junos device on 15.1R7.9 was "not checked".

// junosRe is a Junos version: release, then R or F with its number and service release, or an X train with its D
// release; then an optional build. Lower case.
var junosRe = regexp.MustCompile(`^(\d{1,2})\.(\d{1,2})(?:([rf])(\d{1,3})(?:-s(\d{1,3}))?|x(\d{1,3})-d(\d{1,4}))(?:\.\d{1,4})?$`)

// junosVer is a parsed Junos version. train is 'r', 'f' or 'x'; for 'x', xnum is the train ("X49") and n1 the D
// release; otherwise n1 is the R or F number and n2 the service release.
type junosVer struct {
	major, minor uint64
	train        byte
	xnum, n1, n2 uint64
}

func junosParse(s string) (junosVer, bool) {
	m := junosRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return junosVer{}, false
	}
	n := func(x string) uint64 {
		v, _ := strconv.ParseUint(x, 10, 64) // at most 4 digits, by the pattern
		return v
	}
	v := junosVer{major: n(m[1]), minor: n(m[2])}
	if m[3] != "" {
		v.train, v.n1, v.n2 = m[3][0], n(m[4]), n(m[5])
	} else {
		v.train, v.xnum, v.n1 = 'x', n(m[6]), n(m[7])
	}
	return v, true
}

// release is the NVD version of v: "15.1", or "15.1x49" for an X train.
func (v junosVer) release() string {
	r := strconv.FormatUint(v.major, 10) + "." + strconv.FormatUint(v.minor, 10)
	if v.train == 'x' {
		r += "x" + strconv.FormatUint(v.xnum, 10)
	}
	return r
}

// update is the NVD update of v: "r7", "r3-s5", "f6-s12", "d105".
func (v junosVer) update() string {
	if v.train == 'x' {
		return "d" + strconv.FormatUint(v.n1, 10)
	}
	u := string(v.train) + strconv.FormatUint(v.n1, 10)
	if v.n2 > 0 {
		u += "-s" + strconv.FormatUint(v.n2, 10)
	}
	return u
}

// String is the version as Juniper writes it, without the build: "15.1R7", "12.3X48-D105".
func (v junosVer) String() string {
	if v.train == 'x' {
		return strings.ToUpper(v.release()) + "-" + strings.ToUpper(v.update())
	}
	return v.release() + strings.ToUpper(v.update())
}

// junosBound orders version v against a range bound. A plain release bound ("20.4") is NVD's version alone: every
// update of 20.4 equals it, so "before 20.4" leaves 20.4R1 out (NVD lists the 20.4 updates as entries of their own).
// An X train is a branch of its release, neither before nor after it, so against a bound of its own release it is not
// decidable; the same goes for a bound of another train type of the same release. ok is false when the bound is not
// a Junos or plain two-part release.
func junosBound(v junosVer, bound string) (int, bool) {
	if b, ok := junosParse(bound); ok {
		if c := cmp.Or(cmp.Compare(v.major, b.major), cmp.Compare(v.minor, b.minor)); c != 0 {
			return c, true
		}
		if v.train != b.train || v.xnum != b.xnum {
			return 0, false
		}
		return cmp.Or(cmp.Compare(v.n1, b.n1), cmp.Compare(v.n2, b.n2)), true
	}
	pv, ok := parseVersion(bound)
	if !ok || len(pv.rel) != 2 || pv.q != (qual{}) || pv.tail != "" {
		return 0, false
	}
	if c := cmp.Or(cmp.Compare(v.major, pv.rel[0]), cmp.Compare(v.minor, pv.rel[1])); c != 0 {
		return c, true
	}
	return 0, v.train != 'x'
}

// isJunos reports whether configuration c names Juniper Junos OS (not Junos OS Evolved, another NVD product with
// another version scheme).
func isJunos(c CPE) bool {
	v, okV := c.Vendor.Literal()
	p, okP := c.Product.Literal()
	return okV && okP && norm(v) == "juniper" && norm(p) == "junos"
}

// junosEval decides a Junos configuration for a Junos version (D-510). ok is false when the rule does not apply (not
// Junos, or a version that is not written the Junos way): the generic comparison then answers. Like every scheme rule
// it gives No only when sure: a range bound or an update it cannot read is Unknown.
func junosEval(c CPE, r VersionRange, ver string) (t Tri, within VersionRange, ok bool) {
	if !isJunos(c) {
		return Unknown, r, false
	}
	v, ok := junosParse(ver)
	if !ok {
		return Unknown, r, false
	}
	if !r.IsZero() {
		if c.Version.Kind != Any || c.Update.Kind != Any {
			return Unknown, r, true // a range next to a concrete version or update: contradictory data
		}
		unknown := false
		check := func(bound string, in func(int) bool) bool {
			if bound == "" {
				return true
			}
			c, known := junosBound(v, bound)
			if !known {
				unknown = true
				return true
			}
			return in(c)
		}
		if !check(r.StartIncl, func(c int) bool { return c >= 0 }) || !check(r.StartExcl, func(c int) bool { return c > 0 }) ||
			!check(r.EndIncl, func(c int) bool { return c <= 0 }) || !check(r.EndExcl, func(c int) bool { return c < 0 }) {
			return No, r, true
		}
		if unknown {
			return Unknown, r, true
		}
		return Yes, r, true
	}
	switch c.Version.Kind {
	case Any:
		return Yes, r, true // every version of Junos
	case Value:
	default:
		return Unknown, r, true
	}
	rel, okR := c.Version.Literal()
	if !okR {
		return Unknown, r, true
	}
	if !strings.EqualFold(rel, v.release()) {
		return No, r, true // another release or train: "15.1x49" is not 15.1R7
	}
	exact := VersionRange{StartIncl: v.String(), EndIncl: v.String()}
	switch c.Update.Kind {
	case Any:
		return Yes, exact, true
	case NA:
		return No, r, true // "15.1:-" is the release with no update; a Junos version always has one
	}
	u, okU := c.Update.Literal()
	switch {
	case !okU:
		return Unknown, r, true
	case strings.EqualFold(u, v.update()):
		return Yes, exact, true
	}
	return No, r, true // "r7-s5" is not "r7"
}

// deviceOSes turn the operating system a network device states about itself (the LLDP or SNMP system description the
// sensors fold into the device's OS field: "JUNOS 15.1R7.9", "Junos OS 21.4R3-S5") into the product the exploited
// list names, with its version (W1-32, D-510). Only a full Junos version is taken: nmap's OS guess ("Juniper Junos OS
// 12.1 - 15.1") names a generation, not a release, and stays a guess (D-501). Junos OS Evolved ("22.4R3-EVO") is another
// product and is left out.
//
// ponytail: Junos only; Cisco IOS ("15.2(4)M3" cannot be ordered: a flood of medium findings) and RouterOS are a row
// each here with their real feed data.
var deviceOSes = []struct {
	re *regexp.Regexp
	sw Software
}{
	{
		regexp.MustCompile(`(?i)(?:^|[\s,(])junos(?:\s+os)?\s+(\d{1,2}\.\d{1,2}(?:[rf]\d{1,3}(?:-s\d{1,3})?|x\d{1,3}-d\d{1,4})(?:\.\d{1,4})?)(?:$|[\s,;)\]])`),
		Software{Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS", KevKeys: []string{"juniper|junos os"}},
	},
}

// osSoftwareID is the software id of the row a device's own OS gives (deviceSoftware): no inventory row has it.
func osSoftwareID(assetID string) string { return "os:" + assetID }

// deviceSoftware is the software the matcher reads for a device: its inventory rows and, when the device states a
// network OS with its version (deviceOSes) and no row of it already carries that product's KEV key, one row for that OS.
// A row a person, an agent or a scan recorded for the product wins over the device's own statement.
func deviceSoftware(a Asset) []Software {
	for _, d := range deviceOSes {
		m := d.re.FindStringSubmatch(a.OS)
		if m == nil {
			continue
		}
		for _, s := range a.Software {
			for _, k := range s.KevKeys {
				if slices.Contains(d.sw.KevKeys, NormalizeKevKey(k)) {
					return a.Software
				}
			}
		}
		sw := d.sw
		sw.ID, sw.Version, sw.KevKeys = osSoftwareID(a.ID), m[1], slices.Clone(d.sw.KevKeys)
		return append(slices.Clip(a.Software), sw)
	}
	return a.Software
}

// Juniper names its platforms by series, and CISA's entry names the series a Junos flaw is about ("Juniper Junos OS
// EX Series and SRX Series PHP External Variable Modification Vulnerability"). The model a device states ("EX4200-48T")
// gives its series (D-510).
var (
	kevSeriesRe   = regexp.MustCompile(`\b(EX|SRX|MX|QFX|ACX|PTX|NFX) Series\b`)
	modelSeriesRe = regexp.MustCompile(`(?i)^(?:juniper\s+(?:networks\s+)?)?(v?srx|ex|mx|qfx|acx|ptx|nfx)(?:\d|-|\s|$)`)
)

// otherSeries reports whether a Juniper entry names only platform series (named) the device's model is not one of: an
// SRX-only flaw on an EX4200 (D-510). An unknown model, an entry that names no series, or another vendor's entry never
// rules anything out.
func otherSeries(model string, v Vuln) (named []string, out bool) {
	if norm(v.Vendor) != "juniper" {
		return nil, false
	}
	m := modelSeriesRe.FindStringSubmatch(strings.TrimSpace(model))
	if m == nil {
		return nil, false
	}
	own := strings.TrimPrefix(strings.ToUpper(m[1]), "V") // vSRX is an SRX
	for _, x := range kevSeriesRe.FindAllStringSubmatch(v.Name, -1) {
		if x[1] == own {
			return nil, false
		}
		named = append(named, x[1]+" Series")
	}
	return named, len(named) > 0
}
