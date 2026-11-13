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
	if rel = strings.ToLower(rel); !okR || !junosRelRe.MatchString(rel) {
		return Unknown, r, true // "15.1r7" is not how NVD writes a release: unreadable, not a No (review L1 of #703)
	}
	if rel != v.release() {
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
	u = strings.ToLower(u)
	m := junosUpdRe.FindStringSubmatch(u)
	switch {
	case !okU || u == "":
		return Unknown, r, true
	case u[0] >= 'a' && u[0] <= 'z' && u[0] != v.updateLetter():
		return No, r, true // another release type: "15.1:f", "15.1:a1" are not 15.1R7
	case m == nil:
		return Unknown, r, true // "r7.9", "r7-s1.2": unreadable
	case m[2] == "" || m[1] == "d" && m[3] != "":
		return Unknown, r, true // "f" with no number
	case u == v.update():
		return Yes, exact, true
	}
	return No, r, true // "r7-s5" is not "r7"; junosListed decides what a missing update means
}

// junosRelRe and junosUpdRe are how NVD writes a Junos release ("15.1", "12.3x48") and update ("r7", "r7-s5", "f6",
// "d105"); any other text in a Junos row is unreadable (review L1 of #703).
var (
	junosRelRe = regexp.MustCompile(`^\d{1,2}\.\d{1,2}(?:x\d{1,3})?$`)
	junosUpdRe = regexp.MustCompile(`^([rfd])(\d{1,4})?(?:-s(\d{1,3}))?$`)
)

// updateLetter is the letter NVD's update of v starts with: r, f, or d for an X train.
func (v junosVer) updateLetter() byte {
	if v.train == 'x' {
		return 'd'
	}
	return v.train
}

// junosRow is the Junos version an exact NVD row names ("junos:15.1:r7-s5" is 15.1R7-S5), when it is readable.
func junosRow(c CPE, r VersionRange) (junosVer, bool) {
	rel, okR := c.Version.Literal()
	u, okU := c.Update.Literal()
	if !r.IsZero() || !okR || !okU || !junosRelRe.MatchString(strings.ToLower(rel)) || !junosUpdRe.MatchString(strings.ToLower(u)) {
		return junosVer{}, false
	}
	sep := ""
	if strings.HasPrefix(strings.ToLower(u), "d") {
		sep = "-"
	}
	return junosParse(rel + sep + u)
}

// junosCmp orders two versions of the same release and train.
func junosCmp(a, b junosVer) int { return cmp.Or(cmp.Compare(a.n1, b.n1), cmp.Compare(a.n2, b.n2)) }

// junosList is what the applicable Junos NVD rows of one entry list, for junosListed.
type junosList struct {
	rows []junosVer // the exact rows junosRow reads ("junos:15.1:r7-s5")
	ends []junosVer // the release of each range's end bound ("before 21.2"): the range lists the releases before it
	// own and ownDash: a row of the device's own release in a form junosRow does not read ("15.1:-", "15.1:f", "15.1:a1");
	// ownDash when one of them is the release with no update ("15.1:-").
	own, ownDash bool
}

// junosListed decides a Junos version that every applicable NVD row ruled out, from what NVD lists (review H1 of #703,
// round 2). NVD enumerates Junos updates one by one and leaves gaps, and Juniper fixes per maintenance branch (the R or F
// number of a release, or an X train): "22.3 before 22.3R2-S2, 22.3R3-S1" makes NVD list up to 22.3R2-S1, then 22.3R3,
// skipping the fixed 22.3R2-S2. So the device's own branch decides first: between its first and last listed update it
// is affected (CVE-2020-1631: 12.3R12-S10 between S8 and S11), before the first Unknown, after the last no finding but no
// proof (22.3R2-S2; 15.1R7-S6, where Juniper's fix is S7: see the ponytail below). A branch NVD does not list: between
// listed branches of its release, or before every one, Unknown; after every one, no finding, no proof. A release NVD does
// not list: between listed releases (a range's end counts: "before 15.1" and 16.1 rows leave 15.1 out) Unknown; the
// range's end release itself, a release with only other trains or unread rows listed ("15.1:f"), or one before every
// listed release, no finding, no proof ("15.1:-" alone: Unknown). Only a version after every release NVD lists is proved
// outside (proof true: D-530 may close a finding).
//
// ponytail: the tail of a branch is a guess from NVD's list: a build after the last listed update is taken as fixed (the
// usual case; Unknown would flag every patched build), so a build NVD forgot (15.1R7-S6 of CVE-2020-1631) gets no finding.
// Upgrade path: read the "versions prior to Y" list of Juniper's advisory text (NVD description / JSA) for the exact fixed
// build of each branch; that would also settle a skipped branch exactly.
func junosListed(v junosVer, l junosList) (t Tri, within VersionRange, proof bool) {
	var lo, hi *junosVer
	earlier, later, otherTrain, atEnd, lowerBranch, higherBranch := false, false, false, false, false, false
	for i := range l.rows {
		r := &l.rows[i]
		switch c := cmp.Or(cmp.Compare(v.major, r.major), cmp.Compare(v.minor, r.minor)); {
		case c > 0:
			earlier = true
		case c < 0:
			later = true
		case r.train != v.train || r.xnum != v.xnum:
			otherTrain = true
		case v.train != 'x' && r.n1 < v.n1:
			lowerBranch = true
		case v.train != 'x' && r.n1 > v.n1:
			higherBranch = true
		default: // the device's own branch: its R or F number, or its X train
			if lo == nil || junosCmp(*r, *lo) < 0 {
				lo = r
			}
			if hi == nil || junosCmp(*r, *hi) > 0 {
				hi = r
			}
		}
	}
	for _, e := range l.ends {
		switch c := cmp.Or(cmp.Compare(v.major, e.major), cmp.Compare(v.minor, e.minor)); {
		case c > 0:
			earlier = true
		case c == 0:
			earlier, atEnd = true, true
		}
	}
	switch {
	case lo != nil && junosCmp(v, *lo) < 0:
		return Unknown, VersionRange{}, false
	case lo != nil && junosCmp(v, *hi) > 0:
		return No, VersionRange{}, false
	case lo != nil:
		return Yes, VersionRange{StartIncl: lo.String(), EndIncl: hi.String()}, false
	case higherBranch: // a branch NVD skips, between listed ones or before every one
		return Unknown, VersionRange{}, false
	case lowerBranch:
		return No, VersionRange{}, false
	case l.ownDash:
		return Unknown, VersionRange{}, false
	case otherTrain || l.own:
		return No, VersionRange{}, false
	case earlier && later:
		return Unknown, VersionRange{}, false
	case later || atEnd:
		return No, VersionRange{}, false
	}
	return No, VersionRange{}, true
}

// junosEnd is the release of a range's end bound ("21.2", "21.2r3"), when it reads.
func junosEnd(r VersionRange) (junosVer, bool) {
	b := cmp.Or(r.EndExcl, r.EndIncl)
	if b == "" {
		return junosVer{}, false
	}
	if e, ok := junosParse(b); ok {
		return e, true
	}
	pv, ok := parseVersion(b)
	if !ok || len(pv.rel) != 2 {
		return junosVer{}, false
	}
	return junosVer{major: pv.rel[0], minor: pv.rel[1]}, true
}

// deviceOSes turn the operating system a network device states about itself (Asset.StatedOS: the OS the LLDP or SNMP
// system description gave, "JUNOS 15.1R7.9", "Junos OS 21.4R3-S5"; never nmap's) into the product the exploited list
// names, with its version (W1-32, D-510). Only the whole value, a full Junos version: nmap's OS guess ("Juniper Junos OS
// 12.1 - 15.1", "Juniper JUNOS 10.4R1.9 (EX4200 switch)") is a guess (D-501) and is not read even when it won the device's
// OS field (review M2 of #703). Junos OS Evolved ("22.4R3-EVO") is another product and is left out.
//
// ponytail: Junos only; Cisco IOS ("15.2(4)M3" cannot be ordered: a flood of medium findings) and RouterOS are a row
// each here with their real feed data.
var deviceOSes = []struct {
	re *regexp.Regexp
	sw Software
}{
	{
		regexp.MustCompile(`(?i)^\s*junos(?:\s+os)?\s+(\d{1,2}\.\d{1,2}(?:[rf]\d{1,3}(?:-s\d{1,3})?|x\d{1,3}-d\d{1,4})(?:\.\d{1,4})?)\s*$`),
		Software{Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS", KevKeys: []string{"juniper|junos os"}},
	},
}

// osSoftwareID is the software id of the row a device's own OS gives (deviceSoftware): no inventory row has it.
func osSoftwareID(assetID string) string { return "os:" + assetID }

// deviceSoftware is the software the matcher reads for a device: its inventory rows and, when the device states a
// network OS with its version (deviceOSes), one row for that OS. A row a person, an agent or a scan recorded for that
// product with a full Junos version wins over the device's statement (no OS row). A recorded row of the product without a
// readable version, all of whose KEV keys are the OS row's, gives way to it: the device's own version decides instead of
// "add the version" (review M3 of #703).
func deviceSoftware(a Asset) []Software {
	for _, d := range deviceOSes {
		m := d.re.FindStringSubmatch(a.StatedOS)
		if m == nil {
			continue
		}
		out := make([]Software, 0, len(a.Software)+1)
		for _, s := range a.Software {
			keyed, covered := false, len(s.KevKeys) > 0
			for _, k := range s.KevKeys {
				in := slices.Contains(d.sw.KevKeys, NormalizeKevKey(k))
				keyed, covered = keyed || in, covered && in
			}
			_, junos := junosParse(s.Version)
			switch {
			case keyed && junos: // "15.1" or "JUNOS 15.1R7.9" typed by a person is not a Junos version: the stated one decides (review L2)
				return a.Software
			case covered:
				continue
			}
			out = append(out, s)
		}
		sw := d.sw
		sw.ID, sw.Version, sw.KevKeys = osSoftwareID(a.ID), m[1], slices.Clone(d.sw.KevKeys)
		return append(out, sw)
	}
	return a.Software
}

// Juniper names its platforms by series, and CISA's entry names the series a Junos flaw is about ("Juniper Junos OS
// EX Series and SRX Series PHP External Variable Modification Vulnerability"). The model a device states ("EX4200-48T")
// gives its series (D-510).
var (
	kevSeriesRe   = regexp.MustCompile(`\b(vSRX|SRX|EX|MX|QFX|ACX|PTX|NFX)(\d*)\b`)
	modelSeriesRe = regexp.MustCompile(`(?i)^(?:juniper\s+(?:networks\s+)?)?(v?srx|ex|mx|qfx|acx|ptx|nfx)(?:\d|-|\s|$)`)
)

// otherSeries reports whether a Juniper entry names platform series (named) and the device's model is none of them: an
// SRX-only flaw on an EX4200 (D-510). Every series token of the name counts, in any list form ("SRX and EX Series", "MX
// Series and EX9200 Series", review M1 of #703): the device is ruled out only when its own series appears nowhere in the
// name. An unknown model, a name without "Series", or another vendor's entry never rules anything out.
func otherSeries(model string, v Vuln) (named []string, out bool) {
	if norm(v.Vendor) != "juniper" || !strings.Contains(v.Name, "Series") {
		return nil, false
	}
	m := modelSeriesRe.FindStringSubmatch(strings.TrimSpace(model))
	if m == nil {
		return nil, false
	}
	own := strings.TrimPrefix(strings.ToUpper(m[1]), "V") // vSRX is an SRX
	for _, x := range kevSeriesRe.FindAllStringSubmatch(v.Name, -1) {
		if strings.TrimPrefix(x[1], "v") == own {
			return nil, false
		}
		if n := x[0] + " Series"; !slices.Contains(named, n) {
			named = append(named, n)
		}
	}
	return named, len(named) > 0
}
