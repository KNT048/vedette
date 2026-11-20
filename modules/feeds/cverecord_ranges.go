package feeds

import (
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/core/productid"
)

// The affected versions of a CVE record as catalogue ranges (feeds_cve_range, origin cna or adp).
//
// Identity. An affected entry that names CPEs (CISA's ADP gives them) is that CPE's product: part, vendor and product as NVD writes
// them, and cpe is the CPE with any version. Any other entry is named by its own vendor and product, normalised the way the exploited
// lists are compared with the inventory (RecordProductKey): part and cpe stay empty. An entry whose vendor is "n/a" (VMware's records)
// is the CNA's product: its vendor is the assigner's short name. Nothing is mapped to an NVD name by guessing.
//
// Versions. "affected" versions become ranges: version + lessThan = [version, lessThan), + lessThanOrEqual = [version, x], a version
// alone is that exact version ([v, v]), a start of "0", "*" or "n/a" is no start, an end of "*" is no end. fixed is the end of a
// lessThan range whose change at that end says unaffected (the CNA states the fixed release). version_type is the entry's versionType.
// Whatever cannot be compared without guessing makes the whole product's rows from that container unusable (counted, none stored):
// git commits, wildcards and text ("3.x", "< 2.4", "all"), a reversed range, a status change inside a range or an unaffected version
// inside an affected one (a hotfix hole), "affected except the listed versions", an entry limited to some operating systems or models
// (platforms other than processors: anyPlatform). "n/a" and "unspecified" say nothing and are passed over; "all versions" is every
// version.
//
// default_status is the entry's defaultStatus (affected, unaffected, or unknown when absent): a product's list is complete when every
// row says affected or unaffected. An entry of the product that gives no row and does not say what an unlisted version is makes all of
// the product's rows unknown.

// RecordProductKey is the product key of a CVE record's affected entry that names no CPE, as feeds_cve_range stores it: the vendor
// without its company words and the product without the vendor's name in front, each [a-z0-9] only ("Palo Alto Networks", "PAN-OS"
// is "paloalto", "panos"; "Oracle Corporation", "Oracle Java SE" is "oracle", "javase"). A matcher asks Store.Ranges with this key
// of a product's names beside its NVD CPE names.
func RecordProductKey(vendor, product string) ProductKey {
	return ProductKey{Vendor: productid.NormVendor(vendor), Product: productid.NormProduct(product, vendor)}
}

// noVendor is a vendor an entry gives when it names none.
var noVendor = map[string]bool{"": true, "na": true, "unknown": true, "unspecified": true, "notapplicable": true, "none": true}

// recordGroup is the rows of one product of one container, as they are read.
type recordGroup struct {
	key       string
	rows      []Range
	complete  bool // every entry of the product says what a version it does not list is
	unusable  bool
	noRowPart bool // an entry gave no row and does not say what an unlisted version is
}

// recordRanges converts the CNA's affected list and each ADP's into ranges of cve (recordGroup rules above). skipped is the products
// that had entries but no usable rows.
func recordRanges(cve, assigner string, cna []cnaAffected, adps []rawContainer) (rows []Range, skipped int) {
	conv := func(origin string, list []cnaAffected, fallback string) {
		if len(list) == 0 {
			return
		}
		if len(list) > recordMaxEntries {
			skipped++
			return
		}
		var groups []*recordGroup
		for _, a := range list {
			part, vendor, product, cpe, ok := entryIdentity(a, fallback)
			if !ok {
				continue
			}
			key := part + "|" + vendor + "|" + product
			i := slices.IndexFunc(groups, func(g *recordGroup) bool { return g.key == key })
			if i < 0 {
				groups = append(groups, &recordGroup{key: key, complete: true})
				i = len(groups) - 1
			}
			g := groups[i]
			if g.unusable {
				continue
			}
			got, complete, ok := entryRows(a)
			if !ok {
				g.unusable, g.rows = true, nil
				continue
			}
			g.complete = g.complete && complete
			if len(got) == 0 && !complete {
				g.noRowPart = true
			}
			def := cnaDefault(a.DefaultStatus)
			for _, r := range got {
				r.CVE, r.Origin, r.Part, r.Vendor, r.Product, r.CPE, r.DefaultStatus = cve, origin, part, vendor, product, cpe, def
				if j := slices.IndexFunc(g.rows, func(h Range) bool { return sameSpan(h, r) }); j >= 0 {
					if def == DefaultUnknown {
						g.rows[j].DefaultStatus = DefaultUnknown // a row two entries give carries the weaker word
					}
					continue
				}
				g.rows = append(g.rows, r)
			}
		}
		for _, g := range groups {
			switch {
			case g.unusable:
				skipped++
				continue
			case len(g.rows) == 0:
				continue
			}
			if !g.complete && g.noRowPart {
				for i := range g.rows {
					g.rows[i].DefaultStatus = DefaultUnknown
				}
			}
			rows = append(rows, g.rows...)
		}
	}
	conv(OriginCNA, cna, assigner)
	for _, a := range adps {
		conv(OriginADP, a.Affected, "")
	}
	return rows, skipped
}

// sameSpan says two rows of one product state the same versions.
func sameSpan(a, b Range) bool {
	return a.StartIncl == b.StartIncl && a.StartExcl == b.StartExcl && a.EndIncl == b.EndIncl && a.EndExcl == b.EndExcl &&
		a.Fixed == b.Fixed && a.VersionType == b.VersionType
}

// entryIdentity is the product an affected entry names: its CPE's when it gives CPEs (all of one product), else its own names
// (RecordProductKey; fallback when its vendor is "n/a"). ok is false when it names none Vedette can key.
func entryIdentity(a cnaAffected, fallback string) (part, vendor, product, cpe string, ok bool) {
	if len(a.Vendor) > recordMaxName || len(a.Product) > recordMaxName || len(a.CPEs) > recordMaxVersions {
		return "", "", "", "", false
	}
	if len(a.CPEs) > 0 {
		for _, c := range a.CPEs {
			p, v, pr := cpeParts(strings.TrimSpace(c))
			if p != "a" && p != "o" && p != "h" || !cpeName(v) || !cpeName(pr) || part != "" && (p != part || v != vendor || pr != product) {
				return "", "", "", "", false
			}
			part, vendor, product = p, v, pr
		}
		return part, vendor, product, "cpe:2.3:" + part + ":" + vendor + ":" + product + ":*:*:*:*:*:*:*:*", true
	}
	v := a.Vendor
	if noVendor[productid.NormVendor(v)] {
		v = fallback
	}
	k := RecordProductKey(v, a.Product)
	if noVendor[k.Vendor] || noVendor[k.Product] || len(k.Vendor) > recordMaxName || len(k.Product) > recordMaxName {
		return "", "", "", "", false
	}
	return "", k.Vendor, k.Product, "", true
}

// cpeName is a CPE vendor or product Vedette keeps as a name: printable, no wildcard, no escape, no blank.
func cpeName(s string) bool {
	return s != "" && len(s) <= recordMaxName && printableASCII(s) && !strings.ContainsAny(s, `*?\ :`)
}

// cnaSpan is one affected range of a product, as read ("" = no bound).
type cnaSpan struct {
	start, end string
	incl       bool
}

// entryRows converts the versions of one affected entry (recordGroup rules); ok false: they cannot be ranges without guessing.
// complete says whether the entry states the status of the versions it does not list.
func entryRows(a cnaAffected) (rows []Range, complete, ok bool) {
	if len(a.Versions) > recordMaxVersions || !anyPlatform(a.Platforms) {
		return nil, false, false // only some operating systems: the rows would name every device of the product
	}
	if cnaDefault(a.DefaultStatus) == DefaultAffected { // versions not listed are affected
		for _, v := range a.Versions {
			if strings.EqualFold(strings.TrimSpace(v.Status), "unaffected") {
				return nil, false, false // everything but these versions: not a list of ranges
			}
		}
		return []Range{{}}, true, true // every version is affected
	}
	var spans []cnaSpan
	var fixed []string // the unaffected versions the entry lists
	for _, v := range a.Versions {
		start := strings.TrimSpace(v.Version)
		switch strings.ToLower(strings.TrimSpace(v.Status)) {
		case "affected":
		case "unaffected":
			if cnaVersionOK(start) && start != "0" {
				fixed = append(fixed, start)
			}
			continue
		default: // "unknown" says nothing
			continue
		}
		vt := strings.ToLower(strings.TrimSpace(v.VersionType))
		if vt == "git" || v.LessThan != nil && v.LessThanOrEqual != nil {
			return nil, false, false
		}
		end, incl, bounded := "", false, v.LessThan != nil || v.LessThanOrEqual != nil
		switch {
		case v.LessThan != nil:
			end = strings.TrimSpace(*v.LessThan)
		case v.LessThanOrEqual != nil:
			end, incl = strings.TrimSpace(*v.LessThanOrEqual), true
		}
		changedAtEnd := false
		for _, c := range v.Changes {
			if strings.TrimSpace(c.At) != end || !strings.EqualFold(strings.TrimSpace(c.Status), "unaffected") || incl {
				return nil, false, false // a status change inside the range (a hotfix): holes
			}
			changedAtEnd = true
		}
		r := Range{VersionType: recordWord(vt)}
		if !bounded {
			switch w := strings.ToLower(start); {
			case saysNothing[w]:
				continue // "n/a", "unspecified": no version to compare
			case everyVersion[w]:
				rows = append(rows, r) // "all versions": every version, as the CNA says
				spans = append(spans, cnaSpan{})
				continue
			case !cnaVersionOK(start) || start == "0":
				return nil, false, false
			}
			r.StartIncl, r.EndIncl = start, start
			rows = append(rows, r)
			spans = append(spans, cnaSpan{start: start, end: start, incl: true})
			continue
		}
		switch {
		case end == "*": // "and every later version"
			end = ""
		case !cnaVersionOK(end):
			return nil, false, false
		case incl:
			r.EndIncl = end
		default:
			r.EndExcl = end
			if changedAtEnd {
				r.Fixed = end
			}
		}
		switch strings.ToLower(start) {
		case "", "0", "*", "n/a", "unspecified": // "affected below the end"
			start = ""
		default:
			if !cnaVersionOK(start) {
				return nil, false, false
			}
			r.StartIncl = start
		}
		if start != "" && end != "" { // a reversed, empty or unordered range is a typo, not data
			c, ok := cmpLead(start, end)
			if !ok || c > 0 || c == 0 && (start != end || !incl) { // equal numbers, other texts ("3.0.5-h2" to "3.0.5-h1"): no order to trust
				return nil, false, false
			}
		}
		rows = append(rows, r)
		spans = append(spans, cnaSpan{start: start, end: end, incl: incl})
	}
	for _, f := range fixed { // an unaffected version inside an affected range: a backported fix the rows cannot say
		for _, sp := range spans {
			if within(f, sp) {
				return nil, false, false
			}
		}
	}
	return rows, cnaDefault(a.DefaultStatus) == DefaultUnaffected, true
}

// saysNothing and everyVersion are the version words of an "affected" entry without a range that are not versions: no version to
// compare ("n/a"), or every version of the product ("all versions").
var (
	saysNothing  = map[string]bool{"n/a": true, "na": true, "unspecified": true, "unknown": true, "-": true, "0": true, "see references": true}
	everyVersion = map[string]bool{"*": true, "all": true, "all versions": true, "any": true, "every version": true}
)

// archWords are the platforms that name a processor or say "all": they do not limit which devices run the product (the entries of
// each processor give the same versions). Any other platform (an operating system, a model) limits it, and Vedette does not guess.
var archWords = map[string]bool{
	"x64-based systems": true, "arm64-based systems": true, "32-bit systems": true, "64-bit systems": true, "x86-based systems": true,
	"x64": true, "x86": true, "x86_64": true, "x86-64": true, "amd64": true, "arm": true, "arm64": true, "aarch64": true,
	"32 bit": true, "64 bit": true, "32-bit": true, "64-bit": true, "all": true, "all platforms": true, "default": true,
}

// anyPlatform says the platforms of an entry do not limit it (none, or only archWords). Modules (a component of the product) never
// limit it: every installation of the product has them.
func anyPlatform(ps []string) bool {
	for _, p := range ps {
		if !archWords[strings.ToLower(strings.TrimSpace(p))] {
			return false
		}
	}
	return true
}

// The defaultStatus words of an affected entry, as feeds_cve_range.default_status keeps them (NVD's rows: "").
const (
	DefaultAffected   = "affected"   // versions the entry does not list are affected
	DefaultUnaffected = "unaffected" // versions the entry does not list are not affected
	DefaultUnknown    = "unknown"    // the entry does not say (absent, or another word)
)

// cnaDefault is a defaultStatus as stored.
func cnaDefault(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case DefaultAffected:
		return DefaultAffected
	case DefaultUnaffected:
		return DefaultUnaffected
	}
	return DefaultUnknown
}

// within says whether version v may lie in sp; a comparison it cannot make (the leading numbers are equal but the
// texts differ, or one has none) counts as inside: when in doubt, skip.
func within(v string, sp cnaSpan) bool {
	if sp.start != "" {
		if c, ok := cmpLead(v, sp.start); ok && c < 0 {
			return false
		}
	}
	if sp.end != "" {
		c, ok := cmpLead(v, sp.end)
		switch {
		case ok && c > 0:
			return false
		case ok && c == 0 && v == sp.end:
			return sp.incl
		}
	}
	return true
}

// cmpLead compares the leading dotted numbers of two versions ("10.2.9-h1" -> 10.2.9; a missing part is 0). ok is false
// when either starts with no number; 0 means the numbers are equal (the rest of the texts may still differ).
func cmpLead(a, b string) (int, bool) {
	x, okA := leadNums(a)
	y, okB := leadNums(b)
	if !okA || !okB {
		return 0, false
	}
	for i := 0; i < max(len(x), len(y)); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			if p < q {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func leadNums(s string) ([]int, bool) {
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || s[end] == '.') {
		end++
	}
	var out []int
	for _, part := range strings.Split(strings.TrimRight(s[:end], "."), ".") {
		if len(part) > 9 {
			return nil, false
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

// cnaVersionOK accepts a version that can be compared: printable, with a digit, no blanks, no wildcard or comparison
// ("3.x", "< 2.4", "all", "n/a" are refused), at most nvdMaxVersion bytes (the column's size).
func cnaVersionOK(s string) bool {
	if s == "" || len(s) > nvdMaxVersion || !printableASCII(s) || !strings.ContainsAny(s, "0123456789") || strings.ContainsAny(s, " *?<>=,;\"'`\\") {
		return false
	}
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' }) {
		if strings.EqualFold(seg, "x") {
			return false
		}
	}
	return true
}

// cpeEscape quotes the characters a CPE 2.3 formatted string cannot carry plainly ("15.2(4)M3" -> "15.2\(4\)M3").
func cpeEscape(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !isAlnumByte(b) && b != '_' && b != '.' && b != '-' {
			sb.WriteByte('\\')
		}
		sb.WriteByte(b)
	}
	return sb.String()
}

func isAlnumByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}
