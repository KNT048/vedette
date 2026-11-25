package feeds

import (
	"regexp"
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
//
// Vendor notation. The versions of a product the rules above refuse are not lost: they are kept as the vendor states them, beside
// NVD's, with version_type "vendor:" and the entry's versionType ("vendor:custom"; "vendor:text" when it gives none). They are
// display-only for the generic comparison (Range.Generic, genericRowSQL): every reader that matches reads generic rows only, so what
// is matched is what it was before these rows were kept. A product's version scheme (core/versionscheme, declared in the product
// catalogue) reads them per release train (RangeScheme): VMware's "8.0 lessThan ESXi80U3d-24585383". statedRows says which rows are kept.

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
	key       [3]string // part, vendor, product
	cpe       string
	entries   []cnaAffected // every entry of the product, read again as the vendor states them when the group is unusable
	rows      []Range
	complete  bool // every entry of the product says what a version it does not list is
	unusable  bool
	noRowPart bool // an entry gave no row and does not say what an unlisted version is
}

// recordRanges converts the CNA's affected list and each ADP's into ranges of cve (recordGroup rules above). skipped is the products
// that had entries but no usable rows.
func recordRanges(cve, assigner string, cna []cnaAffected, adps []rawContainer) (rows []Range, skipped, statedDropped int) {
	stated := 0 // the rows kept as the vendor states them, at most recordMaxStated a record
	conv := func(origin string, list []cnaAffected, fallback string) {
		if len(list) == 0 {
			return
		}
		if len(list) > recordMaxEntries {
			skipped++
			return
		}
		var groups []*recordGroup
		worded, used := esxiTextRows(list, fallback) // VMware's ESXi versions written as words (esxitext.go)
		for i, a := range list {
			if len(used) > 0 {
				kept := a.Versions[:0:0]
				for j, v := range a.Versions {
					if !used[[2]int{i, j}] {
						kept = append(kept, v)
					}
				}
				if len(kept) == 0 {
					continue // every version of the entry is read from its words
				}
				a.Versions = kept
			}
			part, vendor, product, cpe, ok := entryIdentity(a, fallback)
			if !ok {
				continue
			}
			key := [3]string{part, vendor, product}
			i := slices.IndexFunc(groups, func(g *recordGroup) bool { return g.key == key })
			if i < 0 {
				groups = append(groups, &recordGroup{key: key, cpe: cpe, complete: true})
				i = len(groups) - 1
			}
			g := groups[i]
			g.entries = append(g.entries, a)
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
				got, ok := statedRows(g.entries, min(recordMaxStatedProduct, recordMaxStated-stated))
				if !ok { // more rows than a product or the record may keep: none of the product's, counted
					statedDropped++
					continue
				}
				stated += len(got)
				for _, r := range got {
					r.CVE, r.Origin, r.Part, r.Vendor, r.Product, r.CPE = cve, origin, g.key[0], g.key[1], g.key[2], g.cpe
					rows = append(rows, r)
				}
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
		for _, r := range worded {
			r.CVE, r.Origin = cve, origin
			rows = append(rows, r)
		}
	}
	conv(OriginCNA, cna, assigner)
	for _, a := range adps {
		conv(OriginADP, a.Affected, "")
	}
	return rows, skipped, statedDropped
}

// recordMaxStatedProduct and recordMaxStated bound the rows kept as the vendor states them, per product and per record (415 is the
// most one product of the count sample has: Cisco's list of every affected ASA release). A product over either is kept in no form and
// counted (CVERecord.StatedDropped): a hostile record of many hotfix changes cannot make thousands of rows.
const (
	recordMaxStatedProduct = 500
	recordMaxStated        = 2000
)

// VendorNotation is the prefix of the version_type of a row kept as the vendor states it (display-only for the generic comparison).
const VendorNotation = "vendor:"

// genericRowSQL is the rows of feeds_cve_range (alias r) the generic comparison reads: NVD's and the record rows it can order.
const genericRowSQL = `r.version_type NOT LIKE 'vendor:%'`

// Generic says the generic comparison reads the row: an NVD row, or a record row it can order (not one kept as the vendor states it).
func (r Range) Generic() bool { return !strings.HasPrefix(r.VersionType, VendorNotation) }

// statedRows keeps the versions of a product's entries as the vendor states them, for a product the generic rules refuse: an affected
// version or range with its bounds as written (lessThan: the end excluded; the fixed release when the record says the versions from
// there are unaffected, by a change at the end or by defaultStatus), a range with changes split into its affected stretches (each
// ending at the change to unaffected, its fix), and for an entry whose unlisted versions are affected, one range per unaffected
// version the entry lists (the fixed release of a branch: "6.1.149" of the kernel), from the version it names as affected when it
// names one. Left out: git commits (no device reports one), an entry limited to some operating systems or models (the row could not
// say which), a bound that is not printable ASCII, holds quotes, a backslash or a semicolon, or is longer than the column.
// At most limit rows: ok is false past it (the work stops there too).
func statedRows(entries []cnaAffected, limit int) (out []Range, ok bool) {
	type key struct{ si, ei, ee, fixed, typ, def string }
	seen := map[key]bool{}
	add := func(r Range) {
		k := key{r.StartIncl, r.EndIncl, r.EndExcl, r.Fixed, r.VersionType, r.DefaultStatus}
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	for _, a := range entries {
		if len(out) > limit {
			return nil, false
		}
		if len(a.Versions) > recordMaxVersions || !anyPlatform(a.Platforms) {
			continue
		}
		def := cnaDefault(a.DefaultStatus)
		if def == DefaultAffected {
			for _, r := range exceptRows(a) {
				add(r)
			}
			continue
		}
		for _, v := range a.Versions {
			vt := strings.ToLower(strings.TrimSpace(v.VersionType))
			if !strings.EqualFold(strings.TrimSpace(v.Status), "affected") || vt == "git" || v.LessThan != nil && v.LessThanOrEqual != nil {
				continue
			}
			typ := vendorType(vt)
			start, ok := vendorBound(v.Version)
			if !ok {
				continue
			}
			if v.LessThan == nil && v.LessThanOrEqual == nil {
				switch w := strings.ToLower(start); {
				case everyVersion[w]:
					add(Range{VersionType: typ, DefaultStatus: def})
				case start != "" && !saysNothing[w]:
					add(Range{StartIncl: start, EndIncl: start, VersionType: typ, DefaultStatus: def})
				}
				continue
			}
			if saysNothing[strings.ToLower(start)] || everyVersion[strings.ToLower(start)] {
				start = ""
			}
			if v.LessThanOrEqual != nil {
				end, ok := vendorBound(*v.LessThanOrEqual)
				if !ok {
					continue
				}
				if end == "*" {
					end = ""
				}
				add(Range{StartIncl: start, EndIncl: end, VersionType: typ, DefaultStatus: def})
				continue
			}
			end, ok := vendorBound(*v.LessThan)
			if !ok {
				continue
			}
			if end == "*" {
				end = ""
			}
			if fixes, ok := branchFixes(end); ok && len(v.Changes) == 0 { // Juniper's "22.3R2-S2, 22.3R3-S1": one fix per branch
				for i, f := range fixes {
					from := start
					if i > 0 {
						if from = branchStart(f); from == "" {
							continue // a plain release ("22.4R3") starts its own branch fixed: nothing of it is affected
						}
					}
					r := Range{StartIncl: from, EndExcl: f, VersionType: typ, DefaultStatus: def}
					if def == DefaultUnaffected {
						r.Fixed = f
					}
					add(r)
				}
				continue
			}
			// the stretches of the range: affected from its start, unaffected from a change, affected again from the next one
			from, affected := start, true
			for _, c := range v.Changes {
				if len(out) > limit {
					return nil, false
				}
				at, ok := vendorBound(c.At)
				if !ok || at == "" {
					break
				}
				switch st := strings.ToLower(strings.TrimSpace(c.Status)); {
				case st == "unaffected" && affected:
					add(Range{StartIncl: from, EndExcl: at, Fixed: at, VersionType: typ, DefaultStatus: def})
					affected = false
				case st == "affected" && !affected:
					from, affected = at, true
				}
			}
			if !affected || from == end && end != "" {
				continue
			}
			r := Range{StartIncl: from, EndExcl: end, VersionType: typ, DefaultStatus: def}
			if end != "" && def == DefaultUnaffected {
				r.Fixed = end
			}
			for _, c := range v.Changes {
				if strings.TrimSpace(c.At) == end && strings.EqualFold(strings.TrimSpace(c.Status), "unaffected") {
					r.Fixed = end
				}
			}
			add(r)
		}
	}
	if len(out) > limit {
		return nil, false
	}
	return out, true
}

// junosFixRe is one fixed release of a Junos branch as Juniper's records list them after lessThan: release, R number, an optional
// service release and respin ("22.3R2-S2", "25.2R2", "21.4R3-S5.4").
var junosFixRe = regexp.MustCompile(`^([0-9]{1,2}\.[0-9]{1,2})R([0-9]{1,3})(?:-S([0-9]{1,3}))?(?:\.[0-9]{1,3})?$`)

// branchFixes reads a lessThan that lists the fixed release of each maintenance branch of one release ("22.3R2-S2, 22.3R3-S1",
// "25.2R1-S2, 25.2R2"): Juniper writes "22.3 versions before 22.3R2-S2, 22.3R3-S1" for a flaw fixed in 22.3R2-S2 on the R2 branch and in
// 22.3R3-S1 on the R3 branch, so 22.3R2-S3 is fixed and 22.3R3 is not. ok is false unless every item is such a release of one
// release, in rising branch order: anything else stays as written (a scheme cannot read it, so it decides nothing).
func branchFixes(end string) ([]string, bool) {
	if !strings.Contains(end, ",") {
		return nil, false
	}
	items := strings.Split(end, ",")
	line, lastR := "", -1
	for i, it := range items {
		it = strings.TrimSpace(it)
		m := junosFixRe.FindStringSubmatch(strings.ToUpper(it))
		if m == nil || i > 0 && m[1] != line {
			return nil, false
		}
		r, _ := strconv.Atoi(m[2])
		if r <= lastR {
			return nil, false
		}
		line, lastR, items[i] = m[1], r, it
	}
	return items, len(items) > 1
}

// branchStart is where the branch of a fixed release f of branchFixes starts: its R release when f is a service release of it
// ("22.3R3" for "22.3R3-S1"), "" when f is the R release itself.
func branchStart(f string) string {
	m := junosFixRe.FindStringSubmatch(strings.ToUpper(f))
	if m == nil || m[3] == "" {
		return ""
	}
	return f[:len(m[1])+1+len(m[2])]
}

// exceptRows reads an entry whose unlisted versions are affected (defaultStatus affected): each unaffected version it lists, alone or
// up to a wildcard of its own branch ("6.1.149" lessThanOrEqual "6.1.*"), or with "and later", is a fixed release; the one version it
// lists as affected, when it lists one, is where the flaw starts. An unaffected range below a version ("0" lessThan "6.0") only says
// where the flaw starts.
func exceptRows(a cnaAffected) []Range {
	var intro, fixes []string
	fixed := map[string]bool{}
	for _, v := range a.Versions {
		ver, ok := vendorBound(v.Version)
		if !ok || ver == "" || saysNothing[strings.ToLower(ver)] || strings.EqualFold(strings.TrimSpace(v.VersionType), "git") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(v.Status)) {
		case "affected":
			if v.LessThan == nil && v.LessThanOrEqual == nil && !everyVersion[strings.ToLower(ver)] {
				intro = append(intro, ver)
			}
		case "unaffected":
			if v.LessThan != nil {
				continue
			}
			if v.LessThanOrEqual != nil {
				end := strings.TrimSpace(*v.LessThanOrEqual)
				if end != "*" && !strings.HasSuffix(end, ".*") {
					continue
				}
			}
			ver = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(ver, " and later"), " or later"))
			if ver != "" && !fixed[ver] {
				fixed[ver] = true
				fixes = append(fixes, ver)
			}
		}
	}
	start := ""
	if len(intro) == 1 {
		start = intro[0]
	}
	typ := vendorType("")
	for _, v := range a.Versions {
		if w := strings.ToLower(strings.TrimSpace(v.VersionType)); w != "" && w != "git" && w != "original_commit_for_fix" {
			typ = vendorType(w)
			break
		}
	}
	var out []Range
	for _, f := range fixes {
		out = append(out, Range{StartIncl: start, EndExcl: f, Fixed: f, VersionType: typ, DefaultStatus: DefaultAffected})
	}
	if len(out) == 0 && start != "" {
		out = append(out, Range{StartIncl: start, VersionType: typ, DefaultStatus: DefaultAffected})
	}
	return out
}

// vendorType is the version_type of a row kept as the vendor states it: VendorNotation and the entry's versionType ("vendor:custom"),
// "vendor:text" when it gives none (or one that is not a word).
func vendorType(vt string) string {
	w := recordWord(vt)
	if w == "" {
		w = "text"
	}
	return (VendorNotation + w)[:min(len(VendorNotation)+len(w), 40)]
}

// vendorBound is a version or bound as the vendor writes it, blanks collapsed ("" for none); ok is false for one the column cannot
// hold or that is not plain text.
func vendorBound(s string) (string, bool) {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > nvdMaxVersion || !printableASCII(s) || strings.ContainsAny(s, "\"'`;\\") {
		return "", false
	}
	return s, true
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
