package feeds

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
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
// lessThan range whose change at that end says unaffected (the CNA states the fixed release), or, on the highest row of an entry whose
// only unaffected statements are single versions above every affected row, the highest of them when it is on that row's release line
// (highestAbove, lineFixOf).
// version_type is the entry's versionType.
// Whatever cannot be compared without guessing makes the whole product's rows from that container unusable (counted, none stored):
// git commits, wildcards and text ("3.x", "before 2.4", "all"), a reversed range, a status change inside a range or an unaffected version
// inside an affected one (a hotfix hole), "affected except the listed versions", an entry limited to some models
// (platforms other than processors and operating systems: recordSystems; an entry limited to operating systems gives its rows once per
// system, the system in platforms). "n/a" and "unspecified" say nothing and are passed over; "all versions" is every
// version. Versions a CNA writes in a notation of its own inside these fields (GitHub's comparators "< 2.4", ">= 2.0, < 2.3.1"; the
// product's name in front, "openssl-1.1.0"; a fix per release train after lessThan, "1.20.4,2.0.2"; a range written with a hyphen in
// "version", "1.0-1.23") are read first
// (recordNotation, cverecord_notation.go); one that does not read makes the product unusable, as above.
//
// default_status is the entry's defaultStatus (affected, unaffected, or unknown when absent; on these rows "unaffected" only from the
// vendor's own CNA, ownCNA, else unknown): a product's list is complete when every row says affected or unaffected. An entry of the product that gives no row and does not say what an unlisted version is makes all of
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
			if cnaDefault(a.DefaultStatus) == DefaultUnaffected && (origin != OriginCNA || noVendor[productid.NormVendor(a.Vendor)]) {
				// an ADP, or an entry that names no vendor, is never the vendor's own word; a CNA's other rows keep its word, read as
				// the vendor's own or not when they are read (trustRow); g.entries keep its word
				a.DefaultStatus = DefaultUnknown
			}
			got, complete, ok := entryRows(a, schemeReads(part, vendor, product))
			if !ok {
				g.unusable, g.rows = true, nil
				continue
			}
			g.complete = g.complete && complete
			if len(got) == 0 && !complete {
				g.noRowPart = true
			}
			def := cnaDefault(a.DefaultStatus)
			if def == DefaultUnaffected && !complete {
				def = DefaultUnknown // a version of the entry was left out (a letter release): an unlisted version may be one of it
			}
			for _, r := range got {
				r.CVE, r.Origin, r.Part, r.Vendor, r.Product, r.CPE, r.DefaultStatus = cve, origin, part, vendor, product, cpe, def
				if j := slices.IndexFunc(g.rows, func(h Range) bool { return sameSpan(h, r) && slices.Equal(h.Platforms, r.Platforms) }); j >= 0 {
					if def == DefaultUnknown {
						g.rows[j].DefaultStatus = DefaultUnknown // a row two entries give carries the weaker word
					}
					continue
				}
				g.rows = append(g.rows, r)
			}
		}
		for _, g := range groups {
			schemed := SchemeProduct(Range{Part: g.key[0], Vendor: g.key[1], Product: g.key[2]})
			// the rows of a CNA that names the vendor keep its word, read as the vendor's own or not when they are read (trustRow)
			vendors := origin == OriginCNA && !slices.ContainsFunc(g.entries, func(a cnaAffected) bool { return noVendor[productid.NormVendor(a.Vendor)] })
			own := func(got []Range) {
				for _, r := range got {
					r.CVE, r.Origin, r.Part, r.Vendor, r.Product, r.CPE = cve, origin, g.key[0], g.key[1], g.key[2], g.cpe
					if r.ModelLimited() && !vendors && r.DefaultStatus == DefaultUnaffected {
						// a third party lists the hardware it tested: its "unaffected" for the rest says nothing about other models
						// (ownCNA); only the vendor's own record of a model-limited row says the product is affected on those models only
						r.DefaultStatus = DefaultUnknown
					}
					rows = append(rows, r)
				}
			}
			// the vendor's explicit "unaffected" ranges, for the product's version scheme only (unaffectedRows), kept only beside the
			// product's affected rows: without them nothing would show an affected version inside a range stated unaffected
			unaffected := func() {
				if !schemed {
					return
				}
				if got := unaffectedRows(g.entries); len(got) <= min(recordMaxStatedProduct, recordMaxStated-stated) {
					stated += len(got)
					own(got)
				} else {
					statedDropped++
				}
			}
			switch {
			case g.unusable:
				skipped++
				got, ok := statedRows(g.entries, min(recordMaxStatedProduct, recordMaxStated-stated), schemed)
				if !ok { // more rows than a product or the record may keep: none of the product's, counted
					statedDropped++
					continue
				}
				stated += len(got)
				unaffected()
				own(got)
				continue
			case len(g.rows) == 0:
				unaffected()
				continue
			}
			unaffected()
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

// maxAssigner bounds the stored assigner (feeds_cve.assigner): a CNA's short name is a word, never longer.
const maxAssigner = 64

// clipAssigner is the assigner as feeds_cve stores it: at most maxAssigner bytes.
func clipAssigner(s string) string {
	if len(s) > maxAssigner {
		return s[:maxAssigner]
	}
	return s
}

// ownCNA says the record's assigner is the vendor of the entry: assignerShortName and vendor name the same company once company words
// are dropped ("fortinet" and "Fortinet", "openssl" and "OpenSSL"), or the assigner goes by the name of a product of the catalogue
// that only that vendor ships ("chrome" for Google: catalogueProductVendors, from the catalogue's own names, no list of CNAs). Only
// then does the entry's defaultStatus "unaffected" say anything about the versions it does not list: the vendor knows every release
// it shipped, while a third-party CNA (VulnCheck, a bug bounty platform, a national CERT) lists the releases it tested, and its
// "unaffected" for the rest is no evidence (CVE JSON 5 leaves the trust in defaultStatus to the reader; versions.md). An entry that
// names no vendor ("n/a", empty) does not say whose product it is, so it is never the assigner's own. Such an entry is read with
// defaultStatus unknown: its listed versions still say "affected", a version it does not list stays a question.
// The CVE Program's CNA list (cnalist.go) also makes the assigner the vendor's own CNA when the list types it as a vendor and one form
// of its organization name is the vendor's ("zz" of "Zenith Widgets, Inc."): org is that organization name, "" while the box
// holds no list recent enough or the list does not hold the assigner as a possible vendor; then the rules above stand alone.
func ownCNA(assigner, vendor, org string) bool {
	return ownCNAIn(catalogueProductVendors(), assigner, vendor, org)
}

// ownCNAIn is ownCNA with the vendors of each product name (productVendors).
func ownCNAIn(names map[string][]string, assigner, vendor, org string) bool {
	v := productid.NormVendor(vendor)
	if noVendor[v] {
		return false
	}
	a := productid.NormVendor(assigner)
	if a == "" {
		return false
	}
	if a == v {
		return true
	}
	if vs := names[productid.Norm(assigner)]; len(vs) == 1 && vs[0] == v { // a name two vendors' products share says nothing
		return true
	}
	return orgNamesVendor(org, vendor)
}

// trustRow applies, as a stored row is read, what the record's CNA is worth for it: VendorCNA says the assigner is the row's vendor
// (ownCNA, with org the CNA's organization from a recent CNA list), and a CNA row's defaultStatus "unaffected" from any other CNA is
// read as unknown: what a third party did not list, it did not test. That holds for every row the generic comparison reads and for a
// model-limited row (a third party lists the hardware it tested); the rows kept in a vendor's notation keep the record's word, as
// recordRanges stored them before. Every reader of stored ranges goes through it (readRanges, rangesComplete, RecordStamps), so a
// CNA list that arrives or changes later changes what is read without reading the records again.
func trustRow(r *Range, assigner, org string) {
	r.VendorCNA = r.Origin != OriginADP && ownCNA(assigner, r.Vendor, org)
	if r.Origin == OriginCNA && r.DefaultStatus == DefaultUnaffected && !r.VendorCNA && (r.Generic() || r.ModelLimited()) {
		r.DefaultStatus = DefaultUnknown
	}
}

// catalogueProductVendors is productVendors of the product catalogue built into the box.
var catalogueProductVendors = sync.OnceValue(func() map[string][]string { return productVendors(productid.Products()) })

// productVendors is, per product name (a product's own name and the product of each of its CPE names, productid.Norm), the vendors
// (productid.NormVendor) whose products go by it.
func productVendors(ps []productid.Product) map[string][]string {
	out := map[string][]string{}
	add := func(name, vendor string) {
		n, v := productid.Norm(name), productid.NormVendor(vendor)
		if n == "" || v == "" || slices.Contains(out[n], v) {
			return
		}
		out[n] = append(out[n], v)
	}
	for _, p := range ps {
		add(p.Product, p.Vendor)
		for _, c := range p.CPEs {
			add(c.Product, c.Vendor)
		}
	}
	return out
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

// UnaffectedNotation is the version_type of a row that states versions the vendor says are NOT affected ("unaffected" from 0 before
// 24.4R1: Juniper's statement that releases before 24.4 do not have the flaw; unaffectedRows). Kept in the vendor's notation, so no
// reader of affected ranges reads it (Range.Generic, RangeScheme); StatementScheme reads it for a product's version scheme.
const UnaffectedNotation = VendorNotation + "unaffected"

// Unaffected says the row states versions the vendor says are not affected (UnaffectedNotation), not affected ones.
func (r Range) Unaffected() bool { return r.VersionType == UnaffectedNotation }

// ModelLimited says the row is a CVE record's affected range that holds only on the devices its platforms name (Juniper's "EX4000-48T",
// "EX Series"): Vedette does not know a device's model for certain, so the row can only tell that versions outside it are not
// affected, never that a version inside it is (StatementScheme). NVD's rows keep their own platforms (running-on CPEs).
func (r Range) ModelLimited() bool {
	return r.Origin != OriginNVD && len(r.Platforms) > 0 && !r.Unaffected()
}

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
func statedRows(entries []cnaAffected, limit int, models bool) (out []Range, ok bool) {
	type key struct{ si, ei, ee, fixed, typ, def, plats string }
	seen := map[key]bool{}
	var plats []string // the models the entry being read is limited to (ModelLimited), nil for every device
	add := func(r Range) {
		r.Platforms = plats
		k := key{r.StartIncl, r.EndIncl, r.EndExcl, r.Fixed, r.VersionType, r.DefaultStatus, strings.Join(plats, "\x00")}
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	for _, a := range entries {
		if len(out) > limit {
			return nil, false
		}
		var limited bool
		plats, limited = entryModels(a.Platforms)
		if len(a.Versions) > recordMaxVersions || limited && (!models || plats == nil) {
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

// recordMaxModels and recordMaxModel bound the models an entry may be limited to and each model's name (a hostile record cannot make
// a row of thousands of names); an entry past either is kept in no form, as before models were kept.
const (
	recordMaxModels = 64
	recordMaxModel  = 100
)

// entryModels is the platforms an entry is limited to, as written (limited: one of them is not a processor word, anyPlatform), nil
// when it is not limited or when a name cannot be kept (not printable, quotes, too long, too many).
func entryModels(ps []string) (models []string, limited bool) {
	if anyPlatform(ps) {
		return nil, false
	}
	if len(ps) > recordMaxModels {
		return nil, true
	}
	for _, p := range ps {
		p = strings.Join(strings.Fields(p), " ")
		if p == "" || len(p) > recordMaxModel || !printableASCII(p) || strings.ContainsAny(p, "\"'`;\\") {
			return nil, true
		}
		models = append(models, p)
	}
	return models, true
}

// unaffectedRows keeps the version ranges an entry explicitly states as unaffected ("0" lessThan "24.4R1"), for a product with a
// version scheme: the vendor's word that those versions do not have the flaw. An entry limited to some models speaks for every device
// only when every entry of the product is limited to the same models (the record names no other device; its platforms are kept for
// display); none is kept when an entry of the product is kept in no form (too many versions, models that cannot be kept). Only an entry whose unlisted versions are not stated affected (defaultStatus not affected: an
// "affected except" entry's unaffected versions are fixed releases, exceptRows), and only a range with an end: an unaffected version
// alone is a fixed release (read as such elsewhere), "*" or a list as the end says nothing a scheme reads, and a range with changes
// is left out. A start written as words that name no release (no digit: "all version prior to" lessThan "23.4R1") is read as no
// start, as "0" is: the range is every release before its end.
func unaffectedRows(entries []cnaAffected) []Range {
	var first []string
	sameModels := true // every entry of the product is limited to the same models (or none is limited)
	for i, a := range entries {
		plats, limited := entryModels(a.Platforms)
		if len(a.Versions) > recordMaxVersions || limited && plats == nil {
			return nil // an entry kept in no form may state affected the versions another entry states unaffected
		}
		if i == 0 {
			first = plats
		} else if !slices.Equal(first, plats) {
			sameModels = false
		}
	}
	var out []Range
	seen := map[[3]string]bool{}
	for _, a := range entries {
		def := cnaDefault(a.DefaultStatus)
		plats, _ := entryModels(a.Platforms)
		if def == DefaultAffected || plats != nil && !sameModels {
			// an entry limited to some models while another entry names other devices: its statement holds for its models only,
			// and Vedette does not know the device's model
			continue
		}
		for _, v := range a.Versions {
			if !strings.EqualFold(strings.TrimSpace(v.Status), "unaffected") || strings.EqualFold(strings.TrimSpace(v.VersionType), "git") ||
				len(v.Changes) > 0 || (v.LessThan == nil) == (v.LessThanOrEqual == nil) {
				continue
			}
			start, ok := vendorBound(v.Version)
			if !ok {
				continue
			}
			if w := strings.ToLower(start); saysNothing[w] || everyVersion[w] || !strings.ContainsAny(start, "0123456789") {
				start = "" // words that name no release ("all version prior to" lessThan "23.4R1"): from the first release, as "0"
			}
			bound, incl := v.LessThan, false
			if bound == nil {
				bound, incl = v.LessThanOrEqual, true
			}
			end, ok := vendorBound(*bound)
			if !ok || end == "" || end == "*" || strings.HasSuffix(end, ".*") || strings.Contains(end, ",") {
				continue
			}
			r := Range{StartIncl: start, VersionType: UnaffectedNotation, DefaultStatus: def, Platforms: plats}
			if incl {
				r.EndIncl = end
			} else {
				r.EndExcl = end
			}
			if k := [3]string{start, r.EndIncl, r.EndExcl}; !seen[k] {
				seen[k] = true
				out = append(out, r)
			}
		}
	}
	return out
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
// complete says whether the entry states the status of the versions it does not list. A version with a letter-release bound
// (letterBranch) is left out alone, not the entry: the entry is then not complete.
// reads is the product's version scheme reading a range (schemeReads; nil for a product without one): a letter-release branch it reads
// is not left out (the entry then stays as the vendor states it, which the scheme reads).
//
// An entry limited to operating systems (platforms ["Windows"]) gives each row once per system, the system kept in Platforms: the
// matcher reads it as the CPE's target_sw, as NVD writes a row for one system (recordSystems). Only for a product without a version
// scheme (reads nil): a scheme's product keeps its rule for limited entries (statedRows).
func entryRows(a cnaAffected, reads func(start, end string, incl bool) bool) (rows []Range, complete, ok bool) {
	systems, ok := recordSystems(a.Platforms)
	if !ok || len(systems) > 0 && reads != nil {
		return nil, false, false // only some models, or systems of a scheme's product: the rows would name every device of the product
	}
	rows, complete, ok = entryVersions(a, reads)
	if !ok || len(systems) == 0 {
		return rows, complete, ok
	}
	out := make([]Range, 0, len(rows)*len(systems))
	for _, sys := range systems {
		for _, r := range rows {
			r.Platforms = []string{sys}
			out = append(out, r)
		}
	}
	return out, complete, true
}

// entryVersions is entryRows for every platform of the entry.
func entryVersions(a cnaAffected, reads func(start, end string, incl bool) bool) (rows []Range, complete, ok bool) {
	if len(a.Versions) > recordMaxVersions {
		return nil, false, false
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
	unaffected := 0    // the entry's unaffected statements, of any form
	var lone []string  // its unaffected versions stated alone (no range)
	partial := false   // a letter-release version was left out
	for _, v := range a.Versions {
		switch strings.ToLower(strings.TrimSpace(v.Status)) {
		case "affected":
		case "unaffected":
			unaffected++
			if start := withoutProduct(strings.TrimSpace(v.Version), a); cnaVersionOK(start) && start != "0" {
				fixed = append(fixed, start)
				if v.LessThan == nil && v.LessThanOrEqual == nil {
					lone = append(lone, start)
				}
			}
			continue
		default: // "unknown" says nothing
			continue
		}
		vt := strings.ToLower(strings.TrimSpace(v.VersionType))
		if vt == "git" || v.LessThan != nil && v.LessThanOrEqual != nil {
			return nil, false, false
		}
		noted, ok := recordNotation(a, v, reads) // a CNA's own notation inside the fields (cverecord_notation.go)
		if !ok {
			return nil, false, false
		}
		for _, n := range noted {
			start, end, incl, bounded := n.start, n.end, n.incl, n.bounded
			changedAtEnd := false
			for _, c := range v.Changes {
				if withoutProduct(strings.TrimSpace(c.At), a) != end || !strings.EqualFold(strings.TrimSpace(c.Status), "unaffected") || incl {
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
				if n.startExcl {
					r.StartExcl = start
				} else {
					r.StartIncl = start
				}
			}
			if start != "" && end != "" { // a reversed, empty or unordered range is a typo, not data
				c, ok := cmpLead(start, end)
				if ok && c == 0 && start != end && !n.startExcl && letterBranch(start, end) && (reads == nil || !reads(start, end, incl)) {
					partial = true // one letter-release branch ("1.1.1" to "1.1.1zk"): this version is left out, not the entry
					continue
				}
				if !ok || c > 0 || c == 0 && (start != end || !incl || n.startExcl) { // equal numbers, other texts ("3.0.5-h2" to "3.0.5-h1"): no order to trust
					return nil, false, false
				}
			}
			rows = append(rows, r)
			spans = append(spans, cnaSpan{start: start, end: end, incl: incl})
		}
	}
	for _, f := range fixed { // an unaffected version inside an affected range: a backported fix the rows cannot say
		for _, sp := range spans {
			if within(f, sp) {
				return nil, false, false
			}
		}
	}
	if len(lone) > 0 && unaffected == len(lone) && !partial && reads == nil {
		if y, ok := highestAbove(lone, spans); ok {
			if i, ok := lineFixOf(y, spans); ok {
				rows[i].Fixed = y
			}
		}
	}
	return rows, cnaDefault(a.DefaultStatus) == DefaultUnaffected && !partial, true
}

// highestAbove is the highest of an entry's lone unaffected versions when every one of them is above the end of every affected row
// (a fixed release per train above the last affected release: "7.21.5" and "7.23.1" above 7.20.8); ok is false when one is not, or
// when two do not compare. Only the highest can be the fix of a line (lineFixOf): a release past it is past every fix the entry states.
func highestAbove(lone []string, spans []cnaSpan) (string, bool) {
	top := ""
	for _, y := range lone {
		for _, sp := range spans {
			if c, ok := cmpLead(y, sp.end); sp.end == "" || !ok || c <= 0 {
				return "", false
			}
		}
		if top == "" {
			top = y
		} else if c, ok := cmpLead(y, top); !ok {
			return "", false
		} else if c > 0 {
			top = y
		}
	}
	return top, top != ""
}

// lineFixOf says which affected row a lone unaffected version y of an entry fixes, read as OSV reads "fixed": the entry lists its
// affected versions from 0 up to a last one ("0 through 6.49.18", "7.0.0 through 7.11.2") and states only y unaffected ("7.24.0"),
// or y and lower fixed releases (highestAbove), above every one of them. y is then the fix of the release line the highest row ends on, when y is on that line (its first number):
// a version at or past y on that line is not affected (Range.LineFix, read by the matcher for a partial list only). A version between
// the last affected one and y, or on another line, is not stated either way. ok is false when y is not above every row's end (it would
// be a backport or a release of an earlier line), a row has no end, an end does not compare, or y is on another line.
func lineFixOf(y string, spans []cnaSpan) (top int, ok bool) {
	if len(spans) == 0 {
		return 0, false
	}
	for i, sp := range spans {
		if sp.end == "" {
			return 0, false
		}
		if c, ok := cmpLead(y, sp.end); !ok || c <= 0 {
			return 0, false
		}
		if c, ok := cmpLead(sp.end, spans[top].end); !ok {
			return 0, false
		} else if c > 0 {
			top = i
		}
	}
	x, okY := leadNums(y)
	z, okE := leadNums(spans[top].end)
	return top, okY && okE && len(x) > 0 && len(z) > 0 && x[0] == z[0]
}

// letterReleaseRE is a release in a letter notation: numbers, then up to two lower-case letters ("1.1.1", "1.1.1zk", "3.6a").
var letterReleaseRE = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}[a-z]{0,2}$`)

// letterBranch says whether a range's two bounds with the same numbers are releases of one letter-release branch (OpenSSL's
// "1.1.1" lessThan "1.1.1zk", beside the numeric 3.x ranges of the same entry). Only the letters order them (1.1.1 < 1.1.1k <
// 1.1.1za), which the generic comparison does not read: such a version is left out alone. Before, it made the record's whole product
// unusable, and the numeric ranges beside it were lost.
//
// A product whose version scheme reads such a range keeps the rule before it (schemeReads, entryRows).
func letterBranch(start, end string) bool {
	return letterReleaseRE.MatchString(start) && letterReleaseRE.MatchString(end) && (hasLetter(start) || hasLetter(end))
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

// systemWords are the platforms of a CVE record entry that name an operating system, as NVD's target_sw writes it.
var systemWords = map[string]string{
	"windows": "windows", "microsoft windows": "windows",
	"macos": "macos", "mac os": "macos", "mac os x": "macos", "macosx": "macos", "os x": "macos",
	"linux":   "linux",
	"android": "android",
	"ios":     "iphone_os", "iphone os": "iphone_os", "ipados": "iphone_os",
}

// systemTargets are the target_sw words of systemWords.
var systemTargets = map[string]bool{"windows": true, "macos": true, "linux": true, "android": true, "iphone_os": true}

// recordSystems are the operating systems an entry's platforms limit it to, as target_sw words, sorted and once each; none when the
// platforms do not limit it (anyPlatform). ok is false when a platform is neither a processor word nor an operating system (a model,
// "Unix"): which devices it means is not known.
func recordSystems(ps []string) (systems []string, ok bool) {
	for _, p := range ps {
		w := strings.ToLower(strings.Join(strings.Fields(p), " "))
		if archWords[w] {
			continue
		}
		sys, known := systemWords[w]
		if !known {
			return nil, false
		}
		if !slices.Contains(systems, sys) {
			systems = append(systems, sys)
		}
	}
	slices.Sort(systems)
	return systems, true
}

// recordSystem is the operating system a record row is limited to (one of recordSystems' words), "" for an NVD row, a row of every
// system or one limited to models.
func recordSystem(r Range) string {
	if r.Origin == OriginNVD || len(r.Platforms) != 1 || !systemTargets[r.Platforms[0]] {
		return ""
	}
	return r.Platforms[0]
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

// schemeReads is the version scheme of the product a record names reading a range, nil for a product without a scheme.
func schemeReads(part, vendor, product string) func(start, end string, incl bool) bool {
	p, ok := productid.ByRangeName(part, vendor, product)
	if !ok || p.Scheme == "" {
		return nil
	}
	s, ok := versionscheme.Lookup(p.Scheme)
	if !ok {
		return nil
	}
	return func(start, end string, incl bool) bool {
		if incl {
			_, ok := s.Span(start, "", end)
			return ok
		}
		_, ok := s.Span(start, end, "")
		return ok
	}
}
