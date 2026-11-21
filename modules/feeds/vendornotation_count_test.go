package feeds

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// The class of vendor notations: the products of CVE records whose versions the generic comparison refuses (it cannot order them
// without guessing), on the frozen public sample of cverecord_count_test.go plus VMware's record of CVE-2025-22225 (testdata/brief).
// The sample holds the exploited CVEs listed in 90 days and the window's records that name a product of the test inventory, so it
// counts what a box like that one meets, not the whole catalogue. Rerun it on a whole daily archive with -update-records (it rebuilds
// the sample) to count the catalogue.
//
// Before: the reader dropped every such product (no row, "skipped"). After: its rows are kept as the vendor states them, display-only
// for the generic comparison; a product whose catalogue entry declares a version scheme that reads every one of its rows is read per
// release train. The vendors of recordSkipVendors (Juniper, Microsoft; Citrix until NetScaler got its scheme) keep their generic rows, which the exploited-list view
// leaves out: counted apart.

// notationReason is why the generic comparison refuses one affected entry (the first rule it breaks), "" when it reads it.
func notationReason(a cnaAffected) string {
	if _, _, ok := entryRows(a); ok {
		return ""
	}
	switch {
	case len(a.Versions) > recordMaxVersions:
		return "too many versions"
	case !anyPlatform(a.Platforms):
		return "limited to some systems"
	case cnaDefault(a.DefaultStatus) == DefaultAffected:
		return "affected except listed fixes"
	}
	for _, v := range a.Versions {
		if strings.EqualFold(strings.TrimSpace(v.VersionType), "git") {
			return "git commits"
		}
	}
	for _, v := range a.Versions {
		if len(v.Changes) > 0 {
			return "hotfix changes inside a range"
		}
	}
	for _, v := range a.Versions {
		for _, b := range []*string{&v.Version, v.LessThan, v.LessThanOrEqual} {
			if b == nil {
				continue
			}
			x := strings.ToLower(strings.TrimSpace(*b))
			if x == "" || x == "*" || saysNothing[x] || everyVersion[x] {
				continue
			}
			if !cnaVersionOK(*b) {
				return "text or wildcards (5.x, R82 Take 43)"
			}
		}
	}
	for _, v := range a.Versions {
		end := v.LessThan
		if end == nil {
			end = v.LessThanOrEqual
		}
		if end != nil && *end != "*" && v.Version != "" && v.Version != "0" {
			if _, ok := cmpLead(v.Version, *end); !ok {
				return "vendor build notation (ESXi80U3d-24585383, V3.1.6)"
			}
			return "bounds out of order or equal"
		}
	}
	return "unaffected version inside a range"
}

type notationGroup struct {
	origin, part, vendor, product string
	reason                        string
}

type notationAudit struct {
	refused      int            // products the generic comparison refuses (all dropped before)
	refusedRows  int            // their affected versions as the vendor states them (rows after)
	byReason     map[string]int // products by reason
	byVendor     map[string]int // products by "vendor: reason"
	scheme       map[string]int // products a declared scheme reads, by scheme
	schemeRows   int            // their rows
	displayOnly  int            // products kept display-only (no scheme reads them)
	displayRows  int            // their rows
	dropped      int            // products that keep no row (git commits only, limited to some systems, unsafe text)
	skipVendors  int            // listed CVEs whose owner vendor is in recordSkipVendors and whose record has generic rows for it
	skipRows     int            // CNA rows of recordSkipVendors' vendors in the sample (generic rows no view reads)
	skipByScheme int            // of those rows, the ones a declared scheme reads
}

func auditNotations(t *testing.T) notationAudit {
	t.Helper()
	s, recs := loadRecordSample(t)
	raws := maps.Clone(s.Records)
	esxi := []byte(testFile(t, "brief/"+briefCVE+".record.json"))
	raws[briefCVE] = esxi
	rec, err := ParseCVERecord(esxi, briefCVE)
	if err != nil {
		t.Fatal(err)
	}
	recs[briefCVE] = rec
	a := notationAudit{byReason: map[string]int{}, byVendor: map[string]int{}, scheme: map[string]int{}}
	type rawRec struct {
		Meta struct {
			Assigner string `json:"assignerShortName"`
		} `json:"cveMetadata"`
		Containers struct {
			CNA struct {
				Affected []cnaAffected `json:"affected"`
			} `json:"cna"`
			ADP []struct {
				Affected []cnaAffected `json:"affected"`
			} `json:"adp"`
		} `json:"containers"`
	}
	for _, cve := range slices.Sorted(maps.Keys(raws)) {
		var raw rawRec
		if err := json.Unmarshal(raws[cve], &raw); err != nil {
			t.Fatalf("%s: %v", cve, err)
		}
		lists := [][]cnaAffected{raw.Containers.CNA.Affected}
		for _, c := range raw.Containers.ADP {
			lists = append(lists, c.Affected)
		}
		var groups []notationGroup
		for i, list := range lists {
			if len(list) > recordMaxEntries {
				continue
			}
			origin, fallback := OriginCNA, recordWord(raw.Meta.Assigner)
			if i > 0 {
				origin, fallback = OriginADP, ""
			}
			for _, e := range list {
				part, vendor, product, _, ok := entryIdentity(e, fallback)
				if !ok {
					continue
				}
				g := notationGroup{origin: origin, part: part, vendor: vendor, product: product}
				j := slices.IndexFunc(groups, func(h notationGroup) bool { h.reason = ""; return h == g })
				if j < 0 {
					groups = append(groups, g)
					j = len(groups) - 1
				}
				if why := notationReason(e); why != "" && groups[j].reason == "" {
					groups[j].reason = why
				}
			}
		}
		for _, g := range groups {
			if g.reason == "" {
				continue
			}
			a.refused++
			a.byReason[g.reason]++
			a.byVendor[g.vendor+": "+g.reason]++
			var rows []Range
			for _, r := range recs[cve].Ranges {
				if !r.Generic() && r.Origin == g.origin && r.Part == g.part && r.Vendor == g.vendor && r.Product == g.product {
					rows = append(rows, r)
				}
			}
			a.refusedRows += len(rows)
			name := ""
			for _, r := range rows {
				sc, _, _, ok := RangeScheme(r)
				if !ok {
					name = ""
					break
				}
				name = sc.Name
			}
			switch {
			case len(rows) == 0:
				a.dropped++
			case name != "":
				a.scheme[name]++
				a.schemeRows += len(rows)
			default:
				a.displayOnly++
				a.displayRows += len(rows)
			}
		}
	}
	for _, k := range s.KEV {
		key := RecordProductKey(k.Vendor, k.Product)
		if recordSkipVendors[key.Vendor] && slices.ContainsFunc(recs[k.CVE].Ranges, func(r Range) bool {
			return r.Generic() && r.Origin == OriginCNA && r.Vendor == key.Vendor && r.Product == key.Product
		}) {
			a.skipVendors++
		}
	}
	for _, r := range recs {
		for _, x := range r.Ranges {
			if x.Origin == OriginCNA && x.Generic() && recordSkipVendors[x.Vendor] {
				a.skipRows++
				if _, _, _, ok := RangeScheme(x); ok {
					a.skipByScheme++
				}
			}
		}
	}
	return a
}

// The counts of this reader. Before it, the reader dropped all 115 refused products: no row kept, none read by a scheme; the 139 CNA
// rows of recordSkipVendors' vendors (all Microsoft's in this sample) were stored and read by no view, as they still are.
const (
	notationRefused      = 115
	notationRefusedRows  = 650
	notationSchemeRows   = 62
	notationDisplayOnly  = 86
	notationDropped      = 17
	notationSkipVendors  = 0
	notationSkipRows     = 139
	notationSkipByScheme = 0
)

var notationSchemes = map[string]int{"citrix-netscaler": 4, "linux-kernel": 5, "vmware-esxi": 3}

func TestCount_VendorNotations(t *testing.T) {
	t.Parallel()
	if *updateRecords {
		t.Skip("rebuilding the sample")
	}
	a := auditNotations(t)
	read := 0
	for _, n := range a.scheme {
		read += n
	}
	t.Logf("products the generic comparison refuses: %d (before: all dropped, 0 rows kept)", a.refused)
	t.Logf("after: %d rows kept as the vendor states them; %d products (%d rows) read per train by a version scheme %v, %d products (%d rows) display-only, %d keep no row",
		a.refusedRows, read, a.schemeRows, a.scheme, a.displayOnly, a.displayRows, a.dropped)
	for _, k := range slices.SortedFunc(maps.Keys(a.byReason), func(x, y string) int { return a.byReason[y] - a.byReason[x] }) {
		t.Logf("  %4d  %s", a.byReason[k], k)
	}
	top := slices.SortedFunc(maps.Keys(a.byVendor), func(x, y string) int {
		if a.byVendor[x] != a.byVendor[y] {
			return a.byVendor[y] - a.byVendor[x]
		}
		return strings.Compare(x, y)
	})
	for _, k := range top[:min(len(top), 15)] {
		t.Logf("  %4d  %s", a.byVendor[k], k)
	}
	t.Logf("recordSkipVendors: %d listed CVEs of Juniper, Microsoft or Citrix with record rows the exploited-list view leaves out; %d such CNA rows in the sample, %d of them read by a version scheme",
		a.skipVendors, a.skipRows, a.skipByScheme)
	got := fmt.Sprint(a.refused, a.refusedRows, a.schemeRows, a.displayOnly, a.dropped, a.skipVendors, a.skipRows, a.skipByScheme, a.scheme)
	want := fmt.Sprint(notationRefused, notationRefusedRows, notationSchemeRows, notationDisplayOnly, notationDropped, notationSkipVendors, notationSkipRows,
		notationSkipByScheme, notationSchemes)
	if got != want {
		t.Errorf("vendor notations moved: %s, want %s", got, want)
	}
}
