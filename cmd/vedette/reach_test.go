package main

import (
	"cmp"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// reachFixture is the whole CISA KEV list (1,781 entries) with NVD's affected entries of each CVE as the N100 held them on
// 2026-11-16 (feeds_vuln, feeds_affected, feeds_affected_cve; public data, CC0 and NVD), gzipped JSON, one object per entry:
// cve, vendor, product, name, date_added, answered (NVD answered), affected ([cpe] or [cpe, start_incl, start_excl, end_incl,
// end_excl]).
const reachFixture = "testdata/kev-nvd-2026-11-16.json.gz"

// reachWant is the class count of every entry of the fixture against the software Vedette produces today (reachRows: pkgmap.json, the
// Windows release rows of core/winrel, the curated catalog with its KEV keys, nvd-cpe.json aliases, network-os.json). A code or map
// change that moves entries out of 3v or 4 (a version comparison) turns this red: that is the point (kien's root-cause rule, #910).
// A change that makes more entries reachable updates these numbers in the same PR, and says so.
var reachWant = map[findings.ReachClass]int{
	findings.ReachNoNVDData:     1,
	findings.ReachNoNVDVersions: 72,
	findings.ReachKeyedVersion:  712,
	findings.ReachKeyedOnly:     248,
	findings.ReachViaNVD:        110,
	findings.ReachNone:          638,
}

func TestReachability_910_Fixture(t *testing.T) {
	t.Parallel()
	vulns := loadReachFixture(t)
	if len(vulns) != 1781 {
		t.Fatalf("fixture has %d entries, want 1781", len(vulns))
	}
	cat, err := inventory.NewCatalog(catalogdata.Curated, reachKEVProducts(vulns))
	if err != nil {
		t.Fatal(err)
	}
	r := findings.Reachability(vulns, reachRows(cat))
	if r.Total != len(vulns) {
		t.Errorf("total = %d, want %d", r.Total, len(vulns))
	}
	if !maps.Equal(r.Counts, reachWant) {
		var b strings.Builder
		for _, c := range findings.ReachClasses {
			fmt.Fprintf(&b, "\n  class %-2s got %4d want %4d", c, r.Counts[c], reachWant[c])
			if c.Unreachable() && r.Counts[c] > reachWant[c] {
				fmt.Fprintf(&b, " (grew: an entry that had a version comparison lost it; its CVEs: %s)", strings.Join(r.CVEs[c], " "))
			}
		}
		t.Errorf("KEV reachability classes changed (#910):%s", b.String())
	}
}

func loadReachFixture(t *testing.T) []findings.Vuln {
	t.Helper()
	f, err := os.Open(reachFixture)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		CVE       string     `json:"cve"`
		Vendor    string     `json:"vendor"`
		Product   string     `json:"product"`
		Name      string     `json:"name"`
		DateAdded string     `json:"date_added"`
		Answered  bool       `json:"answered"`
		Affected  [][]string `json:"affected"`
	}
	if err := json.NewDecoder(z).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	out := make([]findings.Vuln, len(rows))
	for i, r := range rows {
		v := findings.Vuln{CVE: r.CVE, Vendor: r.Vendor, Product: r.Product, Name: r.Name, NVDAnswered: r.Answered}
		v.DateAdded, _ = time.Parse(time.DateOnly, r.DateAdded)
		for _, a := range r.Affected {
			af := findings.Affected{CPE: a[0]}
			if len(a) == 5 {
				af.Range = findings.VersionRange{StartIncl: a[1], StartExcl: a[2], EndIncl: a[3], EndExcl: a[4]}
			}
			v.Affected = append(v.Affected, af)
		}
		out[i] = v
	}
	return out
}

// reachKEVProducts is the KEV pairs with their counts, as feeds' KevProducts gives the catalog.
func reachKEVProducts(vulns []findings.Vuln) []inventory.KEVProduct {
	n := map[[2]string]int{}
	for _, v := range vulns {
		n[[2]string{v.Vendor, v.Product}]++
	}
	out := make([]inventory.KEVProduct, 0, len(n))
	for k, c := range n {
		out = append(out, inventory.KEVProduct{Vendor: k[0], Product: k[1], Count: c})
	}
	slices.SortFunc(out, func(a, b inventory.KEVProduct) int {
		return cmp.Or(cmp.Compare(a.Vendor, b.Vendor), cmp.Compare(a.Product, b.Product))
	})
	return out
}
