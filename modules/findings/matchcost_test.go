package findings

import (
	"fmt"
	"testing"
)

// notAffectedHeavy is one device and 500 exploited CVEs of its product, each with eight branched rows the version is past the fix of
// its own line on: every pair is decided not affected by the ranges.
func notAffectedHeavy() (Asset, []Vuln) {
	var vulns []Vuln
	for i := range 500 {
		var rows []Affected
		for line := range 8 {
			rows = append(rows, Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: fmt.Sprintf("6.%d", line), EndExcl: fmt.Sprintf("6.%d.2", line)}})
		}
		v := qnapVuln(rows...)
		v.CVE = fmt.Sprintf("CVE-2026-%d", 10000+i)
		vulns = append(vulns, v)
	}
	return nas("6.3.9"), vulns
}

// go test ./modules/findings -run '^$' -bench 'BenchmarkMatchAsset_NotAffectedHeavy' -benchmem
func BenchmarkMatchAsset_NotAffectedHeavy(b *testing.B) {
	a, vulns := notAffectedHeavy()
	b.ReportAllocs()
	for b.Loop() {
		MatchAsset(a, vulns, nil, t0)
	}
}
