package findings

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/core/productid"
)

// The older-than-the-first-start rule reads Junos OS's numbering only (R1 is a branch's first release, "23.2R2-S1" a release inside
// it). Another scheme's first release of a line is a build number ("7.2.1-69057" is DSM 7.2.1's first release), so there the rule
// decides nothing and an older line stays a question; and the proof names who listed the ranges: the vendor's record, or NVD.
func TestOlderThanEveryStart_JunosOnlyAndNamesWhoListed(t *testing.T) {
	t.Parallel()
	dsmKey, junosKey := productid.Key("Synology", "DiskStation Manager"), productid.Key("Juniper", "Junos OS")
	t.Run("another scheme: no decision", func(t *testing.T) {
		v := Vuln{CVE: "CVE-2099-73001", NVDAnswered: true, Schemed: schemedRows(t, "synology-dsm", dsmKey, [3]string{"7.2.1-69057", "7.2.1-69057-2", ""})}
		a := Asset{ID: "nas", Name: "nas", Software: []Software{{ID: "s-nas", Display: "Synology DSM 7.1.1-42962", Vendor: "Synology", Product: "DiskStation Manager",
			Version: "7.1.1-42962", Source: "manual"}}}
		if r, ok := schemeJudge(a, a.Software[0], swInfoOn(a.Software[0], a), v); ok && r.before != nil {
			t.Errorf("DSM 7.1.1 decided not affected by a range starting at 7.2.1-69057, the first release of 7.2.1")
		}
	})
	junos := func(origin string) (Asset, Vuln) {
		rows := schemedRows(t, "juniper-junos", junosKey, [3]string{"23.2R2-S1", "23.2R2-S5", ""})
		for i := range rows {
			rows[i].Origin = origin
		}
		a := Asset{ID: "ex", Name: "ex-01", Software: []Software{{ID: "s-ex", Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS",
			Version: "15.1R7.9", Source: "manual"}}}
		return a, Vuln{CVE: "CVE-2099-73002", NVDAnswered: true, Schemed: rows}
	}
	for _, c := range []struct{ origin, want, not string }{
		{RangeCNA, "the vendor lists", "NVD lists"},
		{RangeNVD, "NVD lists", "the vendor lists"},
	} {
		t.Run("Junos rows from "+c.origin, func(t *testing.T) {
			a, v := junos(c.origin)
			r, ok := schemeJudge(a, a.Software[0], swInfoOn(a.Software[0], a), v)
			if !ok || r.before == nil {
				t.Fatalf("15.1R7.9 older than 23.2R2-S1: not decided (%v)", ok)
			}
			_, _, note := schemeDecision(a, v, r)
			if !strings.Contains(note, c.want) || strings.Contains(note, c.not) {
				t.Errorf("proof %q: want %q, not %q", note, c.want, c.not)
			}
		})
	}
}
