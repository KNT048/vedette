package feeds

import (
	"maps"
	"reflect"
	"slices"
	"testing"
)

// fixedCalledAffected counts the fixed releases a record's rows call affected through an open-ended row: the end of a bounded row of a
// product that an "every later version" row of the same product contains. Such a release is no fix for the matcher and the fix
// reader, so a device that installs it stays affected.
func fixedCalledAffected(rows []Range) (n int, cves map[string]bool) {
	cves = map[string]bool{}
	for _, b := range rows {
		if !boundedTrain(b) || b.EndExcl == "" {
			continue
		}
		for _, o := range rows {
			if openEnded(o) && sameRecordProduct(o, b) && inRange(b.EndExcl, o) {
				n++
				cves[b.CVE] = true
				break
			}
		}
	}
	return n, cves
}

// Class count: fixed releases a CVE record's own rows call affected because of an open-ended "every later version" row below them, on
// the frozen sample of 1091 CVE records and F5's record of CVE-2026-95101 (testdata/cveorg). Before CutCatchAll: 2 fixed releases of
// 1 CVE (1.30.6 and 1.31.7; the sample holds none of the shape). After: 0.
func TestCount_RecordFixesCalledAffectedByACatchAllRow(t *testing.T) {
	t.Parallel()
	if *updateRecords {
		t.Skip("rebuilding the sample")
	}
	_, recs := loadRecordSample(t)
	f5, err := ParseCVERecord(fixture(t, "cveorg/CVE-2026-95101.json"), "CVE-2026-95101")
	if err != nil {
		t.Fatal(err)
	}
	recs["CVE-2026-95101"] = f5
	before, after := 0, 0
	bCVEs, aCVEs := map[string]bool{}, map[string]bool{}
	for _, cve := range slices.Sorted(maps.Keys(recs)) {
		n, c := fixedCalledAffected(recs[cve].Ranges)
		before += n
		maps.Copy(bCVEs, c)
		n, c = fixedCalledAffected(CutCatchAll(recs[cve].Ranges))
		after += n
		maps.Copy(aCVEs, c)
	}
	t.Logf("of %d records, fixed releases their own rows call affected: before %d (%d CVEs), after %d (%d CVEs)", len(recs), before, len(bCVEs), after, len(aCVEs))
	if before != 2 || len(bCVEs) != 1 {
		t.Errorf("before moved: %d fixed releases of %d CVEs, want 2 of 1", before, len(bCVEs))
	}
	if after != 0 {
		t.Errorf("%d fixed releases of %d CVEs are still called affected by their own record: %v", after, len(aCVEs), slices.Sorted(maps.Keys(aCVEs)))
	}
}

// F5's record of CVE-2026-95101 (NGINX Open Source): two trains with their fixes and "1.25.0, every later version".
func TestCutCatchAll_StopsAtTheFirstEvaluatedTrain(t *testing.T) {
	t.Parallel()
	row := func(start, end string) Range {
		return Range{CVE: "CVE-2026-95101", Origin: OriginCNA, Vendor: "f5", Product: "nginxopensource", StartIncl: start, EndExcl: end, VersionType: "custom"}
	}
	plus := Range{CVE: "CVE-2026-95101", Origin: OriginCNA, Vendor: "f5", Product: "nginxplus", StartIncl: "36", VersionType: "custom"}
	in := []Range{row("1.31.0", "1.31.7"), row("1.30.0", "1.30.6"), row("1.25.0", ""), plus}
	got := CutCatchAll(in)
	if got[2].EndExcl != "1.30.0" || got[2].Fixed != "" {
		t.Errorf("open row = %+v, want 1.25.0 before 1.30.0 with no fix named", got[2])
	}
	if in[2].EndExcl != "" {
		t.Error("the input rows were changed")
	}
	if !reflect.DeepEqual(got[3], plus) {
		t.Errorf("another product's open row changed: %+v", got[3])
	}
	if !reflect.DeepEqual(got[:2], in[:2]) {
		t.Error("bounded rows changed")
	}
}

func TestCutCatchAll_LeavesRowsWithoutATrainAbove(t *testing.T) {
	t.Parallel()
	r := func(origin, start, end string) Range {
		return Range{CVE: "CVE-2026-1", Origin: origin, Vendor: "example", Product: "relay", StartIncl: start, EndExcl: end}
	}
	exact := Range{CVE: "CVE-2026-1", Origin: OriginCNA, Vendor: "example", Product: "relay", StartIncl: "3.1", EndIncl: "3.1"}
	cases := map[string][]Range{
		"train below the open row":   {r(OriginCNA, "1.0", "1.5"), r(OriginCNA, "2.0", "")},
		"no start":                   {r(OriginCNA, "", ""), r(OriginCNA, "2.0", "2.3")},
		"NVD rows":                   {r(OriginNVD, "1.0", ""), r(OriginNVD, "2.0", "2.3")},
		"an exact version above":     {r(OriginCNA, "2.0", ""), exact},
		"starts that do not compare": {r(OriginCNA, "R33", ""), r(OriginCNA, "R35", "R35.2")},
	}
	for name, in := range cases {
		if got := CutCatchAll(in); !reflect.DeepEqual(got, in) {
			t.Errorf("%s: rows changed to %+v", name, got)
		}
	}
}
