package main

import (
	"os"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
)

// F5's record of CVE-2026-95101 lists NGINX Open Source 1.31.0 before 1.31.7 and 1.30.0 before 1.30.6, and "1.25.0, every later
// version" for the trains it no longer evaluates. Read through the match set's conversion (CutCatchAll, then the match row), nginx
// 1.30.5 is affected with the fix 1.30.6 (not "see the vendor advisory"), a device that updates to 1.30.6 or to 1.31.9 is no longer
// affected, and 1.29.0 (a train the record does not evaluate) still is.
func TestRecordCatchAll_NginxGetsItsTrainFix(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../modules/feeds/testdata/cveorg/CVE-2026-95101.json")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := feeds.ParseCVERecord(raw, "CVE-2026-95101")
	if err != nil {
		t.Fatal(err)
	}
	v := findings.Vuln{CVE: "CVE-2026-95101", NVDAnswered: true, Origin: feeds.OriginCNA, RangesFrom: findings.RangesCVEOrg}
	for _, r := range feeds.CutCatchAll(rec.Ranges) {
		if row, ok := r.MatchRow(); ok {
			v.Affected = append(v.Affected, findings.Affected{CPE: row.CPE,
				Range: findings.VersionRange{StartIncl: row.StartIncl, StartExcl: row.StartExcl, EndIncl: row.EndIncl, EndExcl: row.EndExcl}})
		}
	}
	device := func(version string) (findings.Asset, findings.Software) {
		s := findings.Software{ID: "s-nginx", Display: "nginx", Vendor: "F5", Product: "nginx", Version: version,
			CPE: "cpe:2.3:a:f5:nginx:" + version + ":*:*:*:*:*:*:*", Source: "manual"}
		return findings.Asset{ID: "web-01", Name: "web-01", Software: []findings.Software{s}}, s
	}
	at := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		version  string
		affected bool
		fix      string
	}{{"1.30.5", true, "1.30.6"}, {"1.31.6", true, "1.31.7"}, {"1.30.6", false, ""}, {"1.31.9", false, ""}, {"1.29.0", true, ""}} {
		a, s := device(c.version)
		res := findings.MatchAsset(a, []findings.Vuln{v}, nil, at)
		if got := len(res.New) == 1; got != c.affected {
			t.Errorf("nginx %s: affected %v, want %v", c.version, got, c.affected)
			continue
		}
		if !c.affected {
			continue
		}
		fx := findings.FixOf(a, s, v)
		switch {
		case c.fix != "" && (fx.Kind != findings.FixUpdate || fx.Version != c.fix):
			t.Errorf("nginx %s: fix %+v, want update to %s", c.version, fx, c.fix)
		case c.fix == "" && fx.Kind == findings.FixUpdate:
			t.Errorf("nginx %s: fix %+v, want none named (a train the record does not evaluate)", c.version, fx)
		}
	}
}
