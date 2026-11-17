package findings

import "testing"

// D-606: NVD names SQL Server releases by year ("sql_server:2014:sp3"); a computer reports a build ("16.0.4135.4", agent-intake's
// release row). Another major is not affected, the same major cannot be told (the service pack), a typed release is that release.
// Only NVD's own sql_server product: sql_server_2016's build ranges are compared as ranges, and other products are not touched.
func TestSQLServerRelease(t *testing.T) {
	for _, tc := range []struct {
		cpe, ver string
		want     Tri
		applies  bool
	}{
		{"cpe:2.3:a:microsoft:sql_server:2014:sp2:*:*:*:*:*:*", "16.0.1000.6", No, true},   // SQL Server 2022 is not 2014
		{"cpe:2.3:a:microsoft:sql_server:2016:sp2:*:*:*:*:x64:*", "16.0.4135.4", No, true}, // nor 2016
		{"cpe:2.3:a:microsoft:sql_server:2014:sp3:*:*:*:*:*:*", "12.0.6024.0", Unknown, true},
		{"cpe:2.3:a:microsoft:sql_server:2008:r2_sp3:*:*:*:*:*:*", "10.50.6000.34", Unknown, true}, // 2008 and 2008 R2 share 10
		{"cpe:2.3:a:microsoft:sql_server:2012:sp4:*:*:*:*:*:*", "2012", Unknown, true},             // typed, service pack pinned
		{"cpe:2.3:a:microsoft:sql_server:2012:*:*:*:*:*:*:*", "2012", Yes, true},
		{"cpe:2.3:a:microsoft:sql_server:2012:sp4:*:*:*:*:*:*", "2019", No, true},
		{"cpe:2.3:a:microsoft:sql_server:2014:sp3:*:*:*:*:*:*", "16", Unknown, false},               // not a build
		{"cpe:2.3:a:microsoft:sql_server:2014:sp3:*:*:*:*:*:*", "", Unknown, false},                 // no version
		{"cpe:2.3:a:microsoft:sql_server:2014:sp3:*:*:*:*:*:*", "21.6.17", Unknown, false},          // SSMS-sized major
		{"cpe:2.3:a:microsoft:sql_server:15.0.2000.5:*:*:*:*:*:*:*", "16.0.1000.6", Unknown, false}, // a build, not a release name
		{"cpe:2.3:a:microsoft:office:2016:*:*:*:*:*:*:*", "16.0.1000.6", Unknown, false},
		{"cpe:2.3:a:oracle:sql_server:2014:*:*:*:*:*:*:*", "16.0.1000.6", Unknown, false},
	} {
		c, err := ParseCPE(tc.cpe)
		if err != nil {
			t.Fatal(err)
		}
		lit, _ := c.Version.Literal()
		got, ok := sqlServerRelease(c, VersionRange{StartIncl: lit, EndIncl: lit}, true, tc.ver)
		if got != tc.want || ok != tc.applies {
			t.Errorf("%s vs %q: %v %v, want %v %v", tc.cpe, tc.ver, got, ok, tc.want, tc.applies)
		}
	}
	// a range configuration is never a release name
	c, _ := ParseCPE("cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*")
	if _, ok := sqlServerRelease(c, VersionRange{StartIncl: "2014", EndExcl: "2016"}, false, "16.0.1000.6"); ok {
		t.Error("a range took the release rule")
	}
	// through evalAffected: SQL Server 2022 is outside both CISA entries' NVD lists of the N100 (CVE-2019-1068, CVE-2020-0618)
	for _, cfg := range []struct{ cpe, start, end string }{
		{"cpe:2.3:a:microsoft:sql_server:2014:sp2:*:*:*:*:*:*", "", ""},
		{"cpe:2.3:a:microsoft:sql_server_2016:*:*:*:*:*:*:*:*", "13.0.4001.0", "13.0.4259.0"},
		{"cpe:2.3:a:microsoft:sql_server_2017:*:*:*:*:*:*:*:*", "14.0.3006.16", "14.0.3192.2"},
		{"cpe:2.3:a:microsoft:sql_server:2016:sp2:*:*:*:*:x64:*", "", ""},
	} {
		c, err := ParseCPE(cfg.cpe)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := evalAffected(c, VersionRange{StartIncl: cfg.start, EndExcl: cfg.end}, "16.0.1000.6", CPE{}, false); got != No {
			t.Errorf("%s: %v for SQL Server 2022 RTM", cfg.cpe, got)
		}
	}
}
