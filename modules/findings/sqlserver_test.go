package findings

import (
	"slices"
	"strings"
	"testing"
)

// NVD names SQL Server releases by year ("sql_server:2014:sp3"); a computer reports a build ("16.0.4135.4", agent-intake's
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
		// a release's own product (alias of Microsoft|SQL Server): typed releases, a service pack's minor, another major; builds of its major
		// go to the ranges
		{"cpe:2.3:a:microsoft:sql_server_2016:*:*:*:*:*:*:*:*", "2022", No, true},
		{"cpe:2.3:a:microsoft:sql_server_2016:*:*:*:*:*:*:*:*", "2016", Unknown, true},
		{"cpe:2.3:a:microsoft:sql_server_2016:*:*:*:*:*:*:*:*", "13.2.5026.0", Unknown, true},
		{"cpe:2.3:a:microsoft:sql_server_2016:*:*:*:*:*:*:*:*", "13.0.5026.0", Unknown, false},
		{"cpe:2.3:a:microsoft:sql_server_2016:*:*:*:*:*:*:*:*", "16.0.1000.6", No, true},            // another major: a range with no start must not reach it
		{"cpe:2.3:a:microsoft:sql_server_2008:r2:sp1:*:*:*:*:*:*", "10.50.6000.34", Unknown, false}, // NVD's release-in-version scheme
		{"cpe:2.3:a:microsoft:sql_server_reporting_services:2016:*:*:*:*:*:*:*", "2016", Unknown, false},
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
	// through evalAffected: SQL Server 2022 is outside both CISA entries' NVD lists on a test box (CVE-2019-1068, CVE-2020-0618)
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

// sqlVerdicts is what the matcher says about each CVE for one SQL Server row of version ver (an agent's row keyed to CISA's
// "Microsoft | SQL Server"): "finding <basis>", "not affected", "need", "unchecked" (could not be checked, no finding), "-".
func sqlVerdicts(t *testing.T, vulns []Vuln, ver, source string) map[string]string {
	t.Helper()
	sw := Software{ID: "s-sql", Display: "Microsoft SQL Server (64-bit)", Vendor: "Microsoft", Product: "SQL Server", Version: ver,
		KevKeys: []string{"microsoft|sql server"}, Source: source}
	have := map[string]bool{} // every pair has a finding already: "not affected" is what would close it
	for _, v := range vulns {
		have[v.CVE] = true
	}
	res := MatchAsset(Asset{ID: "a", Name: "db-01", OS: "Microsoft Windows Server 2022 Datacenter", AgentOS: "Microsoft Windows Server 2022 Datacenter",
		Software: []Software{sw}}, vulns, have, t0)
	out := map[string]string{}
	for _, v := range vulns {
		out[v.CVE] = "-"
	}
	for _, m := range res.NameOnly {
		out[m.CVE] = "unchecked"
	}
	for _, u := range res.Unchecked {
		out[u.CVE] = "unchecked"
	}
	for _, m := range res.NotAffected {
		out[m.CVE] = "not affected"
	}
	for _, n := range res.NeedVersion {
		for _, c := range n.CVEs {
			out[c] = "need"
		}
	}
	for _, m := range slices.Concat(res.New, res.Existing) {
		out[m.CVE] = "finding " + string(m.Basis)
	}
	return out
}

// PR #967 review r1 H1: every KEV entry whose NVD list names microsoft:sql_server*, against SQL Server rows of
// every release, at RTM and at an update. NVD lists CVE-2019-1068 for 2016 and 2017 under their own products with build ranges
// (sql_server_2016, sql_server_2017): those builds are findings by version, never "not affected" from the 2014 release rows
// (the year rule answers sql_server:2014 alone). 2019 and 2022 are outside both CISA entries; 2014 cannot be told (the build does
// not say the service pack); a service pack's 13.2.x form is not compared with NVD's 13.0.x ranges. Typed releases: "2016" and
// "2017" are not "not affected" for CVE-2019-1068 (on main they were, review r1), "2022" is.
func TestSQLServer_EveryReleaseAgainstNVD(t *testing.T) {
	// the aliases are NVD's per-release products by exact name: no sql_server* prefix (Reporting Services, Management Studio)
	ids := cpeAliases[identity{vendor: "microsoft", product: "sqlserver"}]
	if len(ids) != 5 || slices.ContainsFunc(ids, func(id identity) bool {
		return id.prefix || !sqlServerProducts[strings.TrimPrefix(id.product, "sqlserver")]
	}) {
		t.Fatalf("Microsoft|SQL Server aliases %+v", ids)
	}
	vulns := loadGolden(t, "testdata/kev-nvd-sqlserver-n100.json")
	const c1068, c0618, c1856, c0158 = "CVE-2019-1068", "CVE-2020-0618", "CVE-2012-1856", "CVE-2012-0158"
	for _, tc := range []struct {
		ver, source  string
		v1068, v0618 string
	}{
		{"16.0.1000.6", "agent", "not affected", "not affected"},      // 2022 RTM
		{"16.0.4135.4", "agent", "not affected", "not affected"},      // 2022 CU14
		{"15.0.2000.5", "agent", "not affected", "not affected"},      // 2019 RTM
		{"15.0.4385.2", "agent", "not affected", "not affected"},      // 2019 CU
		{"14.0.1000.169", "agent", "finding version", "not affected"}, // 2017 RTM: inside 14.0.1000.169–14.0.2027.2
		{"14.0.3045.24", "agent", "finding version", "not affected"},  // 2017 CU12: inside 14.0.3006.16–14.0.3192.2
		{"14.0.3460.9", "agent", "not affected", "not affected"},      // 2017, a later CU
		{"13.0.5026.0", "agent", "finding version", "unchecked"},      // 2016 SP2: inside 13.0.5026.0–13.0.5101.9
		{"13.0.5292.0", "agent", "finding version", "unchecked"},      // 2016 SP2 CU: inside 13.0.5149.0–13.0.5366.0
		{"13.2.5026.0", "agent", "unchecked", "unchecked"},            // 2016 SP2 as its programs read it
		{"12.0.6024.0", "agent", "unchecked", "unchecked"},
		{"13.0.1601.5", "agent", "not affected", "unchecked"},      // 2016 RTM: NVD lists SP1 and SP2 builds only
		{"11.0.7001.0", "agent", "not affected", "unchecked"},      // 2012 SP4
		{"10.50.6000.34", "agent", "not affected", "not affected"}, // 2008 R2 SP3            // 2014 SP3: the build does not say the service pack
		{"2016", "manual", "unchecked", "unchecked"},
		{"2017", "manual", "unchecked", "not affected"},
		{"2022", "manual", "not affected", "not affected"},
	} {
		got := sqlVerdicts(t, vulns, tc.ver, tc.source)
		if got[c1068] != tc.v1068 || got[c0618] != tc.v0618 {
			t.Errorf("%s: %s %q (want %q), %s %q (want %q)", tc.ver, c1068, got[c1068], tc.v1068, c0618, got[c0618], tc.v0618)
		}
		if strings.HasPrefix(got[c1856], "finding") || got[c1856] == "not affected" || strings.HasPrefix(got[c0158], "finding") || got[c0158] == "not affected" {
			t.Errorf("%s: the Office and MSCOMCTL entries decided a SQL Server row: %s %q, %s %q", tc.ver, c1856, got[c1856], c0158, got[c0158])
		}
	}
}
