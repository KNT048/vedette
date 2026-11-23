package main

import (
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// End to end, a test box's DESKTOP-55UKKFV: CISA's two "Microsoft | SQL Server" entries with NVD's ranges as the test box holds them
// (SQL Server 2012 to 2017 only). The release's own row without a version is "Needs your input" for both; with the version the
// agent now gives it (the components' 16.0.1000.6, or the setup registry's PatchLevel after an update) the list drops it and NVD's
// ranges decide both CVEs: no finding on SQL Server 2022.
func TestSQLServerVersionLeavesNeedsYourInput(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.kevAdded("CVE-2019-1068", "Microsoft", "SQL Server", time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC))
	s.kevAdded("CVE-2020-0618", "Microsoft", "SQL Server", time.Date(2024, 9, 18, 0, 0, 0, 0, time.UTC))
	affected := [][6]string{
		{"CVE-2019-1068", "cpe:2.3:a:microsoft:sql_server:2014:sp2:*:*:*:*:*:*", "", "", "", ""},
		{"CVE-2019-1068", "cpe:2.3:a:microsoft:sql_server:2014:sp3:*:*:*:*:*:*", "", "", "", ""},
		{"CVE-2019-1068", "cpe:2.3:a:microsoft:sql_server_2016:*:*:*:*:*:*:*:*", "13.0.4001.0", "", "", "13.0.4259.0"},
		{"CVE-2019-1068", "cpe:2.3:a:microsoft:sql_server_2016:*:*:*:*:*:*:*:*", "13.0.4411.0", "", "", "13.0.4604.0"},
		{"CVE-2019-1068", "cpe:2.3:a:microsoft:sql_server_2016:*:*:*:*:*:*:*:*", "13.0.5026.0", "", "", "13.0.5101.9"},
		{"CVE-2019-1068", "cpe:2.3:a:microsoft:sql_server_2016:*:*:*:*:*:*:*:*", "13.0.5149.0", "", "", "13.0.5366.0"},
		{"CVE-2019-1068", "cpe:2.3:a:microsoft:sql_server_2017:*:*:*:*:*:*:*:*", "14.0.1000.169", "", "", "14.0.2027.2"},
		{"CVE-2019-1068", "cpe:2.3:a:microsoft:sql_server_2017:*:*:*:*:*:*:*:*", "14.0.3006.16", "", "", "14.0.3192.2"},
		{"CVE-2020-0618", "cpe:2.3:a:microsoft:sql_server:2012:sp4:*:*:*:*:*:*", "", "", "", ""},
		{"CVE-2020-0618", "cpe:2.3:a:microsoft:sql_server:2014:sp3:*:*:*:*:*:*", "", "", "", ""},
		{"CVE-2020-0618", "cpe:2.3:a:microsoft:sql_server:2016:sp2:*:*:*:*:x64:*", "", "", "", ""},
	}
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, cve := range []string{"CVE-2019-1068", "CVE-2020-0618"} {
			if err := seedNVD(ctx, tx, cve, time.Time{}, 0); err != nil {
				return err
			}
		}
		for _, a := range affected {
			if err := seedRange(ctx, tx, a[0], a[1], a[2], a[3], a[4], a[5]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "DESKTOP-55UKKFV", OS: "Microsoft Windows 11 Pro"})
	if err != nil {
		t.Fatal(err)
	}
	// report is the agent's SQL Server rows as agent-intake maps DESKTOP-55UKKFV's programs (the tests in `../../modules/agent-intake/sqlserver_test.go`, `../../modules/findings/sqlserver_test.go`): the release's own
	// row, then the components that are not keyed to the product.
	report := func(version string) {
		t.Helper()
		items := []inventory.SoftwareItem{
			{Display: "Microsoft SQL Server 2022 (64-bit)", Vendor: "Microsoft", Product: "SQL Server", Version: version, KevKeys: []string{"microsoft|sql server"}, Confidence: 0.95},
			{Display: "SQL Server 2022 Database Engine Services", Vendor: "Microsoft Corporation", Product: "SQL Server 2022 Database Engine Services", Version: "16.0.1000.6", Confidence: 0.95},
		}
		if err := s.d.Inventory.UpsertSoftware(ctx, id, items, "osquery"); err != nil {
			t.Fatal(err)
		}
		if err := findingsJobs(*s.d)[0].Run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	state := func() ([]string, int) {
		t.Helper()
		qs, err := s.d.Findings.Questions(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, q := range qs {
			if q.Kind == findings.QuestionVersionNeeded {
				names = append(names, q.Detail.Software)
			}
		}
		recs, err := s.d.Findings.List(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return names, len(recs)
	}

	report("") // before the fix: the test box's state
	if need, _ := state(); len(need) != 1 || need[0] != "Microsoft SQL Server 2022 (64-bit)" {
		t.Fatalf("without a version: needs %v", need)
	}
	for _, v := range []string{"16.0.1000.6", "16.0.4135.4"} { // the components' build, then the setup registry's after CU14
		report(v)
		if need, n := state(); len(need) != 0 || n != 0 {
			recs, _ := s.d.Findings.List(ctx, id)
			for _, r := range recs {
				t.Logf("%s %s %s %+v %s %s", r.CVE, r.Status, r.Basis, r.Evidence, r.ResolutionReason, r.ResolutionNote)
			}
			t.Fatalf("SQL Server 2022 %s: needs %v, %d findings", v, need, n)
		}
	}
}
