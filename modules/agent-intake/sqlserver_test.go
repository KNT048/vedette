package agentintake

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// labSQL is the SQL Server part of DESKTOP-55UKKFV's programs list as osquery gives it: the release's own
// Uninstall entry without a version and its 13 components at the RTM build, among other Microsoft rows that are not of the release.
func labSQL() []row {
	r := func(name, version string) row {
		return row{"name": name, "version": version, "publisher": "Microsoft Corporation", "install_date": "20261012", "reg_key": ""}
	}
	const rtm = "16.0.1000.6"
	return []row{
		r("Microsoft SQL Server 2022 (64-bit)", ""),
		r("Browser for SQL Server 2022", rtm),
		r("Microsoft SQL Server 2022 RsFx Driver", rtm),
		r("Microsoft VSS Writer for SQL Server 2022", rtm),
		r("SQL Server 2022 Batch Parser", rtm),
		r("SQL Server 2022 Common Files", rtm),
		r("SQL Server 2022 Connection Info", rtm),
		r("SQL Server 2022 DMF", rtm),
		r("SQL Server 2022 Database Engine Services", rtm),
		r("SQL Server 2022 Database Engine Shared", rtm),
		r("SQL Server 2022 SQL Diagnostics", rtm),
		r("SQL Server 2022 Shared Management Objects", rtm),
		r("SQL Server 2022 Shared Management Objects Extensions", rtm),
		r("SQL Server 2022 XEvent", rtm),
		// not components of the release: other products, another release's major
		r("Microsoft ODBC Driver 17 for SQL Server", "17.10.6.1"),
		r("Microsoft OLE DB Driver for SQL Server", "18.7.4.0"),
		r("Microsoft System CLR Types for SQL Server 2019 CTP3.0", "15.0.1600.8"),
		r("SQL Server Management Studio 21", "21.6.17"),
	}
}

// setupRow is a row of the programs query's registry arm: an instance's PatchLevel.
func setupRow(instance, build string) row {
	return row{"name": "", "version": build, "publisher": "", "install_date": "",
		"reg_key": `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\` + instance + `\Setup`}
}

// sqlRows maps a programs list and returns its rows keyed to CISA's "Microsoft | SQL Server".
func sqlRows(t *testing.T, rows []row) []observe.Software {
	t.Helper()
	items, dropped := mapPackages(map[string][]row{"programs": rows}, maxRows)
	if dropped != 0 {
		t.Fatalf("%d rows dropped", dropped)
	}
	var out []observe.Software
	for _, s := range items {
		if slices.Contains(s.KevKeys, "microsoft|sql server") {
			out = append(out, s)
		}
		if s.Display == "" || strings.HasPrefix(s.Version, "HKEY") {
			t.Fatalf("a setup value became a software row: %+v", s)
		}
	}
	return out
}

func with(rows []row, more ...row) []row { return append(slices.Clone(rows), more...) }

// The umbrella row takes the build of the instance's setup registry, cumulative update included, at the
// confidence of a version the machine stated; the RsFx Driver, a component the product catalogue maps to the same product, keeps its own name
// (its RTM build would keep open what the update fixed). The setup value is no software row.
func TestSQLServer_SetupRegistryGivesTheRelease(t *testing.T) {
	got := sqlRows(t, with([]row{setupRow("MSSQL16.MSSQLSERVER", "16.0.4135.4")}, labSQL()...))
	if len(got) != 1 || got[0].Display != "Microsoft SQL Server 2022 (64-bit)" || got[0].Version != "16.0.4135.4" || got[0].Confidence != softwareConfidence ||
		got[0].Vendor != "Microsoft" || got[0].Product != "SQL Server" {
		t.Fatalf("SQL Server rows %+v", got)
	}
	items, _ := mapPackages(map[string][]row{"programs": with([]row{setupRow("MSSQL16.MSSQLSERVER", "16.0.4135.4")}, labSQL()...)}, maxRows)
	i := slices.IndexFunc(items, func(s observe.Software) bool { return s.Display == "Microsoft SQL Server 2022 RsFx Driver" })
	if i < 0 || items[i].Vendor != "Microsoft Corporation" || items[i].Product != "Microsoft SQL Server 2022 RsFx Driver" || items[i].KevKeys != nil || items[i].Version != "16.0.1000.6" {
		t.Fatalf("the RsFx Driver: %+v", items[i])
	}
	if len(items) != len(labSQL()) {
		t.Fatalf("%d rows for %d programs", len(items), len(labSQL()))
	}
}

// Fallback (Wazuh, an agent without the setup-registry query): every component agrees on the RTM build and the Database Engine is one of them, so
// the umbrella row takes it below a stated version's confidence. It is the RsFx Driver's own row (same product and build), whose
// stated version keeps its confidence; the merged row keeps the release's name in whatever order osquery lists the two (review r1
// L2 of #967). A test box before the fix had the umbrella row without a version: "Needs your input".
func TestSQLServer_ComponentsGiveTheRelease(t *testing.T) {
	rsfxFirst := labSQL()
	rsfxFirst[0], rsfxFirst[2] = rsfxFirst[2], rsfxFirst[0] // osquery lists the RsFx Driver before the release
	for _, rows := range [][]row{labSQL(), rsfxFirst} {
		got := sqlRows(t, rows)
		if len(got) != 1 || got[0].Display != "Microsoft SQL Server 2022 (64-bit)" || got[0].Version != "16.0.1000.6" || got[0].Confidence != softwareConfidence {
			t.Fatalf("SQL Server rows %+v", got)
		}
	}
	// without the RsFx Driver the row is the umbrella's alone, at the components' confidence
	rows := slices.DeleteFunc(labSQL(), func(r row) bool { return strings.Contains(r["name"], "RsFx") })
	got := sqlRows(t, rows)
	if len(got) != 1 || got[0].Display != "Microsoft SQL Server 2022 (64-bit)" || got[0].Version != "16.0.1000.6" || got[0].Confidence != componentConfidence {
		t.Fatalf("SQL Server rows without RsFx %+v", got)
	}
}

// The fallback never guesses. Components that disagree, no Database Engine, a service pack's family (13.2.x for 13.0), a
// version that is no build: the umbrella row stays without a version (findings asks, as before). Rows of other releases, products or
// majors are not components.
func TestSQLServer_NoGuess(t *testing.T) {
	versionOf := func(rows []row) string {
		t.Helper()
		for _, s := range sqlRows(t, rows) {
			if strings.HasPrefix(s.Display, "Microsoft SQL Server 2022 (") {
				return s.Version
			}
		}
		t.Fatal("no umbrella row")
		return ""
	}
	set := func(name, version string) []row {
		rows := labSQL()
		for i := range rows {
			if rows[i]["name"] == name {
				rows[i]["version"] = version
			}
		}
		return rows
	}
	noRsFx := func(rows []row) []row {
		return slices.DeleteFunc(rows, func(r row) bool { return strings.Contains(r["name"], "RsFx") })
	}
	for name, rows := range map[string][]row{
		"one component updated":        noRsFx(set("SQL Server 2022 Common Files", "16.0.4135.4")),
		"no Database Engine":           noRsFx(slices.DeleteFunc(labSQL(), func(r row) bool { return strings.Contains(r["name"], "Database Engine Services") })),
		"engine of another family":     noRsFx(set("SQL Server 2022 Database Engine Services", "16.2.1000.6")),
		"a component that is no build": noRsFx(set("SQL Server 2022 DMF", "16.0.1000")),
	} {
		v := versionOf(rows)
		if name == "a component that is no build" { // a row whose version is no build is not read at all: the others still agree
			if v != "16.0.1000.6" {
				t.Errorf("%s: %q", name, v)
			}
			continue
		}
		if v != "" {
			t.Errorf("%s: the umbrella row took %q", name, v)
		}
	}
	// a row of another major that names the release is not one of its components
	if v := versionOf(noRsFx(with(labSQL(), row{"name": "SQL Server 2022 Odd Tool", "version": "15.0.2000.5", "publisher": "x"}))); v != "16.0.1000.6" {
		t.Errorf("another major: %q", v)
	}
	// no components at all, no setup value: as before
	if v := versionOf([]row{{"name": "Microsoft SQL Server 2022 (64-bit)", "version": "", "publisher": "Microsoft Corporation"}}); v != "" {
		t.Errorf("umbrella alone: %q", v)
	}
	// SQL Server 2016 SP2: every component reads 13.2.5026.0 (major.SP.build), not a 13.0 build NVD's ranges use
	sp := []row{{"name": "Microsoft SQL Server 2016 (64-bit)", "version": ""}, {"name": "SQL Server 2016 Database Engine Services", "version": "13.2.5026.0"},
		{"name": "SQL Server 2016 Common Files", "version": "13.2.5026.0"}}
	for _, s := range sqlRows(t, sp) {
		if s.Display == "Microsoft SQL Server 2016 (64-bit)" && s.Version != "" {
			t.Errorf("2016 SP2 components gave %q", s.Version)
		}
	}
}

// The setup values are read strictly. Several instances of the release give the lowest build; an instance of another
// release, Analysis Services' key, a build of another family under the key, and text that is no build are not read; an umbrella
// row that has a version of its own (the build the release was installed with) takes the setup value too.
func TestSQLServer_SetupValues(t *testing.T) {
	umbrella := row{"name": "Microsoft SQL Server 2022 (64-bit)", "version": "", "publisher": "Microsoft Corporation", "reg_key": ""}
	versionOf := func(rows ...row) string {
		t.Helper()
		for _, s := range sqlRows(t, append(rows, umbrella)) {
			if s.Display == umbrella["name"] {
				return s.Version
			}
		}
		t.Fatal("no umbrella row")
		return ""
	}
	if v := versionOf(setupRow("MSSQL16.MSSQLSERVER", "16.0.4135.4"), setupRow("MSSQL16.SQLEXPRESS", "16.0.4125.3"), setupRow("MSSQL16.DEV", "16.0.4175.1")); v != "16.0.4125.3" {
		t.Errorf("three instances: %q, want the lowest", v)
	}
	if v := versionOf(setupRow("MSSQL16.A", "16.0.4135.4"), setupRow("MSSQL16.B", "16.0.900.1")); v != "16.0.900.1" {
		t.Errorf("number order: %q", v) // 900 < 4135, though "9" > "4"
	}
	for name, r := range map[string]row{
		"another release":   setupRow("MSSQL15.MSSQLSERVER", "15.0.4385.2"),
		"Analysis Services": {"name": "", "version": "16.0.43.1", "reg_key": `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSAS16.MSSQLSERVER\Setup`},
		"another family":    setupRow("MSSQL16.MSSQLSERVER", "15.0.4385.2"),
		"no build":          setupRow("MSSQL16.MSSQLSERVER", "16.0.4135"),
		"text":              setupRow("MSSQL16.MSSQLSERVER", "16.0.4135.4 CU14"),
		"another key":       {"name": "", "version": "16.0.4135.4", "reg_key": `HKEY_LOCAL_MACHINE\SOFTWARE\Evil\MSSQL16.X\Setup`},
		"a deeper key":      {"name": "", "version": "16.0.4135.4", "reg_key": `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.X\Setup\SQL_Engine_Core_Inst`},
	} {
		if v := versionOf(r); v != "" {
			t.Errorf("%s: the umbrella row took %q", name, v)
		}
	}
	// an umbrella row with a version of its own takes the setup value as the one without does: one row
	two := sqlRows(t, []row{setupRow("MSSQL16.MSSQLSERVER", "16.0.4135.4"), {"name": "Microsoft SQL Server 2022 (64-bit)", "version": "16.0.1000.6"}, umbrella})
	if len(two) != 1 || two[0].Version != "16.0.4135.4" {
		t.Errorf("an umbrella row with a version: %+v", two)
	}
	// without a setup value it keeps its own
	if own := sqlRows(t, []row{{"name": "Microsoft SQL Server 2022 (64-bit)", "version": "16.0.4003.1"}}); len(own) != 1 || own[0].Version != "16.0.4003.1" {
		t.Errorf("an umbrella row with a version, no setup value: %+v", own)
	}
	// 2008 R2 keys carry the minor: MSSQL10_50 gives 10.50 builds to the 2008 R2 release, not to 2008
	r2 := row{"name": "Microsoft SQL Server 2008 R2 (64-bit)", "version": "", "publisher": "Microsoft Corporation"}
	got := sqlRows(t, []row{setupRow("MSSQL10_50.MSSQLSERVER", "10.50.6000.34"), r2, {"name": "Microsoft SQL Server 2008 (64-bit)", "version": ""}})
	for _, s := range got {
		want := map[string]string{"Microsoft SQL Server 2008 R2 (64-bit)": "10.50.6000.34", "Microsoft SQL Server 2008 (64-bit)": ""}[s.Display]
		if s.Version != want {
			t.Errorf("%s: %q, want %q", s.Display, s.Version, want)
		}
	}
}

// The programs query reads the registry for the version values of fixed key patterns, with the list, and the registry arms come first
// (a list cut at maxRows keeps them). The SQL is SQLite's: a compound SELECT whose arms have the same five columns.
func TestSQLServer_ProgramsQuery(t *testing.T) {
	q := programsQuery
	want := `SELECT '' AS name, r.data AS version, '' AS publisher, '' AS install_date, r.key AS reg_key FROM registry r ` +
		`WHERE r.key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL%\Setup' AND r.name = 'PatchLevel' ` +
		`UNION ALL SELECT '', r.name, '', '', r.key FROM registry r ` +
		`WHERE r.key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\dotnet\Setup\InstalledVersions\%\sharedfx\%' AND r.type != 'subkey' ` +
		`UNION ALL SELECT '', r.name, '', '', r.key FROM registry r ` +
		`WHERE r.key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions\%\sharedfx\%' AND r.type != 'subkey' ` +
		`UNION ALL SELECT name, version, publisher, install_date, '' FROM programs;`
	if q != want {
		t.Fatalf("programs query:\n%s\nwant\n%s", q, want)
	}
	// each registry arm is one key LIKE below a fixed path, each % one key level (osquery pushes a single LIKE on key down; %% recurses)
	arms := strings.Split(q, " UNION ALL ")
	for _, a := range arms[:len(arms)-1] {
		if strings.Count(a, "r.key LIKE 'HKEY_LOCAL_MACHINE\\SOFTWARE\\") != 1 || strings.Contains(a, "%%") || regexp.MustCompile(`(?i)\bOR\b`).MatchString(a) {
			t.Fatalf("registry arm %q", a)
		}
	}
	if !strings.HasSuffix(arms[len(arms)-1], "FROM programs;") || !slices.Contains(columns["programs"], "reg_key") {
		t.Fatal("the list is not the last arm, or reg_key is not read")
	}
}
