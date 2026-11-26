package findings

import "testing"

// SQL Server ships for x64 only from SQL Server 2016 (version 13) on; 2014 and 2012 also shipped 32-bit builds, so a release year a
// person typed is read as a year, not as a build major.
func TestInstallOf_SQLServerArchitectureFromRelease(t *testing.T) {
	t.Parallel()
	for ver, want := range map[string]string{"16.0.1000.6": "x64", "13.0.5026.0": "x64", "12.0.6024.0": "", "2022": "x64", "2016": "x64",
		"2014": "", "2012": ""} {
		s := Software{ID: "s", Display: "Microsoft SQL Server", Vendor: "Microsoft", Product: "SQL Server", Version: ver}
		if got := installOf(s, Asset{ID: "db"}).arch; got != want {
			t.Errorf("SQL Server %s: architecture %q, want %q", ver, got, want)
		}
	}
}
