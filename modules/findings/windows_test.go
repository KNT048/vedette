package findings

import (
	"slices"
	"testing"
	"time"
)

// D-524: the Windows row an agent gives with the update revision ("Windows 11 23H2" 10.0.22631.<UBR>, CPE windows_11_23h2, x64)
// is compared with NVD's ranges of its own release: below the fixed build it is a version finding, at or above it the open
// finding is proved not affected and closes. An entry whose NVD list names only other Windows releases raises nothing and
// proves nothing; one that may cover every release (o:microsoft:windows, windows_10 with any version) is decided as before.
func TestMatchAsset_D524_WindowsByUpdateRevision(t *testing.T) {
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	pc := func(ubr string) Asset {
		v := "10.0.22631." + ubr
		return Asset{ID: "a-pc", Name: "pc-01", OS: "Microsoft Windows 11 Pro " + v, Software: []Software{{
			ID: "s-win", Display: "Windows 11 23H2", Vendor: "microsoft", Product: "Windows 11 23H2", Version: v, Source: "agent",
			CPE: "cpe:2.3:o:microsoft:windows_11_23h2:" + v + ":*:*:*:*:*:x64:*", KevKeys: []string{"microsoft|windows"},
		}}}
	}
	win := func(cve string, affected ...Affected) Vuln {
		return Vuln{CVE: cve, Vendor: "Microsoft", Product: "Windows", Affected: affected}
	}
	end := func(cpe, end string) Affected { return Affected{CPE: cpe, Range: VersionRange{EndExcl: end}} }
	clfs := win("CVE-2025-29824", // NVD's rows of the CLFS flaw, cut to three releases
		end("cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:arm64:*", "10.0.22631.5189"),
		end("cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*", "10.0.22631.5189"),
		end("cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*", "10.0.26100.3775"),
		end("cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", "10.0.20348.3453"))
	old := win("CVE-2017-0144", // an older release's flaw, named the old way
		Affected{CPE: "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"}, Affected{CPE: "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*"},
		Affected{CPE: "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*"})
	family := win("CVE-2099-0001", Affected{CPE: "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"})
	anyTen := win("CVE-2099-0002", Affected{CPE: "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"})
	vulns := []Vuln{clfs, old, family, anyTen}

	cves := func(ms []Match) []string {
		var out []string
		for _, m := range ms {
			out = append(out, m.CVE)
		}
		slices.Sort(out)
		return out
	}
	// unpatched: a version finding for the CLFS flaw (the x64 row decides, not "not checked"), nothing for the older release's flaw
	res := MatchAsset(pc("4460"), vulns, nil, now)
	if got := cves(res.New); !slices.Equal(got, []string{"CVE-2025-29824", "CVE-2099-0001", "CVE-2099-0002"}) {
		t.Fatalf("unpatched: %v", got)
	}
	for _, m := range res.New {
		if m.CVE == clfs.CVE && (m.Basis != BasisVersion || m.Severity != SeverityHigh) {
			t.Fatalf("CLFS on 4460: %+v", m)
		}
	}
	// patched by the April update (5189): the open CLFS finding is proved not affected; the older flaw has no proof, so an open
	// finding of it stays open (FORBID-2)
	have := map[string]bool{clfs.CVE: true, old.CVE: true}
	res = MatchAsset(pc("5189"), vulns, have, now)
	if got := cves(res.NotAffected); !slices.Equal(got, []string{"CVE-2025-29824"}) {
		t.Fatalf("patched, proved: %v (new %v)", got, cves(res.New))
	}
	if got := cves(append(res.New, res.Existing...)); slices.Contains(got, clfs.CVE) || slices.Contains(got, old.CVE) {
		t.Fatalf("patched, still matched: %v", got)
	}
	// a Windows 10 1607 device is the release windows_10:1607 names: the older flaw is not ruled out for it
	ltsb := Asset{ID: "a-ltsb", Name: "ltsb", Software: []Software{{ID: "s", Display: "Windows 10 1607", Vendor: "microsoft", Product: "Windows 10 1607",
		Version: "10.0.14393.7969", CPE: "cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.7969:*:*:*:*:*:*:*", KevKeys: []string{"microsoft|windows"}}}}
	if got := cves(MatchAsset(ltsb, []Vuln{old}, nil, now).New); !slices.Equal(got, []string{old.CVE}) {
		t.Fatalf("1607 and windows_10:1607: %v", got)
	}
	// a row without a Windows release CPE (a person's "Windows 11") is decided as before
	manual := Asset{ID: "a-m", Name: "m", Software: []Software{{ID: "s", Display: "Windows 11", Vendor: "Microsoft", Product: "Windows 11", Version: "10.0.22631.4460", KevKeys: []string{"microsoft|windows"}}}}
	if got := cves(MatchAsset(manual, []Vuln{old}, nil, now).New); !slices.Equal(got, []string{old.CVE}) {
		t.Fatalf("a row without a release CPE: %v", got)
	}
}
