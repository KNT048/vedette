package main

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// exposureGolden is the real KEV + NVD golden set of findings (D-500) with the two Apache path-traversal entries added as CISA and NVD
// publish them (KEV dateAdded 2021-11-03; NVD: CVE-2021-41773 affects http_server 2.4.49, CVE-2021-42013 affects 2.4.49 and 2.4.50;
// the Fedora, NetApp and Oracle entries of those CVEs are left out), Exim CVE-2019-10149 (KEV 2021-11-03, NVD exim 4.87 to 4.91),
// and one made-up entry for nginx under NVD's current name f5:nginx (no KEV entry names nginx).
func exposureGolden(t *testing.T) []findings.Vuln {
	t.Helper()
	b, err := os.ReadFile("../../modules/findings/testdata/kev-nvd-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Vulns []struct {
			CVE, Vendor, Product, Name string
			Ransomware                 bool
			DateAdded                  string `json:"date_added"`
			Affected                   []struct {
				CPE       string
				StartIncl string `json:"start_incl"`
				StartExcl string `json:"start_excl"`
				EndIncl   string `json:"end_incl"`
				EndExcl   string `json:"end_excl"`
			}
		}
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	var out []findings.Vuln
	for _, v := range g.Vulns {
		x := findings.Vuln{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, Name: v.Name, Ransomware: v.Ransomware}
		x.DateAdded, _ = time.Parse(time.DateOnly, v.DateAdded)
		for _, a := range v.Affected {
			x.Affected = append(x.Affected, findings.Affected{CPE: a.CPE, Range: findings.VersionRange{StartIncl: a.StartIncl, StartExcl: a.StartExcl, EndIncl: a.EndIncl, EndExcl: a.EndExcl}})
		}
		out = append(out, x)
	}
	added := time.Date(2021, 11, 3, 0, 0, 0, 0, time.UTC)
	apache := func(cve string, versions ...string) findings.Vuln {
		v := findings.Vuln{CVE: cve, Vendor: "Apache", Product: "HTTP Server", Name: "Apache HTTP Server Path Traversal Vulnerability", DateAdded: added}
		for _, ver := range versions {
			v.Affected = append(v.Affected, findings.Affected{CPE: "cpe:2.3:a:apache:http_server:" + ver + ":*:*:*:*:*:*:*"})
		}
		return v
	}
	return append(out, apache("CVE-2021-41773", "2.4.49"), apache("CVE-2021-42013", "2.4.49", "2.4.50"),
		findings.Vuln{CVE: "CVE-2019-10149", Vendor: "Exim", Product: "Mail Transfer Agent (MTA)", Name: "Exim Mail Transfer Agent (MTA) Improper Input Validation", DateAdded: added,
			Affected: []findings.Affected{{CPE: "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*", Range: findings.VersionRange{StartIncl: "4.87", EndIncl: "4.91"}}}},
		findings.Vuln{CVE: "CVE-2099-0001", Vendor: "F5", Product: "nginx", Name: "made up for this test",
			Affected: []findings.Affected{{CPE: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", Range: findings.VersionRange{EndExcl: "1.21.0"}}}})
}

// The services of modules/exposure/testdata/nmap-external.xml as the scan container hands them over.
var exposureFixtureServices = []exposure.ServiceRow{
	{IP: "203.0.113.10", Port: 443, Name: "http", Product: "nginx", CPE: "cpe:/a:igor_sysoev:nginx"},
	{IP: "203.0.113.10", Port: 8443, Name: "tcpwrapped"},
	{IP: "203.0.113.10", Port: 18443, Name: "http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49"},
}

// S-EXP-2 (exposure INV-20, D-553): Apache 2.4.49 gets CVE-2021-41773 and CVE-2021-42013 by version, nginx without a version is the
// "needs a version" line, tcpwrapped is not compared; a later Apache is outside every range. Exploited CVEs only, from the feeds list.
func TestExposureMatcher_NmapServicesAgainstKEV(t *testing.T) {
	t.Parallel()
	vulns := exposureGolden(t)
	m := exposureMatcher{vulns: func(context.Context) ([]findings.Vuln, error) { return vulns, nil }, now: func() time.Time { return time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC) }}
	got, err := m.Match(t.Context(), exposureFixtureServices)
	if err != nil {
		t.Fatal(err)
	}
	// nginx is igor_sysoev:nginx to nmap and f5:nginx to NVD: not compared, and said so (review MED-2).
	if got.Compared != 1 || got.Listed != len(vulns) || !slices.Equal(got.Unlisted, []string{"nginx (igor_sysoev:nginx)"}) {
		t.Fatalf("compared %d, listed %d, unlisted %v", got.Compared, got.Listed, got.Unlisted)
	}
	var cves []string
	for _, v := range got.Vulns {
		if v.Port != 18443 || v.Basis != "version" || v.DateAdded == nil || *v.DateAdded != "2021-11-03" || v.Name != "Apache HTTP Server Path Traversal Vulnerability" {
			t.Errorf("vuln = %+v", v)
		}
		cves = append(cves, v.CVE)
	}
	slices.Sort(cves)
	if !slices.Equal(cves, []string{"CVE-2021-41773", "CVE-2021-42013"}) {
		t.Fatalf("cves = %v", cves)
	}
	if len(got.Gaps) != 0 {
		t.Fatalf("gaps = %+v", got.Gaps)
	}

	// Apache without a version: the "needs a version" line; Exim 4.89 (Debian 9's package): inside the range by version.
	more := []exposure.ServiceRow{
		{IP: "203.0.113.10", Port: 8080, Name: "http", Product: "Apache httpd", CPE: "cpe:/a:apache:http_server"},
		{IP: "203.0.113.10", Port: 25, Name: "smtp", Product: "Exim smtpd", Version: "4.89", Extra: "Debian", CPE: "cpe:/a:exim:exim:4.89"},
	}
	got, err = m.Match(t.Context(), more)
	if err != nil || got.Compared != 2 || len(got.Gaps) != 1 || got.Gaps[0].Port != 8080 || !slices.Equal(got.Gaps[0].CVEs, []string{"CVE-2021-41773", "CVE-2021-42013"}) {
		t.Fatalf("gaps: %+v %v", got, err)
	}
	if len(got.Vulns) != 1 || got.Vulns[0].CVE != "CVE-2019-10149" || got.Vulns[0].Port != 25 || got.Vulns[0].Basis != "version" {
		t.Fatalf("exim: %+v", got.Vulns)
	}

	later := []exposure.ServiceRow{{IP: "203.0.113.10", Port: 18443, Name: "http", Product: "Apache httpd", Version: "2.4.51", CPE: "cpe:/a:apache:http_server:2.4.51"}}
	if got, err := m.Match(t.Context(), later); err != nil || len(got.Vulns) != 0 || len(got.Gaps) != 0 {
		t.Fatalf("2.4.51: %+v %v", got, err)
	}

	// The catalog seam (inventory.Service.KevKeysForCPE) adds keys the NVD data of the list does not give.
	m.vulns = func(context.Context) ([]findings.Vuln, error) {
		return []findings.Vuln{{CVE: "CVE-2021-41773", Vendor: "Apache", Product: "HTTP Server"}}, nil // no NVD data: product only
	}
	var asked []string
	m.catalog = func(_ context.Context, cpe string) []string {
		asked = append(asked, cpe)
		return []string{"apache|http server"}
	}
	got, err = m.Match(t.Context(), exposureFixtureServices[2:])
	if err != nil || len(got.Vulns) != 1 || got.Vulns[0].Basis != "product" || !slices.Equal(asked, []string{"cpe:/a:apache:http_server:2.4.49"}) {
		t.Fatalf("catalog: %+v %v asked %v", got, err, asked)
	}
}

func TestExposureMatcher_CPE23(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"cpe:/a:apache:http_server:2.4.49": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		"cpe:/a:igor_sysoev:nginx":         "cpe:2.3:a:igor_sysoev:nginx:*:*:*:*:*:*:*:*",
		"cpe:/o:fortinet:fortios:7.2.5":    "cpe:2.3:o:fortinet:fortios:7.2.5:*:*:*:*:*:*:*",
		"cpe:/a:evil:%7e":                  "",
		"cpe:/x:a:b":                       "",
		"cpe:/a::b":                        "",
		"cpe:2.3:a:apache:http_server":     "",
		"cpe:/a:a:b:1:2:3:4:5":             "",
	} {
		if got := cpe23(in); got != want {
			t.Errorf("cpe23(%q) = %q, want %q", in, got, want)
		}
	}
}

// Item 24 slice a: the wiring's hook is inventory's curated catalog. With no NVD data in the list, Apache's CPE reaches the "apache|http
// server" key through curated.json, so the service is compared by product (an unlisted CPE, nginx under nmap's vendor name, now too).
func TestExposureMatcher_CuratedCatalogKevKeys(t *testing.T) {
	t.Parallel()
	inv, err := inventory.New(inventory.Config{DB: &store.DB{}, Audit: &audit.Log{}}) // Catalog reads neither
	if err != nil {
		t.Fatal(err)
	}
	m := exposureMatcher{catalog: inv.KevKeysForCPE, now: time.Now, vulns: func(context.Context) ([]findings.Vuln, error) {
		return []findings.Vuln{{CVE: "CVE-2021-41773", Vendor: "Apache", Product: "HTTP Server"}}, nil
	}}
	got, err := m.Match(t.Context(), exposureFixtureServices[2:])
	if err != nil || got.Compared != 1 || len(got.Vulns) != 1 || got.Vulns[0].CVE != "CVE-2021-41773" || got.Vulns[0].Basis != "product" {
		t.Fatalf("apache: %+v %v", got, err)
	}
	for cpe, want := range map[string]string{"cpe:/a:igor_sysoev:nginx": "f5|nginx", "cpe:/a:openbsd:openssh:9.6": "openbsd|openssh"} {
		if k := inv.KevKeysForCPE(t.Context(), cpe); !slices.Equal(k, []string{want}) {
			t.Errorf("%s -> %v, want %s", cpe, k, want)
		}
	}
}
