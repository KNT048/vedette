package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	zapdata "github.com/knt048/vedette/content/zap"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// exposureGolden is the real KEV + NVD golden set of findings with the two Apache path-traversal entries added as CISA and NVD
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

// S-EXP-2 (exposure INV-20): Apache 2.4.49 gets CVE-2021-41773 and CVE-2021-42013 by version, nginx without a version is the
// "needs a version" line, tcpwrapped is not compared; a later Apache is outside every range. Exploited CVEs only, from the feeds list.
func TestExposureMatcher_NmapServicesAgainstKEV(t *testing.T) {
	t.Parallel()
	vulns := exposureGolden(t)
	m := exposureMatcher{vulns: func(context.Context) ([]findings.Vuln, error) { return vulns, nil }, now: func() time.Time { return time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC) }}
	got, err := m.Match(t.Context(), exposureFixtureServices)
	if err != nil {
		t.Fatal(err)
	}
	// nginx is igor_sysoev:nginx to nmap and f5:nginx to NVD: compared through the catalogue's nmap name (before it was
	// "not compared"). Without a version it can only need one: a gap on port 443, no finding.
	if got.Compared != 2 || got.Listed != len(vulns) || len(got.Unlisted) != 0 {
		t.Fatalf("compared %d, listed %d, unlisted %v", got.Compared, got.Listed, got.Unlisted)
	}
	for _, g := range got.Gaps {
		if g.Port != 443 {
			t.Errorf("gap = %+v", g)
		}
	}
	got.Gaps = nil
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

	// The catalog seam (inventory.Service.KevKeysByCPE) adds keys the NVD data of the list does not give.
	m.vulns = func(context.Context) ([]findings.Vuln, error) {
		return []findings.Vuln{{CVE: "CVE-2021-41773", Vendor: "Apache", Product: "HTTP Server"}}, nil // no NVD data: product only
	}
	var asked []string
	m.catalog = func(context.Context) func(string) []string {
		return func(cpe string) []string { asked = append(asked, cpe); return []string{"apache|http server"} }
	}
	got, err = m.Match(t.Context(), exposureFixtureServices[2:])
	// Product name only, so not listed: ruled out with the reason
	if err != nil || len(got.Vulns) != 0 || len(got.RuledOut) != 1 || !strings.HasPrefix(got.RuledOut[0].Reason, "Only the product name matches") ||
		!slices.Equal(asked, []string{"cpe:/a:apache:http_server:2.4.49"}) {
		t.Fatalf("catalog: %+v %v asked %v", got, err, asked)
	}
}

// A public IP's port 10022 sends "OpenSSH 9.6p1 Ubuntu 3ubuntu13.20": the Alpine-only CVE-2026-123158 is
// not listed and comes back as ruled out with its reason. The office firewall's "OpenSSH 10.2" (no platform) is not listed
// either: no Yes while the platform condition is open; it is ruled out with what is not known.
func TestExposureMatcher_PlatformLimitedCVE(t *testing.T) {
	t.Parallel()
	vulns := exposureGolden(t)
	m := exposureMatcher{vulns: func(context.Context) ([]findings.Vuln, error) { return vulns, nil }, now: func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }}
	got, err := m.Match(t.Context(), []exposure.ServiceRow{
		{IP: "203.0.113.10", Port: 10022, Name: "ssh", Product: "OpenSSH", Version: "9.6p1 Ubuntu 3ubuntu13.20", Extra: "Ubuntu Linux; protocol 2.0", CPE: "cpe:/a:openbsd:openssh:9.6p1"},
		{IP: "203.0.113.20", Port: 22222, Name: "ssh", Product: "OpenSSH", Version: "10.2", Extra: "protocol 2.0", CPE: "cpe:/a:openbsd:openssh:10.2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range got.Vulns {
		if v.CVE == "CVE-2026-123158" {
			t.Fatalf("listed: %+v", v)
		}
	}
	reasons := map[int]string{}
	for _, r := range got.RuledOut {
		if r.CVE == "CVE-2026-123158" {
			reasons[r.Port] = r.Reason
		}
	}
	if len(reasons) != 2 || !strings.Contains(reasons[10022], "Ubuntu") || !strings.Contains(reasons[22222], "affects only OpenSSH built with musl libc and without PAM") ||
		!strings.Contains(reasons[22222], "nothing Vedette reads says which system or build") {
		t.Fatalf("ruled out = %+v", got.RuledOut)
	}
	// Review r1 #11: two OpenSSH ports on one IP, one Ubuntu's build and one with no platform: one row per CVE and address.
	got, err = m.Match(t.Context(), []exposure.ServiceRow{
		{IP: "203.0.113.10", Port: 10022, Name: "ssh", Product: "OpenSSH", Version: "9.6p1 Ubuntu 3ubuntu13.20", Extra: "Ubuntu Linux; protocol 2.0", CPE: "cpe:/a:openbsd:openssh:9.6p1"},
		{IP: "203.0.113.10", Port: 2222, Name: "ssh", Product: "OpenSSH", Version: "10.2", Extra: "protocol 2.0", CPE: "cpe:/a:openbsd:openssh:10.2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ports := []int{}
	for _, v := range got.Vulns {
		if v.CVE == "CVE-2026-123158" {
			ports = append(ports, v.Port)
		}
	}
	// The port with no platform is asked, not listed; one ruled-out row per CVE and address, on that port
	if len(ports) != 0 || len(got.RuledOut) != 1 || got.RuledOut[0].Port != 2222 {
		t.Fatalf("one IP, two ports: CVE on %v, ruled out %+v", ports, got.RuledOut)
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
// server" key through curated.json, so the service is compared by product. nginx and OpenSSH are in the catalog but no entry of the
// list carries their keys, so they stay "not compared" (INV-20).
func TestExposureMatcher_CuratedCatalogKevKeys(t *testing.T) {
	t.Parallel()
	inv, err := inventory.New(inventory.Config{DB: &store.DB{}, Audit: &audit.Log{}}) // Catalog reads neither
	if err != nil {
		t.Fatal(err)
	}
	m := exposureMatcher{catalog: inv.KevKeysByCPE, now: time.Now, vulns: func(context.Context) ([]findings.Vuln, error) {
		return []findings.Vuln{{CVE: "CVE-2021-41773", Vendor: "Apache", Product: "HTTP Server"}}, nil
	}}
	svcs := append(slices.Clone(exposureFixtureServices[2:]),
		exposure.ServiceRow{IP: "203.0.113.10", Port: 443, Name: "http", Product: "nginx", Version: "1.24.0", CPE: "cpe:/a:igor_sysoev:nginx:1.24.0"},
		exposure.ServiceRow{IP: "203.0.113.10", Port: 22, Name: "ssh", Product: "OpenSSH", Version: "9.6", CPE: "cpe:/a:openbsd:openssh:9.6"})
	got, err := m.Match(t.Context(), svcs)
	if err != nil || got.Compared != 1 || len(got.Vulns) != 0 || len(got.RuledOut) != 1 || got.RuledOut[0].CVE != "CVE-2021-41773" { // Product name only
		t.Fatalf("apache: %+v %v", got, err)
	}
	if !slices.Equal(got.Unlisted, []string{"nginx (igor_sysoev:nginx)", "OpenSSH (openbsd:openssh)"}) {
		t.Fatalf("unlisted = %v", got.Unlisted)
	}
	if k := inv.KevKeysByCPE(t.Context())("cpe:/a:igor_sysoev:nginx"); !slices.Equal(k, []string{"f5|nginx"}) {
		t.Errorf("nginx keys = %v", k)
	}
}

// nmap names nginx igor_sysoev:nginx, the list keeps it under F5 (NVD f5:nginx): the alias of
// the product catalogue compares it, and the version is checked against F5's ranges.
func TestExposureMatcher_NginxAliasReachesF5(t *testing.T) {
	t.Parallel()
	vulns := []findings.Vuln{{CVE: "CVE-2026-0001", Vendor: "F5", Product: "NGINX", Name: "F5 NGINX test flaw",
		Affected: []findings.Affected{{CPE: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", Range: findings.VersionRange{StartIncl: "1.0.0", EndExcl: "1.25.4"}}}}}
	m := exposureMatcher{vulns: func(context.Context) ([]findings.Vuln, error) { return vulns, nil }, now: time.Now}
	for _, c := range []struct {
		version string
		hit     bool
	}{{"1.18.0", true}, {"1.27.1", false}} {
		got, err := m.Match(t.Context(), []exposure.ServiceRow{{IP: "203.0.113.10", Port: 443, Name: "http", Product: "nginx", Version: c.version, CPE: "cpe:/a:igor_sysoev:nginx:" + c.version}})
		if err != nil || got.Compared != 1 || len(got.Unlisted) != 0 || (len(got.Vulns) == 1) != c.hit {
			t.Errorf("nginx %s: %+v %v", c.version, got, err)
		}
		if c.hit && (got.Vulns[0].CVE != "CVE-2026-0001" || got.Vulns[0].Basis != "version") {
			t.Errorf("nginx %s: %+v", c.version, got.Vulns[0])
		}
	}
}

// Exploited answers only the CVE ids the list carries, with CISA's name and date; a version ZAP read in a Server header,
// written as the CPE content/zap/header-cpe.json gives nmap's name for it, goes through the same aliases (nginx reaches F5).
func TestExposureMatcher_ZAPVersions(t *testing.T) {
	t.Parallel()
	vulns := exposureGolden(t)
	m := exposureMatcher{vulns: func(context.Context) ([]findings.Vuln, error) { return vulns, nil }, now: func() time.Time { return time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC) }}
	got, err := m.Exploited(t.Context(), []string{"CVE-2021-41773", "CVE-2000-0001"})
	e, ok := got["CVE-2021-41773"]
	if err != nil || len(got) != 1 || !ok || e.Name != "Apache HTTP Server Path Traversal Vulnerability" || e.DateAdded == nil || *e.DateAdded != "2021-11-03" {
		t.Fatalf("%+v %v", got, err)
	}
	var cpes map[string]string
	if err := json.Unmarshal(zapdata.HeaderCPE, &cpes); err != nil {
		t.Fatal(err)
	}
	row := exposure.ServiceRow{IP: "203.0.113.10", Port: 443, Name: "http", Product: "nginx", Version: "1.20.0", CPE: "cpe:/" + cpes["nginx"] + ":1.20.0"}
	res, err := m.Match(t.Context(), []exposure.ServiceRow{row})
	if err != nil || len(res.Vulns) != 1 || res.Vulns[0].CVE != "CVE-2099-0001" || res.Vulns[0].Basis != "version" {
		t.Fatalf("%+v %v", res, err)
	}
}

// On a public IP, an exploited CVE published more than 12 months ago stays listed when the banner's version is
// compared (Exim 4.89 inside CVE-2019-10149's range, published 2019); with only the product name matching (no NVD data to
// compare) it comes back as ruled out with the reason, never silently dropped. A recent one keeps today's rule.
func TestExposureMatcher_OldKEVOnlyProductOnlyIsRuledOut(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	vulns := exposureGolden(t)
	for i := range vulns {
		vulns[i].Published, vulns[i].DateAdded = time.Date(2019, 6, 5, 0, 0, 0, 0, time.UTC), time.Date(2021, 11, 3, 0, 0, 0, 0, time.UTC)
	}
	m := exposureMatcher{vulns: func(context.Context) ([]findings.Vuln, error) { return vulns, nil }, now: func() time.Time { return now }}
	exim := []exposure.ServiceRow{{IP: "203.0.113.10", Port: 25, Name: "smtp", Product: "Exim smtpd", Version: "4.89", Extra: "Debian", CPE: "cpe:/a:exim:exim:4.89"}}
	got, err := m.Match(t.Context(), exim)
	if err != nil || len(got.Vulns) != 1 || got.Vulns[0].CVE != "CVE-2019-10149" || got.Vulns[0].Basis != "version" || len(got.RuledOut) != 0 {
		t.Fatalf("old CVE, banner version compared: %+v %v", got, err)
	}
	productOnly := func(pub time.Time) []findings.Vuln {
		return []findings.Vuln{{CVE: "CVE-2021-41773", Vendor: "Apache", Product: "HTTP Server", Published: pub, DateAdded: pub}} // no NVD data: product only
	}
	m.vulns = func(context.Context) ([]findings.Vuln, error) {
		return productOnly(time.Date(2021, 10, 5, 0, 0, 0, 0, time.UTC)), nil
	}
	m.catalog = func(context.Context) func(string) []string {
		return func(string) []string { return []string{"apache|http server"} }
	}
	got, err = m.Match(t.Context(), exposureFixtureServices[2:])
	if err != nil || len(got.Vulns) != 0 || len(got.RuledOut) != 1 || got.RuledOut[0].CVE != "CVE-2021-41773" || !strings.Contains(got.RuledOut[0].Reason, "only the product name matches") {
		t.Fatalf("old CVE, product only: %+v %v", got, err)
	}
	m.vulns = func(context.Context) ([]findings.Vuln, error) { return productOnly(now.AddDate(0, -2, 0)), nil }
	// A recent one is no finding on the product name alone either, with its own reason
	if got, err = m.Match(t.Context(), exposureFixtureServices[2:]); err != nil || len(got.Vulns) != 0 || len(got.RuledOut) != 1 ||
		!strings.Contains(got.RuledOut[0].Reason, "Vedette is waiting for NVD's data for CVE-2021-41773") {
		t.Fatalf("recent CVE, product only: %+v %v", got, err)
	}
}

// A service the exposure scan identifies (product and version on a public host) gets the CVEs and the fix a device running the same
// software gets, from the same catalogue: the exploited CVE with its fixed release, nothing for the catalogue CVE on no exploited list.
func TestExposureMatcher_SameCVEsAndFixAsADevice(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const exploited, other = "CVE-2026-71001", "CVE-2026-71002"
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		recent := time.Now().UTC().AddDate(0, -2, 0)
		if err := seedKEVRow(ctx, tx, exploited, "Apache", "HTTP Server", "Apache HTTP Server flaw", time.Now().UTC(), false, false); err != nil {
			return err
		}
		if err := seedNVD(ctx, tx, exploited, recent, 9.8); err != nil {
			return err
		}
		if err := seedRange(ctx, tx, exploited, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "", "", "", "2.4.50"); err != nil {
			return err
		}
		if err := seedNVD(ctx, tx, other, recent, 7.5); err != nil { // on no exploited list
			return err
		}
		if err := seedRange(ctx, tx, other, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "", "", "", "2.4.55"); err != nil {
			return err
		}
		return seedRecentDone(ctx, tx, time.Now().UTC())
	})
	if err != nil {
		t.Fatal(err)
	}

	// The device path: the same software on a LAN device, as an nmap scan reads it.
	addr := netip.MustParseAddr("192.0.2.77")
	if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: observe.AssetHint{IP: addr}, Field: observe.Hostname, Value: "web-1", Source: observe.Passive, Confidence: 0.6, SeenAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	addrs, err := s.d.Inventory.AddressMap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := addrs["192.0.2.77"]
	item := inventory.SoftwareItem{Display: "Apache httpd 2.4.49", Vendor: "apache", Product: "http_server", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49",
		KevKeys: []string{"apache|http server"}, Confidence: 0.9}
	if err := s.d.Inventory.UpsertSoftware(ctx, id, []inventory.SoftwareItem{item}, "nmap"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Findings.OnMatchChanged(ctx, id); err != nil {
		t.Fatal(err)
	}
	recs, err := s.d.Findings.List(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	device := map[string]findings.Fix{}
	var all []string
	for _, r := range recs {
		all = append(all, r.CVE)
		if findings.Announced(r.Row) {
			device[r.CVE] = r.Row.Fix
		}
	}
	slices.Sort(all)
	if !slices.Equal(all, []string{exploited}) || len(device) != 1 || device[exploited].Kind != findings.FixUpdate || device[exploited].Version != "2.4.50" {
		t.Fatalf("device findings %v, announced with their fix %+v", all, device)
	}

	// The exposure path: the same product and version on a public host.
	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	feed := findingsFeeds{st: fs.Store(), cache: &vulnCache{}}
	set, err := feed.MatchSet(ctx, findings.NewMatchScope([]findings.Asset{{ID: "x", Software: []findings.Software{{ID: "x:1", CPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}}}}, nil))
	if err != nil || !slices.ContainsFunc(set, func(v findings.Vuln) bool { return v.CVE == other }) {
		t.Fatalf("the catalogue's match set must hold the CVE on no exploited list for this to prove its silence: %v %v", set, err)
	}
	m := exposureMatcher{vulns: feed.Vulns, catalogue: feed.MatchSet, now: time.Now}
	svc := exposure.ServiceRow{IP: "203.0.113.10", Port: 8080, Name: "http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49"}
	got, fixOf, err := m.match(ctx, []exposure.ServiceRow{svc})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]findings.Fix{}
	for _, v := range got.Vulns {
		seen[v.CVE] = fixOf(svc, v.CVE)
	}
	if !maps.Equal(seen, device) {
		t.Errorf("exposure: %+v, the device: %+v", seen, device)
	}
	if len(got.Gaps) != 0 || len(got.RuledOut) != 0 {
		t.Errorf("the catalogue CVE is silent, not a gap or a ruled-out line: %+v %+v", got.Gaps, got.RuledOut)
	}
	// The port's list is the exploited list alone when the catalogue is not given: the CVEs are the same, the others never shown.
	alone := exposureMatcher{vulns: feed.Vulns, now: time.Now}
	if got2, _, err := alone.match(ctx, []exposure.ServiceRow{svc}); err != nil || len(got2.Vulns) != len(got.Vulns) {
		t.Errorf("exploited list alone: %+v %v", got2.Vulns, err)
	}
	t.Logf("service 203.0.113.10:8080 Apache httpd 2.4.49: %d CVE shown (%v), the catalogue holds %d for the product", len(got.Vulns), seen, len(set))

	// Each guard holds on its own. The reading: findings' matcher itself makes nothing of the CVE on no list from a scan's version
	// (trustedReading), whatever Announced says.
	scanned := findings.Asset{ID: "x", Software: []findings.Software{{ID: "x:1", CPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", Version: "2.4.49", Source: "scan"}}}
	for _, m := range findings.MatchAsset(scanned, set, nil, time.Now()).New {
		if m.CVE == other {
			t.Errorf("a version read from the network matched a CVE on no list")
		}
	}
	// The rule: a device that reports its version itself matches both CVEs, and announced says, for each, what findings says of the
	// finding it made: so the CVE on no list is dropped by the rule alone once a reading is trusted.
	agent := inventory.SoftwareItem{Display: "Apache httpd 2.4.49", Vendor: "apache", Product: "http_server", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49",
		KevKeys: []string{"apache|http server"}, Confidence: 0.9}
	if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("192.0.2.78")}, Field: observe.Hostname, Value: "web-2", Source: observe.Passive, Confidence: 0.6, SeenAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	if addrs, err = s.d.Inventory.AddressMap(ctx); err != nil {
		t.Fatal(err)
	}
	id2 := addrs["192.0.2.78"]
	if err := s.d.Inventory.UpsertSoftware(ctx, id2, []inventory.SoftwareItem{agent}, "osquery"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Findings.OnMatchChanged(ctx, id2); err != nil {
		t.Fatal(err)
	}
	recs2, err := s.d.Findings.List(ctx, id2)
	if err != nil || len(recs2) != 2 {
		t.Fatalf("the device that reports its version has %d findings (%v): want both CVEs", len(recs2), err)
	}
	for _, r := range recs2 {
		i := slices.IndexFunc(set, func(v findings.Vuln) bool { return v.CVE == r.CVE })
		if i < 0 || announced(set[i]) != findings.Announced(r.Row) {
			t.Errorf("%s: announced %v, findings says %v", r.CVE, i >= 0 && announced(set[i]), findings.Announced(r.Row))
		}
	}
}

// Two reads of the same services under an unchanged match stamp read the catalogue once; a new stamp reads it again; another set of
// products is another set.
func TestExposureMatcher_CatalogueIsReadOncePerStamp(t *testing.T) {
	t.Parallel()
	vulns := exposureGolden(t)
	reads, stamp := 0, "a"
	m := exposureMatcher{
		vulns:     func(context.Context) ([]findings.Vuln, error) { return vulns, nil },
		catalogue: func(context.Context, findings.MatchScope) ([]findings.Vuln, error) { reads++; return vulns, nil },
		stamp:     func(context.Context) (string, error) { return stamp, nil },
		memo:      &catalogueMemo{},
		now:       time.Now,
	}
	for range 2 {
		if _, err := m.Match(t.Context(), exposureFixtureServices); err != nil {
			t.Fatal(err)
		}
	}
	if reads != 1 {
		t.Fatalf("catalogue read %d times by two Match calls under one stamp", reads)
	}
	// the same product at another version is the same set
	other := []exposure.ServiceRow{{IP: "203.0.113.10", Port: 18443, Name: "http", Product: "Apache httpd", Version: "2.4.50", CPE: "cpe:/a:apache:http_server:2.4.50"}}
	if _, err := m.Match(t.Context(), other); err != nil || reads != 2 {
		t.Fatalf("another product set: %d reads, %v", reads, err)
	}
	if _, err := m.Match(t.Context(), other); err != nil || reads != 2 {
		t.Fatalf("a repeat: %d reads, %v", reads, err)
	}
	stamp = "b"
	if _, err := m.Match(t.Context(), other); err != nil || reads != 3 {
		t.Fatalf("a new stamp: %d reads, %v", reads, err)
	}
}
