package findings

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/productid"
)

// The equivalence fixture: a fixed set of devices and entries that reaches every reader of the matcher and of the fix grouping
// (Windows release rows serviced, on Extended Security Updates and ended; a network OS stated by LLDP and by SNMP; distribution
// packages with fixed, Pro-only and not-affected rows; keyed, "Multiple Products" and catalogue-only entries; rows without a version).
// The answers of the code on it are kept in testdata (equivGolden): a change that is meant to make the code faster must leave them
// exactly as they are. A change of behaviour regenerates them on purpose with VEDETTE_UPDATE_GOLDEN=1, and the diff is reviewed.

// with is a with its own id and name.
func with(a Asset, id string) Asset {
	a.ID, a.Name = id, id
	return a
}

// equivAssets is the fixture's devices, each with its own id.
func equivAssets(t *testing.T) []Asset {
	t.Helper()
	tools := vmwareToolsPC()
	tools.Software = append(tools.Software, Software{ID: "s-fusion", Display: "VMware Fusion", Vendor: "VMware", Product: "Fusion", Version: "12.0.0",
		Source: "agent", KevKeys: []string{"vmware|fusion"}})
	assets := []Asset{
		with(winlab01(), "eq-winlab01"),
		with(winServer2025("2894", "*"), "eq-ws2025"),
		with(winHost(19045, false, 3803, ""), "eq-win10-22h2"),
		with(winHost(22000, false, 2295, ""), "eq-win11-21h2"),
		with(winHost(26100, false, 1742, ""), "eq-win11-24h2"),
		with(winPC(22621, false, "6060", "x64"), "eq-win11-22h2-ended"), // feature_update
		with(winPC(19045, false, "6456", "x64"), "eq-win10-esu"),        // esu
		with(winPC(19044, false, "6000", "x64"), "eq-win10-21h2"),
		with(winPC(22631, false, "4460", "x64"), "eq-win11-23h2"),
		with(desktop55(), "eq-desktop55"),
		with(tools, "eq-tools"),
		with(labEX4200(), "eq-ex4200"),
		with(fortigate(), "eq-fortigate"),
		with(fortiSNMP(), "eq-forti-snmp"),
		with(fortiRow("nmap"), "eq-forti-nmap"),
		with(esxiHost("8.0", "22380479"), "eq-esxi"),
		with(sshHost("8.9p1", ""), "eq-ssh"),
		with(sshHost("", "cpe:2.3:a:openbsd:openssh:9.3:p1:*:*:*:*:*:*"), "eq-ssh-cpe"),
		with(nas("6.1.1"), "eq-nas"),
		{ID: "eq-iphone", Name: "eq-iphone", OS: "iOS 18.2", Software: []Software{
			{ID: "s-ios", Display: "iOS", Vendor: "Apple", Product: "iOS", Version: "18.2", Source: "agent", KevKeys: []string{"apple|ios", "apple|multiple products"}},
			{ID: "s-ipados", Display: "iPadOS", Vendor: "Apple", Product: "iPadOS", Version: "17.7.2", Source: "manual", KevKeys: []string{"apple|ipados"}},
		}},
		{ID: "eq-office", Name: "eq-office", OS: "Microsoft Windows 11 Pro", Software: []Software{
			{ID: "s-office", Display: "Microsoft Office 2016", Vendor: "Microsoft", Product: "Office", Version: "16.0.4266.1001", Source: "agent", KevKeys: []string{"microsoft|office"}},
			{ID: "s-sql", Display: "Microsoft SQL Server 2019", Vendor: "Microsoft", Product: "SQL Server", Version: "15.0.2000.5", Source: "agent", KevKeys: []string{"microsoft|sql server"}},
			{ID: "s-edge", Display: "Microsoft Edge", Vendor: "Microsoft", Product: "Edge", Version: "", Source: "agent", KevKeys: []string{"microsoft|edge"}},
		}},
		{ID: "eq-netscaler", Name: "eq-netscaler", Software: []Software{
			{ID: "s-ns", Display: "NetScaler ADC", Vendor: "Citrix", Product: "NetScaler ADC", Version: "13.1-49.13", Source: "nmap", KevKeys: []string{"citrix|netscaler adc"}},
			{ID: "s-fos", Display: "FortiOS", Vendor: "Fortinet", Product: "FortiOS", Version: "latest", Source: "manual", KevKeys: []string{"fortinet|fortios", "fortinet|multiple products"}},
		}},
	}
	assets = append(assets, equivLinux()...)
	assets = append(assets, equivAnon(t)...)
	return assets
}

// equivPackages are the distribution packages of the fixture's Linux servers: source package, upstream version, full package version.
var equivPackages = []struct{ vendor, product, pkg, version, full string }{
	{"OpenBSD", "OpenSSH", "openssh", "9.6p1", "1:9.6p1-3ubuntu13.4"},
	{"OpenSSL", "OpenSSL", "openssl", "3.0.13", "3.0.13-0ubuntu3.1"},
	{"Sudo Project", "Sudo", "sudo", "1.9.15p5", "1.9.15p5-3ubuntu5"},
	{"Apache", "HTTP Server", "apache2", "2.4.58", "2.4.58-1ubuntu8.4"},
	{"Linux", "Linux Kernel", "linux", "6.8.0", "6.8.0-45.45"},
	{"GNU", "glibc", "glibc", "2.39", "2.39-0ubuntu8.3"},
}

// equivLinux is an Ubuntu 24.04 server whose agent reads its packages, a Debian 12 server with the same packages, and a server whose
// rows a person typed (no package database).
func equivLinux() []Asset {
	rows := func(prefix, suffix string, packaged bool, source string) []Software {
		var out []Software
		for i, p := range equivPackages {
			s := Software{ID: fmt.Sprintf("%s-%d", prefix, i), Display: p.product, Vendor: p.vendor, Product: p.product, Version: p.version, Source: source,
				KevKeys: []string{productid.Key(p.vendor, p.product)}}
			if packaged {
				s.Packaged, s.PkgVersion, s.PkgSource = true, p.full+suffix, p.pkg
			}
			out = append(out, s)
		}
		return out
	}
	return []Asset{
		{ID: "eq-ubuntu", Name: "eq-ubuntu", OS: "Ubuntu 24.04.1 LTS", Software: rows("s-u", "", true, "agent")},
		{ID: "eq-debian", Name: "eq-debian", OS: "Debian GNU/Linux 12 (bookworm)", Software: rows("s-d", "+deb12u1", true, "agent")},
		{ID: "eq-typed", Name: "eq-typed", Software: rows("s-t", "", false, "manual")},
	}
}

// equivAnon is the devices and software lines of testdata/anon-findings-before.json (an anonymised test network).
func equivAnon(t *testing.T) []Asset {
	t.Helper()
	b, err := os.ReadFile("testdata/anon-findings-before.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Software []struct {
			ID      string  `json:"id"`
			AssetID string  `json:"asset_id"`
			Vendor  string  `json:"vendor"`
			Product string  `json:"product"`
			Source  string  `json:"source"`
			Version *string `json:"version"`
		} `json:"software"`
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	by := map[string]*Asset{}
	var order []string
	for _, s := range fx.Software {
		a := by[s.AssetID]
		if a == nil {
			a = &Asset{ID: s.AssetID, Name: s.AssetID}
			by[s.AssetID] = a
			order = append(order, s.AssetID)
		}
		v := ""
		if s.Version != nil {
			v = *s.Version
		}
		a.Software = append(a.Software, Software{ID: s.ID, Display: s.Product, Vendor: s.Vendor, Product: s.Product, Version: v, Source: s.Source,
			KevKeys: []string{productid.Key(s.Vendor, s.Product)}})
	}
	out := make([]Asset, 0, len(order))
	for _, id := range order {
		out = append(out, *by[id])
	}
	return out
}

// equivVulns is the fixture's entries: the real exploited-list entries with their NVD rows from testdata, distribution rows for the
// Linux servers' packages (keyed and catalogue-only), and a synthetic catalogue for every product the devices run.
func equivVulns(t *testing.T, assets []Asset) []Vuln {
	t.Helper()
	var out []Vuln
	for _, f := range []string{"testdata/kev-nvd-golden.json", "testdata/kev-nvd-junos-n23.json", "testdata/kev-nvd-office-n22.json",
		"testdata/kev-nvd-winlab01-n55.json", "testdata/kev-nvd-snmp-os.json", "testdata/kev-nvd-sqlserver-n100.json"} {
		out = append(out, loadGolden(t, f)...)
	}
	out = append(out, cve62215, cve29824, cve36884, cve0367, cve0210)
	for i, p := range equivPackages {
		cpe := "cpe:2.3:a:" + productid.Norm(p.vendor) + ":" + productid.Norm(p.product) + ":*:*:*:*:*:*:*:*"
		aff := []Affected{{CPE: cpe, Range: VersionRange{EndExcl: p.version + ".9"}}}
		ub := func(fixed string, pro bool) DistroFix {
			return DistroFix{Distro: "ubuntu", Release: "24.04", Package: p.pkg, Status: "fixed", Fixed: fixed, Pro: pro}
		}
		deb := DistroFix{Distro: "debian", Release: "12", Package: p.pkg, Status: "fixed", Fixed: p.full + "+deb12u2"}
		id := func(k int) string { return fmt.Sprintf("CVE-2026-9%02d%03d", i, k) }
		out = append(out,
			// keyed by CISA, fixed by the distribution above the installed package
			Vuln{CVE: id(1), Vendor: p.vendor, Product: p.product, NVDAnswered: true, Origin: RangeNVD, Affected: aff, Distro: []DistroFix{ub(p.full+".1", false), deb}},
			// keyed, fixed below the installed package: patched
			Vuln{CVE: id(2), Vendor: p.vendor, Product: p.product, NVDAnswered: true, Origin: RangeNVD, Affected: aff, Distro: []DistroFix{ub("0.1", false)}},
			// keyed, the fix only in Ubuntu Pro
			Vuln{CVE: id(3), Vendor: p.vendor, Product: p.product, NVDAnswered: true, Origin: RangeNVD, Affected: aff, Distro: []DistroFix{ub(p.full+".2", true)}},
			// keyed, not affected on Ubuntu, no Debian word
			Vuln{CVE: id(4), Vendor: p.vendor, Product: p.product, NVDAnswered: true, Origin: RangeNVD, Affected: aff,
				Distro: []DistroFix{{Distro: "ubuntu", Release: "24.04", Package: p.pkg, Status: "not_affected"}}},
			// on no list, upstream range only
			catalogueOnly(id(5), cpe, "", p.version+".1"),
			// on no list, the distribution's word only (no NVD rows yet)
			Vuln{CVE: id(6), NVDAnswered: true, Distro: []DistroFix{ub(p.full+".3", false), deb}},
			// keyed, a range that ends at an affected release
			Vuln{CVE: id(7), Vendor: p.vendor, Product: p.product, NVDAnswered: true, Origin: RangeNVD,
				Affected: []Affected{{CPE: cpe, Range: VersionRange{EndIncl: p.version + ".5"}}}},
		)
	}
	return append(out, syntheticCatalogue(assets, 3000)...)
}

// equivGolden compares got (as indented JSON) with testdata/<name>.json.gz, or writes it there with VEDETTE_UPDATE_GOLDEN=1.
func equivGolden(t *testing.T, name string, got any) {
	t.Helper()
	b, err := json.MarshalIndent(got, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	path := "testdata/" + name + ".json.gz"
	if os.Getenv("VEDETTE_UPDATE_GOLDEN") == "1" {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if _, err := zw.Write(b); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	f, err := os.Open(path) //nolint:gosec // a testdata path named by the test itself
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	want, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(b, want) {
		return
	}
	gl, wl := bytes.Split(b, []byte("\n")), bytes.Split(want, []byte("\n"))
	for i := range max(len(gl), len(wl)) {
		var g, w []byte
		if i < len(gl) {
			g = gl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if !bytes.Equal(g, w) {
			t.Fatalf("%s differs from the kept answers at line %d:\n got: %s\nwant: %s\n(%d lines got, %d kept)", path, i+1, g, w, len(gl), len(wl))
		}
	}
}

// fixAnswers is every fix reader's answer on one device for the CVEs the matcher finds on it (its open findings).
type fixAnswers struct {
	Device string                `json:"device"`
	CVEs   []string              `json:"cves"`
	Rows   map[string]*RowFix    `json:"rows"`
	Groups map[string]groupShown `json:"groups"`
	Pages  map[string]*FixedIn   `json:"pages"`
}

// groupShown is a GroupFix with its sets as sorted lists.
type groupShown struct {
	Kind, Software, Version, Fixed, Distro, KB string
	Closed, Ranged                             []string
	NVDLag                                     bool
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// RowFixes, FixedInForAll and FixedInFor answer exactly what they answered before they read each device's software once: every list
// row's grouped update (KB and software id included), every group's closed and ranged CVEs, and every finding page's fixed release, on
// every device of the equivalence fixture.
func TestFixGrouping_SameAnswersOnTheFixture(t *testing.T) {
	t.Parallel()
	assets := equivAssets(t)
	set := newMatchSet(equivVulns(t, assets))
	var got []fixAnswers
	for _, a := range assets {
		dev := set.forDevice(a)
		r := MatchAsset(a, dev, nil, t0)
		byCVE := map[string]Vuln{}
		for _, v := range dev {
			if _, ok := byCVE[v.CVE]; !ok {
				byCVE[v.CVE] = v
			}
		}
		var open []Vuln
		ans := fixAnswers{Device: a.ID, Groups: map[string]groupShown{}, Pages: map[string]*FixedIn{}}
		for _, m := range slices.Concat(r.New, r.Existing) {
			if slices.Contains(ans.CVEs, m.CVE) {
				continue
			}
			ans.CVEs = append(ans.CVEs, m.CVE)
			open = append(open, byCVE[m.CVE])
		}
		ans.Rows = RowFixes(a, open)
		for cve, g := range FixedInForAll(a, open) {
			ans.Groups[cve] = groupShown{Kind: g.Kind, Software: g.Software, Version: g.Version, Fixed: g.Fixed, Distro: g.Distro, KB: g.KB,
				Closed: sortedKeys(g.Closed), Ranged: sortedKeys(g.Ranged), NVDLag: g.NVDLag}
		}
		for _, v := range open {
			ans.Pages[v.CVE] = FixedInFor(a, v)
		}
		got = append(got, ans)
	}
	rows := 0
	for _, a := range got {
		rows += len(a.Rows)
	}
	if rows == 0 {
		t.Fatal("the fixture groups nothing: it no longer reaches the fix grouping")
	}
	equivGolden(t, "equiv-fixes", got)
}

// keyedBy on keys normalised once answers exactly what keyedTo answers, for every row of the fixture and every entry, and for the
// edge cases of the key: no key, the key separator, "Multiple Products", keys written in another case or spacing.
func TestKeyedBy_SameAsKeyedTo(t *testing.T) {
	t.Parallel()
	assets := equivAssets(t)
	vulns := equivVulns(t, assets)
	vulns = append(vulns, Vuln{CVE: "CVE-2099-0001", Vendor: "Fortinet|x", Product: "FortiOS"}, Vuln{CVE: "CVE-2099-0002", Vendor: "Apple", Product: "Multiple Products"},
		Vuln{CVE: "CVE-2099-0003", Vendor: " FORTINET ", Product: "fortios"}, Vuln{CVE: "CVE-2099-0004", Product: "FortiOS"})
	rows := []Software{{ID: "s-a", KevKeys: []string{" Fortinet | FortiOS "}}, {ID: "s-b", KevKeys: []string{"apple|ios"}}, {ID: "s-c"}}
	for _, a := range assets {
		rows = append(rows, a.Software...)
	}
	n := 0
	for _, s := range rows {
		keys := rowKeys(s)
		for _, v := range vulns {
			if got, want := keyedBy(keys, keyOf(v)), keyedTo(s, v); got != want {
				t.Fatalf("row %s %v, entry %s %q|%q: keyedBy %v, keyedTo %v", s.ID, s.KevKeys, v.CVE, v.Vendor, v.Product, got, want)
			} else if got {
				n++
			}
		}
	}
	if n == 0 {
		t.Fatal("no row is keyed to any entry: the fixture no longer tests the key")
	}
}
