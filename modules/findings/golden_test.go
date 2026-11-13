package findings

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// The golden set (D-500): REAL CISA KEV entries for Apple iOS, Fortinet FortiOS, Microsoft Office and Citrix
// NetScaler (and the "Multiple Products" entries of Apple and Fortinet) with their REAL NVD affected
// configurations, as the box stores them (testdata/kev-nvd-golden.json: KEV catalog 2026.11.10 + NVD CVE API 2.0
// ?hasKev, fetched 2026-11-13). The expected CVE sets below were checked by hand against those ranges.

type goldenFile struct {
	Vulns []struct {
		CVE        string `json:"cve"`
		Vendor     string `json:"vendor"`
		Product    string `json:"product"`
		Ransomware bool   `json:"ransomware"`
		DateAdded  string `json:"date_added"`
		Affected   []struct {
			CPE       string `json:"cpe"`
			StartIncl string `json:"start_incl"`
			StartExcl string `json:"start_excl"`
			EndIncl   string `json:"end_incl"`
			EndExcl   string `json:"end_excl"`
		} `json:"affected"`
	} `json:"vulns"`
}

func goldenVulns(t *testing.T) []Vuln {
	t.Helper()
	b, err := os.ReadFile("testdata/kev-nvd-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g goldenFile
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	out := make([]Vuln, 0, len(g.Vulns))
	for _, v := range g.Vulns {
		x := Vuln{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, Ransomware: v.Ransomware}
		x.DateAdded, _ = time.Parse(time.DateOnly, v.DateAdded)
		for _, a := range v.Affected {
			x.Affected = append(x.Affected, Affected{CPE: a.CPE, Range: VersionRange{StartIncl: a.StartIncl, StartExcl: a.StartExcl, EndIncl: a.EndIncl, EndExcl: a.EndExcl}})
		}
		out = append(out, x)
	}
	return out
}

// keysFor gives a software the KEV keys the inventory catalog gives it (inventory.Catalog.keysFor): every KEV pair
// whose vendor contains the vendor fragment and whose product contains the product fragment.
func keysFor(vulns []Vuln, fragments ...string) []string {
	seen := map[string]bool{}
	var keys []string
	for _, f := range fragments {
		fv, fp, _ := strings.Cut(f, "|")
		for _, v := range vulns {
			if strings.Contains(strings.ToLower(v.Vendor), fv) && strings.Contains(strings.ToLower(v.Product), fp) {
				if k := KevKey(v.Vendor, v.Product); !seen[k] {
					seen[k] = true
					keys = append(keys, k)
				}
			}
		}
	}
	return keys
}

type goldenOut struct {
	version, product, need []string
	severity               map[string]Severity
}

func runGolden(t *testing.T, vulns []Vuln, sw Software) goldenOut {
	t.Helper()
	res := MatchAsset(Asset{ID: "a", Name: "dev", Software: []Software{sw}}, vulns, nil, t0)
	o := goldenOut{severity: map[string]Severity{}}
	for _, m := range res.New {
		o.severity[m.CVE] = m.Severity
		if m.Basis == BasisVersion {
			o.version = append(o.version, m.CVE)
		} else {
			o.product = append(o.product, m.CVE)
		}
	}
	for _, n := range res.NeedVersion {
		o.need = append(o.need, n.CVEs...)
	}
	slices.Sort(o.version)
	slices.Sort(o.product)
	slices.Sort(o.need)
	return o
}

func iPhone(vulns []Vuln, version string) Software {
	return Software{ID: "s-ios", Display: "iOS / iPadOS", Vendor: "Apple", Product: "iOS", Version: version, KevKeys: keysFor(vulns, "apple|ios")}
}

func fortiGate(vulns []Vuln, version string) Software {
	return Software{ID: "s-fgt", Display: "FortiGate", Vendor: "Fortinet", Product: "FortiOS", Version: version, KevKeys: keysFor(vulns, "fortinet|fortios", "fortinet|multiple products")}
}

func office(vulns []Vuln, version string) Software {
	return Software{ID: "s-office", Display: "Microsoft Office (desktop)", Vendor: "Microsoft", Product: "Office", Version: version, KevKeys: keysFor(vulns, "microsoft|office", "microsoft|excel")}
}

func netScaler(vulns []Vuln, version string) Software {
	return Software{ID: "s-ns", Display: "Citrix NetScaler (ADC / Gateway)", Vendor: "Citrix", Product: "NetScaler", Version: version,
		KevKeys: keysFor(vulns, "citrix|netscaler", "citrix|application delivery controller", "citrix|sd-wan and netscaler")}
}

// agentPkg is a package as osquery reports it through agent-intake (pkgmap.json: vendor and product are the KEV
// pair, the version is the Debian upstream version).
func agentPkg(vendor, product, version string) Software {
	return Software{ID: "s-" + strings.ToLower(product), Display: product, Vendor: vendor, Product: product, Version: version, KevKeys: []string{KevKey(vendor, product)}}
}

// ubuntuServer is the box "byn" of the N100 walk (W2-11): Ubuntu 26.04.1, every version from osquery.
func ubuntuServer() []Software {
	return []Software{
		agentPkg("Linux", "Kernel", "7.0.0"), agentPkg("OpenSSL", "OpenSSL", "3.5.5"), agentPkg("GNU", "GNU Bash", "5.3"),
		agentPkg("GNU", "GNU C Library", "2.43"), agentPkg("Sudo", "Sudo", "1.9.17p2"), agentPkg("Red Hat", "Polkit", "127"),
		agentPkg("ISC", "BIND", "9.20.24"), agentPkg("OpenBSD", "OpenSSH", "10.2p1"),
	}
}

func cves(s string) []string { return strings.Fields(s) }

func TestAliases_DataIsValid(t *testing.T) {
	t.Parallel()
	if cpeAliasErr != nil {
		t.Fatal(cpeAliasErr)
	}
	if ids := cpeAliases[identity{vendor: "apple", product: "ios"}]; len(ids) != 2 || ids[0].product != "iphoneos" {
		t.Fatalf("Apple|iOS aliases = %+v", ids)
	}
}

// TestGolden_PatchedUbuntuServer: W2-11. A fully patched Ubuntu 26.04.1 server got ~50 KEV CVEs (Dirty COW, Dirty
// Pipe, Heartbleed, Shellshock, CVE-2023-4911, Baron Samedit, PwnKit…). Only the ranges that include the exact
// versions remain, all by version, none by product only.
func TestGolden_PatchedUbuntuServer(t *testing.T) {
	t.Parallel()
	vulns := goldenVulns(t)
	res := MatchAsset(Asset{ID: "a", Name: "byn", OS: "Ubuntu 26.04.1 LTS", Software: ubuntuServer()}, vulns, nil, t0)
	var got []string
	for _, m := range res.New {
		got = append(got, m.CVE+" "+string(m.Basis))
	}
	slices.Sort(got)
	// The true few: upstream ranges that include these exact versions (kernel 7.0.0 < 7.0.10, 7.1.3, 7.0.x;
	// OpenSSH < 10.6). Ubuntu may have backported the fixes; D-500 records that the distro's own fixed
	// versions are the follow-up. CVE-2021-3493 lists only Ubuntu releases before 20.10: ruled out by the OS.
	want := []string{"CVE-2026-123158 version", "CVE-2026-46300 version", "CVE-2026-53266 version", "CVE-2026-53362 version"}
	if !slices.Equal(got, want) || len(res.NeedVersion) != 0 {
		t.Fatalf("findings %v, items %+v; want %v", got, res.NeedVersion, want)
	}
	// W3-2, D-530: the box already has the old flood (every KEV CVE of these products, by product). The four stay; every
	// other one is proved outside its ranges (or, CVE-2021-3493, outside the OS releases it lists) and closes by itself.
	byn := Asset{ID: "a", Name: "byn", OS: "Ubuntu 26.04.1 LTS", Software: ubuntuServer()}
	flood := map[string]bool{}
	for _, v := range vulns {
		for _, sw := range byn.Software {
			if keyedTo(sw, v) {
				flood[v.CVE] = true
			}
		}
	}
	res = MatchAsset(byn, vulns, flood, t0)
	var kept, closed []string
	for _, m := range res.Existing {
		kept = append(kept, m.CVE+" "+string(m.Basis))
	}
	for _, m := range res.NotAffected {
		closed = append(closed, m.CVE)
	}
	slices.Sort(kept)
	if !slices.Equal(kept, want) || len(res.New) != 0 || len(kept)+len(closed) != len(flood) {
		t.Fatalf("kept %v, closed %d of %d flood findings; want %v kept, the rest closed", kept, len(closed), len(flood), want)
	}
	for _, c := range cves("CVE-2014-0160 CVE-2014-6271 CVE-2021-4034 CVE-2021-3156 CVE-2023-4911 CVE-2016-5195 CVE-2022-0847 CVE-2021-3493") {
		if flood[c] && !slices.Contains(closed, c) {
			t.Errorf("%s is not closed", c)
		}
	}
	t.Logf("byn: %d old findings, %d kept, %d closed by D-530", len(flood), len(kept), len(closed))
	// the same server years ago is caught by version, not by product
	old := []Software{agentPkg("OpenSSL", "OpenSSL", "1.0.1f"), agentPkg("Sudo", "Sudo", "1.8.31"), agentPkg("Red Hat", "Polkit", "0.105"),
		agentPkg("Linux", "Kernel", "4.4.0"), agentPkg("GNU", "GNU C Library", "2.35")}
	must := map[string]bool{"CVE-2014-0160": true, "CVE-2021-3156": true, "CVE-2021-4034": true, "CVE-2016-5195": true, "CVE-2023-4911": true}
	for _, m := range MatchAsset(Asset{ID: "b", Name: "old", Software: old}, vulns, nil, t0).New {
		if must[m.CVE] && m.Basis != BasisVersion {
			t.Errorf("%s: basis %s, want version", m.CVE, m.Basis)
		}
		delete(must, m.CVE)
	}
	if len(must) != 0 {
		t.Errorf("not found by version: %v", must)
	}
}

const (
	// iOS 15.0: every KEV CVE whose iphone_os/ipados range includes 15.0 (fixed in 15.0.2 or later).
	ios150 = `CVE-2021-30883 CVE-2021-30900 CVE-2021-30952 CVE-2021-30983 CVE-2022-22587 CVE-2022-22620 CVE-2022-32893
CVE-2022-32894 CVE-2022-32917 CVE-2022-42827 CVE-2022-42856 CVE-2022-48503 CVE-2022-48618 CVE-2023-23529 CVE-2023-28204
CVE-2023-28205 CVE-2023-28206 CVE-2023-32373 CVE-2023-32409 CVE-2023-32434 CVE-2023-32435 CVE-2023-32439 CVE-2023-37450
CVE-2023-38606 CVE-2023-41061 CVE-2023-41064 CVE-2023-41974 CVE-2023-41990 CVE-2023-41991 CVE-2023-41992 CVE-2023-41993
CVE-2023-42824 CVE-2023-42916 CVE-2023-42917 CVE-2023-43000 CVE-2024-23222 CVE-2024-23225 CVE-2024-23296 CVE-2024-27834
CVE-2024-44308 CVE-2024-44309 CVE-2025-24085 CVE-2025-24200 CVE-2025-31200 CVE-2025-31201 CVE-2025-31277 CVE-2025-43200
CVE-2025-43300 CVE-2025-43510 CVE-2025-43520 CVE-2025-43529 CVE-2026-20700 CVE-2026-86950`
	// Office 16.0.x: NVD names these by edition (2016, 2019, LTSC 2021, 365 Apps) and every 2016+ edition reports 16,
	// so Vedette cannot tell: medium, never critical. Everything for Office 2000 to 2013 is ruled out.
	office16 = `CVE-2015-2545 CVE-2016-3235 CVE-2016-7193 CVE-2017-0199 CVE-2017-0261 CVE-2017-0262 CVE-2017-11774
CVE-2017-11826 CVE-2017-11882 CVE-2017-8570 CVE-2018-0798 CVE-2018-0802 CVE-2021-27059 CVE-2021-38646 CVE-2021-42292
CVE-2023-21715 CVE-2023-23397 CVE-2024-21413 CVE-2026-124194 CVE-2026-21509 CVE-2026-21514`
)

// TestGolden_KEVWithNVDRanges is the table of D-500: input software and version → the exact CVE sets.
func TestGolden_KEVWithNVDRanges(t *testing.T) {
	t.Parallel()
	vulns := goldenVulns(t)
	tests := []struct {
		name             string
		sw               Software
		version, product string // expected findings by basis (space separated)
		need             int    // CVEs in the one "add the version" item
	}{
		// kien's iPhone on the N100 (W1-1): a current iOS is in no range at all.
		{name: "iOS 27.2.1", sw: iPhone(vulns, "27.2.1")},
		{name: "iOS 15.0", sw: iPhone(vulns, "15.0"), version: ios150},
		{name: "iOS without a version", sw: iPhone(vulns, ""), need: 88},
		{name: "FortiOS 7.2.5", sw: fortiGate(vulns, "7.2.5"),
			version: "CVE-2024-21762 CVE-2024-23113 CVE-2025-25249 CVE-2025-59718 CVE-2025-61624 CVE-2025-68686 CVE-2026-24858"},
		// W1-30: FortiOS 7.4.8 had all 22 FortiOS CVEs since 2018; only these four ranges include it.
		{name: "FortiOS 7.4.8", sw: fortiGate(vulns, "7.4.8"), version: "CVE-2025-25249 CVE-2025-59718 CVE-2025-61624 CVE-2026-24858"},
		// FortiOS entries plus the "Multiple Products" entries whose NVD data names FortiOS; the others (FortiMail,
		// FortiVoice…) are about other products, as NVD names FortiOS elsewhere.
		{name: "FortiOS without a version", sw: fortiGate(vulns, ""), need: 21},
		{name: "Office without a version", sw: office(vulns, ""), need: 32},
		{name: "Office 16.0 build", sw: office(vulns, "16.0.17928.20114"), product: office16},
		{name: "Office typed as 2016", sw: office(vulns, "2016"),
			version: "CVE-2016-7193 CVE-2017-0261 CVE-2017-0262 CVE-2017-11774 CVE-2017-11826 CVE-2017-11882 CVE-2018-0798 CVE-2018-0802 CVE-2023-23397",
			product: "CVE-2015-2545 CVE-2016-3235 CVE-2017-0199 CVE-2017-8570 CVE-2021-27059 CVE-2021-38646 CVE-2021-42292 CVE-2023-21715 CVE-2024-21413 CVE-2026-124194 CVE-2026-21509 CVE-2026-21514"},
		// Citrix builds: "13.1-49.13" is inside "13.1 or later, before 13.1-49.15" (Citrix Bleed, CVE-2023-4966).
		{name: "NetScaler 13.1-49.13", sw: netScaler(vulns, "13.1-49.13"),
			version: "CVE-2023-4966 CVE-2023-6548 CVE-2023-6549 CVE-2025-5777 CVE-2025-6543 CVE-2025-7775 CVE-2026-19490 CVE-2026-3055 CVE-2026-8452 CVE-2026-88771 CVE-2026-88772 CVE-2026-88779",
			product: "CVE-2017-6316 CVE-2019-12989 CVE-2019-12991"}, // SD-WAN entries in another numbering
		// a version that cannot be read is no version: one item, not a flood.
		{name: "FortiOS typed as a word", sw: fortiGate(vulns, "latest"), need: 21},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			o := runGolden(t, vulns, tt.sw)
			want := cves(tt.version)
			slices.Sort(want)
			if !slices.Equal(o.version, want) {
				t.Errorf("version findings\n got %v\nwant %v", o.version, want)
			}
			want = cves(tt.product)
			slices.Sort(want)
			if !slices.Equal(o.product, want) {
				t.Errorf("product findings\n got %v\nwant %v", o.product, want)
			}
			if len(o.need) != tt.need {
				t.Errorf("add-the-version item: %d CVEs, want %d", len(o.need), tt.need)
			}
			for _, c := range o.product {
				if o.severity[c] != SeverityMedium {
					t.Errorf("%s: undecided version has severity %s, want medium", c, o.severity[c])
				}
			}
		})
	}
}

// TestGolden_NoVersionIsOneItemPerSoftware: kien's "Add pressed without version floods CVEs" (item 27).
func TestGolden_NoVersionIsOneItemPerSoftware(t *testing.T) {
	t.Parallel()
	vulns := goldenVulns(t)
	a := Asset{ID: "a", Name: "pc", Software: []Software{office(vulns, ""), iPhone(vulns, "0.0.0")}}
	res := MatchAsset(a, vulns, nil, t0)
	if len(res.New) != 0 || len(res.NeedVersion) != 2 {
		t.Fatalf("findings %d, items %d; want 0 and 2", len(res.New), len(res.NeedVersion))
	}
	if n := res.NeedVersion[0]; n.SoftwareID != "s-office" || len(n.CVEs) != 32 || n.Version != "" {
		t.Fatalf("office item = %+v", n)
	}
	if n := res.NeedVersion[1]; n.SoftwareID != "s-ios" || n.Version != "0.0.0" {
		t.Fatalf("placeholder version item = %+v", n)
	}
}
