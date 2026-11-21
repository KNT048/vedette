package findings

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
)

// fixDevice is one device of the fix count: the golden lists' products at versions that the lists' ranges reach.
type fixDevice struct {
	a     Asset
	vulns []Vuln
}

func fixDevices(t *testing.T) []fixDevice {
	t.Helper()
	golden := goldenVulns(t)
	win := loadGolden(t, "testdata/kev-nvd-winlab01-n55.json")
	var out []fixDevice
	for i, sw := range []Software{
		fortiGate(golden, "6.0.2"), fortiGate(golden, "7.0.12"), fortiGate(golden, "7.2.5"), fortiGate(golden, "7.4.1"),
		iPhone(golden, "16.5"), iPhone(golden, "17.4"), office(golden, "16.0.10398.20008"), netScaler(golden, "13.1-49.13"),
		netScaler(golden, "14.1-12.30"),
	} {
		out = append(out, fixDevice{Asset{ID: "a" + string(rune('0'+i)), Name: "dev", Software: []Software{sw}}, golden})
	}
	out = append(out, fixDevice{Asset{ID: "ubuntu", Name: "byn", OS: "Ubuntu 26.04.1 LTS", AgentOS: "Ubuntu 26.04.1 LTS", Software: ubuntuServer()}, golden},
		fixDevice{winlab01(), win}, fixDevice{esxiHost("8.0", "22380479"), []Vuln{esxi22225(t)}})
	return out
}

// esxi22225 is CVE-2025-22225 as the catalogue holds it: NVD lists exact ESXi versions (no fix), VMware states the fixed build of
// each release train in its notation (8.0 U3d, 8.0 U2d, 7.0 U3s).
func esxi22225(t testing.TB) Vuln {
	t.Helper()
	s, ok := versionscheme.Lookup("vmware-esxi")
	if !ok {
		t.Fatal("no ESXi version scheme")
	}
	v := Vuln{CVE: "CVE-2025-22225", Vendor: "VMware", Product: "ESXi", NVDAnswered: true, Origin: RangeNVD,
		Affected: []Affected{{CPE: "cpe:2.3:o:vmware:esxi:8.0:update_2:*:*:*:*:*:*"}, {CPE: "cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*"}}}
	for _, end := range []string{"ESXi80U3d-24585383", "ESXi80U2d-24585300", "ESXi70U3s-24585291"} {
		start := "8.0"
		if strings.HasPrefix(end, "ESXi70") {
			start = "7.0"
		}
		sp, ok := s.Span(start, end, "")
		if !ok {
			t.Fatalf("span %s", end)
		}
		v.Schemed = append(v.Schemed, SchemedRange{Product: productid.Key("VMware", "ESXi"), Scheme: s, Span: sp, Origin: RangeCNA})
	}
	return v
}

func esxiHost(version, build string) Asset {
	stated := "VMware ESXi " + version + " (build " + build + ")" // the line keeps the build the host states (sensor-active)
	return Asset{ID: "esxi", Name: "esx01", OS: stated, Software: []Software{{ID: "s-esxi",
		Display: stated, Vendor: "VMware", Product: "ESXi", Version: version, Source: "snmp", KevKeys: []string{"vmware|esxi"},
		CPE: "cpe:2.3:o:vmware:esxi:8.0:update_2:*:*:*:*:*:*"}}} // the CPE the host's own statement is given (its build's update)
}

// fixPaths is the fixed version each reader of the fix names for one finding: the stored fix (FixOf, written by the match pass), the
// finding page (FixedInFor) and the list row, To fix and the assistant (RowFixes). "" when a reader names none.
type fixPaths struct{ stored, page, row string }

func pathsOf(a Asset, vulns []Vuln) map[string]fixPaths {
	res := MatchAsset(a, vulns, nil, t0)
	byCVE := map[string]Vuln{}
	for _, v := range vulns {
		byCVE[v.CVE] = v
	}
	var mine []Vuln
	for _, m := range res.New {
		mine = append(mine, byCVE[m.CVE])
	}
	rows := RowFixes(a, mine)
	lines := deviceLines(a)
	out := map[string]fixPaths{}
	for _, m := range res.New {
		for _, x := range append([]Match{m}, m.Lines...) {
			l, ok := lines[storedLine(x.SoftwareID)]
			if !ok {
				continue
			}
			var p fixPaths
			p.stored = FixOf(a, l.sw, byCVE[x.CVE]).Version
			if f := FixedInFor(a, byCVE[x.CVE]); f != nil {
				switch {
				case f.DistroFixed != "":
					p.page = f.DistroFixed
				case f.Kind == "fixed" || f.Kind == "esu" || f.Kind == "feature_update":
					p.page = f.Fixed
				}
			}
			if r := rows[x.CVE]; r != nil {
				p.row = r.Fixed
			}
			out[x.CVE+"|"+x.SoftwareID] = p
		}
	}
	return out
}

// The count of the class "one finding, several fixed versions": findings whose fixed version differs between two of the paths that
// name one. Before the match pass stored the fix, the stored fix was unknown for every finding, so every finding a reader named a fix
// for differed from it (storedUnknown), and the ESXi host on 8.0 Update 2 had no fix on any surface while the CVE brief named
// VMware's per-train builds. The stored fix now agrees with the finding page on every finding but the ESXi one, where it is VMware's
// fixed build of the host's train (the page reads NVD's exact versions only). The list row's grouped release (one release for every
// CVE of the software) still differs where a later CVE of the same software needs a later release: the page and the list move to the
// stored fix with the view of the finding.
func TestFixCount_FindingsWithTwoFixedVersions(t *testing.T) {
	t.Parallel()
	var findings, storedUnknown, storedVsPage, pageVsRow int
	for _, d := range fixDevices(t) {
		for k, p := range pathsOf(d.a, d.vulns) {
			findings++
			if p.page != "" || p.row != "" {
				storedUnknown++
			}
			if p.stored != p.page {
				storedVsPage++
				t.Logf("stored %q, page %q: %s on %s", p.stored, p.page, k, d.a.ID)
			}
			if d.a.ID == "esxi" && p.stored != "8.0 U2d (build 24585300)" {
				t.Errorf("ESXi 8.0 Update 2: stored fix %q, want VMware's fixed build of its train", p.stored)
			}
			if p.page != "" && p.row != "" && p.page != p.row {
				pageVsRow++
			}
		}
	}
	t.Logf("findings %d; differing with the stored fix unknown (before): %d; stored vs page: %d; page vs list row: %d",
		findings, storedUnknown, storedVsPage, pageVsRow)
	if findings == 0 || storedUnknown == 0 {
		t.Fatal("the fixture makes no finding with a fix")
	}
	if storedVsPage != 1 { // the ESXi finding: the page reads NVD's exact versions only, the stored fix is VMware's train fix
		t.Errorf("%d findings store another fix than the finding page names, want only the ESXi one", storedVsPage)
	}
}
