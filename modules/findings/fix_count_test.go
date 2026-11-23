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

// fixPaths is the fixed version each reader of the fix names for one finding: the stored fix (FixOf, written by the match pass, which
// every list, Home, the report and the assistant read) and the finding page (FixedInFor). "" when a reader names none. The third
// path, the older list row's grouped release (RowFixes: GET /findings, To fix, the assistant before it read By device), is gone.
type fixPaths struct{ stored, page string }

func pathsOf(a Asset, vulns []Vuln) map[string]fixPaths {
	res := MatchAsset(a, vulns, nil, t0)
	byCVE := map[string]Vuln{}
	for _, v := range vulns {
		byCVE[v.CVE] = v
	}
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
			out[x.CVE+"|"+x.SoftwareID] = p
		}
	}
	return out
}

// The count of the class "one finding, several fixed versions": findings whose fixed version differs between two of the paths that
// name one. Before the match pass stored the fix, the stored fix was unknown for every finding, so every finding a reader named a fix
// for differed from it (storedUnknown), and the ESXi host on 8.0 Update 2 had no fix on any surface while the CVE brief named
// VMware's per-train builds. The stored fix now agrees with the finding page on every finding but the ESXi one, where it is VMware's
// fixed build of the host's train (the page reads NVD's exact versions only). The older list row's grouped release (one release for
// every CVE of the software), which differed from the page on 84 findings of this fixture, is removed with GET /findings' fix field.
func TestFixCount_FindingsWithTwoFixedVersions(t *testing.T) {
	t.Parallel()
	var findings, storedUnknown, storedVsPage int
	for _, d := range fixDevices(t) {
		for k, p := range pathsOf(d.a, d.vulns) {
			findings++
			if p.page != "" {
				storedUnknown++
			}
			if p.stored != p.page {
				storedVsPage++
				t.Logf("stored %q, page %q: %s on %s", p.stored, p.page, k, d.a.ID)
			}
			if d.a.ID == "esxi" && p.stored != "8.0 U2d (build 24585300)" {
				t.Errorf("ESXi 8.0 Update 2: stored fix %q, want VMware's fixed build of its train", p.stored)
			}
		}
	}
	t.Logf("findings %d; differing with the stored fix unknown (before): %d; stored vs page: %d", findings, storedUnknown, storedVsPage)
	if findings == 0 || storedUnknown == 0 {
		t.Fatal("the fixture makes no finding with a fix")
	}
	if storedVsPage != 1 { // the ESXi finding: the page reads NVD's exact versions only, the stored fix is VMware's train fix
		t.Errorf("%d findings store another fix than the finding page names, want only the ESXi one", storedVsPage)
	}
}

// The count of the same class through the new endpoints: the fixture's findings stored by the match pass, then read as By device and
// the finding's view (GET /findings/{id}/view) read them. Both name the stored fix, so the view and a list row agree by construction;
// what this measures is that every combined block names a release that reaches each of its findings' own fix, and that the lists
// count every open finding once. The finding page (GET /findings/{id}) still names FixedInFor's release beside the stored fix
// (TestFixCount_FindingsWithTwoFixedVersions: one finding of this fixture, the ESXi one, differs).
func TestFixCount_ListAndPageReadTheStoredFix(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.inv.mu.Lock()
	e.inv.assets, e.inv.match = map[string]AssetView{}, map[string]Asset{}
	devices := fixDevices(t)
	for _, d := range devices {
		e.inv.match[d.a.ID] = d.a
		e.inv.assets[d.a.ID] = AssetView{ID: d.a.ID, Name: d.a.Name + "-" + d.a.ID, IP: NoIP, Kind: "server", Approved: true}
	}
	e.inv.mu.Unlock()
	for _, d := range devices {
		if _, err := e.svc.UpsertFromMatch(ctx, d.a, d.vulns); err != nil {
			t.Fatal(err)
		}
	}
	var open, keys, cards, byDevice, byFix, rows, pageVsRow, blockShort int
	if err := e.db.Reader().QueryRowContext(ctx, `SELECT count(*), count(DISTINCT fix_key) FROM fnd_finding WHERE state = 'open'`).Scan(&open, &keys); err != nil {
		t.Fatal(err)
	}
	for off := 0; ; off += PageMax {
		cards, err := e.svc.ByDevice(ctx, ListFilter{}, Page{Offset: off, Limit: PageMax})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cards.Items {
			byDevice += c.Findings
			for _, b := range c.Blocks {
				for _, r := range b.Findings {
					rows++
					v, err := e.svc.View(ctx, r.ID)
					if err != nil {
						t.Fatal(err)
					}
					stored, page := v.Finding.Fix, v.JSON().Fix
					if page.Key != v.Finding.FixKey || page.Kind != string(stored.Kind) || ptrOr(page.Version) != stored.Version {
						pageVsRow++
					}
					if bv := ptrOr(b.Fix.Version); b.Fix.Key != v.Finding.FixKey {
						if c, ok := compareFix(stored.Kind, stored.Version, bv); !ok || c > 0 {
							blockShort++
							t.Logf("block %q does not reach %s's own fix %q", bv, r.CVE, stored.Version)
						}
					}
				}
			}
		}
		if off+PageMax >= cards.Total {
			break
		}
	}
	for off := 0; ; off += PageMax {
		fixes, err := e.svc.ByFix(ctx, ListFilter{}, Page{Offset: off, Limit: PageMax})
		if err != nil {
			t.Fatal(err)
		}
		cards = fixes.Total
		for _, c := range fixes.Items {
			byFix += c.Findings
		}
		if off+PageMax >= fixes.Total {
			break
		}
	}
	t.Logf("open %d; by device %d; by fix %d; rows read %d; view vs stored fix: %d; blocks short of a finding's fix: %d; By fix cards %d for %d stored fix keys",
		open, byDevice, byFix, rows, pageVsRow, blockShort, cards, keys)
	if open == 0 || open != byDevice || open != byFix || rows != open {
		t.Errorf("open %d, by device %d, by fix %d, rows %d: want all equal", open, byDevice, byFix, rows)
	}
	if pageVsRow != 0 || blockShort != 0 {
		t.Errorf("list row vs page %d, blocks short %d: want 0", pageVsRow, blockShort)
	}
}

func ptrOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
