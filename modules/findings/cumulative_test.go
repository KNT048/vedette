package findings

import (
	"fmt"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/productid"
)

// cumulativeWorld is a network whose vendors state their fixes per release train, the way VMware and Synology do: each CVE of a device
// is fixed in another patch release of the device's own train (ESXi 8.0 Update 3d, 3i, 3j, 3k; DSM 7.2.1-69057 Update 6, 10, 12, 13),
// and each later release of a train carries the fixes of the earlier ones. A second ESXi host runs Update 2: two of its CVEs are fixed in
// its own train (U2d, U2e), the other three only in Update 3, so only an Update 3 release clears them all.
func cumulativeWorld(t *testing.T) *env {
	t.Helper()
	esxiKey, dsmKey := productid.Key("VMware", "ESXi"), productid.Key("Synology", "DiskStation Manager")
	esxi := func(cve string, ends ...string) Vuln {
		var spans [][3]string
		for _, e := range ends {
			spans = append(spans, [3]string{"8.0", e, ""})
		}
		return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeCNA, Schemed: schemedRows(t, "vmware-esxi", esxiKey, spans...)}
	}
	dsm := func(cve, end string) Vuln {
		return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeCNA, Schemed: schemedRows(t, "synology-dsm", dsmKey, [3]string{"7.2.1", end, ""})}
	}
	e := newEnv(t)
	e.feeds.vulns = []Vuln{
		esxi("CVE-2026-91001", "ESXi80U3d-24585383", "ESXi80U2d-24585300"),
		esxi("CVE-2026-91002", "ESXi80U3d-24585383", "ESXi80U2e-24789317"),
		esxi("CVE-2026-91003", "ESXi80U3j-25429389"),
		esxi("CVE-2026-91004", "ESXi80U3i-25205845"),
		esxi("CVE-2026-91005", "ESXi80U3k-25595708"),
		dsm("CVE-2026-92001", "7.2.1-69057-6"),
		dsm("CVE-2026-92002", "7.2.1-69057-10"),
		dsm("CVE-2026-92003", "7.2.1-69057-12"),
		dsm("CVE-2026-92004", "7.2.1-69057-12"),
		dsm("CVE-2026-92005", "7.2.1-69057-13"),
	}
	nas := Asset{ID: "nas-01", Name: "nas-01", Software: []Software{{ID: "s-nas", Display: "Synology DiskStation Manager", Vendor: "Synology",
		Product: "DiskStation Manager", Version: "7.2.1-69057-5", Source: "manual"}}}
	devices := []Asset{esxiStated("esx-u3", "8.0", "update_3", "24022510"), esxiStated("esx-u2", "8.0", "update_2", "22380479"), nas}
	e.inv.assets = map[string]AssetView{}
	e.inv.match = map[string]Asset{}
	for i, a := range devices {
		e.inv.assets[a.ID] = AssetView{ID: a.ID, Hostname: ptr(a.ID), IP: fmt.Sprintf("192.0.2.%d", 30+i), Kind: "server", Approved: true}
		e.inv.match[a.ID] = a
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	return e
}

// Class count: device lines that By device shows with more than one update block for one product, so the reader cannot tell which
// single release to install. Before releases in a vendor's notation were ordered by their scheme: 3 of 3 lines, 13 blocks (esx-u3
// U3d U3i U3j U3k; esx-u2 U2d U2e U3i U3j U3k; nas-01 Update 6 10 12 13). After: 0 of 3, one block each.
func TestCumulativeTarget_Count_LinesWithSeveralUpdatesOfOneProduct(t *testing.T) {
	t.Parallel()
	e := cumulativeWorld(t)
	cards, err := e.svc.ByDevice(t.Context(), ListFilter{}, Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	lines, split := 0, 0
	for _, c := range cards.Items {
		per := map[string][]string{}
		for _, b := range c.Blocks {
			if b.Fix.Kind == string(FixUpdate) && b.Software != nil {
				per[b.Software.ID] = append(per[b.Software.ID], ptrOr(b.Fix.Version))
			}
		}
		for line, vs := range per {
			lines++
			if len(vs) > 1 {
				split++
				t.Logf("%s %s: %d update blocks %v", c.Device.Name, line, len(vs), vs)
			}
		}
	}
	t.Logf("lines with more than one update of one product: %d of %d", split, lines)
	if split != 0 {
		t.Errorf("%d of %d lines list more than one update of one product", split, lines)
	}
}

// The block names the newest release of the train, which carries every fix of the earlier ones; a host on another train keeps the
// releases of its own train, and By fix, the report's listed fixes and the handling of the block agree.
func TestCumulativeTarget_NewestReleaseOfTheTrain(t *testing.T) {
	t.Parallel()
	e := cumulativeWorld(t)
	got := map[string][]string{}
	for _, b := range listedBlocks(t, e) {
		got[b.asset] = append(got[b.asset], fmt.Sprintf("%s:%d", b.version, len(b.cves)))
	}
	want := map[string][]string{
		"esx-u3": {"8.0 U3k (build 25595708):5"},
		"esx-u2": {"8.0 U3k (build 25595708):5"}, // Update 2's own fixes (U2d, U2e) leave the CVEs only Update 3 fixes open
		"nas-01": {"7.2.1-69057 Update 13:5"},
	}
	for id, w := range want {
		g := got[id]
		slices.Sort(g)
		if !slices.Equal(g, w) {
			t.Errorf("%s: blocks %v, want %v", id, g, w)
		}
	}
	fx, err := e.svc.ByFix(t.Context(), ListFilter{}, Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	if fx.Total != 2 {
		var names []string
		for _, c := range fx.Items {
			names = append(names, ptrOr(c.Fix.Version))
		}
		t.Errorf("By fix: %d cards %v, want 2", fx.Total, names)
	}
	ids, err := e.svc.FixFindings(t.Context(), "nas-01", "s-nas", FixKey(productid.Key("Synology", "DiskStation Manager"),
		Fix{Kind: FixUpdate, Version: "7.2.1-69057 Update 13"}))
	if err != nil || len(ids) != 5 {
		t.Errorf("FixFindings of nas-01's block: %d ids, %v", len(ids), err)
	}
}
