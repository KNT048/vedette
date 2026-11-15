package findings

import (
	"testing"
	"time"
)

// D-619 (customer walk 3 N53-1, n57): WINLAB01's agent reports Microsoft Edge 157.0.4341.46, the Chromium-based Edge. CISA's
// "Microsoft | Edge" entries CVE-2016-7200 and CVE-2016-7201 (Chakra, Edge Legacy's script engine; NVD's real rows in testdata: only
// cpe:2.3:a:microsoft:edge:-, published 10 November 2016) sat on that row as "suspected, cannot compare". They close as not affected
// with the reason; anything that leaves a doubt keeps the finding.
func TestMatchAsset_D619_EdgeLegacy(t *testing.T) {
	var e7200, e7201 Vuln
	for _, v := range loadGolden(t, "testdata/kev-nvd-winlab01-n55.json") {
		switch v.CVE {
		case "CVE-2016-7200":
			e7200 = v
		case "CVE-2016-7201":
			e7201 = v
		}
	}
	if e7200.CVE == "" || e7201.CVE == "" || len(e7200.Affected) != 1 || e7200.Affected[0].CPE != "cpe:2.3:a:microsoft:edge:-:*:*:*:*:*:*:*" {
		t.Fatalf("testdata: %+v %+v", e7200, e7201)
	}
	edge := func(ver string) Asset {
		a := winlab01()
		a.Software[len(a.Software)-1].Version = ver
		return a
	}
	says := []string{"Not affected: NVD lists CVE-2016-7200 only for Microsoft Edge Legacy", "published before Microsoft released the Chromium-based Edge in January 2020",
		"this device's Microsoft Edge 157.0.4341.46 is the Chromium-based Edge"}
	w, m := oneMatch(t, edge("157.0.4341.46"), e7200, true)
	wantMatch(t, "CVE-2016-7200 open on Chromium Edge", w, m, "notaffected", "", "", says...)
	if m.SoftwareDisplay != "Microsoft Edge" {
		t.Errorf("closed on %q", m.SoftwareDisplay)
	}
	if w, _ := oneMatch(t, edge("157.0.4341.46"), e7201, true); w != "notaffected" {
		t.Errorf("CVE-2016-7201: %s", w)
	}
	if w, _ := oneMatch(t, edge("157.0.4341.46"), e7200, false); w != "none" {
		t.Errorf("CVE-2016-7200 on a device without the finding: %s", w)
	}

	// Kept: what Edge it is, or what the CVE is about, is not certain.
	later := e7200
	later.CVE, later.Published = "CVE-2020-1195", time.Date(2020, time.May, 21, 0, 0, 0, 0, time.UTC)
	undated := e7200
	undated.CVE, undated.Published = "CVE-2019-0752", time.Time{}
	chromium := nvdRaw("CVE-2016-7200", "2022-03-28", "cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:*:*")
	chromium.Vendor, chromium.Product, chromium.Published = "Microsoft", "Edge", e7200.Published
	anyEdge := nvdRaw("CVE-2016-7200", "2022-03-28", "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*")
	anyEdge.Vendor, anyEdge.Product, anyEdge.Published = "Microsoft", "Edge", e7200.Published
	noNVD := e7200
	noNVD.Affected = nil
	for _, c := range []struct {
		name string
		a    Asset
		v    Vuln
	}{
		{"the EdgeHTML app's own version", edge("44.19041.1266.0"), e7200},
		{"a version that is not a Chromium build", edge("157"), e7200},
		{"published after Chromium Edge came out", edge("157.0.4341.46"), later},
		{"no published day and a 2019 id", edge("157.0.4341.46"), undated},
		{"an edge_chromium entry", edge("157.0.4341.46"), chromium},
		{"every Edge version", edge("157.0.4341.46"), anyEdge},
		{"no NVD data", edge("157.0.4341.46"), noNVD},
	} {
		if w, m := oneMatch(t, c.a, c.v, true); w != "existing" {
			t.Errorf("%s: %s %q", c.name, w, m.Evidence.Summary)
		}
	}
}

func TestEdgeLegacyEntry(t *testing.T) {
	for _, c := range []struct {
		cpe  string
		r    VersionRange
		want bool
	}{
		{"cpe:2.3:a:microsoft:edge:-:*:*:*:*:*:*:*", VersionRange{}, true},
		{"cpe:2.3:a:microsoft:edge:44.17763:*:*:*:*:*:*:*", VersionRange{}, true},
		{"cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*", VersionRange{EndExcl: "44.18362"}, true},
		{"cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*", VersionRange{}, false},
		{"cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*", VersionRange{EndExcl: "86.0.622.38"}, false},
		{"cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*", VersionRange{StartIncl: "80.0", EndExcl: "44.1"}, false},
		{"cpe:2.3:a:microsoft:edge:85.0.564.41:*:*:*:*:*:*:*", VersionRange{}, false},
		{"cpe:2.3:a:microsoft:edge:44*:*:*:*:*:*:*:*", VersionRange{}, false},
	} {
		cp, err := ParseCPE(c.cpe)
		if err != nil {
			t.Fatal(err)
		}
		if got := edgeLegacyEntry(cp, c.r); got != c.want {
			t.Errorf("%s %+v: %v", c.cpe, c.r, got)
		}
	}
}

// N53-1 (D-619): the finding page's Device panel names the software the finding's CVE is keyed to, not the device's first software by
// name (WINLAB01's Windows CVE showed "Microsoft Edge"). A device none of whose rows is keyed to the entry keeps inventory's display.
func TestFindingDetail_DeviceNamesTheMatchedSoftware(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	id := e.seed()
	a := nas("6.1.1")
	a.Software = append([]Software{{ID: "s-0", Display: "AAA Backup", Vendor: "AAA", Product: "Backup", Version: "1", KevKeys: []string{"aaa|backup"}}}, a.Software...)
	e.inv.mu.Lock()
	e.inv.match["a-1"] = a
	v := e.inv.assets["a-1"]
	v.Display = "AAA Backup" // inventory's display: the first software row by name
	e.inv.assets["a-1"] = v
	e.inv.mu.Unlock()
	_, b := e.call("GET", "/findings/"+id, "viewer", "")
	if got := b["asset"].(map[string]any)["display"]; got != "Photo Station" {
		t.Fatalf("device panel: %v", got)
	}
	e.inv.mu.Lock()
	e.inv.match["a-1"] = Asset{ID: "a-1", Name: "nas01", Software: a.Software[:1]}
	e.inv.mu.Unlock()
	if _, b := e.call("GET", "/findings/"+id, "viewer", ""); b["asset"].(map[string]any)["display"] != "AAA Backup" {
		t.Fatalf("no row keyed to the entry: %v", b["asset"])
	}
}
