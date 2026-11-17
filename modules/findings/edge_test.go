package findings

import (
	"slices"
	"strings"
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
	// D-602: kept means not closed as not affected; where only the product name matches (no version compared) it is under "Could not be
	// checked" instead of a finding (nameonly)
	for _, c := range []struct {
		name string
		a    Asset
		v    Vuln
		want string
	}{
		{"the EdgeHTML app's own version", edge("44.19041.1266.0"), e7200, "nameonly"},
		{"a version that is not a Chromium build", edge("157"), e7200, "nameonly"},
		{"published after Chromium Edge came out", edge("157.0.4341.46"), later, "nameonly"},
		{"no published day and a 2019 id", edge("157.0.4341.46"), undated, "nameonly"},
		{"an edge_chromium entry", edge("157.0.4341.46"), chromium, "existing"},
		{"every Edge version", edge("157.0.4341.46"), anyEdge, "existing"},
		{"no NVD data", edge("157.0.4341.46"), noNVD, "nameonly"},
	} {
		if w, m := oneMatch(t, c.a, c.v, true); w != c.want {
			t.Errorf("%s: %s %q", c.name, w, m.Evidence.Summary)
		}
	}
}

// Review r1 #1 of #807: Microsoft removed Edge Legacy only with April 2021's update and only from Windows 10 1803 and later, so an older
// Windows 10 keeps it, unpatched until its own monthly update, next to Chromium Edge. A Windows 10 client whose build carries no update
// after the CVE's month (or whose month is not known), or a device whose system is not known, keeps the finding; a Windows 10 build that
// carries a later month, a Mac, closes.
func TestMatchAsset_D619_EdgeLegacyBesideAnOldWindows10(t *testing.T) {
	var e7200 Vuln
	for _, v := range loadGolden(t, "testdata/kev-nvd-winlab01-n55.json") {
		if v.CVE == "CVE-2016-7200" {
			e7200 = v
		}
	}
	edge := Software{ID: "s-edge", Display: "Microsoft Edge", Vendor: "microsoft", Product: "edge", Version: "157.0.4341.46", Source: "agent", KevKeys: []string{"microsoft|edge"}}
	pc := func(ubr string) Asset {
		a := winPC(14393, false, ubr, "x64") // Windows 10 1607
		a.Software = append(a.Software, edge)
		return a
	}
	// A Windows CVE of December 2016 whose 1607 fix build is 14393.576: a build at or above it carries December 2016's update.
	dec := nvdRaw("CVE-2016-7259", "2022-03-03", "")
	dec.Affected = []Affected{{CPE: "cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*", Range: VersionRange{EndExcl: "10.0.14393.576"}}}
	dec.Published = time.Date(2016, time.December, 13, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		a    Asset
		want string
	}{
		{"Windows 10 1607 before November 2016's update (14393.321)", pc("321"), "nameonly"}, // D-602: kept, but not a finding
		{"Windows 10 1607 at December 2016's update (14393.576)", pc("576"), "notaffected"},
		{"only the OS name says Windows 10", Asset{ID: "a-pc", Name: "pc-01", OS: "Microsoft Windows 10 Pro", Software: []Software{edge}}, "nameonly"},
		{"no system known", Asset{ID: "a-pc", Name: "pc-01", Software: []Software{edge}}, "nameonly"},
		{"a Mac", Asset{ID: "a-mac", Name: "mac-01", OS: "macOS 15.1", Software: []Software{edge}}, "notaffected"},
	} {
		res := MatchAsset(c.a, []Vuln{e7200, dec}, map[string]bool{"CVE-2016-7200": true}, winNow)
		got := "none"
		switch {
		case slices.ContainsFunc(res.NotAffected, func(m Match) bool { return m.CVE == e7200.CVE }):
			got = "notaffected"
		case slices.ContainsFunc(res.Existing, func(m Match) bool { return m.CVE == e7200.CVE }):
			got = "existing"
		case slices.ContainsFunc(res.NameOnly, func(m Match) bool { return m.CVE == e7200.CVE }):
			got = "nameonly"
		}
		if got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	res := MatchAsset(pc("576"), []Vuln{e7200, dec}, map[string]bool{"CVE-2016-7200": true}, winNow)
	if len(res.NotAffected) != 1 || !strings.Contains(res.NotAffected[0].Evidence.Summary, "Its Windows 10 1607 build carries Microsoft's monthly update of December 2016") {
		t.Errorf("sentence: %+v", res.NotAffected)
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

// Review r1 #2 of #807: a "Multiple Products" entry is keyed to every row of its vendor, so the Device panel names the row the matcher
// matched through NVD's list (macOS), not the vendor's first row by name (Apple Safari).
func TestFindingDetail_MultipleProductsNamesTheMatchedRow(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	mac := Asset{ID: "a-1", Name: "mac-01", Software: []Software{
		{ID: "s-saf", Display: "Apple Safari", Vendor: "Apple", Product: "Safari", Version: "18.1", Source: "agent", KevKeys: []string{"apple|safari"}},
		{ID: "s-os", Display: "macOS", Vendor: "Apple", Product: "macOS", Version: "14.0", Source: "agent", KevKeys: []string{"apple|macos"}},
	}}
	const cve = "CVE-2023-41993"
	e.inv.mu.Lock()
	e.inv.match["a-1"] = mac
	e.inv.mu.Unlock()
	e.feeds.vulns = []Vuln{{CVE: cve, Vendor: "Apple", Product: "Multiple Products", Affected: []Affected{{CPE: "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "14.1"}}}}}
	e.feeds.kev[cve] = KevInfo{Name: "Apple Multiple Products WebKit", Vendor: "Apple", Product: "Multiple Products", RequiredAction: "Apply updates."}
	res, err := e.svc.OnMatchChanged(t.Context(), "a-1")
	if err != nil || len(res.Created) != 1 {
		t.Fatalf("seed: %+v %v", res, err)
	}
	_, b := e.call("GET", "/findings/"+res.Created[0], "viewer", "")
	if got := b["asset"].(map[string]any)["display"]; got != "macOS" {
		t.Fatalf("device panel: %v", got)
	}
}
