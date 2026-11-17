package findings

import (
	"maps"
	"slices"
	"testing"
	"time"
)

// The unchecked list of #910 phase 1 (issue comments 6933401371, 6933429288): exploited CVEs of software the device has that gave
// no finding, no "add the version" item and no proof, one reason each.

var (
	uncNow = time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	uncOld = time.Date(2020, 3, 1, 0, 0, 0, 0, time.UTC) // published and added long before AgeLimit: a product match is aged (D-615)
	uncNew = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
)

func uncVuln(cve, vendor, product string, added time.Time, aff ...Affected) Vuln {
	return Vuln{CVE: cve, Vendor: vendor, Product: product, Name: vendor + " " + product + " flaw", DateAdded: added, Published: added, Affected: aff}
}

func uncAff(cpe, endExcl string) Affected {
	return Affected{CPE: cpe, Range: VersionRange{EndExcl: endExcl}}
}

func uncByCVE(us []Unchecked) map[string]Unchecked {
	out := map[string]Unchecked{}
	for _, u := range us {
		out[u.SoftwareID+" "+u.CVE] = u
	}
	return out
}

// One device, one case per reason, each one CVE.
func TestUnchecked_910_OneReasonEach(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "d", Name: "d", Software: []Software{
		// keyed "acme|widget", a version a scan read: a product match, which the age rule drops for an old CVE (D-615)
		{ID: "w", Display: "Acme Widget", Vendor: "Acme", Product: "Widget", Version: "2.0", Source: "scan", KevKeys: []string{"acme|widget"}},
		// keyed to CISA's "acme|engine", but the row is Acme Engine Pro, which NVD's list does not name
		{ID: "p", Display: "Acme Engine Pro", Vendor: "Acme", Product: "Engine Pro", Version: "5.0", Source: "scan", KevKeys: []string{"acme|engine"}},
		// no key: only NVD's list names it (#910 path)
		{ID: "g", Display: "Acme Gadget", Vendor: "Acme", Product: "Gadget", Version: "9.1", Source: "manual"},
		{ID: "h", Display: "Acme Hub", Vendor: "Acme", Product: "Hub", Version: "4.2", Source: "agent"},
	}}
	vulns := []Vuln{
		uncVuln("CVE-2020-0001", "Acme", "Widget", uncOld),                                                         // no NVD data, aged product match
		uncVuln("CVE-2020-0002", "Acme", "Widget", uncOld, Affected{CPE: "cpe:2.3:a:acme:widget:-:*:*:*:*:*:*:*"}), // no version
		uncVuln("CVE-2020-0003", "Acme", "Engine", uncOld, uncAff("cpe:2.3:a:acme:engine:*:*:*:*:*:*:*:*", "3.0")), // not named
		uncVuln("CVE-2026-0004", "Acme", "Gadget Core", uncNew, Affected{CPE: "cpe:2.3:a:acme:gadget:9.0:*:*:*:*:*:*:*"}),
		uncVuln("CVE-2026-0005", "Acme", "Hub Firmware", uncNew, Affected{CPE: "cpe:2.3:a:acme:hub:-:*:*:*:*:*:*:*"}, uncAff("cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*", "2.0")),
	}
	res := MatchAsset(a, vulns, nil, uncNow)
	if len(res.New) != 0 || len(res.NeedVersion) != 0 || len(res.Aged) != 3 {
		t.Fatalf("no finding and no item expected, three aged: %+v", res)
	}
	want := map[string]UncheckedReason{
		"w CVE-2020-0001": UncheckedNoNVDData,
		"w CVE-2020-0002": UncheckedNoNVDVersions,
		"p CVE-2020-0003": UncheckedNotNamed,
		"g CVE-2026-0004": UncheckedNotComparable, // NVD lists one exact version only (#913): no end to compare with
		"h CVE-2026-0005": UncheckedNoNVDVersions, // NVD names the row with no version
	}
	got := uncByCVE(res.Unchecked)
	if len(got) != len(want) {
		t.Fatalf("unchecked = %+v", res.Unchecked)
	}
	for k, r := range want {
		if got[k].Reason != r {
			t.Errorf("%s: reason %q, want %q (%+v)", k, got[k].Reason, r, res.Unchecked)
		}
	}
	if u := got["g CVE-2026-0004"]; u.Software != "Acme Gadget" || u.Version != "9.1" || u.Source != "manual" {
		t.Errorf("row = %+v", u)
	}
}

// Classic IOS states a version with no order (#919's NotComparable): listed as not comparable, with the OS row's id, unless the
// CVE has no NVD data (precedence).
func TestUnchecked_910_NetworkOSWithoutOrder(t *testing.T) {
	t.Parallel()
	a := snmpDevice("ios", "Cisco IOS 15.2(4)M3")
	vulns := []Vuln{
		uncVuln("CVE-2026-0010", "Cisco", "IOS", uncNew, uncAff("cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*", "15.9")),
		uncVuln("CVE-2026-0011", "Cisco", "IOS", uncNew),
	}
	res := MatchAsset(a, vulns, nil, uncNow)
	got := uncByCVE(res.Unchecked)
	os := osSoftwareID("ios")
	if len(got) != 2 || got[os+" CVE-2026-0010"].Reason != UncheckedNotComparable || got[os+" CVE-2026-0011"].Reason != UncheckedNoNVDData ||
		got[os+" CVE-2026-0010"].Version != "15.2(4)M3" || got[os+" CVE-2026-0010"].Source != "snmp" {
		t.Fatalf("unchecked = %+v", res.Unchecked)
	}
}

// Rule 1: a CVE that gives a finding or an "add the version" item on any row of the device is not in the list, even when another
// row could not check it; noise: an entry for software the device has no row keyed to or named by NVD is never listed.
func TestUnchecked_910_OnePlacePerDeviceAndCVE(t *testing.T) {
	t.Parallel()
	a := Asset{ID: "d", Name: "d", Software: []Software{
		{ID: "x", Display: "Acme Gadget X", Vendor: "Acme", Product: "Gadget", Version: "9.1", Source: "agent"},
		{ID: "k", Display: "Acme Gadget", Vendor: "Acme", Product: "Gadget", Version: "8.0", Source: "agent", KevKeys: []string{"acme|gadget"}},
		{ID: "n", Display: "Acme Gizmo", Vendor: "Acme", Product: "Gizmo", Source: "manual", KevKeys: []string{"acme|gizmo"}},
		{ID: "z", Display: "Acme Gizmo Tool", Vendor: "Acme", Product: "Gizmo", Version: "1.0", Source: "agent"},
	}}
	vulns := []Vuln{
		// row k matches by version (8.0 < 8.5); row x is listed by an exact version only: the finding wins
		uncVuln("CVE-2026-0020", "Acme", "Gadget", uncNew, uncAff("cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*", "8.5"), Affected{CPE: "cpe:2.3:a:acme:gadget:9.0:*:*:*:*:*:*:*"}),
		// row n has no version: "add the version"; row z only by NVD's exact version: the item wins
		uncVuln("CVE-2026-0021", "Acme", "Gizmo", uncNew, Affected{CPE: "cpe:2.3:a:acme:gizmo:0.9:*:*:*:*:*:*:*"}),
		// nothing on the device is keyed to or named by it
		uncVuln("CVE-2026-0022", "Other", "Thing", uncNew, uncAff("cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*", "2.0")),
		uncVuln("CVE-2026-0023", "Other", "Thing", uncNew),
	}
	res := MatchAsset(a, vulns, nil, uncNow)
	if len(res.New) != 1 || res.New[0].CVE != "CVE-2026-0020" || len(res.NeedVersion) != 1 || res.NeedVersion[0].CVEs[0] != "CVE-2026-0021" {
		t.Fatalf("matches = %+v", res)
	}
	if len(res.Unchecked) != 0 {
		t.Fatalf("unchecked = %+v", res.Unchecked)
	}
}

// Rule 3: add_version only for not_comparable on a row a person typed; rule 4: no software id for the OS a device states; rule 5:
// the advisory is the first KEV link; rule 6: devices by name, software by display, CVEs newest first; a CVE no longer on the list
// is left out.
func TestUnchecked_910_ItemsActionAndOrder(t *testing.T) {
	t.Parallel()
	row := func(asset, sw, display, ver, src string, r UncheckedReason, cve string) UncheckedRow {
		return UncheckedRow{AssetID: asset, Unchecked: Unchecked{CVE: cve, SoftwareID: sw, Software: display, Version: ver, Source: src, Reason: r}}
	}
	rows := []UncheckedRow{
		row("a2", "s1", "Zeta App", "1.0", "manual", UncheckedNotComparable, "CVE-2026-0001"),
		row("a2", "s1", "Zeta App", "1.0", "manual", UncheckedNotComparable, "CVE-2026-0003"),
		row("a2", "s1", "Zeta App", "1.0", "manual", UncheckedNotComparable, "CVE-2026-0002"),
		row("a2", "s2", "alpha tool", "", "manual", UncheckedNotNamed, "CVE-2026-0001"),
		row("a1", "os:a1", "Cisco IOS", "15.2(4)M3", "snmp", UncheckedNotComparable, "CVE-2026-0002"),
		row("a1", "s3", "Beta", "2", "agent", UncheckedNotComparable, "CVE-2026-0009"), // not on the list any more
	}
	kev := map[string]KevInfo{
		"CVE-2026-0001": {Name: "One", DateAdded: "2026-01-05", Links: []string{"https://vendor.example/a1", "https://nvd.example"}},
		"CVE-2026-0002": {Name: "Two", DateAdded: "2026-03-01", Ransomware: true},
		"CVE-2026-0003": {Name: "Three", DateAdded: "2026-02-01", Links: []string{"not a url"}},
	}
	assets := map[string]AssetView{"a1": {ID: "a1", Name: "Zulu"}, "a2": {ID: "a2", Name: "alpha"}}
	items := UncheckedItems(rows, kev, assets)
	type got struct {
		asset, sw, action string
		swID              bool
		cves              []string
	}
	var g []got
	for _, it := range items {
		x := got{asset: it.AssetID, sw: it.Software, action: it.Action, swID: it.SoftwareID != nil}
		for _, c := range it.CVEs {
			x.cves = append(x.cves, c.CVE)
		}
		g = append(g, x)
	}
	want := []got{
		{"a2", "alpha tool", "none", true, []string{"CVE-2026-0001"}},
		{"a2", "Zeta App", "add_version", true, []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0001"}},
		{"a1", "Cisco IOS", "none", false, []string{"CVE-2026-0002"}},
	}
	if !slices.EqualFunc(g, want, func(a, b got) bool {
		return a.asset == b.asset && a.sw == b.sw && a.action == b.action && a.swID == b.swID && slices.Equal(a.cves, b.cves)
	}) {
		t.Fatalf("items = %+v", g)
	}
	cves := items[1].CVEs
	if cves[2].Advisory == nil || *cves[2].Advisory != "https://vendor.example/a1" || cves[1].Advisory != nil || cves[0].Advisory != nil ||
		!cves[0].Ransomware || cves[0].Name != "Two" || cves[0].DateAdded != "2026-03-01" {
		t.Fatalf("cves = %+v", cves)
	}
	if items[0].Version != nil || items[1].Version == nil || *items[1].Version != "1.0" {
		t.Fatalf("versions = %+v", items)
	}
	if s := uncheckedCounts(items); s != (SummaryUnchecked{CVEs: 3, Devices: 2}) {
		t.Fatalf("counts = %+v", s)
	}
}

// Stored and served: the rows are written with the match, a finding the device has (here one the age rule closed) keeps its CVE
// out of the list, GET /findings answers the contract's shape, and Home counts the same list.
func TestUnchecked_910_StoredListAndHome(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	sw := Software{ID: "s-g", Display: "Acme Gadget", Vendor: "Acme", Product: "Gadget", Version: "9.1", Source: "manual"}
	w := Software{ID: "s-w", Display: "Acme Widget", Vendor: "Acme", Product: "Widget", Version: "2.0", Source: "scan", KevKeys: []string{"acme|widget"}}
	a := Asset{ID: "a-1", Name: "nas01", Software: []Software{sw, w}}
	e.inv.match["a-1"] = a
	*e.clock = uncNow.Add(-2 * AgeLimit) // the widget entry is recent then: a product finding
	recent := e.clock.Add(-24 * time.Hour)
	e.feeds.vulns = []Vuln{
		uncVuln("CVE-2026-0004", "Acme", "Gadget Core", uncNew, Affected{CPE: "cpe:2.3:a:acme:gadget:9.0:*:*:*:*:*:*:*"}),
		uncVuln("CVE-2024-0007", "Acme", "Widget", recent),
		uncVuln("CVE-2024-0008", "Acme", "Widget", recent),
	}
	maps.Copy(e.feeds.kev, map[string]KevInfo{
		"CVE-2026-0004": {Name: "Acme Gadget Core flaw", DateAdded: "2026-10-01", Links: []string{"https://acme.example/sa-4"}},
		"CVE-2024-0007": {Name: "Acme Widget flaw", DateAdded: recent.Format(time.DateOnly)},
		"CVE-2024-0008": {Name: "Acme Widget flaw 2", DateAdded: recent.Format(time.DateOnly)},
	})
	if _, err := e.svc.UpsertFromMatch(t.Context(), a, e.feeds.vulns[1:2]); err != nil { // 0007 becomes a product finding
		t.Fatal(err)
	}
	*e.clock = uncNow // now 0007 and 0008 are aged: 0007's finding is closed, 0008 never was one
	if _, err := e.svc.UpsertFromMatch(t.Context(), a, e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_unchecked WHERE asset_id = 'a-1'`); n != 3 {
		t.Fatalf("stored rows = %d", n)
	}
	code, b := e.call("GET", "/findings", "viewer", "")
	if code != 200 {
		t.Fatalf("GET /findings = %d %v", code, b)
	}
	items, _ := b["unchecked"].([]any)
	if len(items) != 2 {
		t.Fatalf("unchecked = %v", b["unchecked"])
	}
	keys := func(m map[string]any) []string { return slices.Sorted(maps.Keys(m)) }
	it := items[0].(map[string]any)
	if k := keys(it); !slices.Equal(k, []string{"action", "asset", "asset_id", "cves", "reason", "software", "software_id", "version"}) {
		t.Fatalf("item keys = %v", k)
	}
	if it["software"] != "Acme Gadget" || it["software_id"] != "s-g" || it["version"] != "9.1" || it["reason"] != "not_comparable" || it["action"] != "add_version" {
		t.Fatalf("item = %v", it)
	}
	c := it["cves"].([]any)[0].(map[string]any)
	if k := keys(c); !slices.Equal(k, []string{"advisory", "cve", "date_added", "name", "ransomware"}) {
		t.Fatalf("cve keys = %v", k)
	}
	if c["cve"] != "CVE-2026-0004" || c["advisory"] != "https://acme.example/sa-4" || c["date_added"] != "2026-10-01" {
		t.Fatalf("cve = %v", c)
	}
	w2 := items[1].(map[string]any)
	if w2["software"] != "Acme Widget" || w2["reason"] != "no_nvd_data" || w2["action"] != "none" || len(w2["cves"].([]any)) != 1 ||
		w2["cves"].([]any)[0].(map[string]any)["cve"] != "CVE-2024-0008" {
		t.Fatalf("aged widget item = %v (0007 has a finding: not listed)", w2)
	}
	_, s := e.call("GET", "/findings/summary", "viewer", "")
	if u := s["unchecked"].(map[string]any); u["cves"] != 2.0 || u["devices"] != 1.0 {
		t.Fatalf("home unchecked = %v", s["unchecked"])
	}
	if _, b = e.call("GET", "/findings?asset=other", "viewer", ""); len(b["unchecked"].([]any)) != 0 {
		t.Fatalf("filtered = %v", b["unchecked"])
	}
	if _, err := e.svc.OnAssetDeleted(t.Context(), "a-1"); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_unchecked`); n != 0 {
		t.Fatalf("rows left after delete = %d", n)
	}
}

// #919 r1: CISA keys CVE-2018-0171 "IOS and IOS XE" but NVD lists only classic cisco:ios; on an IOS XE device that states its
// (orderable) version it is not a finding but could not be checked: NVD names another product, so not_named, action none.
func TestUnchecked_910_NetworkOSNVDOtherProductIsNotNamed(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-snmp-os.json")
	res := MatchAsset(snmpDevice("xe", "Cisco IOS XE 17.3.1"), vulns, nil, uncNow)
	u, ok := uncByCVE(res.Unchecked)[osSoftwareID("xe")+" CVE-2018-0171"]
	if !ok || u.Reason != UncheckedNotNamed || u.Version != "17.3.1" || u.Source != "snmp" {
		t.Fatalf("unchecked = %+v", res.Unchecked)
	}
	for _, m := range res.New {
		if m.CVE == "CVE-2018-0171" {
			t.Fatalf("a finding as well: %+v", m)
		}
	}
}
