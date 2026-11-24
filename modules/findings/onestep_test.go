package findings

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/productid"
)

// oneStepWorld is a network where each CVE of a device names a different fixed release of the device's own train, the way VMware writes
// them: two ESXi hosts on 8.0 Update 3 (the same machine seen twice, as a scan and an API reading often do) with CVEs fixed in 8.0 U3d,
// U3i, U3j, U3k and in the security patch 8.0 U3se (build 24659227, a build the build table does not list), and a Junos switch on 15.1
// whose two CVEs are fixed in releases of two lines where neither is known to fix the other's CVE: Juniper's rows of the first name no
// release of 23.2 at all.
func oneStepWorld(t *testing.T) *env {
	t.Helper()
	esxiKey, junosKey := productid.Key("VMware", "ESXi"), productid.Key("Juniper", "Junos OS")
	esxi := func(cve string, ends ...string) Vuln {
		var spans [][3]string
		for _, e := range ends {
			spans = append(spans, [3]string{"8.0", e, ""})
		}
		return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeCNA, Schemed: schemedRows(t, "vmware-esxi", esxiKey, spans...)}
	}
	junos := func(cve string, spans ...[3]string) Vuln {
		return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeCNA, RangesFrom: RangesCVEOrg, Schemed: schemedRows(t, "juniper-junos", junosKey, spans...)}
	}
	e := newEnv(t)
	e.feeds.vulns = []Vuln{
		esxi("CVE-2026-93001", "ESXi80U3d-24585383", "ESXi80U2d-24585300"),
		esxi("CVE-2026-93002", "ESXi80U3j-25429389"),
		esxi("CVE-2026-93003", "ESXi80U3se-24659227", "ESXi80U2e-24789317"),
		esxi("CVE-2026-93004", "ESXi80U3i-25205845"),
		esxi("CVE-2026-93005", "ESXi80U3k-25595708"),
		junos("CVE-2026-94001", [3]string{"0", "19.1R3-S9", ""}, [3]string{"19.2", "19.2R3-S7", ""}),
		junos("CVE-2026-94002", [3]string{"0", "23.2R2-S7.7", ""}),
	}
	jx := Asset{ID: "jx-1", Name: "jx-1", Model: "EX4200-48T", Software: []Software{{ID: "s-jx-1", Display: "Juniper Junos OS", Vendor: "Juniper",
		Product: "Junos OS", Version: "15.1R7.9", Source: "snmp"}}}
	devices := []Asset{esxiStated("esx-a", "8.0", "update_3", "24022510"), esxiStated("esx-b", "8.0", "update_3", "24022510"), jx}
	e.inv.assets = map[string]AssetView{}
	e.inv.match = map[string]Asset{}
	for i, a := range devices {
		e.inv.assets[a.ID] = AssetView{ID: a.ID, Hostname: ptr(a.ID), IP: fmt.Sprintf("192.0.2.%d", 60+i), Kind: "server", Approved: true}
		e.inv.match[a.ID] = a
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	return e
}

// coversAll reports whether release x of line sw on device a clears every CVE of findings fs on that line, judged CVE by CVE the way the
// matcher reads the vendor's rows (rangeParts), never by ordering the findings' own stored fixes: the oracle of the count below.
func coversAll(e *env, a Asset, sw Software, fs []Finding, x string) bool {
	byCVE := map[string]Vuln{}
	for _, v := range e.feeds.vulns {
		byCVE[v.CVE] = v
	}
	for _, f := range fs {
		if f.Fix.Version == x {
			continue
		}
		p := rangeParts(a, sw, byCVE[f.CVE])
		if p == nil {
			if c, ok := compareFix(f.Fix.Kind, productPart(f), x, f.Fix.Version); !ok || c < 0 {
				return false
			}
			continue
		}
		if !p.outside(x) {
			return false
		}
	}
	return true
}

// Class count: device lines that By fix splits into more than one update step although one of those steps' releases clears every CVE
// of the line, so the reader is told to install several releases where one does. Before a release name with a two-letter patch
// ("8.0 U3se (build 24659227)") was read back by its scheme: 2 of 3 lines (esx-a and esx-b, 5 steps each). After: 0 of 3; the Junos
// line keeps two steps, as no single release is known to fix both of its CVEs, and each step says so.
func TestOneStep_Count_LinesSplitWhereOneReleaseCoversAll(t *testing.T) {
	t.Parallel()
	e := oneStepWorld(t)
	fx, err := e.svc.ByFix(t.Context(), ListFilter{}, Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	type line struct{ asset, software string }
	steps := map[line][]string{}
	for _, c := range fx.Items {
		if c.Fix.Kind != string(FixUpdate) || c.Fix.Version == nil {
			continue
		}
		for _, d := range c.Items {
			if d.Software != nil {
				l := line{d.Device.ID, d.Software.ID}
				steps[l] = append(steps[l], *c.Fix.Version)
			}
		}
	}
	split, covered := 0, 0
	for l, vs := range steps {
		if len(vs) < 2 {
			continue
		}
		split++
		a := e.inv.match[l.asset]
		fs, err := e.svc.Findings(t.Context(), l.asset)
		if err != nil {
			t.Fatal(err)
		}
		fs = slices.DeleteFunc(fs, func(f Finding) bool { return !f.Open() || f.SoftwareID != l.software })
		for _, sw := range deviceSoftware(a) {
			if sw.ID != l.software {
				continue
			}
			if i := slices.IndexFunc(vs, func(x string) bool { return coversAll(e, a, sw, fs, x) }); i >= 0 {
				covered++
				t.Logf("%s: %d steps %v, %s alone clears all %d CVEs", l.asset, len(vs), vs, vs[i], len(fs))
			}
		}
	}
	t.Logf("lines split into several update steps where one release covers all: %d of %d lines (%d split)", covered, len(steps), split)
	if covered != 0 {
		t.Errorf("%d lines are split into several steps where one release clears every CVE", covered)
	}
	if len(steps) != 3 {
		t.Errorf("lines with an update step: %d, want 3 (esx-a, esx-b, jx-1)", len(steps))
	}
}

// The ESXi hosts get one step, the newest release of the train (U3k), with the counts of every CVE; the finding page keeps each CVE's
// own fixed release; the Junos switch keeps two steps, each naming the other on the device's row.
func TestOneStep_OneReleasePerTrainAndTheSplitSaysSo(t *testing.T) {
	t.Parallel()
	e := oneStepWorld(t)
	fx, err := e.svc.ByFix(t.Context(), ListFilter{}, Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	var titles []string
	sum := 0
	for _, c := range fx.Items {
		titles = append(titles, c.Fix.Product+" "+ptrOr(c.Fix.Version))
		sum += c.Findings
	}
	slices.Sort(titles)
	want := []string{"Juniper Junos OS 19.1R3-S9", "Juniper Junos OS 23.2R2-S7.7", "VMware ESXi 8.0 U3k (build 25595708)"}
	if !slices.Equal(titles, want) {
		t.Errorf("By fix steps %v, want %v", titles, want)
	}
	if sum != fx.Findings || fx.Findings != 12 {
		t.Errorf("By fix counts %d findings in its steps, %d in all, want 12 (5 + 5 + 2)", sum, fx.Findings)
	}
	for _, c := range fx.Items {
		for _, d := range c.Items {
			var others []string
			for _, o := range d.Others {
				others = append(others, ptrOr(o.Version))
			}
			switch {
			case c.Fix.Product == "VMware ESXi" && len(others) != 0:
				t.Errorf("%s on %s names other steps %v", ptrOr(c.Fix.Version), d.Device.Name, others)
			case ptrOr(c.Fix.Version) == "19.1R3-S9" && !slices.Equal(others, []string{"23.2R2-S7.7"}),
				ptrOr(c.Fix.Version) == "23.2R2-S7.7" && !slices.Equal(others, []string{"19.1R3-S9"}):
				t.Errorf("%s on %s: other steps %v", ptrOr(c.Fix.Version), d.Device.Name, others)
			}
		}
	}
	fs, err := e.svc.Findings(t.Context(), "esx-a")
	if err != nil {
		t.Fatal(err)
	}
	own := map[string]string{}
	for _, f := range fs {
		own[f.CVE] = f.Fix.Version
	}
	if !strings.HasPrefix(own["CVE-2026-93003"], "8.0 U3se") || !strings.HasPrefix(own["CVE-2026-93001"], "8.0 U3d") {
		t.Errorf("each finding keeps its own fixed release: %v", own)
	}
}

// A fix version no order reads stays its own block; the line's other fixes still combine into one, instead of every group becoming its
// own block because one of them does not compare.
func TestCombine_AnUnreadableVersionLeavesTheOthersCombined(t *testing.T) {
	t.Parallel()
	g := func(kind FixKind, v string) lineGroup {
		fx := Fix{Kind: kind, Version: v}
		return lineGroup{Asset: "d", Software: "s", Product: "acme|widget", Key: FixKey("acme|widget", fx), Fix: fx, All: 1, N: 1}
	}
	for _, kind := range []FixKind{FixUpdate, FixFeatureUpdate} {
		gs := []lineGroup{g(kind, "2.4.1"), g(kind, "next build"), g(kind, "2.6.0"), g(kind, "2.5.3")}
		combine(gs, nil)
		got := map[string]string{}
		for _, x := range gs {
			got[x.Fix.Version] = x.BlockFix.Version
		}
		want := map[string]string{"2.4.1": "2.6.0", "2.5.3": "2.6.0", "2.6.0": "2.6.0", "next build": "next build"}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: blocks %v, want %v", kind, got, want)
		}
	}
}
