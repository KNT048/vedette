package findings

import (
	"maps"
	"slices"
	"testing"
)

// The KEV reachability audit (#910 phase 1): one entry per class, through the matcher's own predicates. cmd/vedette's
// TestReachability_910_Fixture runs it over the real list with the real maps.
func TestReachability_910_Classes(t *testing.T) {
	t.Parallel()
	chrome := Software{ID: "s", Display: "Chrome", Vendor: "Google", Product: "Chrome", KevKeys: []string{"google|chrome"}, Source: "agent"}
	aff := func(cpe, end string) Affected { return Affected{CPE: cpe, Range: VersionRange{EndExcl: end}} }
	vulns := []Vuln{
		{CVE: "CVE-2026-0001", Vendor: "Acme", Product: "Widget"}, // no NVD entry
		{CVE: "CVE-2026-0002", Vendor: "Acme", Product: "Widget", Affected: []Affected{aff("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "")}},
		{CVE: "CVE-2026-0003", Vendor: "Google", Product: "Chrome", Affected: []Affected{aff("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "120.0")}},
		{CVE: "CVE-2026-0004", Vendor: "Google", Product: "Chrome", Affected: []Affected{aff("cpe:2.3:a:acme:other:*:*:*:*:*:*:*:*", "2.0")}},
		{CVE: "CVE-2026-0005", Vendor: "Google", Product: "Chromium V8", Affected: []Affected{aff("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "120.0")}},
		{CVE: "CVE-2026-0006", Vendor: "Acme", Product: "Gadget", Affected: []Affected{aff("cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*", "2.0")}},
		{CVE: "CVE-2026-0007", Vendor: "Google", Product: "Multiple Products", Affected: []Affected{aff("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "120.0")}},
		{CVE: "CVE-2026-0008", Vendor: "Google", Product: "Multiple Products", Affected: []Affected{aff("cpe:2.3:a:google:android:*:*:*:*:*:*:*:*", "15.0")}},
		// an exact version is not a range that ends: viaNVD does not read it (review r1 H1 of #913)
		{CVE: "CVE-2026-0009", Vendor: "Google", Product: "Skia", Affected: []Affected{{CPE: "cpe:2.3:a:google:chrome:117.0:*:*:*:*:*:*:*"}}},
		{CVE: "CVE-2026-0003", Vendor: "Google", Product: "Chrome"}, // a CVE twice: the first counts
	}
	want := map[string]ReachClass{"CVE-2026-0001": ReachNoNVDData, "CVE-2026-0002": ReachNoNVDVersions, "CVE-2026-0003": ReachKeyedVersion,
		"CVE-2026-0004": ReachKeyedOnly, "CVE-2026-0005": ReachViaNVD, "CVE-2026-0006": ReachNone, "CVE-2026-0007": ReachKeyedVersion,
		"CVE-2026-0008": ReachKeyedOnly, "CVE-2026-0009": ReachNone}
	r := Reachability(vulns, []Software{chrome})
	if r.Total != len(want) {
		t.Fatalf("total = %d, want %d", r.Total, len(want))
	}
	wantCounts := map[ReachClass]int{}
	wantCVEs := map[ReachClass][]string{}
	for _, cve := range slices.Sorted(maps.Keys(want)) {
		c := want[cve]
		wantCounts[c]++
		if c.Unreachable() {
			wantCVEs[c] = append(wantCVEs[c], cve)
		}
	}
	if !maps.Equal(r.Counts, wantCounts) {
		t.Errorf("counts = %v, want %v", r.Counts, wantCounts)
	}
	if !maps.EqualFunc(r.CVEs, wantCVEs, slices.Equal) {
		t.Errorf("CVEs = %v, want %v", r.CVEs, wantCVEs)
	}
}

// StoreReach keeps one row per run that changed something and names the CVEs new to an unreachable class.
func TestReachability_910_StoreRuns(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	r1 := ReachReport{Total: 2, Counts: map[ReachClass]int{ReachKeyedVersion: 1, ReachNone: 1}, CVEs: map[ReachClass][]string{ReachNone: {"CVE-2026-0006"}}}
	if ok, err := e.svc.StoreReach(ctx, "s1", r1); err != nil || !ok {
		t.Fatalf("first run: %v %v", ok, err)
	}
	if ok, err := e.svc.StoreReach(ctx, "s1", r1); err != nil || ok {
		t.Fatalf("same stamp and classes: stored %v %v", ok, err)
	}
	r2 := ReachReport{Total: 3, Counts: map[ReachClass]int{ReachKeyedVersion: 1, ReachNone: 2}, CVEs: map[ReachClass][]string{ReachNone: {"CVE-2026-0006", "CVE-2026-0010"}}}
	if ok, err := e.svc.StoreReach(ctx, "s2", r2); err != nil || !ok {
		t.Fatalf("second run: %v %v", ok, err)
	}
	var counts, unreach, added string
	if err := e.db.Reader().QueryRowContext(ctx, `SELECT counts, unreachable, added FROM fnd_reach_run ORDER BY id DESC LIMIT 1`).Scan(&counts, &unreach, &added); err != nil {
		t.Fatal(err)
	}
	if counts != `{"1":0,"2":0,"3k":0,"3v":1,"4":0,"5":2}` || unreach != `{"1":[],"2":[],"3k":[],"5":["CVE-2026-0006","CVE-2026-0010"]}` || added != `{"5":["CVE-2026-0010"]}` {
		t.Errorf("row = %s %s %s", counts, unreach, added)
	}
	if n := e.count(`SELECT count(*) FROM fnd_reach_run`); n != 2 {
		t.Errorf("runs = %d, want 2", n)
	}
	for i := range reachKeep + 5 {
		r := ReachReport{Total: i, Counts: map[ReachClass]int{}, CVEs: map[ReachClass][]string{}}
		if _, err := e.svc.StoreReach(ctx, "p"+string(rune('a'+i)), r); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.count(`SELECT count(*) FROM fnd_reach_run`); n != reachKeep {
		t.Errorf("runs kept = %d, want %d", n, reachKeep)
	}
}
