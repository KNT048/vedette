//go:build perf

package findings

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"
)

// TestPerfMatchPerDevice times the matcher alone (no database) per device of an inventory export (VEDETTE_PASS_TIME) against the
// exploited-list goldens plus a synthetic catalogue, the way upsertSplit calls it (once for the questions, once for the write).
// Measurement only.
func TestPerfMatchPerDevice(t *testing.T) {
	path := os.Getenv("VEDETTE_PASS_TIME")
	if path == "" {
		t.Skip("set VEDETTE_PASS_TIME to an inventory export")
	}
	assets := exportAssets(t, path)
	vulns := goldenVulns(t)
	for _, f := range []string{"testdata/kev-nvd-junos-n23.json", "testdata/kev-nvd-office-n22.json", "testdata/kev-nvd-winlab01-n55.json"} {
		vulns = append(vulns, loadGolden(t, f)...)
	}
	vulns = append(vulns, syntheticCatalogue(assets, 100_000)...)
	set := newMatchSet(vulns)
	now := time.Now()
	type row struct {
		id       string
		sw, cand int
		d        time.Duration
	}
	var rows []row
	var total time.Duration
	for _, a := range assets {
		start := time.Now()
		dev := set.forDevice(a)
		a.winList = dev
		_ = MatchAsset(a, dev, nil, now)
		_ = MatchAsset(a, dev, nil, now)
		d := time.Since(start)
		total += d
		rows = append(rows, row{a.ID, len(a.Software), len(dev), d})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].d > rows[j].d })
	for _, r := range rows[:8] {
		t.Logf("%s: %d software lines, %d entries compared, %v", r.id, r.sw, r.cand, r.d.Round(time.Millisecond))
	}
	t.Logf("matcher total %v for %d devices (%d entries in the set, %d exploited-list entries compared with every device)", total.Round(time.Millisecond),
		len(assets), len(vulns), len(set.listed))
}

// TestPerfFixAnswersExport writes every fix reader's answer on the export's devices to VEDETTE_EQUIV_OUT (before/after comparison) and
// times RowFixes the way the findings list calls it. Measurement only.
func TestPerfFixAnswersExport(t *testing.T) {
	path, out := os.Getenv("VEDETTE_PASS_TIME"), os.Getenv("VEDETTE_EQUIV_OUT")
	if path == "" || out == "" {
		t.Skip("set VEDETTE_PASS_TIME and VEDETTE_EQUIV_OUT")
	}
	assets := exportAssets(t, path)
	vulns := goldenVulns(t)
	for _, f := range []string{"testdata/kev-nvd-junos-n23.json", "testdata/kev-nvd-office-n22.json", "testdata/kev-nvd-winlab01-n55.json"} {
		vulns = append(vulns, loadGolden(t, f)...)
	}
	vulns = append(vulns, syntheticCatalogue(assets, 100_000)...)
	set := newMatchSet(vulns)
	var got []fixAnswers
	var spent time.Duration
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
		for _, m := range append(r.New, r.Existing...) {
			if _, ok := ans.Pages[m.CVE]; ok {
				continue
			}
			ans.CVEs = append(ans.CVEs, m.CVE)
			open = append(open, byCVE[m.CVE])
			ans.Pages[m.CVE] = nil
		}
		start := time.Now()
		ans.Rows = RowFixes(a, open)
		spent += time.Since(start)
		for cve, g := range FixedInForAll(a, open) {
			ans.Groups[cve] = groupShown{Kind: g.Kind, Software: g.Software, Version: g.Version, Fixed: g.Fixed, Distro: g.Distro, KB: g.KB,
				Closed: sortedKeys(g.Closed), Ranged: sortedKeys(g.Ranged), NVDLag: g.NVDLag}
		}
		for _, v := range open {
			ans.Pages[v.CVE] = FixedInFor(a, v)
		}
		got = append(got, ans)
	}
	b, _ := json.MarshalIndent(got, "", " ")
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("RowFixes over %d devices: %v", len(assets), spent.Round(time.Millisecond))
}

// TestPerfPassRowsExport writes what two match passes leave in the database for the export's devices to VEDETTE_EQUIV_OUT (before/after
// comparison), with the backlog hook, and times the passes. Measurement only.
func TestPerfPassRowsExport(t *testing.T) {
	path, out := os.Getenv("VEDETTE_PASS_TIME"), os.Getenv("VEDETTE_EQUIV_OUT")
	if path == "" || out == "" {
		t.Skip("set VEDETTE_PASS_TIME and VEDETTE_EQUIV_OUT")
	}
	assets := exportAssets(t, path)
	vulns := goldenVulns(t)
	for _, f := range []string{"testdata/kev-nvd-junos-n23.json", "testdata/kev-nvd-office-n22.json", "testdata/kev-nvd-winlab01-n55.json"} {
		vulns = append(vulns, loadGolden(t, f)...)
	}
	for i := range vulns {
		if i%7 == 0 {
			vulns[i].DateAdded = t0.Add(-48 * time.Hour)
		}
	}
	vulns = append(vulns, syntheticCatalogue(assets, 100_000)...)
	e := newEnv(t)
	e.inv.match = map[string]Asset{}
	for _, a := range assets {
		e.inv.match[a.ID] = a
	}
	e.feeds.vulns = vulns
	svc := e.reconciler(e.pub, e.inv)
	var got []passRows
	for i := range 3 {
		start := time.Now()
		if _, err := svc.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
		t.Logf("pass %d: %v", i+1, time.Since(start).Round(time.Millisecond))
		got = append(got, e.passRows())
		e.advance(time.Hour)
	}
	b, _ := json.MarshalIndent(got, "", " ")
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
