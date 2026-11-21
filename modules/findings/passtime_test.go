package findings

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/productid"
)

// The time of one match pass on an exported inventory (35 devices, 2,467 software lines; anonymised) against the exploited lists alone
// (what the hourly pass compared before) and against a catalogue of the size a box holds, with every product the devices run named by
// many CVEs. It measures, it asserts nothing about the machine: set VEDETTE_PASS_TIME to the export's path to run it.
func TestPassTime_FixtureInventory(t *testing.T) {
	path := os.Getenv("VEDETTE_PASS_TIME")
	if path == "" {
		t.Skip("set VEDETTE_PASS_TIME to an inventory export")
	}
	assets := exportAssets(t, path)
	kev := goldenVulns(t)
	for _, f := range []string{"testdata/kev-nvd-junos-n23.json", "testdata/kev-nvd-office-n22.json", "testdata/kev-nvd-winlab01-n55.json"} {
		kev = append(kev, loadGolden(t, f)...)
	}
	catalogue := syntheticCatalogue(assets, 100_000)
	for _, run := range []struct {
		name  string
		vulns []Vuln
	}{{"exploited lists only", kev}, {"lists and catalogue", append(append([]Vuln{}, kev...), catalogue...)}} {
		e := newEnv(t)
		e.inv.match = map[string]Asset{}
		for _, a := range assets {
			e.inv.match[a.ID] = a
		}
		e.feeds.vulns = run.vulns
		start := time.Now()
		r, err := e.svc.Reconcile(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		first := time.Since(start)
		e.advance(ReconcileEvery)
		start = time.Now()
		if _, err := e.svc.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s (%d entries): first pass %v (%d devices, %d findings), next pass %v", run.name, len(run.vulns), first.Round(time.Millisecond),
			r.Devices, e.count(`SELECT count(*) FROM fnd_finding`), time.Since(start).Round(time.Millisecond))
	}
}

// exportAssets reads the devices and software lines of an inventory export as the matcher's input.
func exportAssets(t *testing.T, path string) []Asset {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // a path the person running the measure gives
	if err != nil {
		t.Fatal(err)
	}
	var x struct {
		Devices []struct {
			ID string  `json:"id"`
			OS *string `json:"os"`
		} `json:"devices"`
		Software []struct {
			ID       string  `json:"id"`
			AssetID  string  `json:"asset_id"`
			Vendor   string  `json:"vendor"`
			Product  string  `json:"product"`
			Display  string  `json:"display"`
			Source   string  `json:"source"`
			Version  *string `json:"version"`
			CPE      *string `json:"cpe"`
			PkgVer   *string `json:"pkg_version"`
			PkgSrc   *string `json:"pkg_source"`
			Packaged int     `json:"packaged"`
		} `json:"software"`
	}
	if err := json.Unmarshal(b, &x); err != nil {
		t.Fatal(err)
	}
	by := map[string]*Asset{}
	var order []string
	for _, d := range x.Devices {
		a := &Asset{ID: d.ID, Name: d.ID}
		if d.OS != nil {
			a.OS = *d.OS
		}
		by[d.ID] = a
		order = append(order, d.ID)
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	for _, s := range x.Software {
		a, ok := by[s.AssetID]
		if !ok {
			continue
		}
		a.Software = append(a.Software, Software{ID: s.ID, Display: s.Display, Vendor: s.Vendor, Product: s.Product, Version: str(s.Version),
			CPE: str(s.CPE), Source: s.Source, Packaged: s.Packaged == 1, PkgVersion: str(s.PkgVer), PkgSource: str(s.PkgSrc),
			KevKeys: []string{productid.Key(s.Vendor, s.Product)}})
	}
	out := make([]Asset, 0, len(order))
	for _, id := range order {
		out = append(out, *by[id])
	}
	return out
}

// syntheticCatalogue is n catalogue CVEs: ten for every product the devices run (half of them reaching the version the device has),
// the rest naming products no device runs.
func syntheticCatalogue(assets []Asset, n int) []Vuln {
	var out []Vuln
	seen := map[string]bool{}
	id := 0
	next := func() string { id++; return fmt.Sprintf("CVE-2026-%07d", 500000+id) }
	for _, a := range assets {
		for _, s := range a.Software {
			v, p := productid.Norm(s.Vendor), productid.Norm(s.Product)
			if v == "" || p == "" || seen[v+p] {
				continue
			}
			seen[v+p] = true
			cpe := "cpe:2.3:a:" + v + ":" + p + ":*:*:*:*:*:*:*:*"
			for i := range 10 {
				end := "0.0.1"
				if i%2 == 0 && s.Version != "" {
					end = s.Version + ".1"
				}
				out = append(out, catalogueOnly(next(), cpe, "", end))
			}
		}
	}
	for len(out) < n {
		out = append(out, catalogueOnly(next(), "cpe:2.3:a:other"+strings.Repeat("x", len(out)%7)+fmt.Sprint(len(out)%5000)+":product:*:*:*:*:*:*:*:*", "1.0", "2.0"))
	}
	return out
}
