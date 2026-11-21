package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/findings/findingstest"
)

// The time of the hourly match pass end to end: an exported inventory (VEDETTE_PASS_TIME names the file; 35 devices and 2,467
// software lines in the anonymised export) read by findings, the real catalogue reads of the adapter (findingsFeeds.MatchSet: range
// products, ranges, pins, catalogue rows, distributions, vendor rows) on a catalogue of a box's size (110,000 CVEs and about 280,000
// ranges), and the writes of every finding. The catalogue's shape: the Linux kernel's 9,000 CVEs, 1,500 Windows CVEs each naming
// 15 Windows releases, 400 Chrome CVEs, 20 CVEs for every other product the devices run, the rest naming products no device runs.
// It asserts nothing about the machine.
func TestPassTime_RealCatalogueReads(t *testing.T) {
	path := os.Getenv("VEDETTE_PASS_TIME")
	if path == "" {
		t.Skip("set VEDETTE_PASS_TIME to an inventory export")
	}
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	db, err := openMigrated(ctx, filepath.Join(t.TempDir(), "v.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	findingstest.ParentRows(t, db) // the export's devices and lines are not in the inventory here
	assets := exportedAssets(t, path)
	start := time.Now()
	n, ranges := seedCatalogue(t, db, assets)
	t.Logf("catalogue: %d CVEs, %d ranges, written in %v", n, ranges, time.Since(start).Round(time.Millisecond))
	inv := &passInv{assets: map[string]findings.Asset{}}
	for _, a := range assets {
		inv.assets[a.ID] = a
	}
	fd := findingsFeeds{st: feeds.NewStore(db), cache: &vulnCache{}}
	svc, err := findings.NewService(findings.ServiceConfig{DB: db, Audit: audit.New(nil), Inventory: inv, Feeds: fd, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		start := time.Now()
		r, err := svc.Reconcile(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var found int
		if err := db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM fnd_finding`).Scan(&found); err != nil {
			t.Fatal(err)
		}
		t.Logf("pass %d: %v (%d devices, %d created, %d findings)", i+1, time.Since(start).Round(time.Millisecond), r.Devices, r.Created, found)
	}
}

func seedCatalogue(t *testing.T, db *store.DB, assets []findings.Asset) (cves, ranges int) {
	t.Helper()
	type product struct{ cpe, version string }
	var own []product
	seen := map[string]bool{}
	for _, a := range assets {
		for _, s := range a.Software {
			v, p := productid.Norm(s.Vendor), productid.Norm(s.Product)
			if v == "" || p == "" || seen[v+"/"+p] || s.Version == "" {
				continue
			}
			seen[v+"/"+p] = true
			own = append(own, product{"cpe:2.3:a:" + v + ":" + p + ":*:*:*:*:*:*:*:*", s.Version})
		}
	}
	now := store.FormatTS(time.Now().UTC())
	pub := store.FormatTS(time.Now().UTC().AddDate(0, -3, 0))
	err := db.Write(t.Context(), func(tx *sql.Tx) error {
		insCVE, err := tx.PrepareContext(t.Context(), `INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, updated_at) VALUES (?, ?, ?, 'Analyzed', ?, ?)`)
		if err != nil {
			return err
		}
		insRange, err := tx.PrepareContext(t.Context(), `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, platforms)
VALUES (?, 'nvd', ?, ?, ?, ?, '', '', '', ?, '[]')`)
		if err != nil {
			return err
		}
		add := func(cpes []string, end string) error {
			cves++
			cve := fmt.Sprintf("CVE-2026-%07d", 100000+cves)
			if _, err := insCVE.ExecContext(t.Context(), cve, pub, now, now, now); err != nil {
				return err
			}
			for _, c := range cpes {
				f := strings.SplitN(strings.TrimPrefix(c, "cpe:2.3:"), ":", 4)
				if _, err := insRange.ExecContext(t.Context(), cve, f[0], f[1], f[2], c, end); err != nil {
					return err
				}
				ranges++
			}
			return nil
		}
		for i := range 9000 {
			if err := add([]string{"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}, fmt.Sprintf("6.%d.%d", i%13, i%200)); err != nil {
				return err
			}
		}
		var win []string
		for _, w := range []string{"windows_10_1607", "windows_10_1809", "windows_10_21h2", "windows_10_22h2", "windows_11_22h2", "windows_11_23h2",
			"windows_11_24h2", "windows_server_2016", "windows_server_2019", "windows_server_2022", "windows_server_2025", "windows_server_2012",
			"windows_server_2012_r2", "windows_11_21h2", "windows_10_1507"} {
			win = append(win, "cpe:2.3:o:microsoft:"+w+":*:*:*:*:*:*:*:*")
		}
		for i := range 1500 {
			if err := add(win, fmt.Sprintf("10.0.%d.%d", 17763+i%5, 1000+i)); err != nil {
				return err
			}
		}
		for i := range 400 {
			if err := add([]string{"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"}, fmt.Sprintf("1%02d.0.%d.0", 20+i%20, i)); err != nil {
				return err
			}
		}
		for _, p := range own {
			for i := range 20 {
				end := "0.0.1"
				if i%2 == 0 {
					end = p.version + ".1"
				}
				if err := add([]string{p.cpe}, end); err != nil {
					return err
				}
			}
		}
		for cves < 110_000 {
			if err := add([]string{fmt.Sprintf("cpe:2.3:a:vendor%d:product%d:*:*:*:*:*:*:*:*", cves%9000, cves%30000), fmt.Sprintf("cpe:2.3:a:vendor%d:product%d:*:*:*:*:*:*:*:*", cves%9000, cves%30000+1),
				fmt.Sprintf("cpe:2.3:a:vendor%d:other%d:*:*:*:*:*:*:*:*", cves%7000, cves%20000)}, "2.0"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return cves, ranges
}

// exportedAssets reads the devices and software lines of an inventory export as the matcher's input.
func exportedAssets(t *testing.T, path string) []findings.Asset {
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
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	by := map[string]*findings.Asset{}
	var order []string
	for _, d := range x.Devices {
		by[d.ID] = &findings.Asset{ID: d.ID, Name: d.ID, OS: str(d.OS)}
		order = append(order, d.ID)
	}
	for _, s := range x.Software {
		if a, ok := by[s.AssetID]; ok {
			a.Software = append(a.Software, findings.Software{ID: s.ID, Display: s.Display, Vendor: s.Vendor, Product: s.Product, Version: str(s.Version),
				CPE: str(s.CPE), Source: s.Source, Packaged: s.Packaged == 1, PkgVersion: str(s.PkgVer), PkgSource: str(s.PkgSrc),
				KevKeys: []string{productid.Key(s.Vendor, s.Product)}})
		}
	}
	out := make([]findings.Asset, 0, len(order))
	for _, id := range order {
		out = append(out, *by[id])
	}
	return out
}

// passInv is the inventory as the measure gives it to findings.
type passInv struct{ assets map[string]findings.Asset }

func (p *passInv) Assets(_ context.Context, ids []string) (map[string]findings.AssetView, error) {
	out := map[string]findings.AssetView{}
	for _, id := range ids {
		if _, ok := p.assets[id]; ok {
			out[id] = findings.AssetView{ID: id, Name: id}
		}
	}
	return out, nil
}

func (p *passInv) MatchInput(_ context.Context, id string) (findings.Asset, bool, error) {
	a, ok := p.assets[id]
	return a, ok, nil
}

func (p *passInv) AssetIDs(context.Context) ([]string, error) { return slices.Sorted(maps.Keys(p.assets)), nil }

func (p *passInv) IgnoredIDs(context.Context) ([]string, error) { return nil, nil }

func (p *passInv) IsIgnored(context.Context, string) (bool, error) { return false, nil }

func (p *passInv) EffectiveSoftware(context.Context, string) ([]findings.EffectiveSoftware, error) { return nil, nil }
