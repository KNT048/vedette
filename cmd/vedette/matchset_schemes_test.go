package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/findings/findingstest"
	"github.com/knt048/vedette/modules/inventory"
)

// seedVendorRow writes one CVE record range of cve as the reader keeps a vendor's own notation (origin cna, no CPE, the product's
// record key, version type "vendor:custom").
func seedVendorRow(ctx context.Context, tx *sql.Tx, cve, vendor, product, start, endExcl string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, version_type, default_status)
VALUES (?, 'cna', '', ?, ?, '', ?, '', '', ?, 'vendor:custom', 'unaffected')`, cve, vendor, product, start, endExcl)
	return err
}

// esxiHostAsset is an ESXi 8.0 Update 2 host as the active sensor states it (build 22380479).
func esxiHostAsset() findings.Asset {
	d := "VMware ESXi 8.0 Update 2 (build 22380479)"
	return findings.Asset{ID: "esx", Name: "esx01", OS: d, Software: []findings.Software{{ID: "s-esxi", Display: d, Vendor: "vmware", Product: "esxi", Version: "8.0",
		CPE: "cpe:2.3:o:vmware:esxi:8.0:update_2:*:*:*:*:*:*", Source: "nmap", KevKeys: []string{"vmware|esxi"}}}}
}

// MatchSet gives an exploited-list entry the same data whichever path builds the set: with no other catalogue CVE in reach (the
// short path) and with one, the entry carries VMware's rows read in the ESXi scheme, so the fix of an ESXi 8.0 Update 2 host is
// VMware's fixed build of its train on both.
func TestMatchSet_ListedEntryKeepsItsVendorRowsOnEveryPath(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const listed, other = "CVE-2025-22225", "CVE-2025-41236"
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedKEVRow(ctx, tx, listed, "VMware", "ESXi", "ESXi arbitrary write", time.Now().AddDate(0, -2, 0), false, false); err != nil {
			return err
		}
		if err := seedNVD(ctx, tx, listed, time.Now().AddDate(0, -3, 0), 8.2); err != nil {
			return err
		}
		if err := seedRange(ctx, tx, listed, "cpe:2.3:o:vmware:esxi:8.0:update_2:*:*:*:*:*:*", "", "", "", ""); err != nil {
			return err
		}
		for _, end := range []string{"ESXi80U3d-24585383", "ESXi80U2d-24585300"} {
			if err := seedVendorRow(ctx, tx, listed, "vmware", "esxi", "8.0", end); err != nil {
				return err
			}
		}
		// a CVE on no list that only VMware's rows describe (NVD has not analysed it)
		if err := seedNVD(ctx, tx, other, time.Now().AddDate(0, -1, 0), 0); err != nil {
			return err
		}
		return seedVendorRow(ctx, tx, other, "vmware", "esxi", "8.0", "ESXi80U2e-24789317")
	})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	a := findingsFeeds{st: fs.Store()}
	host := esxiHostAsset()
	fixOf := func(set []findings.Vuln, cve string) (string, bool) {
		for _, v := range set {
			if v.CVE == cve {
				return findings.FixOf(host, host.Software[0], v).Version, true
			}
		}
		return "", false
	}
	short, err := a.MatchSet(ctx, findings.NewMatchScope(nil, nil)) // nothing in reach: the exploited lists only
	if err != nil {
		t.Fatal(err)
	}
	full, err := a.MatchSet(ctx, findings.NewMatchScope([]findings.Asset{host}, nil))
	if err != nil {
		t.Fatal(err)
	}
	const want = "8.0 U2d (build 24585300)"
	for name, set := range map[string][]findings.Vuln{"short path": short, "full path": full} {
		if got, ok := fixOf(set, listed); !ok || got != want {
			t.Errorf("%s: fix of %s on the 8.0 U2 host %q (in set %v), want %q", name, listed, got, ok, want)
		}
	}
	got, ok := fixOf(full, other)
	if !ok || got != "8.0 U2e (build 24789317)" {
		t.Fatalf("the CVE only VMware's rows describe: in set %v, fix %q", ok, got)
	}
	res := findings.MatchAsset(host, full, nil, time.Now())
	n := 0
	for _, m := range res.New {
		if m.CVE == listed || m.CVE == other {
			n++
		}
	}
	if n != 2 {
		t.Errorf("findings on the 8.0 U2 host: %+v, want %s and %s", res.New, listed, other)
	}
}

// A CVE record's rows of a product with a version scheme (NetScaler's builds) are read by the scheme only, never by the generic
// comparison; a CVE a distribution fixed in a package the devices run reaches the match set before NVD names the product.
func TestMatchSet_SchemeRowsAndDistributionOnlyCVEs(t *testing.T) {
	t.Parallel()
	ns := feeds.Range{CVE: "CVE-2025-5777", Origin: feeds.OriginCNA, Vendor: "citrix", Product: "netscaleradc", StartIncl: "14.1", EndExcl: "14.1-43.56",
		DefaultStatus: feeds.DefaultUnaffected}
	if !feeds.SchemeProduct(ns) {
		t.Fatal("NetScaler's record rows: no scheme product")
	}
	if _, ok := ns.MatchRow(); ok {
		t.Error("a NetScaler record row reached the generic comparison")
	}
	s := newStack(t)
	ctx := t.Context()
	const cve = "CVE-2026-20001"
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedNVD(ctx, tx, cve, time.Now().AddDate(0, -1, 0), 0); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES ('ubuntu-osv', 'ubuntu', '26.04', 'openssh', ?, 'fixed', '1:10.2p1-2ubuntu3.9')`, cve)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	os := "Ubuntu 26.04.1 LTS"
	dev := findings.Asset{ID: "u", Name: "web-01", OS: os, AgentOS: os, Software: []findings.Software{{ID: "s-ssh", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH",
		Version: "10.2p1", Source: "agent", Packaged: true, PkgVersion: "1:10.2p1-2ubuntu3.8", PkgSource: "openssh"}}}
	set, err := findingsFeeds{st: fs.Store()}.MatchSet(ctx, findings.NewMatchScope([]findings.Asset{dev}, nil))
	if err != nil {
		t.Fatal(err)
	}
	res := findings.MatchAsset(dev, set, nil, time.Now())
	if len(res.New) != 1 || res.New[0].CVE != cve {
		t.Fatalf("findings %+v: want %s from Ubuntu's fixed package", res.New, cve)
	}
}

// A ranges update that changed a catalogue CVE (Catalogue, as the NVD and CVE record pulls send it: feeds
// TestNVDPull_CatalogueChangeIsNews) runs findings' match pass now; one that changed only listed CVEs rematches their devices and
// leaves the pass to its hour.
func TestRangesUpdated_CatalogueChangeWakesTheMatchPass(t *testing.T) {
	t.Parallel()
	var woke []string
	s := newStackWith(t, func(d *deps) { d.Wake = func(module, job string) { woke = append(woke, module+"/"+job) } })
	ctx := t.Context()
	s.kevAdded("CVE-2026-7201", "OpenBSD", "OpenSSH", time.Now().AddDate(0, -1, 0))
	on := rangesUpdated(s.d)
	if err := on(ctx, feeds.RangesUpdatedEvent{CVEs: []string{"CVE-2026-7201"}}); err != nil || len(woke) != 0 {
		t.Fatalf("a listed CVE only: woke %v %v", woke, err)
	}
	if err := on(ctx, feeds.RangesUpdatedEvent{Catalogue: true}); err != nil || len(woke) != 1 || woke[0] != "findings/reconcile" {
		t.Fatalf("a catalogue change: woke %v %v", woke, err)
	}
	if err := on(ctx, feeds.RangesUpdatedEvent{CVEs: []string{"CVE-2026-7201", "CVE-2026-7202"}}); err != nil || len(woke) != 2 {
		t.Fatalf("a CVE no list holds: woke %v %v", woke, err)
	}
	if err := on(ctx, feeds.RangesUpdatedEvent{CVEs: []string{"CVE-2026-7201"}, First: true, Catalogue: true}); err != nil || len(woke) != 3 {
		t.Fatalf("the first fill with a catalogue change: woke %v %v", woke, err)
	}
}

// A detected finding's version must be one its software line runs (a self-check reading inventory's lines).
func TestSelfcheck_MatchedVersionOnLine(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, err := openMigrated(ctx, filepath.Join(t.TempDir(), "v.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	findingstest.ParentRows(t, db)
	const ts = "2026-11-01T00:00:00.000Z"
	err = db.Write(ctx, func(tx *sql.Tx) error {
		if err := seedNVD(ctx, tx, "CVE-2025-5777", time.Now().AddDate(0, -3, 0), 0); err != nil {
			return err
		}
		if err := seedRange(ctx, tx, "CVE-2025-5777", "cpe:2.3:a:citrix:netscaler_gateway:*:*:*:*:*:*:*:*", "14.1", "", "", "14.1-43.56"); err != nil {
			return err
		}
		ins := `INSERT INTO fnd_finding (id, asset_id, cve, software_id, detected, basis, verified, range_origin, matched_version, fix_kind, fix_key, state,
			urgency, urgency_at, first_seen, last_seen, updated_at) VALUES (?, 'a1', 'CVE-2025-5777', ?, 1, 'device_version', 'no', 'cna', nullif(?, ''), 'update', ?, 'open', 2, ?, ?, ?, ?)`
		for _, r := range [][4]string{
			{"f-ns", "s-ns", "", "citrix|netscaler|update|14.1-43.56"}, // decided by Citrix's rows: the scheme product
			{"f-other", "s-other", "2.0", "acme|box|update|2.1"},       // a record row beat NVD's: a precedence break
		} {
			if _, err := tx.ExecContext(ctx, ins, r[0], r[1], r[2], r[3], ts, ts, ts, ts); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	count := func(name string) int {
		t.Helper()
		for _, inv := range selfcheck.Registered() {
			if inv.Name == name {
				var n int
				if err := db.Reader().QueryRowContext(ctx, inv.Query).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
		}
		t.Fatalf("no invariant %s", name)
		return 0
	}
	if n := count("findings.matched_version_on_line"); n != 1 {
		t.Errorf("matched_version_on_line %d, want 1 (the test line runs no version, so 2.0 is none it runs)", n)
	}
}

// Range precedence exempts a finding whose line is a product with a version scheme, resolved as the matcher resolves it: a NetScaler
// line nmap names "netscaler gateway" by its CPE is NetScaler, whose vendor rows decide before NVD's. A finding of another product
// that rests on the CVE record's rows while NVD has rows breaks precedence.
func TestSelfcheck_RangePrecedenceResolvesTheLineProduct(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	id, err := s.d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "adc-01"})
	if err != nil {
		t.Fatal(err)
	}
	items := []inventory.SoftwareItem{
		{Display: "Citrix NetScaler Gateway 14.1-12.30", Vendor: "citrix", Product: "netscaler gateway", Version: "14.1-12.30",
			CPE: "cpe:2.3:a:citrix:netscaler_gateway:14.1-12.30:*:*:*:*:*:*:*", Confidence: 0.8},
		{Display: "Acme Box 2.0", Vendor: "acme", Product: "box", Version: "2.0", Confidence: 0.8},
	}
	if err := s.d.Inventory.UpsertSoftware(ctx, id, items, "nmap"); err != nil {
		t.Fatal(err)
	}
	dev, ok, err := s.d.Inventory.MatchInput(ctx, id)
	if err != nil || !ok || len(dev.Software) != 2 {
		t.Fatalf("lines %+v %v %v", dev.Software, ok, err)
	}
	line := map[string]string{}
	for _, sw := range dev.Software {
		line[sw.Product] = sw.ID
	}
	const ts = "2026-11-01T00:00:00.000Z"
	err = s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedNVD(ctx, tx, "CVE-2025-5777", time.Now().AddDate(0, -3, 0), 0); err != nil {
			return err
		}
		if err := seedRange(ctx, tx, "CVE-2025-5777", "cpe:2.3:a:citrix:netscaler_gateway:*:*:*:*:*:*:*:*", "14.1", "", "", "14.1-43.56"); err != nil {
			return err
		}
		ins := `INSERT INTO fnd_finding (id, asset_id, cve, software_id, detected, basis, verified, range_origin, fix_kind, fix_key, state,
			urgency, urgency_at, first_seen, last_seen, updated_at) VALUES (?, ?, 'CVE-2025-5777', ?, 1, 'banner_version', 'no', 'cna', 'update', ?, 'open', 2, ?, ?, ?, ?)`
		for _, r := range [][3]string{
			{"f-ns", line[items[0].Product], "citrix|netscaler gateway|update|14.1-43.56"}, // Citrix's rows decided: the scheme product
			{"f-box", line[items[1].Product], "acme|box|update|2.1"},                       // a record row beat NVD's
		} {
			if r[1] == "" {
				return fmt.Errorf("no line for %s", r[0])
			}
			if _, err := tx.ExecContext(ctx, ins, r[0], id, r[1], r[2], ts, ts, ts, ts); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, inv := range selfcheck.Registered() {
		if inv.Name != "findings.range_precedence" {
			continue
		}
		n, err := inv.Count(ctx, s.d.DB.Reader())
		if err != nil || n != 1 {
			t.Fatalf("range_precedence %d %v, want 1 (the Acme finding only)", n, err)
		}
		return
	}
	t.Fatal("no range_precedence invariant")
}
