package main

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
)

// seedVendorRow writes one CVE record range of cve as the reader keeps a vendor's own notation (origin cna, no CPE, the product's
// record key) or, generic, one it can order.
func seedVendorRow(ctx context.Context, tx *sql.Tx, cve, vendor, product, start, endExcl, versionType string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, version_type, default_status)
VALUES (?, 'cna', '', ?, ?, '', ?, '', '', ?, ?, 'unaffected')`, cve, vendor, product, start, endExcl, versionType)
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
			if err := seedVendorRow(ctx, tx, listed, "vmware", "esxi", "8.0", end, "vendor:custom"); err != nil {
				return err
			}
		}
		// a CVE on no list that only VMware's rows describe (NVD has not analysed it)
		if err := seedNVD(ctx, tx, other, time.Now().AddDate(0, -1, 0), 0); err != nil {
			return err
		}
		return seedVendorRow(ctx, tx, other, "vmware", "esxi", "8.0", "ESXi80U2e-24789317", "vendor:custom")
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

func TestCatalogueChanged(t *testing.T) {
	t.Parallel()
	if catalogueChanged([]string{"CVE-1"}, map[string]bool{"CVE-1": true}) {
		t.Error("a listed CVE only: the per-device rematch covers it")
	}
	if !catalogueChanged([]string{"CVE-1", "CVE-2"}, map[string]bool{"CVE-1": true}) {
		t.Error("a catalogue CVE changed: the match pass must run")
	}
}
