package main

import (
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
)

// VMware's record of CVE-2022-31705 states ESXi's affected versions in words only ("8.0 prior to ESXi80a-20842819, 7.0 prior to
// ESXi70U3si-20841705"), and NVD lists exact releases (8.0 GA the only 8.0 one). End to end on the binary's wiring: an 8.0 Update 3
// host gets neither a finding nor a "gives no affected versions" question (Update 3 began after the fix in 8.0a), and an 8.0 GA host
// gets the finding with VMware's fixed release.
func TestESXiRecordWords_DecideTheHost(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const cve = "CVE-2022-31705"
	record := []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2022-31705","state":"PUBLISHED","assignerShortName":"vmware"},` +
		`"containers":{"cna":{"descriptions":[{"lang":"en","value":"VMware ESXi, Workstation, and Fusion contain a heap out-of-bounds write vulnerability in the USB 2.0 controller (EHCI)."}],` +
		`"affected":[{"vendor":"n/a","product":"VMware ESXi, VMware Workstation Pro / Player, VMware Fusion Pro / Fusion (Fusion), VMware Cloud Foundation","versions":[{"version":"VMware ESXi (8.0 prior to ESXi80a-20842819, 7.0 prior to ESXi70U3si-20841705, VMware Workstation Pro / Player (16.x prior to 16.2.5), VMware Fusion Pro / Fusion (12.x prior to 12.2.5), VMware Cloud Foundation (4.x, 3.x)","status":"affected"}]}]}}}`)
	rec, err := feeds.ParseCVERecord(record, cve)
	if err != nil {
		t.Fatal(err)
	}
	err = s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedNVD(ctx, tx, cve, time.Now().AddDate(0, -2, 0), 9.3); err != nil {
			return err
		}
		for _, release := range []string{"7.0:-", "7.0:update_1", "7.0:update_2", "7.0:update_3c", "7.0:update_3g", "8.0:-"} {
			if err := seedRange(ctx, tx, cve, "cpe:2.3:o:vmware:esxi:"+release+":*:*:*:*:*:*", "", "", "", ""); err != nil {
				return err
			}
		}
		for _, r := range rec.Ranges {
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, fixed, version_type, default_status)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, cve, r.Origin, r.Part, r.Vendor, r.Product, r.CPE, r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl, r.Fixed, r.VersionType, r.DefaultStatus); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	add := func(name, version, ip string) string {
		t.Helper()
		r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "vmware-esxi", Version: version, Name: name, IP: ip})
		if err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	u3a, u3b := add("esxi-01", "8.0.3 build 24022510", "192.0.2.15"), add("esxi-02", "8.0 U3", "192.0.2.16")
	ga := add("esxi-ga", "8.0 build 20513097", "192.0.2.17")
	if _, err := s.d.Findings.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{u3a, u3b} {
		if got := openFindings(t, s, host); slices.Contains(got, cve) {
			t.Errorf("%s: 8.0 Update 3 has %s open, which VMware fixed in 8.0a", host, cve)
		}
		if q := s.count(`SELECT count(*) FROM fnd_question WHERE asset_id = ? AND cve = ?`, host, cve); q != 0 {
			t.Errorf("%s: %d questions about %s, whose record states the fixed build of 8.0", host, q, cve)
		}
	}
	if got := openFindings(t, s, ga); !slices.Contains(got, cve) {
		t.Errorf("8.0 GA host: open findings %v, want %s", got, cve)
	}
	if n := s.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = ? AND cve = ? AND evidence LIKE '%8.0a%'`, ga, cve); n != 1 {
		t.Errorf("8.0 GA host: the finding does not name the fixed release 8.0a")
	}
}
