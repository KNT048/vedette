package main

import (
	"context"
	"database/sql"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
)

// The CVEs of products a person declares, end to end on the binary's wiring: the catalogue as the pulls store it, devices added by
// hand as a person does (a product picked or typed, with the version the product shows), one match pass. Each device gets the
// finding its CVE's record states, and no "gives no affected versions" question for a CVE whose record has versions.
func TestDeclaredDevices_GetTheirCVEsFindings(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	recent := time.Now().AddDate(0, -2, 0)
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		steps := []func() error{
			// DSM: CISA lists it under Synology's own name; NVD writes the bounds in Synology's notation
			func() error {
				return seedKEVRow(ctx, tx, "CVE-2024-10441", "Synology", "DiskStation Manager (DSM)", "Synology DSM output escaping", recent, false, false)
			},
			func() error { return seedNVD(ctx, tx, "CVE-2024-10441", recent, 9.8) },
			func() error {
				return seedRange(ctx, tx, "CVE-2024-10441", "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*", "7.2.1-69057", "", "", "7.2.1-69057-6")
			},
			func() error {
				return seedRange(ctx, tx, "CVE-2024-10441", "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*", "7.2.2", "", "", "7.2.2-72806-1")
			},
			// DSM: a record with no version, its fixed releases in its description
			func() error { return seedNVD(ctx, tx, "CVE-2026-4036", recent, 0) },
			func() error {
				_, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET nvd_status = 'Received', description = ? WHERE cve = 'CVE-2026-4036'`,
					"An SQL injection vulnerability in Sharing API in Synology DiskStation Manager (DSM) before 7.2.1-69057-10, 7.2.2-72806-7 and 7.3.2-86009-2 allows remote authenticated users to obtain arbitrary sharing files.")
				return err
			},
			func() error {
				_, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, default_status)
VALUES ('CVE-2026-4036', 'cna', '', 'synology', 'diskstationmanagerdsm', '', '', '', '', '', 'affected')`)
				return err
			},
			// DSM: two records of one batch: one names a fix of the device's line, the other names only later lines. The fix on the
			// device's line for one CVE says nothing about the other: that one stays a question, never a finding
			func() error { return seedNVD(ctx, tx, "CVE-2026-176954", recent, 0) },
			func() error {
				_, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET nvd_status = 'Received', description = ? WHERE cve = 'CVE-2026-176954'`,
					"A path traversal vulnerability in Synology DiskStation Manager (DSM) before 7.2.1-69057-13, 7.2.2-72806-10, 7.3.2-86009-5, and 7.4.1-90080-1 allows remote attackers to read or write arbitrary files.")
				return err
			},
			func() error {
				_, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, default_status)
VALUES ('CVE-2026-176954', 'cna', '', 'synology', 'diskstationmanagerdsm', '', '', '', '', '', 'affected')`)
				return err
			},
			func() error { return seedNVD(ctx, tx, "CVE-2026-124993", recent, 0) },
			func() error {
				_, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET nvd_status = 'Received', description = ? WHERE cve = 'CVE-2026-124993'`,
					"An incorrect authorization vulnerability in the Security Advisor in Synology DiskStation Manager (DSM) before 7.3.2-86009-5 and 7.4.1-90080-1 allows remote attackers to read specific files.")
				return err
			},
			func() error {
				_, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, default_status)
VALUES ('CVE-2026-124993', 'cna', '', 'synology', 'diskstationmanagerdsm', '', '', '', '', '', 'affected')`)
				return err
			},
			// DSM: a record row in Synology's notation, before NVD analyses the CVE
			func() error { return seedNVD(ctx, tx, "CVE-2025-13392", recent, 0) },
			func() error {
				return seedVendorRow(ctx, tx, "CVE-2025-13392", "synology", "diskstationmanagerdsm", "7.2.1", "7.2.1-69057-8")
			},
			// nginx under NVD's newer name, beside F5's other products ("dos" first in alphabetical order)
			func() error { return seedNVD(ctx, tx, "CVE-2026-123007", recent, 7.5) },
			func() error {
				return seedRange(ctx, tx, "CVE-2026-123007", "cpe:2.3:a:f5:dos:*:*:*:*:*:nginx:*:*", "4.5.0", "", "4.7.0", "")
			},
			func() error {
				return seedRange(ctx, tx, "CVE-2026-123007", "cpe:2.3:a:f5:nginx_open_source:*:*:*:*:*:*:*:*", "1.9.5", "", "", "1.30.7")
			},
			// Java SE: Oracle's OpenJDK range, Corretto's own release numbers
			func() error { return seedNVD(ctx, tx, "CVE-2026-114938", recent, 7.4) },
			func() error {
				return seedRange(ctx, tx, "CVE-2026-114938", "cpe:2.3:a:amazon:corretto:*:*:*:*:*:*:*:*", "27.0.0.33.1", "", "27.0.1.1.4", "")
			},
			func() error {
				return seedRange(ctx, tx, "CVE-2026-114938", "cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*", "21", "", "21.0.13.0.3", "")
			},
			// ESXi: VMware's fixed build per update
			func() error {
				return seedKEVRow(ctx, tx, "CVE-2025-22225", "VMware", "ESXi", "VMware ESXi arbitrary write", recent, false, false)
			},
			func() error { return seedNVD(ctx, tx, "CVE-2025-22225", recent, 8.2) },
			func() error {
				return seedVendorRow(ctx, tx, "CVE-2025-22225", "vmware", "esxi", "8.0", "ESXi80U3d-24585383")
			},
			func() error {
				return seedVendorRow(ctx, tx, "CVE-2025-22225", "vmware", "esxi", "8.0", "ESXi80U2d-24585300")
			},
		}
		for _, f := range steps {
			if err := f(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	add := func(in inventory.AddInput) string {
		t.Helper()
		r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", in)
		if err != nil {
			t.Fatalf("%+v: %v", in, err)
		}
		return r.ID
	}
	nas := add(inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager (DSM)", Version: "7.2.1-69057 Update 5", Name: "nas-office", IP: "192.0.2.10"})
	nasPicked := add(inventory.AddInput{CatalogID: "synology-nas-dsm", Version: "7.2.1-69057-6", Name: "nas-patched", IP: "192.0.2.11"})
	web := add(inventory.AddInput{Vendor: "F5", Product: "nginx", Version: "1.30.5", Name: "web-01", IP: "192.0.2.12"})
	temurin := add(inventory.AddInput{Vendor: "Eclipse Adoptium", Product: "Temurin", Version: "21.0.7", Name: "java-app-01", IP: "192.0.2.13"})
	redhat := add(inventory.AddInput{Vendor: "Red Hat", Product: "OpenJDK", Version: "21.0.7", Name: "java-app-02", IP: "192.0.2.14"})
	esxiTyped := add(inventory.AddInput{CatalogID: "vmware-esxi", Version: "8.0.3 build 24022510", Name: "esxi-01", IP: "192.0.2.15"})
	esxiNamed := add(inventory.AddInput{CatalogID: "vmware-esxi", Version: "8.0 U3", Name: "esxi-02", IP: "192.0.2.16"})
	esxiPatched := add(inventory.AddInput{CatalogID: "vmware-esxi", Version: "8.0 U3e", Name: "esxi-03", IP: "192.0.2.17"})
	if _, err := s.d.Findings.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		device string
		has    []string
		hasNot []string
	}{
		{nas, []string{"CVE-2024-10441", "CVE-2026-4036", "CVE-2025-13392", "CVE-2026-176954"}, []string{"CVE-2026-124993"}},
		{nasPicked, []string{"CVE-2026-4036"}, []string{"CVE-2024-10441", "CVE-2026-124993"}}, // Update 6 is CVE-2024-10441's fix, not CVE-2026-4036's (Update 10)
		{web, []string{"CVE-2026-123007"}, nil},
		{temurin, []string{"CVE-2026-114938"}, nil},
		{redhat, []string{"CVE-2026-114938"}, nil},
		{esxiTyped, []string{"CVE-2025-22225"}, nil},
		{esxiNamed, []string{"CVE-2025-22225"}, nil},
		{esxiPatched, nil, []string{"CVE-2025-22225"}}, // 8.0 U3e is past U3d
	} {
		got := openFindings(t, s, c.device)
		for _, cve := range c.has {
			if !slices.Contains(got, cve) {
				t.Errorf("%s: open findings %v, want %s", c.device, got, cve)
			}
		}
		for _, cve := range c.hasNot {
			if slices.Contains(got, cve) {
				t.Errorf("%s: open findings %v, must not have %s", c.device, got, cve)
			}
		}
		// the CVE whose record names only later DSM lines waits in its own older_line question, never decided
		if q := s.count(`SELECT count(*) FROM fnd_question WHERE asset_id = ? AND kind = 'older_line' AND cve = 'CVE-2026-124993' AND detail LIKE '%"line":"7.2.1"%'`,
			c.device); (c.device == nas || c.device == nasPicked) && q != 1 {
			t.Errorf("%s: %d older_line questions holding the CVE whose record names only later DSM lines, want 1", c.device, q)
		}
		if q := s.count(`SELECT count(*) FROM fnd_question WHERE asset_id = ? AND cve IN ('CVE-2024-10441', 'CVE-2026-4036', 'CVE-2026-176954', 'CVE-2026-123007', 'CVE-2026-114938', 'CVE-2025-22225')`, c.device); q != 0 {
			t.Errorf("%s: %d questions about CVEs whose record has versions", c.device, q)
		}
	}
	// the CVE page names the product a device is matched as, not the first name in alphabetical order
	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	for cve, want := range map[string]string{"CVE-2026-123007": "nginx", "CVE-2026-114938": "Java"} {
		if b, ok, err := fs.Store().Brief(ctx, cve); err != nil || !ok || b.Display != want {
			t.Errorf("%s: brief names %q (%v %v), want %q", cve, b.Display, ok, err, want)
		}
	}
	_ = feeds.OriginNVD
}

// A person's more precise version of a scanned ESXi host keeps every finding of the host's update: correcting "8.0" (the banner) to
// "8.0 U3" is the same release, so no finding fixed only in a later U3 build closes as "the match was corrected".
func TestScannedESXi_CorrectionKeepsItsFindings(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	recent := time.Now().AddDate(0, -2, 0)
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedNVD(ctx, tx, "CVE-2026-41703", recent, 7.0); err != nil {
			return err
		}
		return seedVendorRow(ctx, tx, "CVE-2026-41703", "vmware", "esxi", "8.0", "ESXi80U3i-25205845")
	})
	if err != nil {
		t.Fatal(err)
	}
	host := scannedESXi(ctx, t, s)
	if _, err := s.d.Findings.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := openFindings(t, s, host); !slices.Contains(got, "CVE-2026-41703") {
		t.Fatalf("scanned 8.0 Update 3 host: %v", got)
	}
	lines, err := s.d.Inventory.SoftwareLines(ctx, host)
	if err != nil || len(lines) != 1 || lines[0].Version == nil || *lines[0].Version != "8.0.3" || !strings.Contains(lines[0].Display, "Update 3 (build 24022510)") {
		t.Fatalf("scanned line %+v %v: want version 8.0.3 with its update and build", lines, err)
	}
	v := "8.0 U3"
	if err := s.d.Inventory.EditSoftware(ctx, "it@acme.example", host, lines[0].ID, inventory.SoftwareEdit{Version: &v}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Findings.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := openFindings(t, s, host); !slices.Contains(got, "CVE-2026-41703") {
		t.Fatalf("after the correction to 8.0 U3: %v", got)
	}
}

// scannedESXi is an ESXi 8.0 Update 3 host as the active sensor reads its API (version "8.0", the update in the CPE, the build in the name).
func scannedESXi(ctx context.Context, t *testing.T, s *stack) string {
	t.Helper()
	d := "VMware ESXi 8.0 Update 3 (build 24022510)"
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.67")}
	// the scan's host first, as a device check records it: a list by address only attaches to a device, never makes one
	if err := s.d.Inventory.Record(ctx, []observe.Observation{{AssetHint: hint, Field: observe.Hostname, Value: "esxi-01", Source: observe.Nmap, Confidence: 0.6}}); err != nil {
		t.Fatal(err)
	}
	if err := s.d.Inventory.ReplaceSoftware(ctx, observe.AssetHint{IP: netip.MustParseAddr("192.0.2.67")}, observe.Nmap, nil, []observe.Software{{Display: d, Vendor: "vmware", Product: "esxi", Version: "8.0",
		CPE: "cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*", Confidence: 0.8}}); err != nil {
		t.Fatal(err)
	}
	l, err := s.d.Inventory.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range l.Items {
		if d.IP == "192.0.2.67" {
			return d.ID
		}
	}
	t.Fatal("the scanned host is not in the list")
	return ""
}

func openFindings(t *testing.T, s *stack, device string) []string {
	t.Helper()
	rows, err := s.d.DB.Reader().QueryContext(t.Context(), `SELECT cve FROM fnd_finding WHERE asset_id = ? AND state = 'open' ORDER BY cve`, device)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}
