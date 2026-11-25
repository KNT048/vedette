package main

import (
	"database/sql"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
)

// Juniper's record of CVE-2026-21913 limits its entry to EX4000 models, says versions it does not list are unaffected, states
// "unaffected" from 0 before 24.4R1, and NVD lists exact 24.4 and 25.2 releases only. End to end on the binary's wiring: a switch whose
// Junos release a person entered as 15.1R7.9 (older than every line NVD lists, so NVD alone would ask) gets neither a finding nor a
// question: the vendor's statement decides "not affected". A 24.4R1 switch (inside the EX4000-only range) is not proved affected by
// that range: it gets no version finding from the vendor's rows.
func TestJuniperRecord_UnaffectedStatementDecidesTheSwitch(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const cve = "CVE-2026-21913"
	record := []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-21913","state":"PUBLISHED","assignerShortName":"juniper"},` +
		`"containers":{"cna":{"descriptions":[{"lang":"en","value":"A flaw in Junos OS on EX4000 models."}],` +
		`"affected":[{"vendor":"Juniper Networks","product":"Junos OS","defaultStatus":"unaffected","platforms":["EX4000-48T","EX4000-48P","EX4000-48MP"],"versions":[` +
		`{"version":"0","lessThan":"24.4R1","status":"unaffected","versionType":"semver"},` +
		`{"version":"24.4","lessThan":"24.4R2","status":"affected","versionType":"semver"},` +
		`{"version":"25.2","lessThan":"25.2R1-S2, 25.2R2","status":"affected","versionType":"semver"}]}]}}}`)
	rec, err := feeds.ParseCVERecord(record, cve)
	if err != nil {
		t.Fatal(err)
	}
	err = s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedNVD(ctx, tx, cve, time.Now().AddDate(0, -1, 0), 7.5); err != nil {
			return err
		}
		for _, release := range []string{"24.4:-", "24.4:r1", "24.4:r1-s2", "24.4:r1-s3", "25.2:-", "25.2:r1", "25.2:r1-s1", "25.2:r2"} {
			if err := seedRange(ctx, tx, cve, "cpe:2.3:o:juniper:junos:"+release+":*:*:*:*:*:*", "", "", "", ""); err != nil {
				return err
			}
		}
		for _, r := range rec.Ranges {
			var plats any
			if len(r.Platforms) > 0 {
				b, err := json.Marshal(r.Platforms)
				if err != nil {
					return err
				}
				plats = string(b)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, fixed, version_type, default_status, platforms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, cve, r.Origin, r.Part, r.Vendor, r.Product, r.CPE, r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl, r.Fixed, r.VersionType, r.DefaultStatus, plats); err != nil {
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
		r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "juniper-junos-os", Version: version, Name: name, IP: ip})
		if err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	old, inRange := add("ex-old", "15.1R7.9", "192.0.2.21"), add("ex-new", "24.4R1", "192.0.2.22")
	if _, err := s.d.Findings.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := openFindings(t, s, old); slices.Contains(got, cve) {
		t.Errorf("15.1R7.9: %s open, which Juniper states unaffected before 24.4R1", cve)
	}
	if q := s.count(`SELECT count(*) FROM fnd_question WHERE asset_id = ? AND cve = ?`, old, cve); q != 0 {
		t.Errorf("15.1R7.9: %d questions about %s, whose record states it unaffected", q, cve)
	}
	if n := s.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = ? AND cve = ? AND evidence LIKE '%Juniper fixed%'`, inRange, cve); n != 0 {
		t.Errorf("24.4R1: a finding from the EX4000-only range, which says nothing about this model")
	}
}

// A record with two entries for Junos OS, each limited to other models: the EX4000 entry states releases before 24.4R1 unaffected,
// the MX entry names affected 22.2 and 23.4 releases and says nothing about 23.2. The EX4000 statement does not hold for an MX, and
// Vedette does not know the device's model: a 23.2R1 device is not closed "not affected" on the EX4000 statement, NVD's range decides.
func TestJuniperRecord_OneModelsStatementDoesNotCloseAnother(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const cve = "CVE-2026-21914"
	record := []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-21914","state":"PUBLISHED","assignerShortName":"juniper"},` +
		`"containers":{"cna":{"descriptions":[{"lang":"en","value":"A flaw in Junos OS on EX4000 and MX Series."}],` +
		`"affected":[{"vendor":"Juniper Networks","product":"Junos OS","defaultStatus":"unaffected","platforms":["EX4000-48T"],"versions":[` +
		`{"version":"0","lessThan":"24.4R1","status":"unaffected","versionType":"semver"},` +
		`{"version":"24.4","lessThan":"24.4R2","status":"affected","versionType":"semver"}]},` +
		`{"vendor":"Juniper Networks","product":"Junos OS","defaultStatus":"unaffected","platforms":["MX Series"],"versions":[` +
		`{"version":"22.2","lessThan":"22.2R3-S4","status":"affected","versionType":"semver"},` +
		`{"version":"23.4","lessThan":"23.4R2","status":"affected","versionType":"semver"}]}]}}}`)
	rec, err := feeds.ParseCVERecord(record, cve)
	if err != nil {
		t.Fatal(err)
	}
	err = s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedNVD(ctx, tx, cve, time.Now().AddDate(0, -1, 0), 7.5); err != nil {
			return err
		}
		if err := seedRange(ctx, tx, cve, "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*", "", "", "", "24.4R2"); err != nil {
			return err
		}
		for _, r := range rec.Ranges {
			var plats any
			if len(r.Platforms) > 0 {
				b, err := json.Marshal(r.Platforms)
				if err != nil {
					return err
				}
				plats = string(b)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, fixed, version_type, default_status, platforms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, cve, r.Origin, r.Part, r.Vendor, r.Product, r.CPE, r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl, r.Fixed, r.VersionType, r.DefaultStatus, plats); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "juniper-junos-os", Version: "23.2R1", Name: "edge-mx", IP: "192.0.2.31"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.d.Findings.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	open := slices.Contains(openFindings(t, s, r.ID), cve)
	asked := s.count(`SELECT count(*) FROM fnd_question WHERE asset_id = ? AND cve = ?`, r.ID, cve) > 0
	if !open && !asked {
		t.Errorf("23.2R1: %s neither open nor asked; the EX4000 entry's statement closed it for a device of unknown model", cve)
	}
}

// On a disagreement the affected side wins: Juniper's record states releases before 24.4R1 unaffected, while NVD lists 22.2
// releases before 22.2R3 and the exact release 23.2R1 as affected. A device NVD's rows cover is never closed "not affected" on the
// vendor's statement; one no affected row covers (15.1R7.9) still is.
func TestJuniperRecord_NVDAffectedRowBeatsUnaffectedStatement(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	const cve = "CVE-2026-21915"
	record := []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2026-21915","state":"PUBLISHED","assignerShortName":"juniper"},` +
		`"containers":{"cna":{"descriptions":[{"lang":"en","value":"A flaw in Junos OS on EX4000 models."}],` +
		`"affected":[{"vendor":"Juniper Networks","product":"Junos OS","defaultStatus":"unaffected","platforms":["EX4000-48T"],"versions":[` +
		`{"version":"0","lessThan":"24.4R1","status":"unaffected","versionType":"semver"},` +
		`{"version":"24.4","lessThan":"24.4R2","status":"affected","versionType":"semver"}]}]}}}`)
	rec, err := feeds.ParseCVERecord(record, cve)
	if err != nil {
		t.Fatal(err)
	}
	err = s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedNVD(ctx, tx, cve, time.Now().AddDate(0, -1, 0), 7.5); err != nil {
			return err
		}
		if err := seedRange(ctx, tx, cve, "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*", "22.2", "", "", "22.2R3"); err != nil {
			return err
		}
		for _, release := range []string{"23.2:r1", "24.4:r1"} {
			if err := seedRange(ctx, tx, cve, "cpe:2.3:o:juniper:junos:"+release+":*:*:*:*:*:*", "", "", "", ""); err != nil {
				return err
			}
		}
		for _, r := range rec.Ranges {
			var plats any
			if len(r.Platforms) > 0 {
				b, err := json.Marshal(r.Platforms)
				if err != nil {
					return err
				}
				plats = string(b)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, fixed, version_type, default_status, platforms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, cve, r.Origin, r.Part, r.Vendor, r.Product, r.CPE, r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl, r.Fixed, r.VersionType, r.DefaultStatus, plats); err != nil {
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
		r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "juniper-junos-os", Version: version, Name: name, IP: ip})
		if err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	inRange, exact, old := add("ex-range", "22.2R1", "192.0.2.41"), add("ex-exact", "23.2R1", "192.0.2.42"), add("ex-old", "15.1R7.9", "192.0.2.43")
	if _, err := s.d.Findings.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]string{"22.2R1 (NVD range)": inRange, "23.2R1 (NVD exact release)": exact} {
		if !slices.Contains(openFindings(t, s, id), cve) && s.count(`SELECT count(*) FROM fnd_question WHERE asset_id = ? AND cve = ?`, id, cve) == 0 {
			t.Errorf("%s: %s neither open nor asked; the vendor's unaffected statement overrode NVD's affected row", name, cve)
		}
	}
	if slices.Contains(openFindings(t, s, old), cve) || s.count(`SELECT count(*) FROM fnd_question WHERE asset_id = ? AND cve = ?`, old, cve) != 0 {
		t.Errorf("15.1R7.9: %s open or asked, though no affected row covers it and Juniper states it unaffected", cve)
	}
}
