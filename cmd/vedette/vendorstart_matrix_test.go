package main

import (
	"database/sql"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
)

// Where a vendor's affected ranges start, as one scenario matrix through the binary's wiring (the CVE record as feeds parse it, the
// match pass, the questions). A vendor that states where a flaw came in ("23.2 versions from 23.2R2-S1 before 23.2R2-S5") says an
// older release is not affected; a range with no start ("all versions before 23.2R2-S7") reaches every older release; ranges that each
// start at a branch's own start ("24.2 before 24.2R2-S3") say nothing about older branches the vendor no longer lists.
func TestVendorRangeStartMatrix(t *testing.T) {
	t.Parallel()
	const (
		cve  = "CVE-2099-72001"
		old  = "15.1R7.9"
		note = "older than the first affected release the vendor lists (23.2R2-S1)"
	)
	// record is Juniper's CVE record of cve with the given affected versions (each {from, lessThan}; from "0" is no start).
	record := func(t *testing.T, versions [][2]string) feeds.CVERecord {
		t.Helper()
		var vs []map[string]string
		for _, v := range versions {
			vs = append(vs, map[string]string{"version": v[0], "lessThan": v[1], "status": "affected", "versionType": "semver"})
		}
		b, err := json.Marshal(vs)
		if err != nil {
			t.Fatal(err)
		}
		raw := `{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"` + cve + `","state":"PUBLISHED","assignerShortName":"juniper"},` +
			`"containers":{"cna":{"descriptions":[{"lang":"en","value":"A flaw in Junos OS."}],` +
			`"affected":[{"vendor":"Juniper Networks","product":"Junos OS","versions":` + string(b) + `}]}}}`
		rec, err := feeds.ParseCVERecord([]byte(raw), cve)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	putRecord := func(t *testing.T, s *stack, rec feeds.CVERecord) {
		t.Helper()
		ctx := t.Context()
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			for _, r := range rec.Ranges {
				if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, fixed, version_type, default_status, platforms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`, cve, r.Origin, r.Part, r.Vendor, r.Product, r.CPE, r.StartIncl, r.StartExcl, r.EndIncl, r.EndExcl, r.Fixed, r.VersionType, r.DefaultStatus); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	setup := func(t *testing.T, versions [][2]string) (*stack, func(string) string) {
		t.Helper()
		s := newStack(t)
		ctx := t.Context()
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
			if err := seedKEVRow(ctx, tx, cve, "Juniper", "Junos OS", "Juniper Junos OS flaw", time.Now().AddDate(0, -2, 0), false, false); err != nil {
				return err
			}
			return seedNVD(ctx, tx, cve, time.Now().AddDate(0, -1, 0), 7.5)
		}); err != nil {
			t.Fatal(err)
		}
		if versions != nil {
			putRecord(t, s, record(t, versions))
		}
		add := func(version string) string {
			t.Helper()
			r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "juniper-junos-os", Version: version,
				Name: "ex-" + strings.NewReplacer(".", "-").Replace(version), IP: "192.0.2." + map[string]string{old: "31", "23.2R2-S3": "32", "23.2R1": "33"}[version]})
			if err != nil {
				t.Fatal(err)
			}
			return r.ID
		}
		return s, add
	}
	reconcile := func(t *testing.T, s *stack) {
		t.Helper()
		if _, err := s.d.Findings.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	questions := func(s *stack, device string) int {
		return s.count(`SELECT count(*) FROM fnd_question WHERE asset_id = ? AND (cve = ? OR json_extract(detail, '$.cve_list') LIKE '%' || ? || '%')`, device, cve, cve)
	}

	t.Run("ranges start inside a branch / older release: not affected, no question", func(t *testing.T) {
		t.Parallel()
		s, add := setup(t, [][2]string{{"23.2R2-S1", "23.2R2-S5"}, {"24.2", "24.2R2-S3"}})
		dev := add(old)
		reconcile(t, s)
		if slices.Contains(openFindings(t, s, dev), cve) || questions(s, dev) != 0 {
			t.Errorf("%s: findings %v, %d questions; Juniper states the flaw came in with 23.2R2-S1", old, openFindings(t, s, dev), questions(s, dev))
		}
	})
	t.Run("ranges start inside a branch / a release inside the range: affected", func(t *testing.T) {
		t.Parallel()
		s, add := setup(t, [][2]string{{"23.2R2-S1", "23.2R2-S5"}, {"24.2", "24.2R2-S3"}})
		dev := add("23.2R2-S3")
		reconcile(t, s)
		if !slices.Contains(openFindings(t, s, dev), cve) {
			t.Errorf("23.2R2-S3 is inside 23.2R2-S1 .. 23.2R2-S5: want a finding, got %v", openFindings(t, s, dev))
		}
	})
	t.Run("ranges start inside a branch / same branch before the start: not affected", func(t *testing.T) {
		t.Parallel()
		s, add := setup(t, [][2]string{{"23.2R2-S1", "23.2R2-S5"}, {"24.2", "24.2R2-S3"}})
		dev := add("23.2R1")
		reconcile(t, s)
		if slices.Contains(openFindings(t, s, dev), cve) || questions(s, dev) != 0 {
			t.Errorf("23.2R1 is before 23.2R2-S1: findings %v, %d questions", openFindings(t, s, dev), questions(s, dev))
		}
	})
	t.Run("ranges start at branch starts only / older branch: stays a question", func(t *testing.T) {
		t.Parallel()
		s, add := setup(t, [][2]string{{"24.2", "24.2R2-S3"}, {"24.4", "24.4R1-S2"}})
		dev := add(old)
		reconcile(t, s)
		if slices.Contains(openFindings(t, s, dev), cve) {
			t.Errorf("%s: a finding from ranges that say nothing about 15.1", old)
		}
		if questions(s, dev) == 0 {
			t.Errorf("%s: no question; the vendor lists only its supported branches, so whether 15.1 is affected is not known", old)
		}
	})
	t.Run("a range with no start / older release: affected", func(t *testing.T) {
		t.Parallel()
		s, add := setup(t, [][2]string{{"0", "23.2R2-S7"}, {"24.2", "24.2R2-S3"}})
		dev := add(old)
		reconcile(t, s)
		if !slices.Contains(openFindings(t, s, dev), cve) {
			t.Errorf("all versions before 23.2R2-S7 include %s: want a finding, got %v", old, openFindings(t, s, dev))
		}
	})
	t.Run("an exploited CVE's finding closes with the vendor's reason when the ranges say where the flaw came in", func(t *testing.T) {
		t.Parallel()
		s, add := setup(t, nil)
		ctx := t.Context()
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error { // NVD at first: every Junos release before 24.2R2-S3
			return seedRange(ctx, tx, cve, "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*", "", "", "", "24.2R2-S3")
		}); err != nil {
			t.Fatal(err)
		}
		dev := add(old)
		reconcile(t, s)
		if !slices.Contains(openFindings(t, s, dev), cve) {
			t.Fatalf("%s: no finding from NVD's range", old)
		}
		if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error { // NVD corrects its row; Juniper's record says where the flaw came in
			if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_cve_range WHERE cve = ?`, cve); err != nil {
				return err
			}
			// as a pull of the record does: the CVE's row changes, so the match pass reads the list again
			_, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET updated_at = ? WHERE cve = ?`, store.FormatTS(time.Now().UTC().Add(time.Minute)), cve)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		putRecord(t, s, record(t, [][2]string{{"23.2R2-S1", "23.2R2-S5"}, {"24.2", "24.2R2-S3"}}))
		reconcile(t, s)
		var state, resolution, closing string
		if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT state, ifnull(resolution, ''), ifnull(note, '') FROM fnd_finding WHERE asset_id = ? AND cve = ?`, dev, cve).
			Scan(&state, &resolution, &closing); err != nil {
			t.Fatal(err)
		}
		if state != "handled" || resolution != "not_relevant" || !strings.Contains(closing, note) {
			t.Errorf("state %s, resolution %s, note %q: want closed as not relevant with %q", state, resolution, closing, note)
		}
	})
}
