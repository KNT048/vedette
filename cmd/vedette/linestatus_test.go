package main

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
)

// The match set carries a vendor's release-line statements (findings M-13): a CVE NVD names only at another line's exact release is
// still in reach of a Node.js 22 device by the vendor's line row, and the device gets the finding with the vendor's fix of its line; a
// CVE the vendor lists for line 26 only is not affected on line 22 by its convention while line 22 was supported.
func TestMatchSet_CarriesVendorLineStatements(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	pub := time.Now().AddDate(0, -1, 0)
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, c := range []string{"CVE-2026-105481", "CVE-2026-48936"} {
			if err := seedNVD(ctx, tx, c, pub, 5); err != nil {
				return err
			}
			if err := seedRange(ctx, tx, c, "cpe:2.3:a:nodejs:node.js:26.3.0:*:*:*:*:*:*:*", "", "", "", ""); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_line_cve (source_id, product, cve, stated_at, ref) VALUES ('nodejs-security-wg', 'node.js|node.js', ?, ?, '')`,
				c, pub.Format(time.DateOnly)); err != nil {
				return err
			}
		}
		for _, q := range []string{
			`INSERT INTO feeds_line_status (source_id, product, cve, line, status, fixed, explicit) VALUES ('nodejs-security-wg', 'node.js|node.js', 'CVE-2026-105481', '22', 'affected', '22.23.4', 1)`,
			`INSERT INTO feeds_line_status (source_id, product, cve, line, status, fixed, explicit) VALUES ('nodejs-security-wg', 'node.js|node.js', 'CVE-2026-48936', '26', 'affected', '26.3.1', 1)`,
			`INSERT INTO feeds_line_support (product, line, source_id, released, assessed_until) VALUES ('node.js|node.js', '22', 'endoflife-date', '2024-04-24', '2027-04-30')`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE feeds_source SET last_success = ? WHERE id IN ('nodejs-security-wg', 'endoflife-date')`, store.FormatTS(time.Now().UTC()))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	host := findings.Asset{ID: "dev", Name: "dev01", Software: []findings.Software{{ID: "node", Display: "Node.js", Vendor: "Node.js", Product: "Node.js",
		Version: "22.19.0", Source: "agent"}}}
	set, err := findingsFeeds{st: fs.Store()}.MatchSet(ctx, findings.NewMatchScope([]findings.Asset{host}, nil))
	if err != nil {
		t.Fatal(err)
	}
	res := findings.MatchAsset(host, set, map[string]bool{"CVE-2026-48936": true}, time.Now())
	if len(res.New) != 1 || res.New[0].CVE != "CVE-2026-105481" || !strings.Contains(res.New[0].Evidence.Summary, "22.23.4") {
		t.Fatalf("new %+v", res.New)
	}
	if len(res.NotAffected) != 1 || res.NotAffected[0].CVE != "CVE-2026-48936" {
		t.Fatalf("not affected %+v", res.NotAffected)
	}
}

// Oracle's CSAF statements reach the match set with the source's convention and the builds it numbers: Java 8 Update 491 as Windows
// reports it (8.0.4910.10) gets the finding Oracle's "8u491" row states, where NVD's exact update491 row does not compare; Temurin 21 is
// not affected by Oracle's convention row for line 21; Temurin 8u492, past Oracle's 8u491 by its own numbering, is not closed by it.
func TestMatchSet_CarriesOracleLineStatements(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	pub := time.Now().AddDate(0, -1, 0)
	const cve = "CVE-2026-46917"
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedNVD(ctx, tx, cve, pub, 5); err != nil {
			return err
		}
		if err := seedRange(ctx, tx, cve, "cpe:2.3:a:oracle:jdk:25.0.3:*:*:*:*:*:*:*", "", "", "", ""); err != nil {
			return err
		}
		for _, q := range []string{
			`INSERT INTO feeds_line_cve (source_id, product, cve, stated_at, ref) VALUES ('oracle-cpu-csaf', 'oracle|java se', '` + cve + `', '` + pub.Format(time.DateOnly) + `', 'https://www.oracle.com/security-alerts/cpujul2026.html')`,
			`INSERT INTO feeds_line_status (source_id, product, cve, line, status, last_affected, explicit) VALUES ('oracle-cpu-csaf', 'oracle|java se', '` + cve + `', '8', 'affected', '1.8.0_491', 1)`,
			`INSERT INTO feeds_line_status (source_id, product, cve, line, status, explicit) VALUES ('oracle-cpu-csaf', 'oracle|java se', '` + cve + `', '21', 'unaffected', 0)`,
			`UPDATE feeds_source SET enabled = 1, last_success = '` + store.FormatTS(time.Now().UTC()) + `' WHERE id = 'oracle-cpu-csaf'`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	java := func(display, version string) findings.Software {
		return findings.Software{ID: "java", Display: display, Vendor: "Oracle", Product: "Java SE", Version: version, Source: "agent"}
	}
	host := findings.Asset{ID: "pc", Name: "pc01", Software: []findings.Software{java("Java 8 Update 491 (64-bit)", "8.0.4910.10")}}
	set, err := findingsFeeds{st: fs.Store()}.MatchSet(ctx, findings.NewMatchScope([]findings.Asset{host}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if res := findings.MatchAsset(host, set, nil, time.Now()); len(res.New) != 1 || !strings.Contains(res.New[0].Evidence.Summary, "up to 1.8.0_491") {
		t.Fatalf("Java 8: new %+v", res.New)
	}
	host.Software[0] = java("Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "21.0.7")
	if res := findings.MatchAsset(host, set, map[string]bool{cve: true}, time.Now()); len(res.NotAffected) != 1 {
		t.Fatalf("Temurin 21: not affected %+v", res.NotAffected)
	}
	host.Software[0] = java("Eclipse Temurin JDK with Hotspot 8u492-b09 (x64)", "1.8.0_492")
	if res := findings.MatchAsset(host, set, map[string]bool{cve: true}, time.Now()); len(res.NotAffected) != 0 {
		t.Fatalf("Temurin 8u492 closed by Oracle's numbering: %+v", res.NotAffected)
	}
}
