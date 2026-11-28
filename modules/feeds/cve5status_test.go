package feeds

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// The status semantics of CVE JSON 5 (https://github.com/CVEProject/cve-schema/blob/main/schema/docs/versions.md) as the rows the
// match reads: a version takes the status of the entry that names it, else the entry's defaultStatus; without one, unknown. The table
// is every defaultStatus word by who assigned the record. "unaffected" for the versions an entry does not list counts only from the
// vendor's own CNA (ownCNA): a third party lists the releases it tested, and an entry that names no vendor does not say whose product
// it is. An entry whose defaultStatus is affected states every version
// affected, and the matcher reads it from version 0 (recordEvery); a version word alone ("all") without defaultStatus does not.
func TestCVE5Status_DefaultStatusByAssigner(t *testing.T) {
	t.Parallel()
	ranged := `"versions":[{"version":"4.0.0","lessThan":"4.0.1","status":"affected","versionType":"semver"}]`
	for _, c := range []struct {
		name, assigner, entry string
		def                   string // the default_status the rows keep
		vendorList            bool   // the product's list decides "not affected" too (matchRows' VendorList)
		every                 bool   // the matcher reads the row as every version (from 0)
	}{
		{"affected, the vendor's CNA", "acme", `{"vendor":"Acme","product":"Box","defaultStatus":"affected",` + ranged + `}`, DefaultAffected, true, true},
		{"affected, a third party", "VulnCheck", `{"vendor":"Acme","product":"Box","defaultStatus":"affected",` + ranged + `}`, DefaultAffected, true, true},
		{"unaffected, the vendor's CNA", "acme", `{"vendor":"Acme Inc.","product":"Box","defaultStatus":"unaffected",` + ranged + `}`, DefaultUnaffected, true, false},
		{"unaffected, a third party", "VulnCheck", `{"vendor":"Acme","product":"Box","defaultStatus":"unaffected",` + ranged + `}`, DefaultUnknown, false, false},
		{"unaffected, no vendor named", "acme", `{"vendor":"n/a","product":"Box","defaultStatus":"unaffected",` + ranged + `}`, DefaultUnknown, false, false},
		{"unaffected, no vendor named by a third party", "mitre", `{"vendor":"","product":"Box","defaultStatus":"unaffected",` + ranged + `}`, DefaultUnknown, false, false},
		{"unknown", "acme", `{"vendor":"Acme","product":"Box","defaultStatus":"unknown",` + ranged + `}`, DefaultUnknown, false, false},
		{"absent", "acme", `{"vendor":"Acme","product":"Box",` + ranged + `}`, DefaultUnknown, false, false},
		{"absent, every version as a word", "acme", `{"vendor":"Acme","product":"Box","versions":[{"version":"all","status":"affected"}]}`, DefaultUnknown, false, false},
	} {
		raw := strings.Replace(string(record(c.entry)), `"assignerShortName":"acme"`, `"assignerShortName":"`+c.assigner+`"`, 1)
		rec, err := ParseCVERecord([]byte(raw), "CVE-2026-1000")
		if err != nil || len(rec.Ranges) != 1 {
			t.Fatalf("%s: %+v %v", c.name, rec.Ranges, err)
		}
		r := asRead(rec).Ranges[0]
		if r.DefaultStatus != c.def {
			t.Errorf("%s: default_status %q, want %q", c.name, r.DefaultStatus, c.def)
		}
		nvd := Range{CVE: r.CVE, Origin: OriginNVD, Part: "a", Vendor: "acme", Product: "box", CPE: "cpe:2.3:a:acme:box:4.0.0:*:*:*:*:*:*:*"}
		got := matchRows([]Range{nvd, r})
		if len(got) != 2 || got[1].VendorList != c.vendorList || got[1].AffectedOnly == c.vendorList {
			t.Errorf("%s: beside NVD's rows %+v, want vendor list %v (else affected only)", c.name, got, c.vendorList)
		}
		row, ok := r.MatchRow()
		if every := ok && row.StartIncl == "0" && row.EndExcl == "" && row.EndIncl == ""; every != c.every {
			t.Errorf("%s: the matcher's row %+v, every version %v, want %v", c.name, row, every, c.every)
		}
	}
}

// Migration 0003 reads every stored CNA or ADP generic row's "unaffected" as unknown (the rows do not say who assigned the record) and
// leaves NVD's rows, an "affected" word and the rows kept in a vendor's notation as they are.
func TestMigration0003_StoredUnaffectedWaitsForTheReRead(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateTo(ctx, db, "feeds", Migrations, 2); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ origin, versionType, def, want string }{
		{"cna", "", "unaffected", "unknown"},
		{"adp", "semver", "unaffected", "unknown"},
		{"cna", "", "affected", "affected"},
		{"cna", VendorNotation + "semver", "unaffected", "unaffected"},
		{"nvd", "", "", ""},
	}
	write(t, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve (cve, updated_at) VALUES ('CVE-2026-3008', '2026-11-27T00:00:00.000Z')`); err != nil {
			return err
		}
		for i, r := range rows {
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cve_range (id, cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, version_type, default_status)
VALUES (?, 'CVE-2026-3008', ?, '', 'notepad', 'notepad', '', '8.9.3', '', '8.9.3', '', ?, ?)`, i+1, r.origin, r.versionType, r.def); err != nil {
				return err
			}
		}
		return nil
	})
	if err := store.Migrate(ctx, db, "feeds", Migrations); err != nil {
		t.Fatal(err)
	}
	for i, r := range rows {
		var got string
		if err := db.Reader().QueryRowContext(ctx, `SELECT default_status FROM feeds_cve_range WHERE id = ?`, i+1).Scan(&got); err != nil || got != r.want {
			t.Errorf("%s %q %q: %q %v, want %q", r.origin, r.versionType, r.def, got, err, r.want)
		}
	}
}
