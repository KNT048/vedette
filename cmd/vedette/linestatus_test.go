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
