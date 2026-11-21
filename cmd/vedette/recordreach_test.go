package main

import (
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
)

// recordReach pairs a product as CVE records name it (the CNA's vendor and product) with the software line a device reports for it
// (the inventory's names and the CPE a scan or an agent gives).
var recordReach = []struct {
	recVendor, recProduct      string
	vendor, product, cpe, vers string
}{
	{"Palo Alto Networks", "PAN-OS", "Palo Alto Networks", "PAN-OS", "cpe:2.3:o:paloaltonetworks:pan-os:11.1.0:*:*:*:*:*:*:*", "11.1.0"},
	{"Grafana Labs", "Grafana", "Grafana Labs", "Grafana", "", "11.0.0"},
	{"Jenkins Project", "Jenkins", "Jenkins", "Jenkins", "cpe:2.3:a:jenkins:jenkins:2.440:*:*:*:*:*:*:*", "2.440"},
	{"Extreme Networks", "ExtremeXOS", "Extreme Networks", "ExtremeXOS", "", "31.7.1"},
	{"Hewlett Packard Enterprise (HPE)", "HPE Integrated Lights-Out 5 (iLO 5)", "Hewlett Packard Enterprise (HPE)", "HPE Integrated Lights-Out 5 (iLO 5)", "", "2.80"},
	{"Ivanti", "Connect Secure", "Ivanti", "Connect Secure", "cpe:2.3:a:ivanti:connect_secure:22.7:*:*:*:*:*:*:*", "22.7"},
	{"Apache Software Foundation", "Apache HTTP Server", "Apache", "HTTP Server", "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*", "2.4.58"},
	{"Fortinet", "FortiOS", "Fortinet", "FortiOS", "cpe:2.3:o:fortinet:fortios:7.2.5:*:*:*:*:*:*:*", "7.2.5"},
	{"SonicWall", "SonicOS", "SonicWall", "SonicOS", "", "7.0.1"},
	{"Jenkins Project", "Jenkins Script Security Plugin", "Jenkins", "Jenkins", "cpe:2.3:a:jenkins:jenkins:2.440:*:*:*:*:*:*:*", "2.440"}, // another product: never reached
}

// The class "a CVE known only from its record misses the device": a record names a product by the CNA's names (feeds keeps them as
// RecordProductKey: company words and the vendor's name in front dropped), the device by the inventory's and NVD's. Count the records
// (affected below a fixed release the device runs under) that reach the device through the match scope and the matcher. Measured:
// before the names were resolved through the product catalogue, 6 of the 9 reached it (those whose record names already were the
// device's); after, all 9, and the plugin of another product none.
func TestRecordRanges_ReachTheDeviceThatRunsTheProduct(t *testing.T) {
	t.Parallel()
	reached := 0
	for i, c := range recordReach {
		key := feeds.RecordProductKey(c.recVendor, c.recProduct)
		r := feeds.Range{CVE: "CVE-2026-90000" + string(rune('0'+i)), Origin: feeds.OriginCNA, Vendor: key.Vendor, Product: key.Product, EndExcl: "999",
			DefaultStatus: feeds.DefaultUnaffected}
		row, ok := r.MatchRow()
		if !ok {
			t.Fatalf("%s: no match row", c.recProduct)
		}
		a := findings.Asset{ID: "a", Name: "dev", Software: []findings.Software{{ID: "s", Display: c.product, Vendor: c.vendor, Product: c.product,
			Version: c.vers, CPE: c.cpe, Source: "manual"}}}
		v, p := feeds.MatchName(key.Vendor, key.Product, true)
		sc := findings.NewMatchScope([]findings.Asset{a}, nil)
		kept := sc.Keep(v, p, true) || sc.Keep(key.Vendor, key.Product, true)
		vuln := findings.Vuln{CVE: r.CVE, NVDAnswered: true, Origin: feeds.OriginCNA, RangesFrom: findings.RangesCVEOrg,
			Affected: []findings.Affected{{CPE: row.CPE, Range: findings.VersionRange{EndExcl: row.EndExcl}}}}
		res := findings.MatchAsset(a, []findings.Vuln{vuln}, nil, time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC))
		hit := kept && len(res.New) == 1
		want := i != len(recordReach)-1
		if hit != want {
			t.Errorf("%s %s: kept %v, findings %d; want reached %v (match row %s)", c.recVendor, c.recProduct, kept, len(res.New), want, row.CPE)
		}
		if hit {
			reached++
		}
	}
	t.Logf("record-only CVEs that reach the device running the product: %d of %d", reached, len(recordReach)-1)
}

// A pinned CVE whose ranges were all removed (NVD or the CNA rejected it) stays in the match set with no range, so the pass judges
// its findings gone instead of leaving them open forever; a pinned CVE the catalogue does not hold at all is not judged.
func TestMatchSet_APinnedCVEWithNoRangesIsStillJudged(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := seedNVD(ctx, tx, "CVE-2026-90100", time.Now().AddDate(0, -2, 0), 0); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE feeds_cve SET nvd_status = 'Rejected' WHERE cve = 'CVE-2026-90100'`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := findingsFeeds{st: fs.Store()}.MatchSet(ctx, findings.NewMatchScope(nil, []string{"CVE-2026-90100", "CVE-2026-90101"}))
	if err != nil {
		t.Fatal(err)
	}
	var cves []string
	for _, v := range got {
		cves = append(cves, v.CVE)
		if v.CVE == "CVE-2026-90100" && len(v.Affected) != 0 {
			t.Errorf("rejected CVE with ranges %+v", v.Affected)
		}
	}
	if !slices.Contains(cves, "CVE-2026-90100") || slices.Contains(cves, "CVE-2026-90101") {
		t.Errorf("match set %v: want the rejected pinned CVE and not the one the catalogue does not hold", cves)
	}
}
