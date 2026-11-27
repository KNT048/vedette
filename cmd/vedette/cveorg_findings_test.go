package main

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
)

// review H1, H2, M1, M2, L7 of F6a: a CNA record goes through feeds' conversion and the wiring's source mapping
// into findings' matcher, as on the box. CVE.org ranges may raise a match, and close one only when the record is
// unambiguous: a complete list, sane ranges, no holes, a product without a comparator of its own.
func TestCVEOrgRecordsThroughTheMatcher(t *testing.T) {
	t.Parallel()
	const cve = "CVE-2026-1000"
	rec := func(assigner, affected string) []byte { // each vendor's own CNA writes its record (feeds ownCNA)
		return []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"` + cve + `","state":"PUBLISHED","assignerShortName":"` + assigner +
			`"},"containers":{"cna":{"affected":[` + affected + `]}}}`)
	}
	pan := `{"vendor":"Palo Alto Networks","product":"PAN-OS","defaultStatus":"unaffected","versions":[{"version":"9.1.0","status":"unaffected"},{"version":"10.2.0","lessThan":"10.2.9-h1","status":"affected","versionType":"custom","changes":[{"at":"10.2.9-h1","status":"unaffected"}]}]}`
	forti := `{"vendor":"Fortinet","product":"FortiOS","defaultStatus":"unaffected","versions":[{"version":"7.4.0","lessThanOrEqual":"7.4.2","status":"affected","versionType":"semver"},{"version":"7.2.0","lessThanOrEqual":"7.2.6","status":"affected","versionType":"semver"}]}`
	partial := `{"vendor":"Acme","product":"Gateway","versions":[{"version":"3.0","lessThan":"3.0.5","status":"affected"}]}`
	ivanti := `{"vendor":"Ivanti","product":"Connect Secure","defaultStatus":"unknown","versions":[{"version":"9.1","status":"affected"},{"version":"22.6","status":"affected"}]}`
	junos := `{"vendor":"Juniper Networks","product":"Junos OS","defaultStatus":"unaffected","versions":[{"version":"21.4","lessThan":"21.4R3-S5","status":"affected","versionType":"semver"}]}`
	reversed := `{"vendor":"Acme","product":"Gateway","defaultStatus":"unaffected","versions":[{"version":"3.0.5","lessThan":"3.0","status":"affected"}]}`
	citrix := `{"vendor":"Citrix","product":"NetScaler ADC","defaultStatus":"unaffected","versions":[{"version":"13.1","lessThan":"13.1-51.15","status":"affected","versionType":"semver"}]}`
	hole := `{"vendor":"Acme","product":"Gateway","defaultStatus":"unaffected","versions":[{"version":"1.0","lessThan":"2.0","status":"affected"},{"version":"1.5.3","status":"unaffected"}]}`
	for _, c := range []struct {
		name, vendor, product, affected, version string
		want                                     string // version (a version finding), product (a product finding), closed (not affected)
	}{
		{"complete list, inside", "Palo Alto Networks", "PAN-OS", pan, "10.2.5", "version"},
		{"complete list, outside: closed", "Palo Alto Networks", "PAN-OS", pan, "9.1.17", "closed"},
		{"lessThanOrEqual, inside", "Fortinet", "FortiOS", forti, "7.4.2", "version"},
		{"lessThanOrEqual, outside", "Fortinet", "FortiOS", forti, "7.4.3", "closed"},
		{"partial list (no defaultStatus), inside", "Acme", "Gateway", partial, "3.0.2", "version"},
		{"partial list, an older branch it does not list (H2)", "Acme", "Gateway", partial, "2.9", "product"},
		{"branch names with unknown default (H2)", "Ivanti", "Connect Secure", ivanti, "22.6R2", "product"},
		{"Junos needs its own comparator (H1)", "Juniper", "Junos OS", junos, "21.4R3.15", "product"},
		{"Citrix build written with dots needs its own comparator (review R2-M1)", "Citrix", "NetScaler ADC", citrix, "13.1.49.13", "product"},
		{"reversed range (M1)", "Acme", "Gateway", reversed, "3.0.2", "product"},
		{"unaffected backport inside the range (M2)", "Acme", "Gateway", hole, "1.5.3", "product"},
	} {
		res, err := feeds.ParseCVERecord(rec(strings.ToLower(strings.ReplaceAll(c.vendor, " ", "_")), c.affected), cve)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		v := findings.Vuln{CVE: cve, Vendor: c.vendor, Product: c.product}
		rows, src := feeds.KEVRecordRows(res.Ranges, c.vendor, c.product) // as cmd/vedette reads what feeds stored
		if len(rows) > 0 {
			v.RangesFrom = rangesFrom(src)
			for _, r := range rows {
				v.Affected = append(v.Affected, findings.Affected{CPE: r.CPE,
					Range: findings.VersionRange{StartIncl: r.StartIncl, StartExcl: r.StartExcl, EndIncl: r.EndIncl, EndExcl: r.EndExcl}})
			}
		}
		a := findings.Asset{ID: "a", Name: "dev", Software: []findings.Software{{ID: "s", Display: c.product, Vendor: c.vendor, Product: c.product,
			Version: c.version, KevKeys: []string{productid.Key(c.vendor, c.product)}}}}
		m := findings.MatchAsset(a, []findings.Vuln{v}, map[string]bool{cve: true}, time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC))
		got := "none"
		switch all := append(m.New, m.Existing...); {
		case len(m.NotAffected) > 0:
			got = "closed"
		case len(all) == 1 && all[0].Basis == findings.BasisVersion:
			got = "version"
		case len(all) == 1, len(all) == 0 && len(m.NameOnly) == 1: // Undecided is no finding but "could not be checked" (NameOnly)
			got = "product"
		}
		if got != c.want {
			t.Errorf("%s (%s %s): %s, want %s (rows %+v, %s)", c.name, c.product, c.version, got, c.want, rows, src)
		}
	}
}
