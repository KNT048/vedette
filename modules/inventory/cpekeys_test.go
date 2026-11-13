package inventory_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// D-501: software nmap identified by an OS CPE gets the KEV keys of the catalog entry that names that CPE, so it matches the
// CISA list as the same product added by hand does: nmap's apple:iphone_os is CISA's Apple iOS, microsoft:windows_10 is Microsoft
// Windows, fortinet:fortios keeps FortiOS and gains Multiple Products. A CPE the catalog does not name keeps its vendor|product key.
func TestNmapCPEGetsTheCatalogKEVKeys(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.40")}
	err := e.svc.ReplaceSoftware(e.ctx(), hint, observe.Nmap, []observe.Software{
		{Display: "Apple iOS 15", Vendor: "apple", Product: "iphone os", Version: "15", CPE: "cpe:/o:apple:iphone_os:15", Confidence: 0.9},
		{Display: "Windows 10 1607", Vendor: "microsoft", Product: "windows 10", Version: "1607", CPE: "cpe:/o:microsoft:windows_10:1607", Confidence: 0.9},
		{Display: "FortiOS 7.2", Vendor: "fortinet", Product: "fortios", Version: "7.2", CPE: "cpe:/o:fortinet:fortios:7.2", Confidence: 0.9},
		{Display: "OpenSSH 8.9p1", Vendor: "openbsd", Product: "openssh", Version: "8.9p1", CPE: "cpe:/a:openbsd:openssh:8.9p1", Confidence: 0.9},
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := func(product string) []string {
		t.Helper()
		rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT k.kev_key FROM inv_software s JOIN inv_software_kev k ON k.software_id = s.id WHERE s.product = ? ORDER BY 1`, product)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				t.Fatal(err)
			}
			out = append(out, k)
		}
		return out
	}
	if k := keys("iphone os"); !slices.Contains(k, "apple|ios") || slices.Contains(k, "apple|iphone os") {
		t.Errorf("iOS keys = %v, want the catalog's (apple|ios ...)", k)
	}
	if k := keys("windows 10"); !slices.Contains(k, "microsoft|windows") || slices.Contains(k, "microsoft|windows 10") {
		t.Errorf("Windows 10 keys = %v, want the catalog's (microsoft|windows ...)", k)
	}
	if k := keys("fortios"); !slices.Contains(k, "fortinet|fortios") || !slices.Contains(k, "fortinet|multiple products") {
		t.Errorf("FortiOS keys = %v", k)
	}
	if k := keys("openssh"); !slices.Equal(k, []string{"openbsd|openssh"}) {
		t.Errorf("OpenSSH keys = %v, want its own vendor|product key", k)
	}
}
