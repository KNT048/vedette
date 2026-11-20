package inventory

import (
	"slices"
	"testing"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/core/productid"
)

// A software line keeps only its product key; its match keys come from the product catalogue (matchKeys). Every key a source
// gives an item must still be a match key of the line the item lands on, or a finding would be lost: the keys of every product an
// agent maps, of every product a person picks in the catalog (but a neighbour's name, listed below), of every CPE nmap prints that
// the catalog names, and the Windows release row of an agent.
func TestMatchKeys_KeepEveryKeyASourceGives(t *testing.T) {
	t.Parallel()
	_, kev, err := EmbeddedKEV{}.Products(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCatalog(catalogdata.Curated, kev)
	if err != nil {
		t.Fatal(err)
	}
	items := []SoftwareItem{{Display: "Windows 11 26H2", Vendor: "microsoft", Product: "Windows 11 26H2", Version: "10.0.26300.9974", KevKeys: []string{"microsoft|windows"},
		CPE: "cpe:2.3:o:microsoft:windows_11_26h2:10.0.26300.9974:*:*:*:*:*:x64:*"}}
	for _, p := range productid.AgentProducts() {
		items = append(items, SoftwareItem{Display: p.Product, Vendor: p.Vendor, Product: p.Product, KevKeys: p.KEV})
	}
	for _, e := range c.entries {
		if len(e.kev) > 0 {
			items = append(items, SoftwareItem{Display: e.display, Vendor: e.vendor, Product: e.product, KevKeys: e.kev})
		}
	}
	for cpe, keys := range c.byCPE {
		items = append(items, SoftwareItem{Display: cpe, Vendor: "x", Product: cpe, CPE: "cpe:/" + cpe, KevKeys: keys})
	}
	// The catalogue gives a product only its own exploited-list names (productid ownName): a curated entry's fragment that also
	// reaches a neighbour (WinRAR for 7-Zip, FortiOS for FortiClient, Internet Explorer for Edge, PHPMailer for PHP, a WordPress
	// plugin for WordPress core) is no key of the product.
	neighbour := map[string]bool{"rarlab|unrar": true, "rarlab|winrar": true, "fortinet|fortios and fortiproxy ssl-vpn": true, "microsoft|internet explorer": true,
		"microsoft|internet explorer scripting engine": true, "microsoft|internet key exchange (ike) service extensions": true, "php|phpmailer": true,
		"phpmyadmin|phpmyadmin": true, "phpunit|phpunit": true, "thinkphp|thinkphp": true, "wordpress|file manager plugin": true,
		"wordpress|snap creek duplicator plugin": true, "wordpress|social warfare plugin": true}
	lost := 0
	for _, it := range items {
		id, _ := identify(it, "")
		got := matchKeys(id.productKey, false)
		for _, k := range it.KevKeys {
			if !slices.Contains(got, k) && !neighbour[k] {
				lost++
				t.Errorf("%q %q: key %q is not a match key of its line %q (%v)", it.Vendor, it.Product, k, id.productKey, got)
			}
		}
	}
	t.Logf("%d items, %d keys lost", len(items), lost)
}
