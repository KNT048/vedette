package inventory

import (
	"slices"
	"testing"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/core/productid"
)

// A software line keeps only its product key; its match keys come from the product catalogue (matchKeys). Every key a source
// gives an item must still be a match key of the line the item lands on, or a finding would be lost: the keys of every product an
// agent maps, of every product a person picks in the catalog, of every CPE nmap prints that the catalog names, and the Windows
// release row of an agent.
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
	lost := 0
	for _, it := range items {
		id, _ := identify(it, "")
		got := matchKeys(id.productKey, false)
		for _, k := range it.KevKeys {
			if !slices.Contains(got, k) {
				lost++
				t.Errorf("%q %q: key %q is not a match key of its line %q (%v)", it.Vendor, it.Product, k, id.productKey, got)
			}
		}
	}
	t.Logf("%d items, %d keys lost", len(items), lost)
}
