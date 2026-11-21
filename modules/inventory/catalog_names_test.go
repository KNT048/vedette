package inventory

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/core/productid"
)

// foreignNames counts the picker rows whose line carries an exploited-list name that none of the row's own fragments names (by whole
// words, productid.FragmentMatch): the names the row's picker entry gives its software (Catalog), and the match keys of the line that
// software lands on (the names every finding of the line is matched by). The row's own key, the line's own key, the names the product files list for the line's product and a vendor's "Multiple Products" are its own.
func foreignNames(t *testing.T) (rows int, foreign map[string][]string) {
	t.Helper()
	_, kev, err := EmbeddedKEV{}.Products(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCatalog(catalogdata.Curated, kev)
	if err != nil {
		t.Fatal(err)
	}
	var raw []curatedRow
	if err := json.Unmarshal(catalogdata.Curated, &raw); err != nil {
		t.Fatal(err)
	}
	foreign = map[string][]string{}
	claimed := filesNames(t) // the names the product files give a product themselves (explicit lists, not fragments)
	pair := map[string][2]string{}
	for _, r := range kev {
		pair[productid.Key(r.Vendor, r.Product)] = [2]string{r.Vendor, r.Product}
	}
	for _, e := range c.entries {
		if !e.curated {
			continue
		}
		rows++
		row := raw[e.order]
		id, _ := identify(SoftwareItem{Display: e.display, Vendor: e.vendor, Product: e.product, KevKeys: e.kev}, "manual")
		for _, k := range append(slices.Clone(e.kev), matchKeys(id.productKey, false)...) {
			own := k == productid.Key(e.vendor, e.product) || k == id.productKey || slices.Contains(claimed[id.productKey], k) || strings.HasSuffix(k, "|multiple products")
			if line, ok := productid.ByKEV(k); ok && line.Key == id.productKey && !slices.Contains(e.kev, k) { // a name the line's product has for itself
				own = true
			}
			for _, f := range row.KevMatch {
				if vp, ok := pair[k]; ok && productid.FragmentMatch(f, vp[0], vp[1]) {
					own = true
				}
			}
			if !own && !slices.Contains(foreign[e.display], k) {
				foreign[e.display] = append(foreign[e.display], k)
			}
		}
	}
	return rows, foreign
}

// filesNames are the exploited-list keys (kev and kev_shared) each product of the product files lists for itself, by product key.
func filesNames(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	entries, err := catalogdata.Products.ReadDir("products")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range entries {
		raw, err := catalogdata.Products.ReadFile("products/" + f.Name())
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Products []struct {
				Vendor, Product string
				KEV             []string `json:"kev"`
				KEVShared       []string `json:"kev_shared"`
			} `json:"products"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", f.Name(), err)
		}
		for _, p := range doc.Products {
			key := productid.Key(p.Vendor, p.Product)
			out[key] = append(out[key], p.KEV...)
			out[key] = append(out[key], p.KEVShared...)
		}
	}
	return out
}

// The class guard (every picker row, not one product): a row's line carries only names its own fragments name. Rows that carry a
// name of another product are counted and listed; there are none. Before the fragments matched whole words, 22 rows did (a
// fragment inside a word of another name, a fragment that is the start of another product's name, a list name that merely contains
// the product's name).
func TestCuratedRows_LinesCarryOnlyTheirOwnNames(t *testing.T) {
	t.Parallel()
	rows, foreign := foreignNames(t)
	t.Logf("%d picker rows, %d rows carry a name of another product", rows, len(foreign))
	for row, keys := range foreign {
		t.Errorf("%s carries %s", row, strings.Join(keys, "; "))
	}
}

// Every fragment names a product: a fragment that is only a vendor would take every product the vendor will ever have in the list.
func TestCuratedRows_EveryFragmentNamesAProduct(t *testing.T) {
	t.Parallel()
	var raw []curatedRow
	if err := json.Unmarshal(catalogdata.Curated, &raw); err != nil {
		t.Fatal(err)
	}
	for _, r := range raw {
		for _, f := range r.KevMatch {
			if v, p, ok := strings.Cut(f, "|"); !ok || strings.TrimSpace(v) == "" || strings.TrimSpace(p) == "" {
				t.Errorf("%s: fragment %q does not name a vendor and a product", r.Display, f)
			}
		}
	}
}

// Names that belong to another product stay off a row, and a name that lists several products lands only on the ones it names.
func TestCuratedRows_NamesStayOnTheirProduct(t *testing.T) {
	t.Parallel()
	_, kev, err := EmbeddedKEV{}.Products(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCatalog(catalogdata.Curated, kev)
	if err != nil {
		t.Fatal(err)
	}
	keysOf := func(display string) []string {
		for _, e := range c.entries {
			if e.display == display {
				return e.kev
			}
		}
		t.Fatalf("no picker row %q", display)
		return nil
	}
	const sdwan = "citrix|netscaler sd-wan enterprise, cloudbridge virtual wan, and xenmobile server" // CVE-2017-6316
	for _, tc := range []struct {
		row   string
		never []string
		owns  []string
	}{
		{"Citrix NetScaler (ADC / Gateway)", []string{sdwan}, []string{"citrix|netscaler adc and gateway", "citrix|sd-wan and netscaler"}},
		{"Cisco RV series router (small business)", []string{"cisco|identity services engine"}, []string{"cisco|small business rv160, rv260, rv340, and rv345 series routers"}},
		{"Cisco ASA / Firepower (FTD)", []string{"cisco|secure firewall management center (fmc)"}, []string{"cisco|secure firewall adaptive security appliance and secure firewall threat defense"}},
		{"Cisco IOS / IOS XE router or switch", []string{"cisco|ios xr"}, []string{"cisco|ios and ios xe", "cisco|ios xe software"}},
		{"VMware ESXi", nil, []string{"vmware|esxi and workstation", "vmware|vmware esxi and horizon daas"}},
		{"PHP", []string{"php|phpmailer", "phpmyadmin|phpmyadmin"}, []string{"php|php"}},
		{"Microsoft Exchange Server", []string{"microsoft|internet key exchange (ike) service extensions"}, []string{"microsoft|exchange"}},
		{"Check Point Security Gateway", []string{"check point|smartconsole"}, nil},
		{"WordPress", []string{"wordpress|file manager plugin"}, []string{"wordpress|core"}},
	} {
		got := keysOf(tc.row)
		for _, k := range tc.never {
			if slices.Contains(got, k) {
				t.Errorf("%s takes %q, which names another product", tc.row, k)
			}
		}
		for _, k := range tc.owns {
			if !slices.Contains(got, k) {
				t.Errorf("%s lost its own name %q", tc.row, k)
			}
		}
	}
	// the line a picked NetScaler lands on is matched by its own names only
	id, _ := identify(SoftwareItem{Display: "Citrix NetScaler (ADC / Gateway)", Vendor: "Citrix", Product: "NetScaler", KevKeys: keysOf("Citrix NetScaler (ADC / Gateway)")}, "manual")
	if got := matchKeys(id.productKey, false); slices.Contains(got, sdwan) {
		t.Errorf("the NetScaler line is matched by %q (SD-WAN's CVE-2017-6316): %v", sdwan, got)
	}
}
