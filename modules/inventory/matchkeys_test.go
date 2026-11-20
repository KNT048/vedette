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
			if q, ok := productid.ByKEV(k); ok && q.Key != id.productKey && !slices.Contains(got, k) {
				continue // another product's name (FortiClient EMS for FortiClient, Edge and Internet Explorer for Edge): its line has it
			}
			if !slices.Contains(got, k) && !neighbour[k] {
				lost++
				t.Errorf("%q %q: key %q is not a match key of its line %q (%v)", it.Vendor, it.Product, k, id.productKey, got)
			}
		}
	}
	t.Logf("%d items, %d keys lost", len(items), lost)
}

// Names that belong to a neighbour stay off a product's line, so its exploited CVEs never match it: Chromium Edge does not take
// "Edge and Internet Explorer" or "Internet Explorer" (CVE-2017-0037, CVE-2016-3351, CVE-2020-0878 are Internet Explorer's and the
// old EdgeHTML's), the FortiClient endpoint does not take "FortiClient EMS" (CVE-2026-21643, CVE-2026-35616, CVE-2023-48788 are the
// EMS server's), 7-Zip does not take WinRAR. Each of those names is the match key of its own product's line.
func TestMatchKeys_NeighboursStayOff(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		source string
		it     SoftwareItem
		owns   []string
		never  []string
	}{
		{"osquery", SoftwareItem{Display: "Microsoft Edge", Vendor: "Microsoft", Product: "Edge", Version: "131.0.2903.70", KevKeys: []string{"microsoft|edge"}},
			[]string{"microsoft|edge"}, []string{"microsoft|edge and internet explorer", "microsoft|internet explorer and edge", "microsoft|internet explorer"}},
		{"osquery", SoftwareItem{Display: "FortiClient", Vendor: "Fortinet", Product: "FortiClient", Version: "7.4.4", KevKeys: []string{"fortinet|forticlient"}},
			[]string{"fortinet|forticlient"}, []string{"fortinet|forticlient ems", "fortinet|fortios and fortiproxy ssl-vpn"}},
		{"osquery", SoftwareItem{Display: "7-Zip 23.01 (x64)", Vendor: "7-Zip", Product: "7-Zip", Version: "23.01", KevKeys: []string{"7-zip|7-zip"}},
			[]string{"7-zip|7-zip"}, []string{"rarlab|winrar", "rarlab|unrar"}},
		{"manual", SoftwareItem{Display: "FortiClient EMS", Vendor: "Fortinet", Product: "FortiClient EMS", Version: "7.2.2"},
			[]string{"fortinet|forticlient ems"}, nil},
		{"manual", SoftwareItem{Display: "Microsoft Internet Explorer", Vendor: "Microsoft", Product: "Internet Explorer", Version: "11"},
			[]string{"microsoft|internet explorer", "microsoft|edge and internet explorer", "microsoft|internet explorer and edge"}, nil},
		{"manual", SoftwareItem{Display: "Microsoft Edge and Internet Explorer", Vendor: "Microsoft", Product: "Edge and Internet Explorer", KevKeys: []string{"microsoft|edge and internet explorer"}},
			[]string{"microsoft|edge and internet explorer"}, nil},
		{"manual", SoftwareItem{Display: "WinRAR", Vendor: "RARLAB", Product: "WinRAR", Version: "7.01"}, []string{"rarlab|winrar"}, nil},
	} {
		id, _ := identify(c.it, c.source)
		got := matchKeys(id.productKey, false)
		for _, k := range c.owns {
			if !slices.Contains(got, k) {
				t.Errorf("%s: %q missing from %v", c.it.Display, k, got)
			}
		}
		for _, k := range c.never {
			if slices.Contains(got, k) {
				t.Errorf("%s: takes %q, a neighbour's name (%v)", c.it.Display, k, got)
			}
		}
	}
}
