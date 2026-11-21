package inventory

import (
	"encoding/json"
	"os"
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

// neverOnRow are names of another product that must never land on the picker row (each has its own CPE and its own picker entry).
var neverOnRow = [][2]string{
	{"Cisco ASA / Firepower (FTD)", "cisco|secure firewall management center (fmc)"},
	{"Cisco ASA / Firepower (FTD)", "cisco|secure firewall management center (fmc) and security cloud control (scc) firewall management"},
	{"Cisco IOS / IOS XE router or switch", "cisco|ios xr"},
	{"Cisco RV series router (small business)", "cisco|identity services engine"},
	{"Check Point Security Gateway", "check point|smartconsole"},
	{"DrayTek Vigor router", "draytek|vigorconnect"},
	{"TP-Link router (Archer, ER)", "tp-link|tl-wa855re"},
	{"Netgear router or access point", "netgear|jgs516pe devices"},
	{"Aruba / HPE ProCurve switch", "hewlett packard (hp)|procurve manager (pcm), pcm+, identity driven manager (idm), and application lifecycle management"},
	{"Citrix NetScaler (ADC / Gateway)", "citrix|netscaler sd-wan enterprise, cloudbridge virtual wan, and xenmobile server"},
	{"Fortinet FortiClient / SSL VPN", "fortinet|forticlient ems"},
	{"Microsoft Exchange Server", "microsoft|internet key exchange (ike) service extensions"},
	{"Active Directory / domain controller", "microsoft|active directory federation services"},
	{"WordPress", "wordpress|file manager plugin"},
	{"WordPress", "wordpress|snap creek duplicator plugin"},
	{"WordPress", "wordpress|social warfare plugin"},
	{"PHP", "php|phpmailer"},
	{"PHP", "phpmyadmin|phpmyadmin"},
	{"PHP", "phpunit|phpunit"},
	{"PHP", "thinkphp|thinkphp"},
	{"SolarWinds Orion / Serv-U", "solarwinds|web help desk"},
	{"SolarWinds Orion / Serv-U", "solarwinds|virtualization manager"},
	{"WinRAR", "rarlab|unrar"},
	{"Oracle WebLogic Server", "oracle|http server and oracle weblogic server proxy plug-in"},
}

// The count above only proves a line is covered by its fragments; this fixed list proves the fragments are not too broad.
func TestCuratedRows_FixedForeignNamesNeverLand(t *testing.T) {
	t.Parallel()
	_, kev, err := EmbeddedKEV{}.Products(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCatalog(catalogdata.Curated, kev)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range neverOnRow {
		found := false
		for _, e := range c.entries {
			if e.curated && e.display == p[0] {
				found = true
				if slices.Contains(e.kev, p[1]) {
					t.Errorf("%s takes %q, which names another product", p[0], p[1])
				}
			}
		}
		if !found {
			t.Errorf("no picker row %q", p[0])
		}
	}
}

// A list name that starts with a row's product words and goes on with a word that is no qualifier ("FortiOS SSL-VPN" for FortiOS)
// is dropped by that row: it may be another product (IOS XR) or a component of the row's own (a missed exploited CVE). Every such
// name is listed here with the decision; a name CISA adds later that is not listed fails this test until someone decides (a family
// fragment with "*" when it is the row's own, an entry here when it is not).
func TestCuratedRows_NearMissesAreDecided(t *testing.T) {
	t.Parallel()
	decided := map[string]bool{
		"Cisco IOS / IOS XE router or switch|cisco|ios xr": true, // another OS
		"Aruba / HPE ProCurve switch|hewlett packard (hp)|procurve manager (pcm), pcm+, identity driven manager (idm), and application lifecycle management": true, // management software
		"Citrix NetScaler (ADC / Gateway)|citrix|netscaler sd-wan enterprise, cloudbridge virtual wan, and xenmobile server":                                 true, // SD-WAN
		"Fortinet FortiClient / SSL VPN|fortinet|forticlient ems":                                                                                            true, // the EMS server
		"Active Directory / domain controller|microsoft|active directory federation services":                                                                true, // a separate server role
	}
	_, kev, err := EmbeddedKEV{}.Products(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var raw []curatedRow
	if err := json.Unmarshal(catalogdata.Curated, &raw); err != nil {
		t.Fatal(err)
	}
	for _, r := range raw {
		for _, k := range kev {
			named, near := false, false
			for _, f := range r.KevMatch {
				named = named || productid.FragmentMatch(f, k.Vendor, k.Product)
				near = near || productid.NearMiss(f, k.Vendor, k.Product)
			}
			if key := r.Display + "|" + productid.Key(k.Vendor, k.Product); near && !named && !decided[key] {
				t.Errorf("%s: the list name %q starts like the row's product but no fragment names it; add a fragment or decide it here", r.Display, productid.Key(k.Vendor, k.Product))
			}
		}
	}
}

// A component word after the product's name is no match without a family fragment, and the guard sees it.
func TestFragmentMatch_ComponentNamesAndFamilies(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		fragment, vendor, product string
		match, near               bool
	}{
		{"fortinet|fortios", "Fortinet", "FortiOS SSL-VPN", false, true},
		{"fortinet|fortios*", "Fortinet", "FortiOS SSL-VPN", true, false},
		{"fortinet|fortios", "Fortinet", "FortiOS and FortiProxy", true, false},
		{"cisco|rv*", "Cisco", "RV160 and RV260 Routers", true, false},
		{"cisco|rv*", "Cisco", "RVS4000", false, false},
		{"google|chrome*", "Google", "Chrome Blink", true, false},
		{"google|chrome*", "Google", "ChromeOS", false, false},
		{"oracle|java*", "Oracle", "JavaFX", false, false},
		{"oracle|java*", "Oracle", "Java SE", true, false},
	} {
		if got := productid.FragmentMatch(c.fragment, c.vendor, c.product); got != c.match {
			t.Errorf("FragmentMatch(%q, %q, %q) = %v", c.fragment, c.vendor, c.product, got)
		}
		if got := productid.NearMiss(c.fragment, c.vendor, c.product); got != c.near {
			t.Errorf("NearMiss(%q, %q, %q) = %v", c.fragment, c.vendor, c.product, got)
		}
	}
}

// Go and web read every fragment of curated.json against every list name and must agree: the shared file lists each pair that
// matches. Regenerate it with `pnpm --dir web exec vitest run -u src/features/inventory/catalog.golden.test.ts`.
func TestFragmentMatch_ParityWithTheWeb(t *testing.T) {
	t.Parallel()
	_, kev, err := EmbeddedKEV{}.Products(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var raw []curatedRow
	if err := json.Unmarshal(catalogdata.Curated, &raw); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var lines []string
	for _, r := range raw {
		for _, f := range r.KevMatch {
			if seen[f] {
				continue
			}
			seen[f] = true
			for _, k := range kev {
				if productid.FragmentMatch(f, k.Vendor, k.Product) {
					lines = append(lines, f+" => "+productid.Key(k.Vendor, k.Product))
				}
			}
		}
	}
	slices.Sort(lines)
	want, err := os.ReadFile("../../content/catalog/fragment-parity.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(lines, "\n") + "\n"; got != string(want) {
		t.Errorf("fragment-parity.txt differs from the Go rule (%d pairs); regenerate it from the web test and compare", len(lines))
	}
}
