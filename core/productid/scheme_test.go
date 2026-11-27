package productid

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/core/versionscheme"
)

// A range names a product of the catalogue files by its NVD CPE or by the names its CVE record gives (the record key feeds stores),
// and the product's version scheme is a core/versionscheme scheme. A curated product has no scheme and is not found.
func TestByRangeName(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		part, vendor, product string
		scheme                string
	}{
		{"o", "vmware", "esxi", "vmware-esxi"},
		{"", "vmware", "esxi", "vmware-esxi"}, // "n/a", "VMware ESXi" of assigner vmware
		{"", "vmware", "esx", "vmware-esxi"},  // ESX 9's name
		{"", "netscaler", "adc", "citrix-netscaler"},
		{"", "citrixnetscaler", "gateway", "citrix-netscaler"},
		{"", "citrix", "adc", "citrix-netscaler"},
		{"a", "citrix", "netscaler_gateway", "citrix-netscaler"},
		{"", "linux", "linux", "linux-kernel"},
		{"o", "linux", "linux_kernel", "linux-kernel"},
	} {
		p, ok := ByRangeName(c.part, c.vendor, c.product)
		if !ok || p.Scheme != c.scheme {
			t.Errorf("%s:%s:%s: %v %q, want %q", c.part, c.vendor, c.product, ok, p.Scheme, c.scheme)
		}
	}
	if p, ok := ByRangeName("", "acme", "gateway"); ok {
		t.Errorf("an unknown product: %+v", p)
	}
	for _, p := range Products() {
		if _, ok := versionscheme.Lookup(p.Scheme); p.Scheme != "" && !ok {
			t.Errorf("%s: scheme %q", p.ID, p.Scheme)
		}
	}
}

// A scheme the registry does not have is refused when the catalogue loads.
func TestCatalogue_UnknownSchemeRefused(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{"products/x.json": {Data: []byte(`{"products":[{"id":"x","display":"X","vendor":"Acme","product":"X","scheme":"acme-build"}]}`)}}
	if _, err := load(fsys, catalogdata.Curated, catalogdata.KEVProducts); err == nil || !strings.Contains(err.Error(), "acme-build") {
		t.Fatalf("loaded: %v", err)
	}
}

// An exploited-list name that names ESXi with other products ("ESXi and Workstation") stays one of ESXi's match keys but never
// resolves to ESXi: a person who picks that row for Workstation or Fusion gets no ESXi line.
func TestKEVShared(t *testing.T) {
	t.Parallel()
	esxi, ok := ByKey("vmware|esxi")
	if !ok {
		t.Fatal("no ESXi")
	}
	for _, k := range []string{"vmware|esxi and workstation", "vmware|esxi, workstation, and fusion", "vmware|vmware esxi and horizon daas"} {
		if !slices.Contains(esxi.KEV, k) {
			t.Errorf("%s is not an ESXi match key", k)
		}
		if p, ok := ByKEV(k); ok {
			t.Errorf("%s resolves to %s", k, p.ID)
		}
	}
	if p, ok := ByKEV("broadcom|vmware esx"); !ok || p.ID != "vmware-esxi" {
		t.Errorf("Broadcom's ESX name: %+v %v", p, ok)
	}
}

// A product's version_map rewrites a reported version into the vendor's notation before its release line is read (Java on Windows
// reports "8.0.4910.10" for 8u491); a row that does not match the whole version, or rewrites it to nothing, is refused at load.
func TestCatalogue_VersionMap(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{"products/x.json": {Data: []byte(`{"products":[{"id":"x","display":"X","vendor":"Acme","product":"X","trains":"major",
		"version_map":[{"re":"^8\\.0\\.(\\d{1,3})0\\.\\d+$","to":"1.8.0_$1"},{"re":"^ad (.+)$","to":"$1"}]}]}`)}}
	c, err := load(fsys, catalogdata.Curated, catalogdata.KEVProducts)
	if err != nil {
		t.Fatal(err)
	}
	p := c.byKey["acme|x"].p
	for in, want := range map[string]string{"8.0.4910.10": "1.8.0_491", "ad 9.0.4": "9.0.4", "21.0.7": "21.0.7", " 8.0.4910.10 ": "1.8.0_491"} {
		if got := p.Canonical(in); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{`{"re":"8\\.0","to":"x"}`, `{"re":"^(\\d$","to":"x"}`, `{"re":"^x$","to":" "}`} {
		fsys := fstest.MapFS{"products/x.json": {Data: []byte(`{"products":[{"id":"x","display":"X","vendor":"Acme","product":"X","version_map":[` + bad + `]}]}`)}}
		if _, err := load(fsys, catalogdata.Curated, catalogdata.KEVProducts); err == nil || !strings.Contains(err.Error(), "version_map") {
			t.Errorf("%s loaded: %v", bad, err)
		}
	}
	if p, ok := ByID("nodejs"); !ok || p.Key != "node.js|node.js" || p.Line("22.19.0") != "22" {
		t.Errorf("ByID(nodejs) = %+v, %v", p, ok)
	}
}
