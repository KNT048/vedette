package inventory_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/modules/inventory"
)

// declaredLine declares a device by hand with one product and returns the software row the matcher reads for it.
func declaredLine(t *testing.T, e *env, in inventory.AddInput) inventory.MatchSoftware {
	t.Helper()
	id := e.addDevice(in)
	md, ok, err := e.svc.MatchInput(e.ctx(), id)
	if err != nil || !ok || len(md.Software) != 1 {
		t.Fatalf("%+v: matcher input %+v (ok %v, err %v)", in, md, ok, err)
	}
	return md.Software[0]
}

// The class of hand-declared products: a product a person declares by the name its maker or an exploited list gives it is the
// catalogue's product, with the keys and version form the matcher compares. Before, a typed "Red Hat" "OpenJDK" took every
// exploited product of Red Hat (the line became the ABRT bug reporter), "Eclipse Adoptium" "Temurin" was a product of its own that no
// Java range named, and ESXi's "8.0.3 build 24022510" was a version no rule read.
func TestDeclared_ProductsAreTheCatalogues(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, listed, err := inventory.EmbeddedKEV{}.Products(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		in                    inventory.AddInput
		key, version, display string
		hasKey                string // a match key the line must carry
		notVendor             string // no exploited-list name of this vendor's other products
	}{
		{in: inventory.AddInput{Vendor: "Red Hat", Product: "OpenJDK", Version: "21.0.7", IP: "192.0.2.31"}, key: "oracle|java se", version: "21.0.7",
			display: "Red Hat OpenJDK", hasKey: "oracle|java se", notVendor: "Red Hat"},
		{in: inventory.AddInput{Vendor: "Eclipse Adoptium", Product: "Temurin", Version: "21.0.7", IP: "192.0.2.32"}, key: "oracle|java se", version: "21.0.7",
			display: "Eclipse Adoptium Temurin", hasKey: "oracle|java se"},
		{in: inventory.AddInput{CatalogID: "eclipse-temurin-openjdk", Version: "21.0.7", IP: "192.0.2.33"}, key: "oracle|java se", version: "21.0.7",
			display: "Eclipse Temurin (OpenJDK)", hasKey: "oracle|java se"},
		{in: inventory.AddInput{Vendor: "Synology", Product: "DiskStation Manager (DSM)", Version: "7.2.1-69057 Update 5", IP: "192.0.2.34"},
			key: "synology|diskstation manager", version: "7.2.1-69057-5", display: "Synology DiskStation Manager (DSM)", hasKey: "synology|diskstation manager (dsm)"},
		{in: inventory.AddInput{CatalogID: "synology-nas-dsm", Version: "7.2.1-69057-5", IP: "192.0.2.35"}, key: "synology|diskstation manager",
			version: "7.2.1-69057-5", display: "Synology NAS (DSM)", hasKey: "synology|diskstation manager (dsm)"},
		{in: inventory.AddInput{Vendor: "VMware", Product: "ESXi", Version: "8.0.3 build 24022510", IP: "192.0.2.36"}, key: "vmware|esxi", version: "8.0.3",
			display: "VMware ESXi 8.0 Update 3 (build 24022510)", hasKey: "vmware|esxi"},
		{in: inventory.AddInput{CatalogID: "vmware-esxi", Version: "8.0 U3", IP: "192.0.2.37"}, key: "vmware|esxi", version: "8.0.3",
			display: "VMware ESXi 8.0 Update 3 (build 24022510)", hasKey: "vmware|esxi"},
		{in: inventory.AddInput{Vendor: "F5", Product: "nginx", Version: "1.30.5", IP: "192.0.2.38"}, key: "f5|nginx", version: "1.30.5", display: "F5 nginx",
			hasKey: "f5|nginx"},
	} {
		sw := declaredLine(t, e, c.in)
		if sw.Version != c.version || sw.Display != c.display || !slices.Contains(sw.KevKeys, c.hasKey) {
			t.Errorf("%+v: line %q %q keys %v, want %q %q with %q", c.in, sw.Display, sw.Version, sw.KevKeys, c.display, c.version, c.hasKey)
		}
		if key := e.count(`SELECT count(*) FROM inv_software WHERE id = ? AND product_key = ?`, sw.ID, c.key); key != 1 {
			t.Errorf("%+v: the line is not product %q", c.in, c.key)
		}
		for _, k := range listed {
			if k.Vendor == c.notVendor && slices.Contains(sw.KevKeys, productid.Key(k.Vendor, k.Product)) {
				t.Errorf("%+v: carries %s|%s, a product of the vendor that is not this one", c.in, k.Vendor, k.Product)
			}
		}
	}
	// a product nobody lists keeps its own name and claims no exploited flaw
	r, err := e.svc.AddDevice(e.ctx(), "it@acme.example", inventory.AddInput{Vendor: "Red Hat", Product: "Some Future Tool", Version: "1.0", IP: "192.0.2.39"})
	if err != nil || r.KevCVEs != 0 {
		t.Fatalf("an unlisted product of a listed vendor: %+v %v", r, err)
	}
}

// A newer release the box's own agent reports after a person declared an older one replaces it (the version dialog's promise); an
// older one does not.
func TestDeclared_NewerAgentReportEndsAnOlderEntry(t *testing.T) {
	t.Parallel()
	c := &lineCase{t: t, e: newEnv(t), hint: observe.AssetHint{IP: netip.MustParseAddr("192.0.2.71")}}
	ossl := func(v string) observe.Software {
		return observe.Software{Display: "OpenSSL", Vendor: "OpenSSL", Product: "OpenSSL", Version: v, Confidence: 0.95}
	}
	c.send(observe.Osquery, nil, ossl("3.5.5"))
	id := c.line("OpenSSL").ID
	c.e.tick(time.Minute)
	older := "3.5.1"
	if err := c.e.svc.EditSoftware(c.e.ctx(), "op@example.com", c.dev(), id, inventory.SoftwareEdit{Version: &older}); err != nil {
		t.Fatal(err)
	}
	if l := c.line("OpenSSL"); ver(l) != "3.5.1" || l.Source != "manual" {
		t.Fatalf("entry: %+v", l)
	}
	c.send(observe.Osquery, nil, ossl("3.5.5")) // the agent's next report
	if l := c.line("OpenSSL"); ver(l) != "3.5.5" || l.Source != "agent" || !slices.Contains(c.history(id), "entry_lapsed") {
		t.Fatalf("the newer release the agent reports after the entry is the line: %+v %v", l, c.history(id))
	}
	newer := "3.6.0"
	if err := c.e.svc.EditSoftware(c.e.ctx(), "op@example.com", c.dev(), id, inventory.SoftwareEdit{Version: &newer}); err != nil {
		t.Fatal(err)
	}
	c.send(observe.Osquery, nil, ossl("3.5.5"))
	if l := c.line("OpenSSL"); ver(l) != "3.6.0" || l.Source != "manual" {
		t.Fatalf("an older agent reading keeps the person's newer release: %+v", l)
	}
}

// Versions are stored as the product's scheme writes them, whoever states them: a scan's ESXi banner "8.0" with its build is 8.0.3,
// and a Debian upstream "X+reallyY" is Y.
func TestDeclared_VersionsInTheSchemesForm(t *testing.T) {
	t.Parallel()
	c := &lineCase{t: t, e: newEnv(t), hint: observe.AssetHint{IP: netip.MustParseAddr("192.0.2.72")}}
	c.send(observe.Nmap, nil, observe.Software{Display: "VMware ESXi 8.0 Update 3 (build 24022510)", Vendor: "vmware", Product: "esxi", Version: "8.0",
		CPE: "cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*", Confidence: 0.8})
	if l := c.line("esxi"); ver(l) != "8.0.3" || l.Display != "VMware ESXi 8.0 Update 3 (build 24022510)" {
		t.Fatalf("scanned ESXi: %q %q", l.Display, ver(l))
	}
	c.send(observe.Box, nil, observe.Software{Display: "util-linux", Vendor: "kernel.org", Product: "util-linux", Version: "4.16.0-2+really2.41.3",
		PkgVersion: "1:4.16.0-2+really2.41.3-3ubuntu2.2", PkgSource: "util-linux", Confidence: 0.95})
	if l := c.line("util-linux"); ver(l) != "2.41.3" {
		t.Fatalf("util-linux: %q", ver(l))
	}
}
