package inventory_test

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/modules/inventory"
)

// A person's entries stored before the claim rules: a package release on firmware is dropped, an entry with no author gets the
// unknown author, a package release on a distribution's package stays; each change is one audit row, and a second run changes nothing.
func TestCleanStoredClaims_DropsStrayPackageReleasesAndNamesLostAuthors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	junos := e.addDevice(inventory.AddInput{Vendor: "Juniper", Product: "Junos OS", Version: "15.1R7.9", Name: "core-switch", IP: "192.0.2.80"})
	ssh := e.addDevice(inventory.AddInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6", Name: "ubuntu-01", IP: "192.0.2.81"})
	ubuntu := "Ubuntu 24.04"
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", ssh, inventory.Patch{OS: &ubuntu}); err != nil {
		t.Fatal(err)
	}
	// rows as an earlier release stored them: a package release typed on the switch's firmware, and no author on either entry
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(e.ctx(), `UPDATE inv_software_reading SET pkg_version = '15.1R7.9', set_by = NULL
			WHERE source = 'manual' AND software_id IN (SELECT id FROM inv_software WHERE asset_id = ?)`, junos); err != nil {
			return err
		}
		_, err := tx.ExecContext(e.ctx(), `UPDATE inv_software_reading SET pkg_version = '1:9.6p1-3ubuntu13.4'
			WHERE source = 'manual' AND software_id IN (SELECT id FROM inv_software WHERE asset_id = ?)`, ssh)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	before := len(e.auditActions())
	if err := e.svc.CleanStoredClaims(e.ctx()); err != nil {
		t.Fatal(err)
	}
	reading := func(asset string) (pkg, by string) {
		t.Helper()
		if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT ifnull(r.pkg_version, ''), ifnull(r.set_by, '') FROM inv_software_reading r
			JOIN inv_software s ON s.id = r.software_id WHERE s.asset_id = ? AND r.source = 'manual'`, asset).Scan(&pkg, &by); err != nil {
			t.Fatal(err)
		}
		return pkg, by
	}
	if pkg, by := reading(junos); pkg != "" || by != inventory.UnknownAuthor {
		t.Errorf("switch entry: package %q, author %q; want no package release and the unknown author", pkg, by)
	}
	if pkg, by := reading(ssh); pkg != "1:9.6p1-3ubuntu13.4" || by != "it@acme.example" {
		t.Errorf("Ubuntu entry: package %q, author %q; want both kept", pkg, by)
	}
	if n := e.count(`SELECT count(*) FROM inv_software WHERE asset_id = ? AND pkg_version IS NOT NULL`, junos); n != 0 {
		t.Errorf("the switch's line still shows a package release")
	}
	acts := e.auditActions()[before:]
	if len(acts) != 1 || acts[0] != "inventory.entry_cleaned" {
		t.Errorf("audit rows %v, want one inventory.entry_cleaned", acts)
	}
	before = len(e.auditActions())
	if err := e.svc.CleanStoredClaims(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := len(e.auditActions()) - before; n != 0 {
		t.Errorf("a second run wrote %d audit rows", n)
	}
}

// What a person gives a line is checked against it: a package release on firmware is refused, an edit that changes nothing says so,
// and a version the device's own statement contradicts is refused until the person confirms it.
func TestEdit_ClaimsAreCheckedAgainstTheLine(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	junos := e.addDevice(inventory.AddInput{Vendor: "Juniper", Product: "Junos OS", Version: "15.1R7.9", Name: "core-switch", IP: "192.0.2.82"})
	var line string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM inv_software WHERE asset_id = ?`, junos).Scan(&line); err != nil {
		t.Fatal(err)
	}
	pkg := "15.1R7.9"
	_, err := e.svc.Edit(e.ctx(), "it@acme.example", junos, line, inventory.SoftwareEdit{PkgVersion: &pkg})
	wantAPIError(t, err, 400, "not_a_package")
	same := "15.1R7.9"
	changed, err := e.svc.Edit(e.ctx(), "it@acme.example", junos, line, inventory.SoftwareEdit{Version: &same})
	if err != nil || changed {
		t.Errorf("the same version again: changed %v, %v; want nothing changed", changed, err)
	}
	other := "21.4R3"
	if changed, err := e.svc.Edit(e.ctx(), "it@acme.example", junos, line, inventory.SoftwareEdit{Version: &other}); err != nil || !changed {
		t.Errorf("a person's own entry, no device statement: changed %v, %v", changed, err)
	}
}
