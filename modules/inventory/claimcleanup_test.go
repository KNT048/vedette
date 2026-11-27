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

// The OS a person set on a device is a reading the device's observations rebuild (its author comes from the OS correction). When
// that correction carries no author, every rebuild writes the reading back without one: the cleanup must not name an author there,
// or it rewrites the same reading and writes another audit row every day.
func TestCleanStoredClaims_LeavesTheRebuiltOSReadingAlone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	sw := e.addDevice(inventory.AddInput{Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6", Name: "edge-switch", IP: "192.0.2.83"})
	os := "JUNOS 15.1R7.9"
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", sw, inventory.Patch{OS: &os}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_software_reading r JOIN inv_software s ON s.id = r.software_id
		WHERE s.asset_id = ? AND r.source = 'manual' AND r.instance = 'os'`, sw); n != 1 {
		t.Fatalf("%d OS readings from the person's OS, want 1", n)
	}
	// an OS correction that kept no author (an earlier release, or a device split off a merge), then the device is observed again
	rebuild := func() {
		t.Helper()
		if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(e.ctx(), `DELETE FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = 'manual'`, sw); err != nil {
				return err
			}
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at, first_seen)
				VALUES ('o-no-author', ?, 'os', ?, 'manual', 1, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`, sw, os); err != nil {
				return err
			}
			_, err := e.svc.RecomputeAsset(e.ctx(), tx, sw)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	rebuild()
	if err := e.svc.CleanStoredClaims(e.ctx()); err != nil {
		t.Fatal(err)
	}
	rebuild()
	before := len(e.auditActions())
	if err := e.svc.CleanStoredClaims(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := len(e.auditActions()) - before; n != 0 {
		t.Errorf("a run after the next observation wrote %d audit rows: the cleanup rewrites a reading every rebuild resets", n)
	}
}
