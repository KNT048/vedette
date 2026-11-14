package inventory_test

import (
	"database/sql"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
)

// W9-1, D-515: a product declared with neither an IP nor a name ("Microsoft Office (no device)") has no device type, from the add form
// (catalog kind pc) or from "I have this" (feeds suggests pc). The same product on a device with an IP keeps the type, and an
// appliance declared alone keeps its type (the product is the device; mitigation reads a declared firewall).
func TestContract_D515_AProductWithNoDeviceHasNoDeviceType(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	kind := func(id string) string {
		t.Helper()
		d, err := e.svc.Device(e.ctx(), id)
		if err != nil {
			t.Fatal(err)
		}
		return d.Kind
	}
	var fed string
	var txp *sql.Tx
	err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		var err error
		txp = tx
		fed, err = e.svc.AddManualDevice(e.ctx(), tx, "kien", inventory.ManualDevice{Kind: "pc", Vendor: "Microsoft", Product: "Office", Display: "Microsoft Office", Key: "microsoft|office"})
		return err
	})
	e.svc.Settle(e.ctx(), txp, err == nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		id, want string
	}{
		"I have this":           {fed, "unknown"},
		"add form, no device":   {e.addDevice(inventory.AddInput{CatalogID: "microsoft-office-desktop"}), "unknown"},
		"add form, with an IP":  {e.addDevice(inventory.AddInput{CatalogID: "microsoft-office-desktop", IP: "192.168.30.5"}), "pc"},
		"add form, with a name": {e.addDevice(inventory.AddInput{CatalogID: "microsoft-office-desktop", Name: "ACC-PC-01"}), "pc"},
		"an appliance alone":    {e.addDevice(inventory.AddInput{CatalogID: "fortigate"}), "firewall"},
	} {
		if got := kind(c.id); got != c.want {
			t.Errorf("%s: kind %q, want %q", name, got, c.want)
		}
	}
}

// Review M2 of #722: a type a person writes in a CSV is kept even on a product with no device; only the catalog's own suggestion
// is left out.
func TestContract_D515_ACSVTypeIsKept(t *testing.T) {
	t.Parallel()
	for csv, want := range map[string]string{
		"product,type\nExchange Server,server\n": "server",
		"product\nExchange Server\n":             "unknown",
	} {
		e := newEnv(t)
		if r := e.importCSV(csv); r.Created != 1 {
			t.Fatalf("%q: import %+v", csv, r)
		}
		if n := e.count(`SELECT count(*) FROM inv_asset WHERE origin = 'manual' AND ip IS NULL AND kind = ?`, want); n != 1 {
			t.Errorf("%q: no product row of type %s", csv, want)
		}
	}
}

// W9-1, D-515 (4) (migration inventory 0006): a product declared with no device before #722 kept the computer type the catalog
// suggested ("Microsoft Office (no device)" on the N100 showed Computer). The migration untypes exactly what that declare wrote; a
// type a person set later, a product on a device with an IP and an appliance type stay.
func TestMigration0006UntypesAProductWithNoDevice(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	upTo5 := fstest.MapFS{}
	all, _ := fs.Glob(inventory.Migrations, "*.sql")
	for _, name := range all {
		if name < "0006" {
			b, _ := fs.ReadFile(inventory.Migrations, name)
			upTo5[name] = &fstest.MapFile{Data: b}
		}
	}
	if err := store.Migrate(ctx, db, "inventory", upTo5); err != nil {
		t.Fatal(err)
	}
	const at, later = "2026-11-13T14:59:57.440Z", "2026-11-14T08:00:00.000Z"
	// declared writes one product row as createManual did before #722: the row, its vendor and kind observations and its software,
	// all stamped at; kindAt is when the kind observation was last seen, sw when the software row was.
	declared := func(id, ip, kind, kindAt, sw string) []string {
		return []string{
			`INSERT INTO inv_asset (id, ip, kind, vendor, origin, approved, kind_obs_id, vendor_obs_id, first_seen, last_seen)
				VALUES ('` + id + `', ` + ip + `, '` + kind + `', 'Microsoft', 'manual', 1, 'ok-` + id + `', 'ov-` + id + `', '` + at + `', '` + at + `')`,
			`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES
				('ok-` + id + `', '` + id + `', 'kind', '` + kind + `', 'manual', 1, '` + kindAt + `'),
				('ov-` + id + `', '` + id + `', 'vendor', 'Microsoft', 'manual', 1, '` + at + `')`,
			`INSERT INTO inv_software (id, asset_id, display, vendor, product, source, confidence, seen_at)
				VALUES ('s-` + id + `', '` + id + `', 'Microsoft Office', 'Microsoft', 'Office', 'manual', 1, '` + sw + `')`,
		}
	}
	var qs []string
	qs = append(qs, declared("a-n100", "NULL", "pc", at, at)...)           // the N100 row
	qs = append(qs, declared("a-version", "NULL", "server", at, later)...) // the version edited later ("I updated it")
	qs = append(qs, declared("a-repicked", "NULL", "pc", later, at)...)    // a person picked Computer again on the device page
	qs = append(qs, declared("a-ip", "'192.168.30.5'", "pc", at, at)...)   // a product on a device
	qs = append(qs, declared("a-fw", "NULL", "firewall", at, at)...)       // FortiGate: the product is the device
	qs = append(qs, declared("a-chosen", "NULL", "pc", at, at)...)         // a person set Server later
	qs = append(qs,
		`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES ('ok-chosen2', 'a-chosen', 'kind', 'server', 'manual', 1, '`+later+`')`,
		`UPDATE inv_asset SET kind = 'server', kind_obs_id = 'ok-chosen2' WHERE id = 'a-chosen'`)
	for _, q := range qs {
		if err := db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q); return err }); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := store.Migrate(ctx, db, "inventory", inventory.Migrations); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"a-n100": "unknown", "a-version": "unknown", "a-repicked": "pc", "a-ip": "pc", "a-fw": "firewall", "a-chosen": "server"} {
		var kind string
		var obs sql.NullString
		var fragile bool
		if err := db.Reader().QueryRowContext(ctx, `SELECT kind, kind_obs_id, fragile FROM inv_asset WHERE id = ?`, id).Scan(&kind, &obs, &fragile); err != nil {
			t.Fatal(err)
		}
		var kindObs int
		if err := db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM inv_observation WHERE asset_id = ? AND field = 'kind'`, id).Scan(&kindObs); err != nil {
			t.Fatal(err)
		}
		switch {
		case kind != want:
			t.Errorf("%s: kind %q, want %q", id, kind, want)
		case want == "unknown" && (obs.Valid || kindObs != 0 || fragile):
			t.Errorf("%s: untyped but kind_obs_id %v, %d kind observations, fragile %v", id, obs, kindObs, fragile)
		case want != "unknown" && (!obs.Valid || kindObs == 0):
			t.Errorf("%s: kept but kind_obs_id %v, %d kind observations", id, obs, kindObs)
		}
	}
}
