package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// seedLines stores devices × perDevice software lines as an older catalogue left them: per device perDevice-1 lines of products
// no catalogue knows (one scan reading each), and one Python line without trains holding 20 agent readings of 20 releases (3.0 …
// 3.19), which this build's catalogue puts on 20 trains. Each reading keeps its item.
func seedLines(tb testing.TB, db *store.DB, devices, perDevice int) {
	tb.Helper()
	ctx := context.Background()
	now := store.FormatTS(time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC))
	err := db.Write(ctx, func(tx *sql.Tx) error {
		asset, err := tx.PrepareContext(ctx, `INSERT INTO inv_asset (id, kind, origin, approved, first_seen, last_seen) VALUES (?, 'unknown', 'discovered', 1, ?, ?)`)
		if err != nil {
			return err
		}
		line, err := tx.PrepareContext(ctx, `INSERT INTO inv_software (id, asset_id, product_key, line, display, vendor, product, version, source, confidence, seen_at, first_seen, last_seen)
			VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, 0.8, ?, ?, ?)`)
		if err != nil {
			return err
		}
		reading, err := tx.PrepareContext(ctx, `INSERT INTO inv_software_reading (software_id, source, instance, display, version, confidence, first_seen, seen_at, addr_id,
			item_vendor, item_product, item_version, item_kev, item_instance) VALUES (?, ?, ?, ?, ?, 0.8, ?, ?, '', ?, ?, ?, '', ?)`)
		if err != nil {
			return err
		}
		for d := range devices {
			a := fmt.Sprintf("a-%05d", d)
			if _, err := asset.ExecContext(ctx, a, now, now); err != nil {
				return err
			}
			for i := range perDevice - 1 {
				vendor, product, inst := fmt.Sprintf("Vendor%d", i%40), fmt.Sprintf("Product%d", i), fmt.Sprintf("tcp/%d", 1000+i)
				id, display := fmt.Sprintf("s-%05d-%04d", d, i), vendor+" "+product
				if _, err := line.ExecContext(ctx, id, a, productid.Key(vendor, product), display, vendor, product, "1.0", "nmap", now, now, now); err != nil {
					return err
				}
				if _, err := reading.ExecContext(ctx, id, "nmap", inst, display, "1.0", now, now, vendor, product, "1.0", inst); err != nil {
					return err
				}
			}
			id := fmt.Sprintf("s-%05d-py", d)
			if _, err := line.ExecContext(ctx, id, a, "python|python", "Python", "Python", "Python", "3.19.0", "osquery", now, now, now); err != nil {
				return err
			}
			for k := range 20 {
				v := fmt.Sprintf("3.%d.0", k)
				if _, err := reading.ExecContext(ctx, id, "osquery", "@"+v, "Python", v, now, now, "Python", "Python", v, ""); err != nil {
					return err
				}
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO inv_catalogue_pass (id, revision, updated_at) VALUES (1, 'older-catalogue', ?)`, now)
		return err
	})
	if err != nil {
		tb.Fatal(err)
	}
}

// BenchmarkReidentify_100kLines times the pass over 100,000 stored lines on 500 devices: after an update that gives one product
// trains (on every device one line becomes 20), and a pass that finds every line where it is.
func BenchmarkReidentify_100kLines(b *testing.B) {
	const devices, perDevice = 500, 200
	run := func(b *testing.B, moved bool) {
		for b.Loop() {
			b.StopTimer()
			db := storetest.Migrated(b, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "inventory", FS: Migrations})
			seedLines(b, db, devices, perDevice)
			svc, err := New(Config{DB: db, Audit: audit.New(nil)})
			if err != nil {
				b.Fatal(err)
			}
			if !moved {
				if err := svc.ReidentifyLines(b.Context()); err != nil {
					b.Fatal(err)
				}
				if err := db.Write(b.Context(), func(tx *sql.Tx) error {
					_, err := tx.ExecContext(b.Context(), `UPDATE inv_catalogue_pass SET revision = 'older-catalogue'`)
					return err
				}); err != nil {
					b.Fatal(err)
				}
			}
			b.StartTimer()
			if err := svc.ReidentifyLines(b.Context()); err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			var n int
			if err := db.Reader().QueryRowContext(b.Context(), `SELECT count(*) FROM inv_software WHERE product_key = 'python|python' AND line <> ''`).Scan(&n); err != nil || n != devices*20 {
				b.Fatalf("%d Python lines on trains, want %d (%v)", n, devices*20, err)
			}
			b.StartTimer()
		}
	}
	b.Run("one_product_gains_trains", func(b *testing.B) { run(b, true) })
	b.Run("nothing_moves", func(b *testing.B) { run(b, false) })
}
