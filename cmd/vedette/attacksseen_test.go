package main

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	idsmodule "github.com/knt048/vedette/modules/ids"
	"github.com/knt048/vedette/modules/inventory"
)

// The reporting window's date of an attacked CVE is the first and the latest alert that named it, over every address it hit.
func TestAttacksSeen_FirstAndLatestAlertPerCVE(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "inventory", inventory.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "ids", idsmodule.Migrations); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	plant := func(id, dst string, first, last time.Time, cve string) {
		t.Helper()
		err := db.Write(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ids_alert (id, source, signature, priority, src_ip, dst_ip, dst_asset_id, first_ts, last_ts, count, dedupe_key)
				VALUES (?, 'suricata', 'ET EXPLOIT x', 1, '203.0.113.9', ?, NULL, ?, ?, 1, ?)`, id, dst, store.FormatTS(first), store.FormatTS(last), strings.Repeat(id[len(id)-1:], 64)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO ids_alert_cve (alert_id, cve) VALUES (?, ?)`, id, cve)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	plant("al-1", "192.0.2.1", now.Add(-48*time.Hour), now.Add(-40*time.Hour), "CVE-2016-0201")
	plant("al-2", "192.0.2.2", now.Add(-30*time.Hour), now.Add(-time.Hour), "CVE-2016-0201")
	plant("al-3", "192.0.2.2", now.Add(-5*time.Hour), now.Add(-4*time.Hour), "CVE-2016-0202")
	got, err := attacksSeen(ctx, db, now.Add(-72*time.Hour))
	if err != nil || len(got) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	for _, a := range got {
		if a.CVE == "CVE-2016-0201" && (!a.First.Equal(now.Add(-48*time.Hour)) || !a.Last.Equal(now.Add(-time.Hour))) {
			t.Errorf("CVE-2016-0201: %+v", a)
		}
	}
}
