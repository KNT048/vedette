package findings

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/findings/findingstest"
	"github.com/knt048/vedette/modules/inventory"
)

// Migration 0002 adds fnd_finding.fix_channel: the findings a box already has (an ordinary distribution update, a restart into an
// installed kernel, a handled one) read 'public' with their fix and By fix group unchanged, the next match sets a Pro-only fix, and a
// channel the code does not know is refused before it is written (Finding.Validate) and counted by the selfcheck.
func TestMigrationFixChannelKeepsTheStoredFindings(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	for _, m := range []storetest.Migration{{Module: "core", FS: core.Migrations}, {Module: "inventory", FS: inventory.Migrations}} {
		if err := store.Migrate(ctx, db, m.Module, m.FS); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.MigrateTo(ctx, db, "findings", Migrations, 1); err != nil {
		t.Fatal(err)
	}
	findingstest.ParentRows(t, db)
	const ts = "2026-11-26T08:51:00.000Z"
	rows := []string{
		`('f-pip', 'a-1', 'CVE-2025-66471', 's-pip', 1, 'package', 'device', 'distro', '25.1.1+dfsg-1ubuntu2', 'distro_update', '25.1.1+dfsg-1ubuntu2+esm3', NULL,
			'canonical|pip|distro_update|25.1.1+dfsg-1ubuntu2+esm3', 'open', NULL, NULL, NULL, NULL, NULL, NULL, 2)`,
		`('f-kernel', 'a-1', 'CVE-2026-91002', 's-kernel', 1, 'package', 'device', 'distro', '7.0.0-43.43', 'restart', '7.0.0-44.44', NULL,
			'linux|kernel|restart|7.0.0-44.44', 'open', NULL, NULL, NULL, NULL, NULL, NULL, 5)`,
		`('f-ssh', 'a-1', 'CVE-2026-91001', 's-ssh', 0, 'package', 'device', 'distro', '1:9.6p1-3ubuntu13.4', 'distro_update', '1:9.6p1-3ubuntu13.5', NULL,
			'openbsd|openssh|distro_update|1:9.6p1-3ubuntu13.5', 'handled', 'patched', 'version_moved', 'system', '` + ts + `', '1:9.6p1-3ubuntu13.4', '1:9.6p1-3ubuntu13.5', 5)`,
	}
	for _, r := range rows {
		if err := db.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO fnd_finding (id, asset_id, cve, software_id, detected, basis, verified, range_origin, matched_version,
				fix_kind, fix_version, fix_ref, fix_key, state, resolution, via, resolved_by, resolved_at, from_version, to_version, urgency,
				urgency_at, first_seen, last_seen, updated_at) VALUES `+r[:len(r)-1]+`, '`+ts+`', '`+ts+`', '`+ts+`', '`+ts+`')`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Migrate(ctx, db, "findings", Migrations); err != nil {
		t.Fatal(err)
	}
	fs, err := selectFindings(ctx, db.Reader(), `1 = 1 ORDER BY id`)
	if err != nil || len(fs) != 3 {
		t.Fatalf("read after the migration: %d findings, %v", len(fs), err)
	}
	for _, f := range fs {
		if f.Fix.Chan() != ChannelPublic || f.Fix.Channel != "" || f.FixKey != FixKey(productPart(f), f.Fix) {
			t.Errorf("%s after the migration: fix %+v, key %q", f.ID, f.Fix, f.FixKey)
		}
	}
	var broken int
	if err := db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM fnd_finding WHERE length(CAST(fix_key AS BLOB)) < 400
		AND substr(fix_key, -length(`+fixTailSQL+`)) <> `+fixTailSQL).Scan(&broken); err != nil || broken != 0 {
		t.Fatalf("fix keys that do not name their fix after the migration: %d %v", broken, err)
	}
	// the match pass stores a Pro-only fix: its channel, and a group of its own
	f := fs[1]
	f.Fix.Channel, f.FixKey = ChannelUbuntuPro, FixKey(productPart(f), Fix{Kind: f.Fix.Kind, Version: f.Fix.Version, Channel: ChannelUbuntuPro})
	if err := db.Write(ctx, func(tx *sql.Tx) error { return writeFinding(ctx, tx, f, false, nil) }); err != nil {
		t.Fatal(err)
	}
	if got, err := queryFindings(ctx, db.Reader(), `id = ?`, f.ID); err != nil || got[0].Fix.Chan() != ChannelUbuntuPro || got[0].FixKey != "canonical|pip|distro_update|25.1.1+dfsg-1ubuntu2+esm3|ubuntu_pro" {
		t.Fatalf("a Pro-only fix stored: %+v %v", got, err)
	}
	bad := fs[0]
	bad.Fix.Channel = "extended"
	if err := bad.Validate(); err == nil {
		t.Fatal("a channel the code does not know validates")
	}
}
