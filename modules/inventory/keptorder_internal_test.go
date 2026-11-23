package inventory

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// Of two rows of one machine, an automatic join keeps an approved row a person watches over an ignored
// one, even an older or approved ignored one (a duplicate a person ignored by mistake), so a join never hides a watched server's
// findings. An ignored row next to a row nobody approved still follows the usual order (the re-sighted staff phone stays ignored).
func TestKeptOrderKeepsAWatchedApprovedRowOverAnIgnoredOne(t *testing.T) {
	t.Parallel()
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "inventory", FS: Migrations})
	ctx := t.Context()
	old, newer := "2026-11-01T10:00:00.000Z", "2026-11-09T10:00:00.000Z"
	err := db.Write(ctx, func(tx *sql.Tx) error {
		for _, r := range []struct {
			id, first string
			approved  bool
			ignored   *string
		}{
			{"a-ignored-dup", old, true, &old},          // older, approved, ignored
			{"a-server", newer, true, nil},              // approved, watched
			{"a-phone", old, false, &old},               // older, ignored, not approved
			{"a-new-phone", newer, false, nil},          // a new sighting nobody approved
			{"a-declared", old, true, &old},             // added by hand, then ignored (origin set below)
			{"a-declared-unapproved", old, false, &old}, // added by hand, ignored, un-ignored (approval cleared), ignored again
		} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO inv_asset (id, kind, origin, approved, first_seen, last_seen, ignored_at) VALUES (?, 'unknown', 'discovered', ?, ?, ?, ?)`,
				r.id, r.approved, r.first, r.first, r.ignored); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET origin = 'manual' WHERE id IN ('a-declared', 'a-declared-unapproved')`); err != nil {
			return err
		}
		for _, c := range []struct{ x, y, into string }{
			{"a-server", "a-declared", "a-declared"},                       // review r1 L1 of #948: a declared row keeps its origin and address; joinAs watches it again
			{"a-server", "a-declared-unapproved", "a-declared-unapproved"}, // review r1 L1 of #955: joinAs carries the approval onto it
			{"a-ignored-dup", "a-server", "a-server"},
			{"a-server", "a-ignored-dup", "a-server"},
			{"a-phone", "a-new-phone", "a-phone"}, // the usual order: the older row
		} {
			_, into, err := keptOrder(ctx, tx, c.x, c.y)
			if err != nil {
				return err
			}
			if into != c.into {
				t.Errorf("keptOrder(%s, %s) keeps %s, want %s", c.x, c.y, into, c.into)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Review r1 L1 of #955: a hand-added device that was ignored, un-ignored (which clears its approval) and ignored again, joined to the
// row an osquery enrolment approved (agentOrphan, sameMAC), stays the kept row with its origin and typed address, is watched again
// and keeps the enrolment's approval: no watched, unapproved device in To review whose approval nobody will give again. The approval
// still never moves onto a discovered row (review H1 of #722), a suspicious mark on either row keeps the declared row waiting for a
// person, an ignored row's approval never carries and a chassis join never carries (r1 L1 of #959).
// The merge audit row says so only when the approval was kept (r1 L2 of #959).
func TestAJoinCarriesTheApprovalOntoADeclaredRow(t *testing.T) {
	t.Parallel()
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "inventory", FS: Migrations})
	svc, err := New(Config{DB: db, Audit: audit.New(nil)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	old, newer, enrolled := "2026-11-01T10:00:00.000Z", "2026-11-09T10:00:00.000Z", "2026-11-09T10:05:00.000Z"
	type state struct {
		origin, ip     string
		approved       bool
		approvedAt     sql.NullString
		ignored, alive bool
	}
	read := func(tx *sql.Tx, id string) state {
		var s state
		var ip sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT origin, ip, approved, approved_at, ignored_at IS NOT NULL FROM inv_asset WHERE id = ?`, id).
			Scan(&s.origin, &ip, &s.approved, &s.approvedAt, &s.ignored)
		if errors.Is(err, sql.ErrNoRows) {
			return s
		}
		if err != nil {
			t.Fatal(err)
		}
		s.ip, s.alive = ip.String, true
		return s
	}
	carried := 0 // audit rows that say the approval was kept, so far
	for _, c := range []struct {
		name                 string
		declared, suspicious bool // the kept row: hand-added, marked suspicious
		fromSuspicious       bool // the approved row marked suspicious by a person
		fromIgnored          bool // the approved row ignored, the declared row watched and unapproved (review r1 M1 of #959)
		mode                 joinMode
		wantApproved         bool
	}{
		{name: "declared", declared: true, mode: joinMachine, wantApproved: true},
		{name: "declared and marked suspicious", declared: true, suspicious: true, mode: joinMachine},
		{name: "the approved row marked suspicious", declared: true, fromSuspicious: true, mode: joinMachine},
		{name: "the approved row ignored", declared: true, fromIgnored: true, mode: joinMachine},
		{name: "a chassis join (review r1 L1 of #959)", declared: true, mode: joinChassis},
		{name: "discovered (H1 of #722)", mode: joinMachine},
	} {
		err := db.Write(ctx, func(tx *sql.Tx) error {
			for _, q := range []struct {
				sql  string
				args []any
			}{
				{`DELETE FROM inv_asset`, nil},
				{`INSERT INTO inv_asset (id, kind, origin, ip, mac, approved, suspicious, first_seen, last_seen, ignored_at)
					VALUES ('a-kept', 'server', 'discovered', '192.168.18.50', '00:1b:21:aa:bb:cc', 0, 0, ?, ?, ?)`, []any{old, old, old}},
				{`INSERT INTO inv_asset (id, kind, origin, approved, approved_at, first_seen, last_seen) VALUES ('a-agent', 'server', 'discovered', 1, ?, ?, ?)`,
					[]any{enrolled, newer, newer}},
			} {
				if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
					return err
				}
			}
			if c.declared {
				if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET origin = 'manual' WHERE id = 'a-kept'`); err != nil {
					return err
				}
			}
			for _, q := range []struct {
				on  bool
				sql string
			}{
				{c.suspicious, `UPDATE inv_asset SET suspicious = 1 WHERE id = 'a-kept'`},
				{c.fromSuspicious, `UPDATE inv_asset SET suspicious = 1 WHERE id = 'a-agent'`},
				{c.fromIgnored, `UPDATE inv_asset SET ignored_at = last_seen WHERE id = 'a-agent'`},
				{c.fromIgnored, `UPDATE inv_asset SET ignored_at = NULL WHERE id = 'a-kept'`},
			} {
				if !q.on {
					continue
				}
				if _, err := tx.ExecContext(ctx, q.sql); err != nil {
					return err
				}
			}
			from, into := "a-agent", "a-kept"
			if c.declared {
				var err error
				if from, into, err = keptOrder(ctx, tx, "a-agent", "a-kept"); err != nil {
					return err
				}
				if into != "a-kept" {
					t.Fatalf("%s: keptOrder keeps %s, want the declared row", c.name, into)
				}
			}
			watch, err := svc.joinAs(ctx, tx, nil, from, into, "test", c.mode, systemActor, false)
			if err != nil {
				return err
			}
			if c.wantApproved {
				carried++
			}
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM core_audit WHERE action = 'inventory.merge' AND detail LIKE ?`,
				"%; a-agent was approved, so "+deviceName(ctx, tx, "a-kept")+" is approved%").Scan(&n); err != nil {
				return err
			}
			if n != carried {
				t.Errorf("%s: %d merge audit rows say the approval was kept, want %d", c.name, n, carried)
			}
			got := read(tx, "a-kept")
			if watch != EventAssetUnignored || got.ignored || read(tx, "a-agent").alive || got.ip != "192.168.18.50" {
				t.Errorf("%s: watch %q, kept %+v", c.name, watch, got)
			}
			if got.approved != c.wantApproved || (c.wantApproved && got.approvedAt.String != enrolled) || (!c.wantApproved && got.approvedAt.Valid) {
				t.Errorf("%s: approved %v at %v, want %v at %s", c.name, got.approved, got.approvedAt, c.wantApproved, enrolled)
			}
			if c.declared && got.origin != "manual" {
				t.Errorf("%s: origin %s", c.name, got.origin)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
