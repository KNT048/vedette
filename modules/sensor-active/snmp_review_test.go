package sensoractive_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// Review #715 round 1. Every test here fails without its fix.

// newBigWorld is a service over 70 approved devices .10 .. .79 (two batches of a round: 64 + 6), the window open (Monday at hh:mm in
// a 01:00-05:00 window).
func newBigWorld(t *testing.T, r *fakeReader, hh, mm int) (*sa.Service, *fakeInv) {
	t.Helper()
	db := storetest.New(t)
	if err := store.Migrate(t.Context(), db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(t.Context(), db, "sensor-active", sa.Migrations); err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New(bytes.Repeat([]byte{9}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	inv := &fakeInv{
		st:     sa.Settings{Enabled: true, ScopeConfirmed: true, LANRanges: []string{"192.168.10.0/24"}, Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "01:00", To: "05:00", Rate: 100},
		assets: map[string]netip.Addr{}, decision: map[string]sa.Decision{}, approved: map[string]bool{}, addrs: map[netip.Addr]string{},
	}
	for i := 10; i < 80; i++ {
		id, a := fmt.Sprintf("a-%d", i), netip.MustParseAddr(fmt.Sprintf("192.168.10.%d", i))
		inv.assets[id], inv.approved[id], inv.addrs[a] = a, true, id
	}
	nm := writeFakeNmap(t, fakeOpts{})
	base, t0 := local(9, hh, mm), time.Now()
	svc, err := sa.New(sa.Config{DB: db, Inventory: inv, Observe: &sink{}, Software: &sink{}, Services: &sink{}, NmapPath: nm.path,
		Clock: func() time.Time { return base.Add(time.Since(t0)) }, Secrets: sec, Audit: audit.New(time.Now), SNMP: r})
	if err != nil {
		t.Fatal(err)
	}
	return svc, inv
}

// M1, L3: the round picks its devices and credentials when it starts; each batch reads them again, so a device set to never, one no
// longer approved, and a credential deleted while batch 1 ran get nothing in batch 2.
func TestSNMPEachBatchReadsTheDevicesAndCredentialsAgain(t *testing.T) {
	t.Parallel()
	var svc *sa.Service
	var inv *fakeInv
	var gone string
	var second sensorlink.SNMPJob
	batch := 0
	r := &fakeReader{}
	r.answer = func(ctx context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		batch++
		if batch == 1 {
			inv.mu.Lock()
			inv.decision["a-79"] = sa.Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Never: true}
			inv.approved["a-78"] = false
			inv.mu.Unlock()
			if err := svc.DeleteSNMP(ctx, "a", gone); err != nil {
				t.Error(err)
			}
		} else {
			second = j
		}
		return nil, nil
	}
	svc, inv = newBigWorld(t, r, 2, 0)
	if _, err := svc.AddSNMP(t.Context(), "a", v2cInput("all", "community-1")); err != nil {
		t.Fatal(err)
	}
	c, err := svc.AddSNMP(t.Context(), "a", v2cInput("deleted mid-round", "community-2"))
	if err != nil {
		t.Fatal(err)
	}
	gone = c.ID
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if batch != 2 {
		t.Fatalf("%d batches", batch)
	}
	var ips []string
	for _, tg := range second.Targets {
		ips = append(ips, tg.IP)
		if !slices.Equal(tg.Credentials, []int{0}) {
			t.Errorf("%s tries %v", tg.IP, tg.Credentials)
		}
	}
	if !slices.Equal(ips, []string{"192.168.10.74", "192.168.10.75", "192.168.10.76", "192.168.10.77"}) {
		t.Errorf("batch 2 read %v", ips)
	}
	if len(second.Credentials) != 1 || second.Credentials[0].Community != "community-1" {
		t.Errorf("batch 2 carried %d credentials", len(second.Credentials))
	}
}

// M2: a batch of the window's round ends with the window (INV-3), as an nmap run does, not an hour later.
func TestSNMPRoundEndsWithTheWindow(t *testing.T) {
	t.Parallel()
	var deadline time.Time
	var has bool
	r := &fakeReader{answer: func(ctx context.Context, _ sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		deadline, has = ctx.Deadline()
		return nil, nil
	}}
	svc, _ := newBigWorld(t, r, 4, 59) // the window closes at 05:00
	if _, err := svc.AddSNMP(t.Context(), "a", v2cInput("all", "community-1")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(r.sent()) == 0 || !has || time.Until(deadline) > 61*time.Second {
		t.Fatalf("%d jobs, deadline in %v (has %v), want at most the minute left of the window", len(r.sent()), time.Until(deadline), has)
	}
}

// L1, L2: a fragile device at an address of the box (a decoy) is never read; nor is an address the inventory maps to a device that
// now has another one.
func TestSNMPTestRefusesTheBoxAndAMovedDevice(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	decoy, moved := netip.MustParseAddr("192.168.10.25"), netip.MustParseAddr("192.168.10.26")
	w.inv.mu.Lock()
	w.inv.assets["a-decoy"], w.inv.addrs[decoy], w.inv.approved["a-decoy"] = decoy, "a-decoy", true
	w.inv.decision["a-decoy"] = sa.Decision{Reason: "fragile_passive_only", Fragile: true}
	w.inv.box = append(w.inv.box, decoy)
	w.inv.addrs[moved] = "a-sw" // a stale address of the switch, which is at .20 now
	w.inv.mu.Unlock()
	c := w.add(v2cInput("all", "community-1"))
	for ip, want := range map[string]string{decoy.String(): "box", moved.String(): "not_in_inventory"} {
		res, err := w.svc.TestSNMP(t.Context(), "a", c.ID, ip)
		if err != nil || res.Reason != want {
			t.Errorf("%s: %v %+v, want %s", ip, err, res, want)
		}
	}
	if n := len(r.sent()); n != 0 {
		t.Fatalf("%d jobs sent", n)
	}
}

// L5: migration 0004 keeps the probe log's counter: the id of a pruned probe row is never handed out again.
func TestMigration0004KeepsTheProbeCounter(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := storetest.New(t)
	before := fstest.MapFS{}
	if err := fs.WalkDir(sa.Migrations, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(p, "0004") {
			return err
		}
		b, err := fs.ReadFile(sa.Migrations, p)
		before[p] = &fstest.MapFile{Data: b}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "sensor-active", before); err != nil {
		t.Fatal(err)
	}
	exec := func(q string) {
		t.Helper()
		if err := db.Write(ctx, func(tx *sql.Tx) error { _, err := tx.ExecContext(ctx, q); return err }); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO sa_job (id, kind, started_at, status) VALUES ('j', 'sweep', '2026-11-01T01:00:00.000Z', 'done')`)
	for i := 1; i <= 3; i++ {
		exec(fmt.Sprintf(`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-01T01:00:00.000Z', 'j', 'sweep', 1, 1, '-sn', '192.168.1.%d', 'ok')`, i))
	}
	exec(`DELETE FROM sa_probe WHERE id > 1`) // the prune of old rows
	if err := store.Migrate(ctx, db, "sensor-active", sa.Migrations); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO sa_probe (time, job_id, shape, rate, hosts, flags, targets, result) VALUES ('2026-11-13T01:00:00.000Z', 'j', 'snmp', 1, 1, 'GET', '192.168.1.9', 'ok')`)
	var id int
	if err := db.Reader().QueryRowContext(ctx, `SELECT max(id) FROM sa_probe`).Scan(&id); err != nil || id != 4 {
		t.Fatalf("the next probe id is %d (%v), want 4", id, err)
	}
}
