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
	// only for .75, a device of batch 2: deleting it does not stop batch 1, which does not carry it (r2 M1 stops a batch that does)
	c, err := svc.AddSNMP(t.Context(), "a", v2cInput("deleted mid-round", "community-2", "192.168.10.75"))
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

// Review #715 round 2.

// r2 M1 (A, B): a credential edited after the batch read it and before its secrets are opened stops the batch: a v3 password never
// leaves as a v2c community, a rotated community never goes to a device the narrowed scope no longer holds.
func TestSNMPAnEditBetweenTheCheckAndTheJobStopsIt(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	toV3 := w.add(v2cInput("to v3", "s3cret-community"))
	narrowed := w.add(v2cInput("narrowed", "old-community-1"))
	for name, edit := range map[string]struct {
		id string
		in sa.SNMPCredentialInput
	}{
		"v2c to v3":            {toV3.ID, sa.SNMPCredentialInput{Name: "to v3", Version: "v3", Username: "u", Auth: "sha", AuthPassword: secrets.NewValue("auth-pass-XYZ"), Priv: "none", Scope: []string{worldScope}}},
		"rotated and narrowed": {narrowed.ID, v2cInput("narrowed", "rotated-community-1", "192.168.10.30")},
	} {
		w.inv.mu.Lock()
		w.inv.onInScope = func() {
			if _, err := w.svc.EditSNMP(context.Background(), "a", edit.id, edit.in); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
		w.inv.mu.Unlock()
		if _, err := w.svc.TestSNMP(t.Context(), "a", edit.id, "192.168.10.20"); apiCode(err) != "stopped" {
			t.Errorf("%s: %v, want stopped", name, err)
		}
	}
	if jobs := r.sent(); len(jobs) != 0 {
		t.Fatalf("%d jobs left with a changed credential", len(jobs))
	}
}

// r2 M1 (C): a delete or a narrowing edit of a credential stops a job the worker already has.
func TestSNMPADeleteOrANarrowingStopsAJobWithTheWorker(t *testing.T) {
	t.Parallel()
	started := make(chan struct{}, 1)
	r := &fakeReader{answer: func(ctx context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		started <- struct{}{}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second): // only without the fix: the job runs on with the old credential
			return juniperAnswers(j), nil
		}
	}}
	w := newSNMPWorld(t, r)
	gone := w.add(v2cInput("deleted", "community-1"))
	narrow := w.add(v2cInput("narrowed", "community-2"))
	for name, change := range map[string]func() error{
		gone.ID: func() error { return w.svc.DeleteSNMP(context.Background(), "a", gone.ID) },
		narrow.ID: func() error {
			_, err := w.svc.EditSNMP(context.Background(), "a", narrow.ID, v2cInput("narrowed", "", "192.168.10.30"))
			return err
		},
	} {
		go func() {
			<-started
			if err := change(); err != nil {
				t.Error(err)
			}
		}()
		if _, err := w.svc.TestSNMP(t.Context(), "a", name, "192.168.10.20"); apiCode(err) != "stopped" {
			t.Errorf("%s: %v, want stopped", name, err)
		}
	}
}

// r2 L1: a window shortened under a round's batch stops it (its deadline came from the old end), as nmap's run is stopped.
func TestSNMPAShorterWindowStopsTheBatch(t *testing.T) {
	t.Parallel()
	var svc *sa.Service
	var inv *fakeInv
	cancelled := false
	r := &fakeReader{}
	r.answer = func(ctx context.Context, _ sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		if !cancelled {
			inv.set(func(s *sa.Settings) { s.To = "02:30" }) // it is 02:00: still inside, but the batch had until 03:00
			go func() { _ = svc.SettingsChanged(context.WithoutCancel(ctx)) }()
			select {
			case <-ctx.Done():
				cancelled = true
			case <-time.After(5 * time.Second): // only without the fix
			}
		}
		return nil, ctx.Err()
	}
	svc, inv = newBigWorld(t, r, 2, 0)
	if _, err := svc.AddSNMP(t.Context(), "a", v2cInput("all", "community-1")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !cancelled {
		t.Fatal("the shortened window did not stop the batch")
	}
}

// r2 M2: the migrations run in order only (goose has no out-of-order), and 0004_snmp keeps the probe shape of #714's 0003: this
// branch must carry 0003_gentle_titles, numbered without a gap, or a box that got 0004 first would never start the module.
func TestMigrationsKeepTheirOrder(t *testing.T) {
	t.Parallel()
	names, err := fs.Glob(sa.Migrations, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(names, "0003_gentle_titles.sql") {
		t.Fatalf("0003_gentle_titles.sql (#714) is missing: merge origin/main once #714 has landed (%v)", names)
	}
	for i, n := range names {
		if want := fmt.Sprintf("%04d_", i+1); !strings.HasPrefix(n, want) {
			t.Errorf("migration %d is %s, want %s…", i+1, n, want)
		}
	}
}
