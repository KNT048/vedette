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
func newBigWorld(t *testing.T, r *fakeReader, hh, mm int, fixed ...bool) (*sa.Service, *fakeInv) {
	t.Helper()
	db := storetest.New(t)
	if err := store.Migrate(t.Context(), db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(t.Context(), db, "sensor-active", sa.Migrations); err != nil {
		t.Fatal(err)
	}
	inventoryStub(t, db)
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
	clock := func() time.Time { return base.Add(time.Since(t0)) }
	if len(fixed) > 0 && fixed[0] { // the clock stands still: the window never closes under a slow machine
		clock = func() time.Time { return base }
	}
	svc, err := sa.New(sa.Config{DB: db, Inventory: inv, Observe: &sink{}, Software: &sink{}, Services: &sink{}, NmapPath: nm.path,
		Clock: clock, Secrets: sec, Audit: audit.New(time.Now), SNMP: r})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	// every device had its first check a week ago: the tests are about SNMP, and the window's driver checks a device no check reached
	// yet before anything else
	err = db.Write(t.Context(), func(tx *sql.Tx) error {
		for id := range inv.assets {
			if _, err := tx.ExecContext(t.Context(), doneRunSQL, "run-first-"+id, sa.RunCheck, "2026-11-02T02:00:00.000Z", id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO sa_probe (time, run_id, shape, rate, hosts, flags, targets, result)
				VALUES ('2026-11-02T02:00:01.000Z', ?, 'normal', 100, 1, '-sS', '10.0.0.1', 'ok: 1 hosts up')`, "run-first-"+id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, inv
}

// M1, L3: the round picks its devices when it starts; each batch reads them again, so a device set to never, one no longer approved,
// and one whose SNMP was removed while batch 1 ran get nothing in batch 2.
func TestSNMPEachBatchReadsTheDevicesAgain(t *testing.T) {
	t.Parallel()
	var svc *sa.Service
	var inv *fakeInv
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
			// a device of batch 2: removing its SNMP does not stop batch 1, which does not carry it (a batch that carries it is stopped)
			if err := svc.DeleteSNMP(ctx, "a", "a-75"); err != nil {
				t.Error(err)
			}
		} else {
			second = j
		}
		return nil, nil
	}
	svc, inv = newBigWorld(t, r, 2, 0)
	setUpAll(t, svc, inv)
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if batch != 2 {
		t.Fatalf("%d batches", batch)
	}
	if ips := ipsOf(second); !slices.Equal(ips, []string{"192.168.10.74", "192.168.10.76", "192.168.10.77"}) {
		t.Errorf("batch 2 read %v", ips)
	}
}

// A batch of the window's round ends with the window (INV-3), as an nmap run does, not an hour later.
func TestSNMPRoundEndsWithTheWindow(t *testing.T) {
	t.Parallel()
	var deadline time.Time
	var has bool
	r := &fakeReader{answer: func(ctx context.Context, _ sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		deadline, has = ctx.Deadline()
		return nil, nil
	}}
	svc, inv := newBigWorld(t, r, 4, 59, true) // the window closes at 05:00, a minute from the clock, which stands still
	setUpAll(t, svc, inv)
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(r.sent()) == 0 || !has || time.Until(deadline) > 60*time.Second {
		t.Fatalf("%d jobs, deadline in %v (has %v), want at most the minute left of the window", len(r.sent()), time.Until(deadline), has)
	}
}

// Review #715 round 2.

// A device's SNMP edited after the batch read it and before its secrets are opened stops the batch: a v3
// password never leaves as a v2c community, a rotated community never goes to the old read address.
func TestSNMPAnEditBetweenTheCheckAndTheJobStopsIt(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	for name, in := range map[string]sa.SNMPInput{
		"v2c to v3":                  {Version: "v3", Username: "u", Auth: "sha", AuthPassword: secrets.NewValue("auth-pass-XYZ"), Priv: "none"},
		"rotated and read elsewhere": {Version: "v2c", Community: secrets.NewValue("rotated-community-1"), ReadFrom: "192.168.10.30"},
	} {
		w.set("a-sw", v2c("s3cret-community"))
		w.inv.mu.Lock()
		w.inv.onInScope = func() {
			if _, err := w.svc.SetSNMP(context.Background(), "a", "a-sw", in); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
		w.inv.mu.Unlock()
		if _, err := w.svc.CheckSNMP(t.Context(), "a", "a-sw"); apiCode(err) != "stopped" {
			t.Errorf("%s: %v, want stopped", name, err)
		}
	}
	if jobs := r.sent(); len(jobs) != 0 {
		t.Fatalf("%d jobs left with changed settings", len(jobs))
	}
}

// Removing a device's SNMP, or editing it, stops a job the worker already has.
func TestSNMPARemovalOrAnEditStopsAJobWithTheWorker(t *testing.T) {
	t.Parallel()
	started := make(chan struct{}, 1)
	r := &fakeReader{answer: func(ctx context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		started <- struct{}{}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second): // only without the fix: the job runs on with the old settings
			return juniperAnswers(j), nil
		}
	}}
	w := newSNMPWorld(t, r)
	for name, change := range map[string]func() error{
		"removed": func() error { return w.svc.DeleteSNMP(context.Background(), "a", "a-sw") },
		"edited": func() error {
			_, err := w.svc.SetSNMP(context.Background(), "a", "a-sw", sa.SNMPInput{Version: "v2c", Community: secrets.NewValue("other"), ReadFrom: "192.168.10.30"})
			return err
		},
	} {
		w.set("a-sw", v2c("community-1"))
		go func() {
			<-started
			if err := change(); err != nil {
				t.Error(err)
			}
		}()
		if _, err := w.svc.CheckSNMP(t.Context(), "a", "a-sw"); apiCode(err) != "stopped" {
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
	setUpAll(t, svc, inv)
	if err := svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !cancelled {
		t.Fatal("the shortened window did not stop the batch")
	}
}

// The migrations run in order only (goose has no out-of-order): they are numbered from 0001 without a gap.
func TestMigrationsKeepTheirOrder(t *testing.T) {
	t.Parallel()
	names, err := fs.Glob(sa.Migrations, "*.sql")
	if err != nil || len(names) == 0 {
		t.Fatalf("%v %v", names, err)
	}
	for i, n := range names {
		if want := fmt.Sprintf("%04d_", i+1); !strings.HasPrefix(n, want) {
			t.Errorf("migration %d is %s, want %s…", i+1, n, want)
		}
	}
}
