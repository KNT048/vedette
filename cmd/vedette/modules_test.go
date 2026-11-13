package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth/authtest"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/logs"
)

// Migrations run in wiredModules order, so a module whose tables reference another module's must
// come after it. The order is checked against the manifests' depends lists.
func TestWiredModulesFollowDependencies(t *testing.T) {
	t.Parallel()
	manifests, err := modreg.Load(modules.Manifests)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]modreg.Manifest{}
	for _, m := range manifests {
		byID[m.ID] = m
	}
	wired := wiredModules()
	if len(wired) == 0 || wired[0].ID != "core" {
		t.Fatalf("wiredModules must start with core, got %v", ids(wired))
	}
	pos := map[string]int{}
	for i, w := range wired {
		m, ok := byID[w.ID]
		if !ok {
			t.Fatalf("wired module %q has no modules/%s/MANIFEST.yaml", w.ID, w.ID)
		}
		if m.Component {
			t.Fatalf("wired module %q is a component, not a module", w.ID)
		}
		if _, dup := pos[w.ID]; dup {
			t.Fatalf("module %q is wired twice", w.ID)
		}
		for _, dep := range m.Depends {
			if _, ok := pos[dep]; !ok {
				t.Errorf("module %q depends on %q, which is not wired before it (order %v)", w.ID, dep, ids(wired))
			}
		}
		pos[w.ID] = i
	}
}

func TestAddJobs(t *testing.T) {
	t.Parallel()
	run := func(context.Context) error { return nil }
	tests := []struct {
		name    string
		jobs    []jobs.Job
		wantErr string
	}{
		{name: "own module", jobs: []jobs.Job{{Module: "feeds", Name: "pull-kev", Every: time.Hour, Run: run}}},
		{name: "other module", jobs: []jobs.Job{{Module: "core", Name: "pull-kev", Every: time.Hour, Run: run}}, wantErr: `module feeds registers job "pull-kev" for module "core"`},
		{name: "invalid job", jobs: []jobs.Job{{Module: "feeds", Name: "pull-kev", Run: run}}, wantErr: "jobs of feeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sched := jobs.New(slog.New(slog.DiscardHandler), allOn{}, nil)
			var got deps
			wired := []moduleWiring{
				{ID: "core"},
				{ID: "feeds", Jobs: func(d deps) []jobs.Job { got = d; return tt.jobs }},
			}
			d := deps{Clock: time.Now}
			err := addJobs(sched, d, wired)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("addJobs: %v", err)
				}
				if got.Clock == nil {
					t.Fatal("Jobs func did not receive deps")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("addJobs error = %v, want containing %q", err, tt.wantErr)
			}
			if tt.name == "invalid job" && !errors.Is(err, jobs.ErrInvalid) {
				t.Fatalf("addJobs error = %v, want wrapping jobs.ErrInvalid", err)
			}
		})
	}
}

func ids(w []moduleWiring) []string {
	out := make([]string, len(w))
	for i, x := range w {
		out[i] = x.ID
	}
	return out
}

// deps.Inventory publishes on deps.Bus: one service instance, events reach other modules (issue #39).
func TestInventoryEventsReachTheBus(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	db, err := openMigrated(ctx, filepath.Join(t.TempDir(), "v.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d := deps{Log: log, DB: db, Audit: audit.New(nil), Clock: time.Now, Bus: events.NewBus(log)}
	d.Inventory = newInventory(&d)
	got := make(chan events.Event, 1)
	d.Bus.Subscribe(inventory.EventAssetUpdated, func(_ context.Context, e events.Event) error {
		select {
		case got <- e:
		default:
		}
		return nil
	})
	if _, err := d.Inventory.EnsureBox(ctx, inventory.BoxInfo{Hostname: "box"}); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-got:
		if e.Name != inventory.EventAssetUpdated {
			t.Fatalf("event %q", e.Name)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no inventory.asset.updated on the bus")
	}
}

// Every module handler embedded in handler must be built by newHandler: a nil embedded pointer compiles
// but panics on the first request to that module (WP-11 merge nearly shipped one).
func TestNewHandlerSetsEveryModule(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k")
	if err := ensureKey(keyPath); err != nil {
		t.Fatal(err)
	}
	key, err := secrets.LoadKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openMigrated(ctx, filepath.Join(dir, "v.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logsDB := storetest.Migrated(t, storetest.Migration{Module: logs.ModuleID, FS: logs.VolumeMigrations})
	aud := audit.New(nil)
	reg, err := modreg.New(ctx, modreg.Config{DB: db, Audit: aud, Manifests: modules.Manifests, Version: version, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	d := deps{Log: log, DB: db, LogsDB: logsDB, Reg: reg, Secrets: sec, Audit: aud, Clock: time.Now, Bus: events.NewBus(log), Argon2: authtest.Cheap}
	if err := buildServices(t.Context(), &d); err != nil {
		t.Fatal(err)
	}
	h := reflect.ValueOf(newHandler(t.Context(), d))
	for i := range h.NumField() {
		if f := h.Field(i); f.Kind() == reflect.Pointer && f.IsNil() {
			t.Errorf("newHandler leaves %s nil", h.Type().Field(i).Name)
		}
	}
}

// D-189: a real Registry.Publish switch-off of the honeypot reaches its teardown through the OffGuard and addOffGuards, the way main wires it.
func TestSwitchingTheHoneypotOffRunsItsTeardown(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	db, err := openMigrated(ctx, filepath.Join(t.TempDir(), "v.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	wired := wiredModules()
	reg, err := modreg.New(ctx, modreg.Config{DB: db, Audit: audit.New(nil), Manifests: modules.Manifests, Version: version, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	toggle := func(on bool) {
		t.Helper()
		var ch modreg.Change
		err := db.Write(ctx, func(tx *sql.Tx) error {
			var err error
			if on {
				ch, err = reg.Enable(ctx, tx, "admin@acme.example", "honeypot", true)
			} else {
				ch, err = reg.Disable(ctx, tx, "admin@acme.example", "honeypot")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		reg.Publish(ch)
	}
	toggle(true)
	called := make(chan struct{}, 4)
	for i := range wired { // the real wiring entry, with the teardown swapped for a probe
		if wired[i].ID == "honeypot" {
			if wired[i].EnsureOff == nil {
				t.Fatal("the honeypot entry has no EnsureOff")
			}
			wired[i].EnsureOff = func(deps) modreg.Teardown {
				return func(context.Context) error { called <- struct{}{}; return nil }
			}
		}
	}
	guard := modreg.NewOffGuard(ctx, reg, log, nil)
	reg.OnChange(guard.ModuleChanged)
	addOffGuards(guard, deps{}, wired)
	select {
	case <-called:
		t.Fatal("teardown ran while the module is on")
	default:
	}
	toggle(false)
	select {
	case <-called:
	case <-time.After(10 * time.Second):
		t.Fatal("switching the honeypot off did not run its teardown")
	}
	guard.Wait()
}
