package modreg_test

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
)

// Fixture: a (standard, on) <- b (off) <- c (off); d (off) needs a; host is a component.
var fixture = map[string]string{
	"core": coreYAML,
	"a":    "id: a\ntier: standard\ndefault: true\ndepends: [core]\n",
	"b":    "id: b\ntier: optional\ndefault: off\ndepends: [core, a]\n",
	"c":    "id: c\ntier: optional\ndefault: off\ndepends: [core, b]\n",
	"d":    "id: d\ntier: optional\ndefault: off\ndepends: [core, a]\n",
	"host": "id: host\nkind: component\ntier: core\n",
}

type rig struct {
	t   *testing.T
	db  *store.DB
	reg *modreg.Registry
}

func newRig(t *testing.T) *rig {
	t.Helper()
	db := storetest.New(t)
	if err := store.Migrate(t.Context(), db, "core", os.DirFS("../../modules/core/migrations/sqlite")); err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, db: db, reg: newRegistry(t, db)}
}

func newRegistry(t *testing.T, db *store.DB) *modreg.Registry {
	t.Helper()
	reg, err := modreg.New(t.Context(), modreg.Config{
		DB: db, Audit: audit.New(nil), Manifests: fsOf(fixture), Version: "test", Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func (r *rig) enable(id string, withDeps bool) (modreg.Change, error) {
	r.t.Helper()
	var ch modreg.Change
	err := r.db.Write(r.t.Context(), func(tx *sql.Tx) error {
		var err error
		ch, err = r.reg.Enable(r.t.Context(), tx, "admin@acme.example", id, withDeps)
		return err
	})
	if err == nil {
		r.reg.Publish(ch)
	}
	return ch, err
}

func (r *rig) disable(id string) (modreg.Change, error) {
	r.t.Helper()
	var ch modreg.Change
	err := r.db.Write(r.t.Context(), func(tx *sql.Tx) error {
		var err error
		ch, err = r.reg.Disable(r.t.Context(), tx, "admin@acme.example", id)
		return err
	})
	if err == nil {
		r.reg.Publish(ch)
	}
	return ch, err
}

func (r *rig) dbEnabled(id string) bool {
	r.t.Helper()
	var on bool
	if err := r.db.Reader().QueryRowContext(r.t.Context(), "SELECT enabled FROM core_module WHERE id = ?", id).Scan(&on); err != nil {
		r.t.Fatal(err)
	}
	return on
}

func (r *rig) audits() []string {
	r.t.Helper()
	rows, err := r.db.Reader().QueryContext(r.t.Context(), "SELECT action || '|' || target || '|' || user || '|' || coalesce(detail, '') FROM core_audit ORDER BY seq")
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func apiErr(t *testing.T, err error, status int, code string) *apierr.Error {
	t.Helper()
	e, ok := apierr.As(err)
	if !ok || e.Status != status || e.Code != code {
		t.Fatalf("err = %v, want %d %s", err, status, code)
	}
	return e
}

func TestSeedFromDefaultsAndRestart(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	want := map[string]bool{"core": true, "a": true, "b": false, "c": false, "d": false}
	for _, s := range r.reg.List() {
		if s.Enabled != want[s.ID] || (s.Enabled && s.EnabledAt == nil) || (!s.Enabled && s.EnabledAt != nil) {
			t.Errorf("%s: enabled=%v enabledAt=%v", s.ID, s.Enabled, s.EnabledAt)
		}
		delete(want, s.ID)
	}
	if len(want) != 0 {
		t.Errorf("modules missing from List: %v", want)
	}
	if _, err := r.enable("d", false); err != nil {
		t.Fatal(err)
	}
	if _, err := r.disable("a"); err != nil {
		t.Fatal(err)
	}
	// A restart (a second registry on the same database) keeps the admin's choices: seeds never overwrite.
	again := newRegistry(t, r.db)
	if again.Enabled("a") || !again.Enabled("d") {
		t.Fatalf("restart changed the state: a=%v d=%v", again.Enabled("a"), again.Enabled("d"))
	}
	// A new manifest module gets its row on the next start.
	var n int
	if err := r.db.Reader().QueryRowContext(t.Context(), "SELECT count(*) FROM core_module").Scan(&n); err != nil || n != 5 {
		t.Fatalf("core_module rows = %d, %v (want 5; a component has no row)", n, err)
	}
}

func TestCoreIsRepairedAtStart(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	err := r.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), "UPDATE core_module SET enabled = 0 WHERE id = 'core'")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	again := newRegistry(t, r.db)
	if !again.Enabled("core") || !r.dbEnabled("core") {
		t.Fatal("core was left off")
	}
}

func TestEnabledForUnknownAndComponent(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	for id, want := range map[string]bool{"core": true, "a": true, "b": false, "host": true, "findings": false, "": false, "../x": false} {
		if got := r.reg.Enabled(id); got != want {
			t.Errorf("Enabled(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestEnableRefusals(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	_ = apiErr(t, errOf(r.enable("core", false)), http.StatusBadRequest, "core_module")
	_ = apiErr(t, errOf(r.enable("core", true)), http.StatusBadRequest, "core_module")
	_ = apiErr(t, errOf(r.enable("nope", false)), http.StatusNotFound, "not_found")
	_ = apiErr(t, errOf(r.enable("host", false)), http.StatusNotFound, "not_found")
	_ = apiErr(t, errOf(r.disable("core")), http.StatusBadRequest, "core_module")
	_ = apiErr(t, errOf(r.disable("nope")), http.StatusNotFound, "not_found")
	if got := r.audits(); len(got) != 0 {
		t.Fatalf("refusals wrote audit rows: %v", got)
	}
}

func errOf(_ modreg.Change, err error) error { return err }

// D-381: on a container-only install a needs_host module is listed as not available and cannot be turned on; the appliance runs it.
func TestNeedsHostOnContainerOnly(t *testing.T) {
	t.Parallel()
	fx := map[string]string{"core": coreYAML, "hp": "id: hp\ntier: optional\ndefault: off\nneeds_host: true\ndepends: [core]\n"}
	for _, container := range []bool{true, false} {
		db := storetest.New(t)
		if err := store.Migrate(t.Context(), db, "core", os.DirFS("../../modules/core/migrations/sqlite")); err != nil {
			t.Fatal(err)
		}
		reg, err := modreg.New(t.Context(), modreg.Config{DB: db, Audit: audit.New(nil), Manifests: fsOf(fx), Version: "test", Log: slog.New(slog.DiscardHandler), ContainerOnly: container})
		if err != nil {
			t.Fatal(err)
		}
		r := &rig{t: t, db: db, reg: reg}
		if reg.ContainerOnly() != container || r.state("hp").Available == container || !r.state("core").Available {
			t.Fatalf("container=%v: ContainerOnly=%v, hp available=%v", container, reg.ContainerOnly(), r.state("hp").Available)
		}
		_, err = r.enable("hp", true)
		if container {
			_ = apiErr(t, err, http.StatusConflict, "not_appliance")
			if reg.Enabled("hp") || r.dbEnabled("hp") || len(r.audits()) != 0 {
				t.Fatal("the refusal changed something")
			}
		} else if err != nil || !reg.Enabled("hp") {
			t.Fatalf("appliance: %v", err)
		}
	}
}

func (r *rig) state(id string) modreg.State {
	r.t.Helper()
	for _, s := range r.reg.List() {
		if s.ID == id {
			return s
		}
	}
	r.t.Fatalf("no module %s", id)
	return modreg.State{}
}

// INV-3 in the registry: missing dependencies (all of them, dependencies first) refuse and change nothing.
func TestEnableMissingDependencies(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	if _, err := r.disable("a"); err != nil {
		t.Fatal(err)
	}
	auditBefore := len(r.audits())
	e := apiErr(t, errOf(r.enable("c", false)), http.StatusConflict, "missing_dependencies")
	if got := e.Extra["missing"]; !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("missing = %v, want [a b]", got)
	}
	if r.reg.Enabled("c") || r.reg.Enabled("b") || r.reg.Enabled("a") || r.dbEnabled("c") || r.dbEnabled("b") || r.dbEnabled("a") {
		t.Fatal("a refused enable changed state")
	}
	if len(r.audits()) != auditBefore {
		t.Fatal("a refused enable wrote an audit row")
	}
}

func TestEnableWithDependencies(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	if _, err := r.disable("a"); err != nil {
		t.Fatal(err)
	}
	var seen []string
	r.reg.OnChange(func(id string, on bool) {
		if on {
			seen = append(seen, id)
		}
	})
	ch, err := r.enable("c", true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ch.Enabled, []string{"a", "b", "c"}) {
		t.Fatalf("Enabled = %v, want [a b c]", ch.Enabled)
	}
	if !reflect.DeepEqual(seen, []string{"a", "b", "c"}) {
		t.Fatalf("subscribers saw %v", seen)
	}
	for _, id := range []string{"a", "b", "c"} {
		if !r.reg.Enabled(id) || !r.dbEnabled(id) {
			t.Errorf("%s not on", id)
		}
	}
	if r.reg.Enabled("d") {
		t.Error("an unrelated module was turned on")
	}
	last := r.audits()[len(r.audits())-1]
	if last != "module.enable|c|admin@acme.example|also turned on: a, b" {
		t.Fatalf("audit = %q", last)
	}
	for _, s := range r.reg.List() {
		if s.Enabled && s.EnabledAt == nil {
			t.Errorf("%s on without enabled_at", s.ID)
		}
	}
}

func TestEnableAlreadyOnIsHarmless(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	called := 0
	r.reg.OnChange(func(string, bool) { called++ })
	before := r.reg.List()
	ch, err := r.enable("a", false)
	if err != nil || len(ch.Enabled) != 0 {
		t.Fatalf("Enable on a module that is on: %+v, %v", ch, err)
	}
	if called != 0 || !reflect.DeepEqual(before, r.reg.List()) {
		t.Fatal("a no-op enable changed state or notified")
	}
	if got := r.audits(); len(got) != 1 || got[0] != "module.enable|a|admin@acme.example|already on" {
		t.Fatalf("audits = %v", got)
	}
}

// INV-4: disabling never cascades, never drops data, and reports the dependents that are on.
func TestDisableDoesNotCascade(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	if _, err := r.enable("c", true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.enable("d", false); err != nil {
		t.Fatal(err)
	}
	var flips []string
	r.reg.OnChange(func(id string, on bool) {
		if !on {
			flips = append(flips, id)
		}
	})
	ch, err := r.disable("a")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ch.Affected, []string{"b", "d"}) {
		t.Fatalf("Affected = %v, want [b d]", ch.Affected)
	}
	for id, want := range map[string]bool{"a": false, "b": true, "c": true, "d": true} {
		if r.reg.Enabled(id) != want || r.dbEnabled(id) != want {
			t.Errorf("%s: cache=%v db=%v, want %v", id, r.reg.Enabled(id), r.dbEnabled(id), want)
		}
	}
	if !reflect.DeepEqual(flips, []string{"a"}) {
		t.Fatalf("subscribers saw %v, want only [a]", flips)
	}
	if got := r.audits(); got[len(got)-1] != "module.disable|a|admin@acme.example|affected: b, d" {
		t.Fatalf("audit = %v", got)
	}
	// Disabling a leaf: nothing affected, Affected is an empty list (it is JSON, never null).
	ch, err = r.disable("c")
	if err != nil || ch.Affected == nil || len(ch.Affected) != 0 {
		t.Fatalf("leaf: %+v, %v", ch, err)
	}
	var rows int
	if err := r.db.Reader().QueryRowContext(t.Context(), "SELECT count(*) FROM core_module").Scan(&rows); err != nil || rows != 5 {
		t.Fatalf("rows = %d, %v: disabling dropped a row", rows, err)
	}
}

// A change whose transaction rolled back is never published: cache and database agree.
func TestRolledBackChangeLeavesNoTrace(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	called := false
	r.reg.OnChange(func(string, bool) { called = true })
	boom := context.Canceled
	err := r.db.Write(t.Context(), func(tx *sql.Tx) error {
		if _, err := r.reg.Enable(t.Context(), tx, "admin@acme.example", "d", false); err != nil {
			return err
		}
		return boom // the caller's own step failed after Enable: roll back, do not Publish
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if r.reg.Enabled("d") || r.dbEnabled("d") || called || len(r.audits()) != 0 {
		t.Fatal("rolled-back change is visible")
	}
}

// Changes are applied in commit order even if Publish calls arrive out of order.
func TestPublishIgnoresStaleChange(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	var on, off modreg.Change
	if err := r.db.Write(t.Context(), func(tx *sql.Tx) (err error) {
		on, err = r.reg.Enable(t.Context(), tx, "x@y.example", "d", false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.db.Write(t.Context(), func(tx *sql.Tx) (err error) {
		off, err = r.reg.Disable(t.Context(), tx, "x@y.example", "d")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r.reg.Publish(off) // the newer change arrives first
	r.reg.Publish(on)  // the older one must not bring d back
	if r.reg.Enabled("d") || r.dbEnabled("d") {
		t.Fatal("a stale change overwrote a newer one")
	}
}

func TestConcurrentReadsDuringChanges(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for range 4 {
		wg.Go(func() {
			for ctx.Err() == nil {
				_ = r.reg.Enabled("a")
				_ = r.reg.List()
			}
		})
	}
	for range 20 {
		if _, err := r.disable("a"); err != nil {
			t.Error(err)
		}
		if _, err := r.enable("a", false); err != nil {
			t.Error(err)
		}
	}
	cancel()
	wg.Wait()
	if !r.reg.Enabled("a") {
		t.Fatal("a should end on")
	}
}

func TestListOrderAndShape(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	var ids []string
	for _, s := range r.reg.List() {
		ids = append(ids, s.ID)
	}
	if want := []string{"core", "a", "b", "c", "d"}; !slices.Equal(ids, want) {
		t.Fatalf("order = %v, want %v (core, standard, optional by id; no components)", ids, want)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	if _, err := modreg.New(t.Context(), modreg.Config{DB: db, Audit: audit.New(nil), Manifests: fsOf(fixture), Version: "v", Log: slog.New(slog.DiscardHandler)}); err == nil {
		t.Error("New before the core migration succeeded")
	}
	if _, err := modreg.New(t.Context(), modreg.Config{}); err == nil {
		t.Error("empty config accepted")
	}
}

// Reset (the factory reset, D-154) puts every module at its manifest default inside the caller's transaction, whether the table was
// emptied first or still holds the admin's choices; the cache and the subscribers follow only after Publish, and a rolled-back reset
// changes neither the database nor the cache.
func TestResetBringsBackTheDefaults(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	if _, err := r.enable("d", false); err != nil {
		t.Fatal(err)
	}
	if _, err := r.disable("a"); err != nil {
		t.Fatal(err)
	}
	var flipped []string
	r.reg.OnChange(func(id string, enabled bool) {
		flipped = append(flipped, id+"="+map[bool]string{true: "on", false: "off"}[enabled])
	})

	// A reset that rolls back leaves everything as it was.
	errRollback := errors.New("rollback")
	err := r.db.Write(t.Context(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(t.Context(), "DELETE FROM core_module"); err != nil {
			return err
		}
		if _, err := r.reg.Reset(t.Context(), tx); err != nil {
			return err
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) || r.reg.Enabled("a") || !r.reg.Enabled("d") || r.dbEnabled("a") || len(flipped) != 0 {
		t.Fatalf("a rolled-back reset changed something: %v a=%v d=%v", err, r.reg.Enabled("a"), r.reg.Enabled("d"))
	}

	// Emptied table: the rows come back, the cache follows Publish.
	var ch modreg.Change
	err = r.db.Write(t.Context(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(t.Context(), "DELETE FROM core_module"); err != nil {
			return err
		}
		var err error
		ch, err = r.reg.Reset(t.Context(), tx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.reg.Enabled("a") || !r.reg.Enabled("d") {
		t.Fatal("the cache changed before Publish")
	}
	r.reg.Publish(ch)
	want := map[string]bool{"core": true, "a": true, "b": false, "c": false, "d": false}
	for _, s := range r.reg.List() {
		if s.Enabled != want[s.ID] || r.dbEnabled(s.ID) != want[s.ID] {
			t.Errorf("%s after reset: cache %v, database %v, want %v", s.ID, s.Enabled, r.dbEnabled(s.ID), want[s.ID])
		}
	}
	slices.Sort(flipped)
	if !slices.Equal(flipped, []string{"a=on", "d=off"}) {
		t.Errorf("subscribers heard %v, want a=on and d=off (only the modules that flipped)", flipped)
	}
	var n int
	if err := r.db.Reader().QueryRowContext(t.Context(), "SELECT count(*) FROM core_module").Scan(&n); err != nil || n != 5 {
		t.Errorf("core_module rows = %d, %v", n, err)
	}

	// Not emptied first: the rows are rewritten, not duplicated.
	if _, err := r.enable("b", true); err != nil {
		t.Fatal(err)
	}
	err = r.db.Write(t.Context(), func(tx *sql.Tx) error { var err error; ch, err = r.reg.Reset(t.Context(), tx); return err })
	if err != nil {
		t.Fatal(err)
	}
	r.reg.Publish(ch)
	if r.reg.Enabled("b") || r.dbEnabled("b") {
		t.Error("reset over existing rows left b on")
	}
}
