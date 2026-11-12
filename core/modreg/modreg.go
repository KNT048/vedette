// Package modreg is the module registry: which modules exist (MANIFEST.yaml), which are on
// (core_module), and the rules for turning them on and off (core CONTRACT INV-1, INV-3, INV-4).
// There are no globals; the process builds one Registry and hands it to the HTTP gate and the
// job scheduler, which only need Enabled and OnChange.
package modreg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// Config is what New needs. The core migrations must already be applied.
type Config struct {
	DB        *store.DB
	Audit     *audit.Log
	Manifests fs.FS            // <module>/MANIFEST.yaml, see Load
	Version   string           // stored in core_module.version for rows created now
	Clock     func() time.Time // nil: time.Now
	Log       *slog.Logger
	// ContainerOnly: core runs without vedette-host (started with an empty -host-socket, D-55, D-168). The install
	// kind of the whole box comes from here (D-381): modules with needs_host cannot be turned on, and GET /modules says so.
	ContainerOnly bool
}

// State is one module as GET /modules shows it.
type State struct {
	ID        string
	Tier      Tier
	Depends   []string
	Enabled   bool
	EnabledAt *time.Time // nil while off
	// Available is false for a module this install cannot run (needs_host on a container-only install, D-381).
	Available bool
}

type entry struct {
	Manifest
	enabled   bool
	enabledAt *time.Time
	ver       uint64 // version of the last Change applied to this entry
}

// Registry holds the manifests and a cache of core_module. The database is the truth; the cache is
// updated only by Publish, after the transaction that made the change has committed.
type Registry struct {
	db    *store.DB
	audit *audit.Log
	now   func() time.Time
	log   *slog.Logger
	order []string // module ids (not components), core first, then standard, then optional, each by id
	next  atomic.Uint64
	ver   string // Config.Version, for the rows Reset makes
	// containerOnly is Config.ContainerOnly: the install kind, fixed for the life of the process.
	containerOnly bool

	mu   sync.RWMutex
	mods map[string]*entry
	subs []func(id string, enabled bool)
}

// New loads and validates the manifests, inserts the missing core_module rows from each manifest's
// default (existing rows are never touched, so a restart keeps what the admin chose), makes sure the
// core module is on, and fills the cache.
func New(ctx context.Context, cfg Config) (*Registry, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Log == nil || cfg.Manifests == nil {
		return nil, errors.New("modreg: DB, Audit, Log and Manifests are required")
	}
	if cfg.Version == "" {
		return nil, errors.New("modreg: empty version")
	}
	manifests, err := Load(cfg.Manifests)
	if err != nil {
		return nil, err
	}
	r := &Registry{db: cfg.DB, audit: cfg.Audit, now: cfg.Clock, log: cfg.Log, ver: cfg.Version, containerOnly: cfg.ContainerOnly, mods: make(map[string]*entry, len(manifests))}
	if r.now == nil {
		r.now = time.Now
	}
	for _, m := range manifests {
		r.mods[m.ID] = &entry{Manifest: m}
		if !m.Component {
			r.order = append(r.order, m.ID)
		}
	}
	slices.SortFunc(r.order, func(a, b string) int {
		if c := tierRank(r.mods[a].Tier) - tierRank(r.mods[b].Tier); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	if err := r.seed(ctx, cfg.Version); err != nil {
		return nil, err
	}
	return r, nil
}

func tierRank(t Tier) int {
	switch t {
	case TierCore:
		return 0
	case TierStandard:
		return 1
	}
	return 2
}

func (r *Registry) seed(ctx context.Context, version string) error {
	return r.db.Write(ctx, func(tx *sql.Tx) error {
		q := coredb.New(tx)
		now := store.FormatTS(r.now())
		for _, id := range r.order {
			m := r.mods[id]
			var at *string
			if m.Default {
				at = &now
			}
			if err := q.InsertModuleIfMissing(ctx, coredb.InsertModuleIfMissingParams{ID: id, Enabled: m.Default, EnabledAt: at, Version: version}); err != nil {
				return fmt.Errorf("modreg: seed %s: %w", id, err)
			}
			if m.Tier == TierCore { // INV-1: a database that says otherwise is repaired, not obeyed
				if _, err := q.SetModuleState(ctx, coredb.SetModuleStateParams{Enabled: true, EnabledAt: &now, ID: id}); err != nil {
					return fmt.Errorf("modreg: keep %s on: %w", id, err)
				}
			}
		}
		rows, err := q.ListModules(ctx)
		if err != nil {
			return fmt.Errorf("modreg: read modules: %w", err)
		}
		for _, row := range rows {
			e, ok := r.mods[row.ID]
			if !ok || e.Component {
				continue // a row of a module this build does not have: keep it, ignore it
			}
			e.enabled, e.enabledAt = row.Enabled, parseTS(row.EnabledAt)
			if !row.Enabled {
				e.enabledAt = nil
			}
		}
		return nil
	})
}

func parseTS(s *string) *time.Time {
	if s == nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	if err != nil {
		return nil
	}
	return &t
}

// Enabled reports whether a module is on. An id with no manifest is off (the module is not in this
// build). A component such as host has no switch and counts as present. Core is always on.
func (r *Registry) Enabled(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.mods[id]
	if !ok {
		return false
	}
	return e.Component || e.Tier == TierCore || e.enabled
}

// List returns every module (not components) in a stable order: core, standard, optional, each by id.
func (r *Registry) List() []State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]State, 0, len(r.order))
	for _, id := range r.order {
		e := r.mods[id]
		out = append(out, State{ID: id, Tier: e.Tier, Depends: slices.Clone(e.Depends), Enabled: e.enabled, EnabledAt: e.enabledAt, Available: !r.containerOnly || !e.NeedsHost})
	}
	return out
}

// ContainerOnly reports the install kind (D-381): true when core runs without vedette-host. It is the one place the
// API and the GUI learn it from (GET /modules, GET /core/setup/modules).
func (r *Registry) ContainerOnly() bool { return r.containerOnly }

// OnChange registers fn, called after a change is published, once per module whose state flipped.
// fn runs on the publishing goroutine and must not block; it must not call back into Publish.
func (r *Registry) OnChange(fn func(id string, enabled bool)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subs = append(r.subs, fn)
}

type update struct {
	id        string
	enabled   bool
	enabledAt *time.Time
}

// Change is the result of Enable or Disable inside a transaction. Pass it to Publish after the
// transaction has committed; dropping it (the transaction rolled back) leaves the cache as it was.
type Change struct {
	Enabled  []string // Enable: modules turned on by the call, dependencies first, the target last
	Affected []string // Disable: modules still on that depend on the one just turned off (INV-4)
	ver      uint64
	updates  []update
}

// Publish applies a committed Change to the cache and tells the subscribers. Calling it for a
// Change whose transaction rolled back is a bug: the cache would show what the database does not.
func (r *Registry) Publish(c Change) {
	var flipped []update
	r.mu.Lock()
	for _, u := range c.updates {
		e := r.mods[u.id]
		if e == nil || c.ver <= e.ver {
			continue // a newer change was already applied
		}
		e.ver = c.ver
		if e.enabled != u.enabled {
			flipped = append(flipped, u)
		}
		e.enabled, e.enabledAt = u.enabled, u.enabledAt
	}
	subs := slices.Clone(r.subs)
	r.mu.Unlock()
	for _, u := range flipped {
		for _, fn := range subs {
			fn(u.id, u.enabled)
		}
	}
}

// state reads the enabled flags inside tx: the decision is made on what the database says now, under
// the write lock, not on the cache.
func (r *Registry) state(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	rows, err := coredb.New(tx).ListModules(ctx)
	if err != nil {
		return nil, fmt.Errorf("modreg: read modules: %w", err)
	}
	on := make(map[string]bool, len(rows))
	for _, row := range rows {
		on[row.ID] = row.Enabled
	}
	for id, e := range r.mods { // core is on whatever a row says
		if e.Tier == TierCore && !e.Component {
			on[id] = true
		}
	}
	return on, nil
}

// toggleable returns the API error for an unknown id, a component (no switch), or a core module.
func (r *Registry) toggleable(id string) error {
	e, ok := r.mods[id]
	if !ok || e.Component {
		return apierr.New(http.StatusNotFound, apierr.CodeNotFound, "No such module.")
	}
	if e.Tier == TierCore {
		return apierr.New(http.StatusBadRequest, apierr.CodeCoreModule, "Core modules are always on.")
	}
	return nil
}

// notHere refuses to turn on a module this install cannot run (D-381), with the code the OS endpoints of a
// container-only install already use.
func (r *Registry) notHere(id string) error {
	if e := r.mods[id]; r.containerOnly && e != nil && e.NeedsHost {
		return apierr.New(http.StatusConflict, "not_appliance", fmt.Sprintf("Module %s needs vedette-host, which only the appliance install has. This is a container-only install, so it cannot run here.", id))
	}
	return nil
}

// Enable turns a module on inside tx and writes the core_audit row (module.enable) in the same
// transaction. When modules it depends on are off it returns 409 missing_dependencies with
// Extra "missing" (all of them, dependencies first) and changes nothing, unless withDeps is true:
// then they are turned on too (INV-3: never implicitly). Core: 400 core_module; unknown: 404.
func (r *Registry) Enable(ctx context.Context, tx *sql.Tx, actor, id string, withDeps bool) (Change, error) {
	if err := r.toggleable(id); err != nil {
		return Change{}, err
	}
	if err := r.notHere(id); err != nil {
		return Change{}, err
	}
	on, err := r.state(ctx, tx)
	if err != nil {
		return Change{}, err
	}
	var missing []string
	r.collectMissing(id, on, map[string]bool{id: true}, &missing)
	for _, m := range missing { // a dependency switched on with it must be runnable here too (D-381)
		if err := r.notHere(m); err != nil {
			return Change{}, err
		}
	}
	if len(missing) > 0 && !withDeps {
		return Change{}, apierr.New(http.StatusConflict, apierr.CodeMissingDeps,
			fmt.Sprintf("Module %s also needs: %s. Turn them on first, or turn them on together.", id, strings.Join(missing, ", "))).
			With("missing", missing)
	}
	now := r.now()
	nowTS := store.FormatTS(now)
	ch := Change{ver: r.next.Add(1)}
	q := coredb.New(tx)
	for _, m := range append(missing, id) {
		if on[m] {
			continue
		}
		if err := setState(ctx, q, m, true, &nowTS, nil); err != nil {
			return Change{}, err
		}
		ch.Enabled = append(ch.Enabled, m)
		ch.updates = append(ch.updates, update{id: m, enabled: true, enabledAt: &now})
	}
	detail := ""
	switch {
	case len(ch.Enabled) == 0:
		detail = "already on"
	case len(ch.Enabled) > 1:
		detail = "also turned on: " + strings.Join(ch.Enabled[:len(ch.Enabled)-1], ", ")
	}
	if err := r.audit.Append(ctx, tx, audit.Entry{User: actor, Action: "module.enable", Target: id, Detail: detail}); err != nil {
		return Change{}, err
	}
	return ch, nil
}

// collectMissing appends the modules id needs that are off, dependencies before dependents.
func (r *Registry) collectMissing(id string, on, seen map[string]bool, out *[]string) {
	for _, d := range r.mods[id].Depends {
		if seen[d] {
			continue
		}
		seen[d] = true
		r.collectMissing(d, on, seen, out)
		if !on[d] {
			*out = append(*out, d)
		}
	}
}

// Disable turns a module off inside tx and writes the core_audit row (module.disable, detail lists
// the affected modules) in the same transaction. It never cascades and never drops data (INV-4):
// Change.Affected names the modules that are on and depend on it, so the caller can say what runs
// degraded. Core: 400 core_module; unknown: 404.
func (r *Registry) Disable(ctx context.Context, tx *sql.Tx, actor, id string) (Change, error) {
	if err := r.toggleable(id); err != nil {
		return Change{}, err
	}
	on, err := r.state(ctx, tx)
	if err != nil {
		return Change{}, err
	}
	ch := Change{ver: r.next.Add(1), Affected: []string{}}
	for _, other := range r.order {
		if on[other] && slices.Contains(r.mods[other].Depends, id) {
			ch.Affected = append(ch.Affected, other)
		}
	}
	if on[id] {
		nowTS := store.FormatTS(r.now())
		if err := setState(ctx, coredb.New(tx), id, false, nil, &nowTS); err != nil {
			return Change{}, err
		}
		ch.updates = []update{{id: id}}
	}
	detail := ""
	if len(ch.Affected) > 0 {
		detail = "affected: " + strings.Join(ch.Affected, ", ")
	}
	if err := r.audit.Append(ctx, tx, audit.Entry{User: actor, Action: "module.disable", Target: id, Detail: detail}); err != nil {
		return Change{}, err
	}
	return ch, nil
}

// Reset puts every module back to the state of a fresh install inside tx: core on, every other module at the default of its
// manifest, with the rows of core_module written (or rewritten) here. It is the factory reset's step after the caller emptied the
// tables (POST /core/data/purge); it writes no audit row. Pass the Change to Publish after the transaction has committed:
// the cache then follows the database, and the subscribers (the job scheduler) hear of every module whose state flipped.
func (r *Registry) Reset(ctx context.Context, tx *sql.Tx) (Change, error) {
	q := coredb.New(tx)
	now := r.now()
	nowTS := store.FormatTS(now)
	ch := Change{ver: r.next.Add(1)}
	for _, id := range r.order {
		m := r.mods[id]
		on := m.Default || m.Tier == TierCore
		var at *string
		var t *time.Time
		if on {
			at, t = &nowTS, &now
		}
		if err := q.InsertModuleIfMissing(ctx, coredb.InsertModuleIfMissingParams{ID: id, Enabled: on, EnabledAt: at, Version: r.ver}); err != nil {
			return Change{}, fmt.Errorf("modreg: reset %s: %w", id, err)
		}
		if err := setState(ctx, q, id, on, at, nil); err != nil {
			return Change{}, err
		}
		ch.updates = append(ch.updates, update{id: id, enabled: on, enabledAt: t})
	}
	return ch, nil
}

func setState(ctx context.Context, q *coredb.Queries, id string, enabled bool, enabledAt, disabledAt *string) error {
	n, err := q.SetModuleState(ctx, coredb.SetModuleStateParams{Enabled: enabled, EnabledAt: enabledAt, DisabledAt: disabledAt, ID: id})
	if err != nil {
		return fmt.Errorf("modreg: update %s: %w", id, err)
	}
	if n != 1 {
		return fmt.Errorf("modreg: update %s: %d rows changed, want 1 (is the core_module row missing?)", id, n)
	}
	return nil
}
