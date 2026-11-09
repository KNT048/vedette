package main

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/core"
)

// deps is what module constructors may take. serve builds one value and hands it to every module's
// handler constructor and Jobs func, so a module asks for what it needs without editing main.go.
type deps struct {
	Log     *slog.Logger
	DB      *store.DB
	Reg     *modreg.Registry
	Secrets *secrets.Store
	Audit   *audit.Log
	Clock   func() time.Time
}

// moduleWiring is one module the binary carries. Adding a module = one entry in wiredModules and
// its handler struct in handler.go (issue #33).
type moduleWiring struct {
	ID         string
	Migrations fs.FS                   // nil when the module owns no tables
	Jobs       func(d deps) []jobs.Job // nil when it has none; a job runs only while its module is on
}

// wiredModules lists the modules in migration order: a module comes after every module it depends on
// (core first). TestWiredModulesFollowDependencies checks the order against the manifests.
func wiredModules() []moduleWiring {
	return []moduleWiring{
		{ID: "core", Migrations: core.Migrations},
	}
}

// migrateAll applies every wired module's migrations, in order, whether the module is on or off
// (DATA_MODEL §5.6: the schema always matches the code; a module that is off keeps its data).
func migrateAll(ctx context.Context, db *store.DB, wired []moduleWiring) error {
	for _, w := range wired {
		if w.Migrations == nil {
			continue
		}
		if err := store.Migrate(ctx, db, w.ID, w.Migrations); err != nil {
			return fmt.Errorf("migrate %s: %w", w.ID, err)
		}
	}
	return nil
}

// addJobs registers every wired module's jobs with the scheduler.
func addJobs(sched *jobs.Scheduler, d deps, wired []moduleWiring) error {
	for _, w := range wired {
		if w.Jobs == nil {
			continue
		}
		for _, j := range w.Jobs(d) {
			if j.Module != w.ID {
				return fmt.Errorf("module %s registers job %q for module %q", w.ID, j.Name, j.Module)
			}
			if err := sched.Add(j); err != nil {
				return fmt.Errorf("jobs of %s: %w", w.ID, err)
			}
		}
	}
	return nil
}
