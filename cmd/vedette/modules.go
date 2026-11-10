package main

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/read"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/honeypot"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/mitigation"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/response"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
	sensorpassive "github.com/knt048/vedette/modules/sensor-passive"
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
	Bus     *events.Bus   // in-process event bus (core/events); modules publish after commit and subscribe here
	Auth    *auth.Service // sessions, sign-in and two-step (core/auth)
	// BaseURL is the address people open Vedette at (links in notify messages); empty on loopback, see baseURL.
	BaseURL string
	Conn    *conn.Service // connections to devices (core/conn, D-93): core's handlers, response and the Privacy page share it
	// ConnReader is the read tools of the connections for the ai module (WP-25, D-93 (3)): list them, call one. It is the only thing of
	// core/conn that ai is given; the writer goes to response alone. nil when there is no Conn.
	ConnReader *read.Reader
	Core       *core.APIHandlers     // core's own operations (sign-in, account, users, setup, audit, general settings)
	OS         *core.OSHandlers      // operating system updates and the backup download, on top of vedette-host
	Network    *core.NetworkHandlers // Box network (S-CORE-8, routes of the host module) on top of vedette-host
	// HostSocket is the unix socket of vedette-host ("" = this install has none: every OS endpoint answers 409 not_appliance).
	// DataDir is core_data, the directory of the database file; KeyPath the master key file: both feed the snapshots of host-api 6.11.
	HostSocket, DataDir, KeyPath string
	// Hosts are the names and addresses the box answers to (-hosts or the certificate): the IP literals among them are the box itself
	// for core/conn (D-94). HostNet is the one cached provider of every address vedette-host reports for the appliance's interfaces and its decoys
	// (host-api state/net, as single-address prefixes); nil when this install has no host. conn, sensor-active and the honeypot's box
	// address share it, so they agree and a host that blinks does not make the box vanish from one of them.
	Hosts   []string
	HostNet *hostNetCache

	// Module services other modules use through their own ports (issue #38, #39). Built once in serve,
	// after the fields above, so every handler, job and subscriber shares one instance.
	Inventory          *inventory.Service
	Findings           *findings.Service
	FindingHandlers    *findings.FindingHandlers // also carries mitigation's guidance (SetGuidance) and is mitigation's Details
	MitigationHandlers *mitigation.ActionHandlers
	Honeypot           *honeypot.Service      // the run job, the HTTP handler and the inventory subscription share it
	HoneypotDir        string                 // shared volume with the honeypot container (-honeypot-dir); empty = no container wired
	SensorPassive      *sensorpassive.Service // the capture job and the HTTP handler share it: the SPAN measurement lives in its memory
	Response           *response.Service      // the only module that may change another device (D-41): handler, jobs and bus subscriptions share it
}

// moduleWiring is one module the binary carries. Adding a module = one entry in wiredModules and
// its handler struct in handler.go (issue #33).
type moduleWiring struct {
	ID         string
	Migrations fs.FS                   // nil when the module owns no tables
	Jobs       func(d deps) []jobs.Job // nil when it has none; a job runs only while its module is on
	BodyLimits map[string]int64        // operationId → request body cap in bytes, for operations over 1 MiB
}

// wiredModules lists the modules in migration order: a module comes after every module it depends on
// (core first). TestWiredModulesFollowDependencies checks the order against the manifests.
func wiredModules() []moduleWiring {
	return []moduleWiring{
		{ID: "core", Migrations: core.Migrations},
		{ID: "feeds", Migrations: feeds.Migrations, Jobs: feedsJobs, BodyLimits: feeds.BodyLimits},
		{ID: "inventory", Migrations: inventory.Migrations, Jobs: inventoryJobs},
		{ID: "sensor-active", Migrations: sensoractive.Migrations, Jobs: sensorActiveJobs},
		{ID: "honeypot", Migrations: honeypot.Migrations, Jobs: honeypotJobs},
		{ID: "findings", Migrations: findings.Migrations},
		{ID: "mitigation", Migrations: mitigation.Migrations},
		{ID: "notify", Migrations: notify.Migrations, Jobs: notifyJobs},
		{ID: "sensor-passive", Migrations: sensorpassive.Migrations, Jobs: sensorPassiveJobs},
		{ID: "response", Migrations: response.Migrations, Jobs: responseJobs}, // after notify and inventory (manifest depends)
		{ID: "exposure", Migrations: exposure.Migrations, Jobs: exposureJobs}, // depends on core and inventory (MANIFEST)
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

// bodyLimits merges the modules' per-operation body caps for server.Config. server.New refuses an
// operationId that does not exist, so a typo fails at start-up.
func bodyLimits(wired []moduleWiring) map[string]int64 {
	out := map[string]int64{}
	for _, w := range wired {
		maps.Copy(out, w.BodyLimits)
	}
	return out
}
