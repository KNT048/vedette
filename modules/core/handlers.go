package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	// The zone list of the box must not depend on the host (a slim container has none): PUT /core/general
	// validates time zone names and the audit filters turn a day into hours with them.
	_ "time/tzdata"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
)

// APIHandlers implements the sign-in, account, user, first-run setup, audit and general-settings operations of
// the core module (S-CORE-1 and S-CORE-3). Embed it in the composite handler beside ModuleHandlers; the two
// implement disjoint operations. The handlers are thin: the rules live in core/auth, the checks of the
// contract (route table, roles, CSRF) in core/server.
type APIHandlers struct {
	db      *store.DB
	auth    *auth.Service
	reg     *modreg.Registry
	audit   *audit.Log
	secrets *secrets.Store
	log     *slog.Logger
	now     func() time.Time
	facts   PrivacyFacts  // nil: the answers of today (see PrivacyFacts)
	conns   *conn.Service // nil: the connection routes answer 501
	logs    *logexport.Registry
	logsDir string // where /core/logs/export spools its file ("" = os.TempDir())
	logsCap int64  // test hook: the size cap of /core/logs/export (0 = logExportMaxBytes)
	// One log download at a time, from the busy check until the response is closed, and at most one start per
	// logsGap (like /core/data/backup, INV-19): each one reads the logs into a spool of up to 128 MiB.
	logsMu   sync.Mutex
	logsBusy bool
	logsLast time.Time
	logsGap  time.Duration // 0 = logExportGap; a test sets a negative value to turn the limit off

	exporting atomic.Bool // one /core/data/export at a time, from the audit row until the body is closed
	exportCap int64       // test hook: the size cap of /core/data/export (0 = exportMaxBytes)

	// The factory reset (/core/data/purge, D-154).
	dataDir    string      // core_data: where the module data files and snapshots/ are ("" = none to remove)
	dataFiles  []string    // plain names of the module data files in dataDir (logs.db)
	schema     []SchemaSet // migrations of every module, to learn what a fresh install holds
	restart    func()      // asked to restart the process after a purge; nil = no restart
	keyPath    string      // the encryption key file the purge replaces ("" = none)
	purgeHost  PurgeHost   // vedette-host, for the backups; nil = no helper on this box
	osBusy     func(context.Context) bool
	beforeWipe func(context.Context) error
	gate       *PurgeGate
	alsoKept   []oas.CorePostCoreDataPurgeOKKeptItem
	keepRows   []KeepRow
	freezes    []*store.DB // other databases of the box (logs.db): frozen for the purge, thawed when it fails

	scope SetupScope // the inventory for first-run setup; nil = the ranges stay only in setup.scope
}

// HandlersConfig wires APIHandlers; every field but Clock and Facts is required.
type HandlersConfig struct {
	DB      *store.DB
	Auth    *auth.Service
	Reg     *modreg.Registry
	Audit   *audit.Log
	Secrets *secrets.Store
	Log     *slog.Logger
	Facts   PrivacyFacts  // optional
	Conns   *conn.Service // optional: without it /core/connections answers 501 not_implemented
	// SpoolDir is where /core/logs/export writes its temporary file: a directory on the data volume (cmd/vedette gives
	// <data>/tmp/logs-export), created 0700 and swept of leftovers at startup. "" = os.TempDir() (tests).
	SpoolDir string
	Logs     *logexport.Registry // optional: where the modules register their log sources (INV-13); core adds "audit"; nil = a registry of its own
	Clock    func() time.Time    // nil: time.Now

	// The factory reset, POST /core/data/purge (D-154). DataDir is core_data (the directory of the database file); DataFiles are plain
	// names of the data files the modules keep there besides vedette.db (today logs.db, D-151), checked against dataFileRE; both
	// optional (no DataDir: no files are removed). Schema is the migrations of every module in order and is required for the purge.
	// Restart, when not nil, is called shortly after a purge has answered: the process must start again, because what its modules
	// hold in memory (the sensor CA, caches) belongs to the data that is gone; the supervisor (Quadlet, Restart=always) brings it back.
	DataDir   string
	DataFiles []string
	Schema    []SchemaSet
	Restart   func()
	// KeyPath is the encryption key file (-key): the purge replaces it with a fresh key (D-154). Host is vedette-host as far as the purge
	// needs it (nil = no helper: backups are not deleted and the answer says so). OSBusy reports a running OS update of core itself.
	// BeforeWipe runs before anything is deleted and may refuse the purge with an error; cmd/vedette turns the honeypot off (decoy
	// addresses leave the host) and empties its log there. All optional.
	KeyPath    string
	Host       PurgeHost
	OSBusy     func(context.Context) bool
	BeforeWipe func(context.Context) error
	// Gate is shared with the OS and network handlers (OSConfig.Gate, NetworkConfig.Gate): shut while a purge runs (N4). nil = its own.
	Gate *PurgeGate
	// AlsoKept names what a purge leaves on the box besides what it always reports ("honeypot_log": the honeypot's raw log, which the
	// honeypot container owns), and KeepRows the rows that must survive the wipe because they describe it (the honeypot's read position
	// in that log, so old events are not read again). Both set by cmd/vedette.
	AlsoKept []string
	KeepRows []KeepRow
	// AlsoFreeze are the other databases of the box whose files the purge removes or that must not take a write once it has wiped (logs.db,
	// DataFiles): each is frozen under its own write lock (so a write in flight finishes first, and nothing is written after) before the
	// files move, and thawed if the purge fails. After a success they stay frozen until the process stops.
	AlsoFreeze []*store.DB
	// Scope is the inventory as far as first-run setup needs it (INV-15): the LAN ranges and the scan commitment of the wizard become
	// the scope of Devices -> Scope and sensors in the setup's own transaction. nil = a build without the inventory: the ranges stay only
	// in core_setting setup.scope.
	Scope SetupScope
}

// SetupScope is the inventory port of POST /core/setup (INV-15). SetupScope writes inside the setup's transaction tx and may refuse the
// ranges with an *apierr.Error (the whole setup is then refused); Settle is called once that transaction is over, with whether it committed.
type SetupScope interface {
	SetupScope(ctx context.Context, tx *sql.Tx, actor string, lan []string, confirmed bool) error
	Settle(ctx context.Context, tx *sql.Tx, committed bool)
}

// NewAPIHandlers returns the handlers.
func NewAPIHandlers(c HandlersConfig) (*APIHandlers, error) {
	if c.DB == nil || c.Auth == nil || c.Reg == nil || c.Audit == nil || c.Secrets == nil || c.Log == nil {
		return nil, errors.New("core: HandlersConfig needs DB, Auth, Reg, Audit, Secrets and Log")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.Logs == nil {
		c.Logs = logexport.New()
	}
	if c.SpoolDir != "" {
		if err := prepareSpoolDir(c.SpoolDir); err != nil {
			return nil, err
		}
	}
	if err := checkDataFiles(c.DataFiles); err != nil {
		return nil, err
	}
	if c.DataDir != "" { // what an interrupted purge left behind: the old data in the trash, the scratch databases, a half-written new key
		sweepPurgeLeftovers(c.DataDir, c.KeyPath)
	}
	if c.Gate == nil {
		c.Gate = &PurgeGate{}
	}
	var alsoKept []oas.CorePostCoreDataPurgeOKKeptItem
	for _, k := range c.AlsoKept {
		if k != string(oas.CorePostCoreDataPurgeOKKeptItemHoneypotLog) {
			return nil, fmt.Errorf("core: HandlersConfig.AlsoKept: %q is not a kept item a caller may add", k)
		}
		alsoKept = append(alsoKept, oas.CorePostCoreDataPurgeOKKeptItem(k))
	}
	h := &APIHandlers{scope: c.Scope, freezes: c.AlsoFreeze, gate: c.Gate, alsoKept: alsoKept, keepRows: c.KeepRows, dataDir: c.DataDir, dataFiles: c.DataFiles, schema: c.Schema, restart: c.Restart, keyPath: c.KeyPath, purgeHost: c.Host, osBusy: c.OSBusy, beforeWipe: c.BeforeWipe, logsDir: c.SpoolDir, db: c.DB, auth: c.Auth, reg: c.Reg, audit: c.Audit, secrets: c.Secrets, log: c.Log, now: c.Clock, facts: c.Facts, conns: c.Conns, logs: c.Logs}
	c.Logs.Register("audit", h.exportAudit)
	return h, nil
}

// caller is who a signed-in request acts as.
type caller struct {
	server.Principal
	SessionID string
}

// caller returns the principal the server authenticated and the id of the session the request came in on.
// Both exist for every non-public operation; their absence is a wiring bug, not a client error.
func (h *APIHandlers) caller(ctx context.Context) (caller, error) { return callerOf(ctx, h.auth) }

// callerOf is caller for any handler set that holds the auth service.
func callerOf(ctx context.Context, a *auth.Service) (caller, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return caller{}, apierr.Unauthenticated()
	}
	x, ok := server.ExchangeFrom(ctx)
	if !ok {
		return caller{}, errors.New("core: no HTTP exchange in the request context")
	}
	sid, err := a.Sessions.CurrentID(x.R)
	if errors.Is(err, server.ErrNoSession) {
		return caller{}, apierr.Unauthenticated()
	}
	if err != nil {
		return caller{}, err
	}
	return caller{Principal: p, SessionID: sid}, nil
}

// exchange returns the HTTP exchange and the client address; the address must parse (a request without a
// usable peer address cannot be rate limited and is refused as an internal error, never keyed to a shared value).
func exchange(ctx context.Context) (server.Exchange, netip.Addr, error) {
	x, ok := server.ExchangeFrom(ctx)
	if !ok {
		return server.Exchange{}, netip.Addr{}, errors.New("core: no HTTP exchange in the request context")
	}
	ip := x.ClientAddr()
	if !ip.IsValid() {
		return server.Exchange{}, netip.Addr{}, errors.New("core: the client address is not an IP address")
	}
	return x, ip, nil
}

// setSession sends the session, CSRF and device cookies of a sign-in.
func setSession(x server.Exchange, s auth.Issued, device string) {
	for _, c := range s.Cookies() {
		x.SetCookie(c)
	}
	if device != "" {
		x.SetCookie(auth.DeviceCookie(device))
	}
}

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

// renewSession sends the cookies of the session that replaced the caller's (password change, two-step turned
// on or off): the old tokens no longer work, the user stays signed in. device is a new device cookie value
// to set along ("" for none).
func renewSession(ctx context.Context, fresh auth.Issued, device string) error {
	x, ok := server.ExchangeFrom(ctx)
	if !ok {
		return errors.New("core: no HTTP exchange in the request context")
	}
	setSession(x, fresh, device)
	return nil
}
