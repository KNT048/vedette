package response

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
)

// ModuleID is the id of this module in the registry.
const ModuleID = "response"

// This module is the one place where Vedette may change another device (D-41, the single exception to SYS-8), so every
// path that writes to a device goes through Service.runItem (FORBID-1). Part 1 (WP-13a) holds the execution switch, the
// catalog, the rules and the engine, the request and approval flow in the app, the box actions (block list, message,
// webhook) and the log; the real device executors, the connections, approval links and chat approvals, and the AI
// proposals are part 13b and answer 501.

// ModuleGate says whether a module is on (modreg.Registry satisfies it).
type ModuleGate interface{ Enabled(id string) bool }

// Bus is the event bus as this module needs it (core/events.Bus satisfies it).
type Bus interface {
	Flush(ctx context.Context, o *events.Outbox)
	Subscribe(name string, fn events.Handler) (unsubscribe func())
}

// User is an account as this module needs it.
type User struct {
	ID       string
	Name     string
	Email    string
	Role     string // viewer, operator or admin
	TwoStep  bool   // two-step sign-in is on (INV-7)
	Disabled bool
}

// Users reads accounts. cmd/vedette adapts core/auth.
type Users interface {
	Lookup(ctx context.Context, id string) (User, bool, error)
}

// NotifyChannel is an alert channel as the settings and the approval flow need it.
type NotifyChannel struct {
	Type       string // slack, telegram, zalo, zalo-personal, email, webhook
	Label      string
	Configured bool
	Enabled    bool
	Approvals  bool // the channel takes approvals
	Approvers  int
}

// Notifier is the notify module as this module needs it. A nil Notifier means no alert channel exists: messages are
// refused with a plain reason and the settings list no channel.
type Notifier interface {
	Channels(ctx context.Context) ([]NotifyChannel, error)
	// Message sends one short text to the alert channels. It never changes a device.
	Message(ctx context.Context, id, title, text string) error
}

// WebhookTarget is where the webhook_call action posts: the URL (a secret) and the key that signs the body.
type WebhookTarget struct{ URL, SigningKey string }

// Webhooks says where webhook_call posts. A nil Webhooks, or ok=false, means no webhook is set up.
type Webhooks interface {
	Target(ctx context.Context) (t WebhookTarget, ok bool, err error)
}

// DeviceInfo is a device of the inventory.
type DeviceInfo struct {
	ID       string
	Name     string
	IP       string
	MAC      string
	Vendor   string
	Kind     string
	Approved bool
	Seen     time.Time
}

// FindingInfo is a finding.
type FindingInfo struct {
	ID       string
	AssetID  string
	CVE      string
	Severity string
	Status   string // suspected, confirmed, ...
	KEV      bool
}

// Directory resolves the ids an event carries. cmd/vedette adapts inventory and findings; the module never imports them.
type Directory interface {
	// DevicesOfKind lists the inventory devices of the given kinds (router, firewall: the never-touch gateways). An error means the
	// inventory cannot be read: the callers refuse the action instead of going on with fewer entries.
	DevicesOfKind(ctx context.Context, kinds ...string) ([]DeviceInfo, error)
	Device(ctx context.Context, id string) (DeviceInfo, bool, error)
	Finding(ctx context.Context, id string) (FindingInfo, bool, error)
}

// ConnectionInfo is a connection to a customer device (ai_connectors, part 13b).
type ConnectionInfo struct {
	Connection
	Target string // address the API paths are under, for the exact call a request shows
	// UpdatedAt changes whenever the connection is edited (address, credentials, tools). With the id, kind and Target it makes the
	// fingerprint stored in every request item (INV-9).
	UpdatedAt string
}

// connFP is the fingerprint of a connection as a request saw it: the same connection is the same fingerprint.
func connFP(c ConnectionInfo) string {
	h := sha256.Sum256([]byte(c.ID + "\x00" + c.Kind + "\x00" + c.Target + "\x00" + c.UpdatedAt))
	return hex.EncodeToString(h[:16])
}

// Connections lists the connections to devices. nil = none exist.
type Connections interface {
	List(ctx context.Context) ([]ConnectionInfo, error)
}

// DeviceStep is what an Executor is asked to do: one step of one item, already rendered by this module from a stored
// template and checked values. An Executor never sees text that came from a client.
type DeviceStep struct {
	ConnectionID string
	Tool         string // write tool, MCP only
	Phase        string // "run", "rollback" or "verify"
	CLI          string
	Rest         *RestCall
	RequestID    string
	ItemID       string
}

// DeviceResult is what a step did.
type DeviceResult struct {
	Detail   string
	Verified *Verified
}

// Executor carries a step out on a device. The real executors (HTTP API, SSH, NETCONF/RESTCONF, MCP) are part 13b; this
// part has the interface and a fake in the tests. A nil Executor means no device can be changed: such items fail and
// nothing is sent.
type Executor interface {
	Execute(ctx context.Context, s DeviceStep) (DeviceResult, error)
}

// Config wires a Service. DB, Secrets, Audit, Users and Log are required.
type Config struct {
	DB      *store.DB
	Secrets *secrets.Store
	Audit   *audit.Log
	Users   Users
	Log     *slog.Logger

	Modules     ModuleGate  // nil = on (tests)
	Bus         Bus         // nil = events are dropped
	Directory   Directory   // nil = trigger events are logged and skipped
	Notifier    Notifier    // nil = no alert channel
	Connections Connections // nil = no connection
	Executor    Executor    // nil = no device can be changed
	Webhooks    Webhooks    // nil = no webhook

	Clock func() time.Time
	// BoxAddrs adds to the addresses of the network interfaces, which always count as never-touch and as forbidden webhook targets.
	BoxAddrs func() []netip.Addr
	// BaseURL is the address people open Vedette at (https://192.168.10.2:8443). It is the start of the block list address;
	// empty = the address is shown from /api/v1 on.
	BaseURL string
}

// Service is the response module. Create it once with New and share it between the handlers, the jobs and the event
// subscriptions.
type Service struct {
	cfg Config

	// mu serialises the engine and the request lifecycle (plan, create, approve, expire) in this process; execMu serialises the
	// steps that touch a device, so the hourly limit cannot be passed by two approvals at once. The emergency stop takes neither:
	// it is one database transaction and the next step re-reads the switch.
	mu     sync.Mutex
	execMu sync.Mutex

	cat       []builtinDef
	catNote   string
	triggers  []triggerDef
	templates []templateDef
	kinds     []string

	// webhookClient replaces the guarded client of webhook_call. Only export_test.go sets it, so no configuration can
	// reach a webhook without the connect-time address check.
	webhookClient *http.Client
	allowLoopback bool // tests only (export_test.go): the httptest server listens on 127.0.0.1

	seedMu sync.Mutex
	seeded bool

	limitMu    sync.Mutex
	fetchTimes map[string][]time.Time // block list pulls per source address (per /64 for IPv6), for the rate limit

	interfaceFn func() ([]netip.Addr, error) // reads the box interfaces; only export_test.go replaces it
	maxBacklog  int                          // unprocessed events kept; only export_test.go replaces it
	stepLimit   time.Duration                // bound of one item; only export_test.go replaces it
	dropped     atomic.Int64                 // unprocessed events dropped because the backlog was full (M2), the metric
}

// interfaces reads the addresses of the box's network interfaces.
func (s *Service) interfaces() ([]netip.Addr, error) {
	if s.interfaceFn != nil {
		return s.interfaceFn()
	}
	return interfaceAddrs()
}

// DroppedEvents counts the unprocessed trigger events dropped because the backlog was full since the box started. Each drop is
// also a warning in the log and a refused line in the response log.
func (s *Service) DroppedEvents() int64 { return s.dropped.Load() }

// New builds a Service and loads the data files (action templates, rule templates, triggers). The built-in catalog rows are
// written by the first call that reads the catalog.
func New(c Config) (*Service, error) {
	if c.DB == nil || c.Secrets == nil || c.Audit == nil || c.Users == nil || c.Log == nil {
		return nil, errors.New("response: Config needs DB, Secrets, Audit, Users and Log")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	s := &Service{cfg: c, fetchTimes: map[string][]time.Time{}, maxBacklog: maxEventBacklog, stepLimit: stepTimeout}
	if err := s.loadData(); err != nil {
		return nil, err
	}
	return s, nil
}

// ensureSeeded writes the built-in catalog rows the first time something reads the catalog (and again after a failure), so
// the constructor needs no context and no write.
func (s *Service) ensureSeeded(ctx context.Context) error {
	s.seedMu.Lock()
	defer s.seedMu.Unlock()
	if s.seeded {
		return nil
	}
	if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { return s.seedCatalog(ctx, tx) }); err != nil {
		return fmt.Errorf("response: seed the catalog: %w", err)
	}
	s.seeded = true
	return nil
}

func (s *Service) now() time.Time { return s.cfg.Clock() }

func (s *Service) ts() string { return store.FormatTS(s.now()) }

// on reports whether the module is on: the HTTP layer and the scheduler already gate by module, this is for the
// callers that are neither (events).
func (s *Service) on() bool { return s.cfg.Modules == nil || s.cfg.Modules.Enabled(ModuleID) }

func (s *Service) flush(ctx context.Context, ob *events.Outbox) {
	if s.cfg.Bus != nil {
		s.cfg.Bus.Flush(ctx, ob)
	}
}

// boxAddrs lists this box's own addresses: its interfaces (read at every call) and Config.BoxAddrs.
func (s *Service) boxAddrs() ([]netip.Addr, error) {
	var out []netip.Addr
	if s.cfg.BoxAddrs != nil {
		out = append(out, s.cfg.BoxAddrs()...)
	}
	own, err := s.interfaces()
	if err != nil {
		return nil, err
	}
	return append(out, own...), nil
}

// dbq is what *sql.DB and *sql.Tx share.
type dbq interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func strp(s string) *string { return &s }

func ptrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Actor is the person (or system) behind a call.
type Actor struct {
	ID    string
	Name  string
	Email string
	Via   Via
}

// System is the actor of what the box does by itself.
var System = Actor{ID: "system", Name: "Vedette", Email: "system", Via: ViaAuto}

// step is one response step: one core_audit line (SYS-3, INV-20) and one hash-chained resp_log line (INV-19), in the
// caller's transaction. detail must hold no secret (SYS-4): callers pass texts built from checked values only.
func (s *Service) step(ctx context.Context, tx *sql.Tx, auditAction, target string, kind LogKind, detail, actor string) error {
	if actor == "" {
		actor = "system"
	}
	detail = oneLine(detail, 1500)
	if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: auditAction, Target: target, Detail: detail}); err != nil {
		return fmt.Errorf("response: audit %s: %w", auditAction, err)
	}
	return s.appendLog(ctx, tx, kind, actor, detail)
}

// LogKind is the kind of a resp_log line (INV-19).
type LogKind string

// The log kinds.
const (
	LogRuleFired      LogKind = "rule_fired"
	LogProposal       LogKind = "proposal"
	LogRequest        LogKind = "request"
	LogApproved       LogKind = "approved"
	LogRejected       LogKind = "rejected"
	LogExecuted       LogKind = "executed"
	LogRolledBack     LogKind = "rolled_back"
	LogTTLRemoved     LogKind = "ttl_removed"
	LogRefused        LogKind = "refused"
	LogExpired        LogKind = "expired"
	LogFailed         LogKind = "failed"
	LogSettings       LogKind = "settings"
	LogEmergencyStop  LogKind = "emergency_stop"
	LogBlocklistToken LogKind = "blocklist_token"
	LogDryRun         LogKind = "dry_run"
	LogSimulated      LogKind = "simulated"
	LogDeduped        LogKind = "deduped"
	LogBreaker        LogKind = "breaker"
	LogAINote         LogKind = "ai_note"
)

// appendLog adds one line to resp_log inside tx. The caller holds the write transaction (store.DB.Write), which
// serialises the chain. The head moves in the same transaction (core/chain).
func (s *Service) appendLog(ctx context.Context, tx *sql.Tx, kind LogKind, actor, detail string) error {
	prev := chain.Genesis
	err := tx.QueryRowContext(ctx, `SELECT hash FROM resp_log ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("response: read log head: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		prev = chain.Genesis
	}
	id, ts := store.NewID("rl"), s.ts()
	hash, err := chain.HashCanonical(prev, logFields(id, ts, string(kind), actor, detail))
	if err != nil {
		return fmt.Errorf("response: hash log line: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO resp_log (id, ts, kind, actor, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, ts, string(kind), actor, detail, prev, hash); err != nil {
		return fmt.Errorf("response: write log line: %w", err)
	}
	return chain.AdvanceHead(ctx, tx, "resp_log", hash, s.now())
}

func logFields(id, ts, kind, actor, detail string) map[string]any {
	return map[string]any{"id": id, "ts": ts, "kind": kind, "actor": actor, "detail": detail}
}

// refusal records a refusal (INV-19: every refusal is logged) in its own transaction and returns the API error. A
// refusal inside a larger transaction is recorded by the caller before it returns the error from the closure, so the
// line must be written after the transaction rolled back: that is what this does.
func (s *Service) refuse(ctx context.Context, e error, target, actor string) error {
	ae, ok := asAPI(e)
	if !ok {
		return e
	}
	wctx := context.WithoutCancel(ctx) // the write and every query in it use one context: a disconnected caller must not cancel the record of a refusal
	if err := s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		return s.step(wctx, tx, "response.refused", target, LogRefused, ae.Code+": "+ae.Message, actor)
	}); err != nil {
		s.cfg.Log.ErrorContext(ctx, "response: record a refusal", "error", err)
	}
	return e
}
