package response

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/conn"
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
	// Approvers lists the people who may approve on a channel (its saved list), for the check made again when a link is used (INV-3).
	Approvers(ctx context.Context, channel string) ([]Approver, error)
	// RequestApproval sends an approval request to the approvers of the channels in m.Channels and returns the labels of the channels that
	// received it (POST-5). It is called after the request committed, with a 60 second budget, and its error never fails the request.
	RequestApproval(ctx context.Context, m ApprovalMessage) (sentTo []string, err error)
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

// LogSource is a log source declared in the Logs module.
type LogSource struct {
	ID   string
	Name string
}

// LogAddress is a remote address and how many lines of one signature it sent (logs.AddressCount).
type LogAddress struct {
	Addr  netip.Addr
	Count int
}

// LogCounts is the read port of the Logs module for the log_threshold trigger (#332, D-287, D-288); cmd/vedette adapts
// logs.Service. The counts are per declared log source and signature (5-minute buckets); TopAddresses answers the remote
// addresses behind them, most first, never the log sender, the box, its gateway or a decoy (logs CONTRACT), and as lower bounds.
// Sources answers no source and no error while the Logs module is off; an error is a failure, logged, and no event this round.
type LogCounts interface {
	Sources(ctx context.Context) ([]LogSource, error)
	Counts(ctx context.Context, sourceID, signature string, window time.Duration) (int, error)
	TopAddresses(ctx context.Context, sourceID, signature string, window time.Duration, n int) ([]LogAddress, error)
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
	// Allow is the allow-list of the connection (conn.Connection.Allow). nil = not known (a test double): the address check is skipped.
	Allow []string
	// NotReady is why a request cannot use the connection yet (core/conn NotReady: off, never tested, last test failed, SSH host key
	// not pinned), or "" when it can. An action on a connection that is not ready is not available.
	NotReady string
}

// connFP is the fingerprint of a connection as a request saw it: the same connection is the same fingerprint (conn.Fingerprint,
// D-93: id, kind, address and the moment a security field of the connection last changed).
func connFP(c ConnectionInfo) string { return conn.Fingerprint(c.ID, c.Kind, c.Target, c.UpdatedAt) }

// connIdent is conn.Identity of a connection: id, kind and address. An undo is held to it, not to the fingerprint.
func connIdent(c ConnectionInfo) string { return conn.Identity(c.ID, c.Kind, c.Target) }

// ChangesInForce says whether a change made through the connection may still be in force on a device: an item that was carried
// out and not rolled back, one that was sent and whose outcome is not known yet (running), and one the sweep or the step deadline
// failed as "state unknown" (itemRec.StateUnknown). core/conn asks before it deletes a connection (409 in_use, D-93 (4)).
func (s *Service) ChangesInForce(ctx context.Context, connectionID string) (bool, error) {
	var n int
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM resp_actions a, json_each(a.items) i
		WHERE json_extract(i.value, '$.connector_id') = ?1
		AND (json_extract(i.value, '$.status') = 'executed'
			OR json_extract(i.value, '$.state_unknown') = 1
			OR (json_extract(i.value, '$.status') = 'pending' AND coalesce(json_extract(i.value, '$.running_at'), '') <> '')))`, connectionID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("response: changes in force: %w", err)
	}
	return n == 1, nil
}

// Connections lists the connections to devices. nil = none exist.
type Connections interface {
	List(ctx context.Context) ([]ConnectionInfo, error)
}

// DeviceStep is what an Executor is asked to do: one step of one item, exactly as it was rendered when the request was made
// (itemRec.Exec) and approved. An Executor never sees text that came from a client. Phase is "precheck", "run", "rollback" or
// "verify"; precheck and verify only read.
type DeviceStep struct {
	ConnectionID string
	ConnFP       string // conn.Fingerprint of the connection when the request was made: the executor refuses a connection that is not that version
	// ByIdentity holds the step to ConnIdentity (conn.Identity: id, kind, address) instead of ConnFP: an undo and the read-backs that settle an
	// unclear outcome must survive a rotated token or a renewed pin (D-88 (4)).
	ByIdentity   bool
	ConnIdentity string
	Phase        string
	Tool         string   // MCP: the write tool to call
	Lines        []string // SSH: the command lines, one at a time
	Method       string   // API kinds
	URL          string
	Body         string
	Headers      map[string]string
	Args         json.RawMessage // MCP: the typed arguments, a JSON object
	RequestID    string
	ItemID       string
}

// StepStatus says how a step ended.
type StepStatus string

// The ways a step ends. Anything else an Executor answers counts as StepUnknown: a step whose outcome is not understood is
// treated as one that may have been applied.
const (
	StepOK               StepStatus = "ok"
	StepNotSent          StepStatus = "not_sent"           // nothing reached the device
	StepConnectionChange StepStatus = "connection_changed" // the connection is not the version the request was made against; nothing was sent
	StepFailed           StepStatus = "failed"             // the device refused the step; as far as the answer shows nothing changed
	StepUnknown          StepStatus = "unknown"            // sent, outcome not known
)

// DeviceResult is what a step did. Output is what a read step (precheck, verify) printed: it lives in memory only, to be compared
// with the check texts and dropped (INV-22); it is never stored, logged or returned by the API. Detail is one cleaned line.
type DeviceResult struct {
	Status StepStatus
	Detail string
	Output string
}

// Executor carries a step out on a device (cmd/vedette wires core/conn/write, FORBID-1). A nil Executor means no device can be
// changed: such items fail and nothing is sent. Execute must respect ctx (it carries the item's deadline): when ctx ends the
// service stops waiting, records "state unknown" and lets go of the device-step lock, but it cannot stop an Execute that
// ignores ctx from finishing later. A returned error means the step could not be tried at all.
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
	LogCounts   LogCounts   // nil = the log_threshold trigger has no events (#332)
	Notifier    Notifier    // nil = no alert channel
	Connections Connections // nil = no connection
	Executor    Executor    // nil = no device can be changed
	Webhooks    Webhooks    // nil = no webhook
	Links       LinkTokens  // nil = no approval link can be checked: every link is unknown (404)
	TwoStep     TwoStep     // nil = no code can be checked: a high-risk AI request cannot be approved (403 twofa_required)
	Planner     Planner     // nil = no plan is ever written; ai_available is false (13b-11)
	Mailer      LinkMailer  // nil = no link code can be mailed: an email approver cannot link (503 email_not_ready), D-191
	// Critical lists the open critical findings with their device, for the plan job. nil = no plan is asked for.
	Critical func(ctx context.Context) ([]PlanTarget, error)
	Evidence EvidencePorts // a nil port means no such evidence exists: an AI proposal naming it is refused (422 evidence_invalid)

	Clock func() time.Time
	// BoxAddrs adds to the addresses of the network interfaces, which always count as never-touch and as forbidden webhook targets. An error
	// means the set is not known (a configured host that has never answered, an unreadable honeypot record): the callers fail closed
	// (errNeverTouchUnread: nothing is requested or run) instead of checking against a smaller set (D-179 (8)).
	BoxAddrs func() ([]netip.Addr, error)
	// BoxMACs adds to the MAC addresses of the network interfaces, which count as never-touch too: the decoys of the honeypot (macvlan links with
	// MACs of their own) and the cards of the appliance. An error is as for BoxAddrs.
	BoxMACs func() ([]string, error)
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
	// inflight holds the cancel of every device step being sent (a run or an undo); the emergency stop cancels them (D-179 (4)).
	inflightMu sync.Mutex
	inflight   map[*context.CancelCauseFunc]struct{}

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

	limitMu         sync.Mutex
	planFails       map[string]planAttempt // failed or refused plans per finding (limitMu)
	planDay         string                 // the UTC day planCalls counts
	planCalls       int
	proposeTimes    []time.Time // Propose calls of the last hour, any outcome (D-119)
	proposeSkipped  int         // calls refused since the last log line
	proposeLoggedAt time.Time
	fetchTimes      map[string][]time.Time // block list pulls per source address (per /64 for IPv6), for the rate limit
	linkTimes       map[string][]time.Time // approval link calls per source address (the whole address), for their own rate limit
	chatTimes       map[string]*chatEntry  // chat decisions per channel identity, a table of its own (D-135 (7))
	chatNotes       map[string]*chatNote   // refusals of chat senders: one log line per window per identity (D-135 (8))
	chatMax         int                    // identities the chat table remembers (maxFetchKeys; only export_test.go changes it)
	chatFullAt      time.Time              // when "chat rate table full" was last logged
	chatNoteWin     time.Time              // start of the window of the global budget of refusal lines
	chatNoteN       int
	identSends      map[string][]time.Time // link codes made per person and channel in the last hour (D-191)

	// Sending approval requests runs in the background (sendApproval): bg ends it at shutdown (Close), sendSem lets two run at once.
	bg           context.Context
	stopBG       context.CancelFunc
	sendSem      chan struct{}
	sendWG       sync.WaitGroup
	budget       time.Duration                // how long sending one request may take (sendBudget; only export_test.go changes it)
	beforeLock   func()                       // only export_test.go sets it: runs just before a decision through a link takes the service lock
	interfaceFn  func() ([]netip.Addr, error) // reads the box interfaces; only export_test.go replaces it
	macFn        func() ([]string, error)     // reads the MACs of the box interfaces; only export_test.go replaces it
	maxBacklog   int                          // unprocessed events kept; only export_test.go replaces it
	stepLimit    time.Duration                // bound of one item; only export_test.go replaces it
	dropMu       sync.Mutex                   // guards dropUnlogged and dropLoggedAt (coalesced drop lines)
	dropUnlogged int
	dropLoggedAt time.Time
	dropped      atomic.Int64 // unprocessed events dropped because the backlog was full (M2), the metric
	hpMu         sync.Mutex   // guards hpHour and hpCount: the honeypot scan hits let through to the rules this clock hour
	hpHour       time.Time
	hpCount      int
	logPolledAt  time.Time // the last PollLogs that asked the Logs module (only the evaluate job calls it)
}

// interfaces reads the addresses of the box's network interfaces.
func (s *Service) interfaces() ([]netip.Addr, error) {
	if s.interfaceFn != nil {
		return s.interfaceFn()
	}
	return interfaceAddrs()
}

// interfaceMACs reads the MAC addresses of the box's network interfaces, in the canonical lower-case colon form.
func (s *Service) interfaceMACs() ([]string, error) {
	if s.macFn != nil {
		return s.macFn()
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("response: read the box interfaces: %w", err)
	}
	var out []string
	for _, i := range ifs {
		if len(i.HardwareAddr) == 6 {
			out = append(out, i.HardwareAddr.String())
		}
	}
	return out, nil
}

// boxMACs lists this box's own MACs: its interfaces and Config.BoxMACs.
func (s *Service) boxMACs() ([]string, error) {
	out, err := s.interfaceMACs()
	if err != nil {
		return nil, err
	}
	if s.cfg.BoxMACs != nil {
		more, err := s.cfg.BoxMACs()
		if err != nil {
			return nil, err
		}
		out = append(out, more...)
	}
	return out, nil
}

// DroppedEvents counts the unprocessed trigger events dropped because the backlog was full since the box started. Every drop is
// counted here; the warning and the refused line in the response log are coalesced (one per minute, with the count).
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
	s := &Service{cfg: c, fetchTimes: map[string][]time.Time{}, linkTimes: map[string][]time.Time{}, chatTimes: map[string]*chatEntry{}, chatNotes: map[string]*chatNote{}, chatMax: maxFetchKeys, maxBacklog: maxEventBacklog, stepLimit: stepTimeout, sendSem: make(chan struct{}, maxSends), budget: sendBudget}
	s.bg, s.stopBG = context.WithCancel(context.Background())
	if err := s.loadData(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close stops the approval requests that are being sent (their context ends, so a mail server that does not answer cannot hold the
// shutdown) and waits for them to finish. Nothing else in the service runs in the background.
func (s *Service) Close() {
	s.stopBG()
	s.sendWG.Wait()
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
		more, err := s.cfg.BoxAddrs()
		if err != nil {
			return nil, err
		}
		out = append(out, more...)
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
	Chat  string // a decision made in chat: the sender's id on that platform (INV-3), part of the actor text in the log
}

// logActor is the actor of an approval or rejection in resp_log and core_audit: "<name> via <channel> (<ExternalID>)" for chat (D-96 (5)),
// "<email> (<via>)" for the rest.
func (a Actor) logActor() string {
	if a.Chat == "" {
		return a.Email + " (" + string(a.Via) + ")"
	}
	name := truncRunes(cleanLine(a.Name), 80)
	if name == "" {
		name = truncRunes(cleanLine(a.Email), 80)
	}
	return name + " via " + string(a.Via) + " (" + truncRunes(cleanLine(a.Chat), 64) + ")"
}

// refuseActor is the actor of a refusal: the same text as an approval for chat, the email for the rest.
func (a Actor) refuseActor() string {
	if a.Chat == "" {
		return a.Email
	}
	return a.logActor()
}

// System is the actor of what the box does by itself.
var System = Actor{ID: "system", Name: "Vedette", Email: "system", Via: ViaAuto}

// step is one response step: one core_audit line (SYS-3, INV-20) and one hash-chained resp_log line (INV-19), in the
// caller's transaction. detail must hold no secret (SYS-4): callers pass texts built from checked values only.
func (s *Service) step(ctx context.Context, tx *sql.Tx, auditAction, target string, kind LogKind, detail, actor string) error {
	if actor == "" {
		actor = "system"
	}
	detail = capDetail(detail)
	if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: auditAction, Target: target, Detail: detail}); err != nil {
		return fmt.Errorf("response: audit %s: %w", auditAction, err)
	}
	return s.appendLog(ctx, tx, kind, actor, detail)
}

// maxDetail is the size cap of a log line (runes).
const maxDetail = 1500

// capDetail makes a detail one line and cuts it to the cap. A text that the cap cuts keeps its SHA-256 at the end, so the hash-chained row
// still commits to the whole text (D-175: the row of a request and of an execution holds the full call, or its hash).
func capDetail(detail string) string {
	if utf8.RuneCountInString(detail) <= maxDetail {
		return oneLine(detail, maxDetail)
	}
	sum := sha256.Sum256([]byte(detail))
	tail := " [cut; SHA-256 of the full text " + hex.EncodeToString(sum[:]) + "]"
	return oneLine(detail, maxDetail-utf8.RuneCountInString(tail)) + tail
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
	return chainhead.Advance(ctx, tx, "resp_log", hash, s.now())
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
