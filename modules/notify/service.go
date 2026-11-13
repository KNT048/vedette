package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// ModuleID is the id of this module in the registry.
const ModuleID = "notify"

// DefaultTimeZone is the box time zone when core does not say otherwise (the same default as the ai module).
const DefaultTimeZone = "Asia/Ho_Chi_Minh"

// Config wires a Service. DB, Secrets, Audit, Users and Log are required.
type Config struct {
	DB      *store.DB
	Secrets *secrets.Store
	Audit   *audit.Log
	Users   Users
	Log     *slog.Logger

	Modules  ModuleGate       // nil = notify counts as on (tests); main passes modreg.Registry
	Bus      Bus              // nil = events are dropped
	Findings FindingDirectory // nil = finding events are logged and skipped
	Devices  DeviceDirectory  // nil = device events show the asset id
	Tokens   TokenRecorder    // nil = email approvers get a message that says to open Vedette instead of a link
	// ApproverLinks, when set, makes an approver whose address the user has not linked in My account a skipped approver
	// (D-191); an error from it skips the approver too (fail closed). nil = no link check, as before.
	ApproverLinks ApproverLinks
	Decisions     Decisions // module response: takes decisions made in chat (13b-8); nil = chat decisions are not taken
	// LinkCodes makes the code a Zalo personal approver replies with to prove their Zalo account (D-447); nil = no code is sent and the
	// approver stays not linked.
	LinkCodes LinkCodes

	Clock func() time.Time // nil = time.Now
	// Zone returns the IANA name of the box time zone (core_org.timezone), asked at every use so a change applies at
	// once; nil or an empty or unknown name = DefaultTimeZone. The process time zone is never used (quiet hours
	// and the day of the history follow the wall clock of the people, not of the server).
	Zone func(context.Context) string
	// Location, when set, is the box time zone and Zone is not asked (tests).
	Location *time.Location
	// BaseURL is the address people open Vedette at, e.g. https://192.168.10.2:8443 (links in messages). Empty: messages
	// carry no link and say to open Vedette, and approval requests are refused (ErrApprovalUnavailable): a link that
	// approves an action is a credential and must point at the real box.
	BaseURL string
	// BoxAddrs is the machine's addresses (vedette-host, the container's gateway): no webhook or SMTP server on Vedette's own ports
	// there (D-446; the container's own interfaces are read by the channel package, never a target). known=false means the box does not know its own addresses yet (vedette-host has not answered since the start): saving a
	// webhook is then 503 host_unreachable and no webhook connection is made (fail closed, #157). nil = only the interfaces,
	// known (tests, a box without vedette-host).
	BoxAddrs func() (addrs []netip.Addr, known bool)
	// SelfAddrs lists more addresses that are Vedette itself (the honeypot's decoys): no webhook or SMTP server there on any port
	// (D-446). nil: none.
	SelfAddrs func() []netip.Addr
	// HTTPClient is given to the Slack, Telegram and Zalo adapters (not to webhooks: their client always checks the
	// address at connect time). nil = their own clients (no redirects, timeouts). Tests pass a fake. Its Timeout should be 0: the
	// Telegram listener long-polls longer than any usual total timeout, so it clears Timeout on its own copy and gives every call a
	// deadline of its own; the senders keep the client's Timeout.
	HTTPClient *http.Client
	// SMTPLoopback is for tests only (the fake SMTP servers of the notify and cmd/vedette tests, and the e2e box, listen on
	// 127.0.0.1): the email channel may then use a loopback server, and the box's own addresses are not checked. main never sets
	// it: core never runs on the host network, so loopback is core itself.
	SMTPLoopback bool
}

// Service is the notify module: channel settings, delivery, incidents and history. Create it once with
// New and share it between the handlers, the jobs, the event subscriptions and the code mailer.
type Service struct {
	cfg Config

	mu        sync.Mutex
	senders   map[channel.Type]cachedSender
	lastPrune time.Time
	// webhookClient replaces the webhook adapter's own guarded client. Only export_test.go sets it: a client from Config
	// would skip the connect-time address check, so no configuration can reach a webhook.
	webhookClient *http.Client
	// zaloTo makes the direct Zalo sender of one approver (channel.ZaloPersonalTo); only export_test.go replaces it.
	zaloTo func(channel.Sender, string) (channel.Sender, error)
	// zaloListen opens the message connection of the Zalo personal channel (channel.ZaloListen); only export_test.go replaces it.
	zaloListen func(context.Context, channel.Sender) (zaloInbox, error)
	zaloRetry  zaloRetry // the wait of the Zalo listener between connections (zalolisten.go)
	zaloNotes  zaloNotes // rations the audit rows for Zalo messages from non-approvers
	// zaloAnswerBudget rations the private answers of the Zalo listener per approver; zaloSeen remembers the last message ids it took
	// (only the listener's read loop uses it, and the job runs once at a time).
	zaloAnswerBudget zaloBudget
	zaloSeen         seenEnvelopes
	// zalo is the Zalo personal set-up: the one QR sign-in, its rations, the link codes sent (zalologin.go); zaloStartQR starts a sign-in
	// (channel.StartZaloQR), only export_test.go replaces it.
	zalo        zaloSetup
	zaloStartQR func(context.Context, *http.Client) (zaloQRFlow, error)
	// reenabled is set when the module is turned on (modreg tells us) and cleared by the next Flush, which then drops
	// the queued notices that went stale while it was off (D-86 (7)).
	reenabled atomic.Bool
	// urlSealed is set once no webhook row is left with a plain URL (sealLegacyURL).
	urlSealed atomic.Bool
	// urlSealFailing is set while sealLegacyURL keeps failing, so the warning is logged once.
	urlSealFailing atomic.Bool
	// tgOffset is the next Telegram update the approval listener reads (tglisten.go).
	tgOffset telegramOffset
}

// changeNotifier is the part of core/modreg.Registry that tells when a module is switched (OnChange). Config.Modules
// is asserted to it, so the ModuleGate interface stays small.
type changeNotifier interface {
	OnChange(fn func(id string, enabled bool))
}

type cachedSender struct {
	rev    int64
	sender channel.Sender
}

// New builds a Service.
func New(c Config) (*Service, error) {
	if c.DB == nil || c.Secrets == nil || c.Audit == nil || c.Users == nil || c.Log == nil {
		return nil, errors.New("notify: Config needs DB, Secrets, Audit, Users and Log")
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	s := &Service{cfg: c, senders: map[channel.Type]cachedSender{}, zaloTo: channel.ZaloPersonalTo, zaloListen: openZaloInbox, zaloStartQR: startZaloQR}
	if cn, ok := c.Modules.(changeNotifier); ok { // the callback only sets a flag: it runs on the publisher's goroutine and must not block
		cn.OnChange(func(id string, enabled bool) {
			if id == ModuleID && enabled {
				s.reenabled.Store(true)
			}
		})
	}
	return s, nil
}

func (s *Service) now() time.Time { return s.cfg.Clock() }

// on reports whether the module is on; the HTTP layer and the scheduler already gate by module, this is for
// callers that are neither (events, other modules).
func (s *Service) on() bool { return s.cfg.Modules == nil || s.cfg.Modules.Enabled(ModuleID) }

// link makes an absolute URL inside Vedette from a path that starts with "/". Without a BaseURL it is empty: the
// adapters then leave the link out and tell people to open Vedette.
func (s *Service) link(path string) string {
	if s.cfg.BaseURL == "" {
		return ""
	}
	return strings.TrimRight(s.cfg.BaseURL, "/") + path
}

// loc is the box time zone now.
func (s *Service) loc(ctx context.Context) *time.Location {
	if s.cfg.Location != nil {
		return s.cfg.Location
	}
	name := ""
	if s.cfg.Zone != nil {
		name = s.cfg.Zone(ctx)
	}
	if l, err := time.LoadLocation(name); name != "" && err == nil {
		return l
	}
	if l, err := time.LoadLocation(DefaultTimeZone); err == nil {
		return l
	}
	return time.FixedZone("ICT", 7*3600) // no tz database on the machine; Vietnam has no daylight saving
}

// boxAddrs lists the machine's addresses (Config.BoxAddrs): a webhook or an SMTP server is never on Vedette's own ports there
// (D-446). Loopback and core's own interfaces, Vedette itself on every port, are read by the channel package at every check.
// known is false while Config.BoxAddrs says so.
func (s *Service) boxAddrs() (out []netip.Addr, known bool) {
	if s.cfg.BoxAddrs == nil {
		return nil, true
	}
	return s.cfg.BoxAddrs()
}

// flush publishes the events of a committed transaction.
func (s *Service) flush(ctx context.Context, ob *events.Outbox) {
	if s.cfg.Bus != nil {
		s.cfg.Bus.Flush(ctx, ob)
	}
}

// dbtx is what *sql.DB and *sql.Tx share.
type dbtx interface {
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Service) record(ctx context.Context, tx *sql.Tx, who, action, target, detail string) error {
	if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: who, Action: action, Target: target, Detail: detail}); err != nil {
		return fmt.Errorf("notify: audit %s: %w", action, err)
	}
	return nil
}

// nullable turns "" into SQL NULL.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// recordTimeout bounds a write that must happen after a send even if the caller's context ended: the attempt
// is over (INV-6: it has a record), so the record is written under a context that cannot be cancelled.
const recordTimeout = 10 * time.Second

// detached returns a context that keeps the values of ctx but ignores its cancellation, with a short deadline.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
}
