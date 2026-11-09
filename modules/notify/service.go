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
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// ModuleID is the id of this module in the registry.
const ModuleID = "notify"

// defaultBaseURL is used for links when Config.BaseURL is empty (the box address is not known to notify).
const defaultBaseURL = "https://vedette.local"

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
	Tokens   TokenRecorder    // nil = approval links cannot be sent (ErrApprovalUnavailable)

	Clock    func() time.Time // nil = time.Now
	Location *time.Location   // box local time for quiet hours; nil = time.Local
	// BaseURL is the address people open Vedette at, e.g. https://192.168.10.2:8443 (links in messages).
	BaseURL  string
	BoxAddrs func() []netip.Addr // the box's own addresses: never a valid webhook target; nil = none
	// HTTPClient is given to the Slack, Telegram, Zalo and webhook adapters. nil = their own clients
	// (no redirects, timeouts, and for webhooks the connect-time address check). Tests pass a fake.
	HTTPClient *http.Client
}

// Service is the notify module: channel settings, delivery, incidents and history. Create it once with
// New and share it between the handlers, the jobs, the event subscriptions and the code mailer.
type Service struct {
	cfg Config

	mu        sync.Mutex
	senders   map[channel.Type]cachedSender
	lastPrune time.Time
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
	if c.Location == nil {
		c.Location = time.Local
	}
	if c.BaseURL == "" {
		c.BaseURL = defaultBaseURL
	}
	return &Service{cfg: c, senders: map[channel.Type]cachedSender{}}, nil
}

func (s *Service) now() time.Time { return s.cfg.Clock() }

// on reports whether the module is on; the HTTP layer and the scheduler already gate by module, this is for
// callers that are neither (events, other modules).
func (s *Service) on() bool { return s.cfg.Modules == nil || s.cfg.Modules.Enabled(ModuleID) }

// link makes an absolute URL inside Vedette from a path that starts with "/".
func (s *Service) link(path string) string { return strings.TrimRight(s.cfg.BaseURL, "/") + path }

func (s *Service) boxAddrs() []netip.Addr {
	if s.cfg.BoxAddrs == nil {
		return nil
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
