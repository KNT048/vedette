package feeds

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
)

// secretPurpose is the core/secrets purpose of a feed credential (DATA_MODEL 5.4).
const secretPurpose = "feeds_source.secret"

// ModuleGate says whether a module is on; modreg.Registry satisfies it.
type ModuleGate interface {
	Enabled(id string) bool
}

// Publisher puts a module event on the bus. core/events is not on main yet (WP-04b): wiring passes the real bus
// when it lands; nil drops events.
type Publisher interface {
	Publish(ctx context.Context, name string, payload any) error
}

// Event names and payloads (CONTRACT "Events"). Consumers: inventory, scan, notify.
const (
	EventNewKEV      = "feeds.vuln.new_kev"
	EventVulnUpdated = "feeds.vuln.updated"
	EventIOCUpdated  = "feeds.ioc.updated"
	EventFetchFailed = "feeds.fetch.failed"
)

// NewKEVEvent is published once for each CVE the box has never seen before (POST-1).
type NewKEVEvent struct {
	CVE         string `json:"cve"`
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	HasTemplate bool   `json:"has_template"`
	DateAdded   string `json:"date_added"`
}

// VulnUpdatedEvent lists CVEs whose stored data changed (vendor, product, dates, ransomware flag, template).
type VulnUpdatedEvent struct {
	CVEs []string `json:"cves"`
}

// IOCUpdatedEvent says how many listings of a feed were added and removed by a pull.
type IOCUpdatedEvent struct {
	FeedID  string `json:"feed_id"`
	Added   int    `json:"added"`
	Removed int    `json:"removed"`
}

// FetchFailedEvent is published when a pull fails; Error is the user-safe text stored on the feed.
type FetchFailedEvent struct {
	FeedID string `json:"feed_id"`
	Error  string `json:"error"`
}

// Deps is what the module needs from the rest of the box.
type Deps struct {
	DB      *store.DB
	Secrets *secrets.Store
	Audit   *audit.Log
	Modules ModuleGate
	Log     *slog.Logger
	// Inventory is optional: nil, or the inventory module being off, means INV-10 (you_have null).
	Inventory Inventory
	// Events is optional (nil drops events).
	Events Publisher
	// Fetcher does every pull; the zero value works (guarded client). Set Version for the User-Agent.
	Fetcher Fetcher
	// Clock is time.Now when nil; tests inject a fake.
	Clock func() time.Time
}

// Service is the module: the pull logic, the jobs and the data the handlers read. Build it with NewService,
// call Seed once after the migrations, then hand FeedHandlers(s) to the composite handler and Jobs() to the scheduler.
type Service struct {
	Deps
	st *Store

	mu    sync.Mutex
	locks map[string]*sync.Mutex // one pull at a time per feed

	seedMu sync.Mutex
	seeded bool
}

// NewService checks the dependencies.
func NewService(d Deps) (*Service, error) {
	switch {
	case d.DB == nil || d.Secrets == nil || d.Audit == nil || d.Modules == nil || d.Log == nil:
		return nil, errors.New("feeds: DB, Secrets, Audit, Modules and Log are required")
	}
	if d.Clock == nil {
		d.Clock = time.Now
	}
	return &Service{Deps: d, st: NewStore(d.DB), locks: map[string]*sync.Mutex{}}, nil
}

// Store gives other modules the read methods (VulnByCVE, VulnsByProductKey, HasTemplate, IOCLookup, KevPairs).
func (s *Service) Store() *Store { return s.st }

// Seed merges the built-in feeds into the database. Call it after the migrations, every start.
func (s *Service) Seed(ctx context.Context) error { return s.st.SeedBuiltins(ctx, s.Clock()) }

func (s *Service) now() time.Time { return s.Clock().UTC() }

// inventoryOn is INV-10: the inventory is used only when it exists and its module is on.
func (s *Service) inventoryOn() bool { return s.Inventory != nil && s.Modules.Enabled("inventory") }

func (s *Service) publish(ctx context.Context, name string, payload any) {
	if s.Events == nil {
		return
	}
	if err := s.Events.Publish(ctx, name, payload); err != nil {
		s.Log.WarnContext(ctx, "publishing an event failed", "event", name, "error", err)
	}
}

func (s *Service) feedLock(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.locks[id]
	if m == nil {
		m = &sync.Mutex{}
		s.locks[id] = m
	}
	return m
}

// ready seeds the built-in feeds the first time a request or a pull needs them (once, with the caller context), so
// start-up needs no context of its own. Seed stays callable directly (tests, tools).
func (s *Service) ready(ctx context.Context) error {
	s.seedMu.Lock()
	defer s.seedMu.Unlock()
	if s.seeded {
		return nil
	}
	if err := s.Seed(ctx); err != nil {
		return err
	}
	s.seeded = true
	return nil
}

func (s *Service) sources(ctx context.Context) ([]sourceRow, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	return s.st.sources(ctx)
}
