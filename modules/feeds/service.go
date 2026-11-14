package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
)

// secretPurpose is the core/secrets purpose of a feed credential (DATA_MODEL 5.4).
const secretPurpose = "feeds_source.secret"

// ModuleGate says whether a module is on; modreg.Registry satisfies it.
type ModuleGate interface {
	Enabled(id string) bool
}

// Publisher puts a module event on the bus: *events.Bus satisfies it, so wiring passes the real bus; nil drops events.
type Publisher interface {
	Publish(ctx context.Context, e events.Event) error
}

// Event names and payloads (CONTRACT "Events"). Consumers: inventory, scan, notify.
const (
	EventNewKEV        = "feeds.vuln.new_kev"
	EventVulnUpdated   = "feeds.vuln.updated"
	EventIOCUpdated    = "feeds.ioc.updated"
	EventFetchFailed   = "feeds.fetch.failed"
	EventSyncBaseline  = "feeds.sync.baseline"
	EventRangesUpdated = "feeds.ranges.updated"
)

// RangesUpdatedEvent is published after a pull of the NVD affected versions (nvd-kev, D-500) changed the entries of
// some CVEs: findings must match the devices again. First is true when the table was empty before (the first fill:
// like the baseline of D-78, nothing it causes is news).
type RangesUpdatedEvent struct {
	CVEs  []string `json:"cves"`
	First bool     `json:"first"`
}

// SyncBaselineEvent is published once, instead of one NewKEVEvent per CVE, when the first pull of the CISA list
// fills an empty database (D-78). Subscribers recompute everything once; notify sends nothing for it.
type SyncBaselineEvent struct {
	Source string `json:"source"` // "cisa-kev"
	Count  int    `json:"count"`  // CVEs the pull added
}

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
	// KEVPrimary and KEVFallback are the two addresses of the CISA list (D-91); empty means the built-in CISA address and
	// KEVMirrorURL. Tests point them at fake servers. The fallback applies only while the feed still uses KEVPrimary.
	KEVPrimary, KEVFallback string
	// Clock is time.Now when nil; tests inject a fake.
	Clock func() time.Time
}

// Service is the module: the pull logic, the jobs and the data the handlers read. Build it with NewService,
// call Seed once after the migrations, then hand FeedHandlers(s) to the composite handler and Jobs() to the scheduler.
type Service struct {
	Deps
	st *Store

	mu    sync.Mutex
	locks map[string]*feedGate // one pull at a time per feed; entries live while a pull holds or waits

	seedMu sync.Mutex
	seeded bool

	unknownLogged atomic.Bool // the "waiting for the box's addresses" debug line is written once (D-208)

	afterChunk func(chunk int) // tests: runs after each chunk of an indicator list has committed

	idleMu     sync.Mutex
	distroIdle map[string]bool // D-570: the distribution feeds the last check found no device for

	nvdMu sync.Mutex
	nvd   *nvdRun // the NVD pull running now, or paused to go on later (W3-1); nil when none

	wait func(ctx context.Context, d time.Duration) error // tests: replaces the real waits of the NVD pull
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
	return &Service{Deps: d, st: NewStore(d.DB), locks: map[string]*feedGate{}}, nil
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
	if err := s.Events.Publish(ctx, events.Event{Name: name, Data: payload}); err != nil {
		s.Log.WarnContext(ctx, "publishing an event failed", "event", name, "error", err)
	}
}

// feedGate is the pull of one feed: done is open while a pull runs (closed when it ends, so the callers that joined
// it go on); refs counts the pulls holding or waiting for it, so the entry can be dropped when the last one is done.
type feedGate struct {
	done chan struct{}
	refs int
}

// lockFeed takes the pull lock of a feed. When another pull of the feed holds it, the caller joins that pull: it
// waits for it to end (or for ctx) and gets joined true without the lock, so a second "Fetch now" or a job tick
// during a pull never starts a second pull (W3-1: two NVD pulls 0.3 s apart got HTTP 503). The returned func
// releases the lock.
func (s *Service) lockFeed(ctx context.Context, id string) (release func(), joined bool, err error) {
	s.mu.Lock()
	g := s.locks[id]
	if g == nil {
		g = &feedGate{}
		s.locks[id] = g
	}
	g.refs++
	drop := func() { // under s.mu
		if g.refs--; g.refs == 0 {
			delete(s.locks, id)
		}
	}
	if g.done == nil {
		g.done = make(chan struct{})
		s.mu.Unlock()
		return func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			close(g.done)
			g.done = nil
			drop()
		}, false, nil
	}
	done := g.done
	s.mu.Unlock()
	select {
	case <-done:
		joined = true
	case <-ctx.Done():
		err = ctx.Err()
	}
	s.mu.Lock()
	drop()
	s.mu.Unlock()
	return nil, joined, err
}

// busy reports whether a pull of the feed is running now.
func (s *Service) busy(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.locks[id]
	return g != nil && g.done != nil
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

// TxSettler is optional on Inventory: AddManualDevice may leave work for after the caller's transaction (the
// inventory events), and Settle(ctx, tx, committed) tells it whether that transaction committed or rolled back.
type TxSettler interface {
	Settle(ctx context.Context, tx *sql.Tx, committed bool)
}

// writeDeclaring is DB.Write for a transaction that may call declareDevice: whatever the inventory kept for it is
// settled once the transaction is over, whether it committed or not.
func (s *Service) writeDeclaring(ctx context.Context, fn func(tx *sql.Tx) error) error {
	var declared *sql.Tx
	err := s.DB.Write(ctx, func(tx *sql.Tx) error {
		declared = tx
		return fn(tx)
	})
	if st, ok := s.Inventory.(TxSettler); ok && declared != nil {
		st.Settle(context.WithoutCancel(ctx), declared, err == nil)
	}
	return err
}

// declareDevice asks the inventory for the manual device of "I have it" (S-FEED-2, INV-14) inside tx and records the
// device's id on the answer, once (D-484: the "I have this" scope is that device's only).
func (s *Service) declareDevice(ctx context.Context, tx *sql.Tx, actor, key string, v VulnRow) error {
	d := ManualDevice{Kind: KindOf(key), Vendor: v.Vendor, Product: v.Product, Display: DisplayOf(v.Vendor, v.Product), Key: key}
	id, err := s.Inventory.AddManualDevice(ctx, tx, actor, d)
	if err != nil {
		return fmt.Errorf("feeds: add manual device: %w", err)
	}
	if id == "" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE feeds_weekly_answer SET device_id = ? WHERE key = ? AND device_id IS NULL`, id, key); err != nil {
		return fmt.Errorf("feeds: record the declared device: %w", err)
	}
	return nil
}

// HaveWindow is how far before the answered entry "I have this" reaches back: the 7 days of "This week" on Home, so the
// other entries of that product the same week also become findings (D-484).
const HaveWindow = 7 * 24 * time.Hour

// reconcileDevices adds the "I have it" devices that were answered while the inventory was off, once it is on
// (INV-14). Called by every pull tick. A product no longer in the CISA list waits.
func (s *Service) reconcileDevices(ctx context.Context) error {
	if !s.inventoryOn() {
		return nil
	}
	keys, err := s.st.pendingDevices(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		vs, err := s.st.VulnsByProductKey(ctx, k)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(vs, func(v VulnRow) bool { return v.SourceID == "cisa-kev" })
		if i < 0 {
			continue
		}
		v := vs[i]
		err = s.writeDeclaring(ctx, func(tx *sql.Tx) error {
			var added int
			if err := tx.QueryRowContext(ctx, `SELECT device_added FROM feeds_weekly_answer WHERE key = ? AND answer = 'have'`, k).Scan(&added); err != nil || added != 0 {
				return nil // changed meanwhile
			}
			if err := s.declareDevice(ctx, tx, "system", k, v); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE feeds_weekly_answer SET device_added = 1 WHERE key = ?`, k); err != nil {
				return fmt.Errorf("feeds: mark device added: %w", err)
			}
			return s.Audit.Append(ctx, tx, audit.Entry{User: "system", Action: "feeds.weekly_device", Target: DisplayOf(v.Vendor, v.Product), Detail: "added after the inventory became available"})
		})
		if err != nil {
			return err
		}
	}
	return nil
}
