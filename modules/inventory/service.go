package inventory

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

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// systemActor is the audit user of changes nobody asked for in the interface (sensors, agents).
const systemActor = "system"

// Config is what New needs. DB and Audit are required; everything else is optional and degrades:
// no Events means nothing is announced, no KEV means the catalog has only curated products and no CVE
// matching, no Findings means findings_count is 0.
type Config struct {
	DB       *store.DB
	Audit    *audit.Log
	Events   Publisher
	KEV      KEV
	Box      BoxPackages
	Findings FindingCounter
	Modules  ModuleGate // to tell whether notify is on (notify_available)
	// BoxOwnedIPs lists the addresses the box itself answers on besides its own device (the decoy addresses of the
	// honeypot, WP-14). Nothing observed at one of them is a device: Record and ReplaceSoftware ignore such an
	// observation (counted, BoxOwnedSkipped) and ProtectedIPs lists the address. nil means none.
	BoxOwnedIPs func(ctx context.Context) []netip.Addr
	// BoxOwnedMACs lists the box's own MAC addresses: its cards and the decoys' macvlan links (vedette-host state/net). An
	// observation at a box-owned address is the box only when it carries no MAC or one of these; a foreign MAC there is a
	// device sitting on the decoy's address, and is recorded (WP-31 M7), so the honeypot sees the conflict and pulls the
	// decoy (INV-6). nil, or an error (the host has not answered yet), means unknown: everything at the address is dropped.
	BoxOwnedMACs func(ctx context.Context) ([]string, error)
	Clock        func() time.Time
	Log          *slog.Logger
}

// Service is the only writer of the inv_* tables (INV-2). Create it with New.
type Service struct {
	db       *store.DB
	audit    *audit.Log
	events   Publisher
	kev      KEV
	box      BoxPackages
	findings FindingCounter
	modules  ModuleGate
	boxOwned func(ctx context.Context) []netip.Addr
	boxMACs  func(ctx context.Context) ([]string, error)
	ownedHit atomic.Int64 // observations ignored because their address is box-owned
	clock    func() time.Time
	log      *slog.Logger
	cat      catalogCache

	pendMu  sync.Mutex
	pending map[*sql.Tx]*outbox // events of AddManualDevice calls whose caller transaction is still open
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil {
		return nil, errors.New("inventory: New needs DB and Audit")
	}
	s := &Service{db: cfg.DB, audit: cfg.Audit, events: cfg.Events, kev: cfg.KEV, box: cfg.Box, findings: cfg.Findings, modules: cfg.Modules, boxOwned: cfg.BoxOwnedIPs, boxMACs: cfg.BoxOwnedMACs, clock: cfg.Clock, log: cfg.Log}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	return s, nil
}

// ownedIPs is the set of box-owned addresses now (see Config.BoxOwnedIPs), empty when there is none.
func (s *Service) ownedIPs(ctx context.Context) map[netip.Addr]bool {
	if s.boxOwned == nil {
		return nil
	}
	list := s.boxOwned(ctx)
	if len(list) == 0 {
		return nil
	}
	m := make(map[netip.Addr]bool, len(list))
	for _, a := range list {
		m[a] = true
	}
	return m
}

// ownedFilter returns the test "is this observation the box itself": an address in ownedIPs with no MAC, one of the box's own
// MACs, or any MAC while those are unknown (Config.BoxOwnedMACs). nil when no address is box-owned.
func (s *Service) ownedFilter(ctx context.Context) func(ip netip.Addr, mac string) bool {
	owned := s.ownedIPs(ctx)
	if owned == nil {
		return nil
	}
	var macs map[string]bool // nil = unknown; asked only when an observation is at a box-owned address
	asked := false
	return func(ip netip.Addr, mac string) bool {
		if !ip.IsValid() || !owned[ip] {
			return false
		}
		if mac == "" {
			return true
		}
		if !asked && s.boxMACs != nil {
			asked = true
			if list, err := s.boxMACs(ctx); err == nil {
				macs = map[string]bool{}
				for _, m := range list {
					if n, ok := normMAC(m); ok {
						macs[n] = true
					}
				}
			}
		}
		return macs == nil || macs[mac]
	}
}

// BoxOwnedSkipped counts the observations ignored since start because they came from a box-owned address.
func (s *Service) BoxOwnedSkipped() int { return int(s.ownedHit.Load()) }

func (s *Service) now() string { return store.FormatTS(s.clock()) }

// outbox collects the events of one transaction; they go out only after it commits.
type outbox struct {
	events []Event
	// after run once the transaction has committed, to compute events that need data from other modules
	// (the CVEs feeds knows) which must not be read while the write transaction holds the database.
	after []func(ctx context.Context) []Event
}

func (o *outbox) add(name string, data any) {
	o.events = append(o.events, Event{Name: name, Data: data})
}

// write runs fn in one write transaction and announces its events after the commit.
func (s *Service) write(ctx context.Context, fn func(tx *sql.Tx, o *outbox) error) error {
	var o outbox
	if err := s.db.Write(ctx, func(tx *sql.Tx) error { return fn(tx, &o) }); err != nil {
		return err
	}
	events := o.events
	for _, f := range o.after {
		events = append(events, f(ctx)...)
	}
	s.publish(ctx, events)
	return nil
}

func (s *Service) publish(ctx context.Context, events []Event) {
	if s.events == nil {
		return
	}
	for _, e := range events {
		if err := s.events.Publish(ctx, e); err != nil {
			s.log.WarnContext(ctx, "inventory: publishing an event failed", "event", e.Name, "error", err)
		}
	}
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, actor, action, target, detail string) error {
	if actor == "" {
		actor = systemActor
	}
	if target == "" {
		target = "-"
	}
	if err := s.audit.Append(ctx, tx, audit.Entry{User: actor, Action: action, Target: target, Detail: detail}); err != nil {
		return fmt.Errorf("inventory: audit: %w", err)
	}
	return nil
}

// querier is *sql.DB and *sql.Tx.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func ptr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	v := ns.String
	return &v
}
