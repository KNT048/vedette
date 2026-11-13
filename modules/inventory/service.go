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
	// fresh asks for an answer newer than the cache (a decoy added a moment ago has a MAC the cached answer lacks); the provider
	// bounds how often that reaches the host. A MAC the cached answer does not hold is asked again with fresh before it counts.
	BoxOwnedMACs func(ctx context.Context, fresh bool) ([]string, error)
	// BoxDecoyMACs says, per box-owned address, the MAC of the decoy the host holds there now (vedette-host state/net, the same
	// answer as BoxOwnedMACs). A foreign MAC at a box-owned address is a device only when the host holds a decoy there with
	// another MAC; while it holds none (a Trap IP being added, a namespace being rebuilt) the frame is the box's own link coming
	// up and is dropped (B2 lab: a Trap IP added a second ago became a device and then a conflict of itself). nil = not known:
	// the rule of BoxOwnedMACs alone.
	BoxDecoyMACs func(ctx context.Context, fresh bool) (map[netip.Addr]string, error)
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
	boxMACs  func(ctx context.Context, fresh bool) ([]string, error)
	decoyMAC func(ctx context.Context, fresh bool) (map[netip.Addr]string, error)
	ownedHit atomic.Int64 // observations ignored because their address is box-owned
	clock    func() time.Time
	log      *slog.Logger
	cat      catalogCache

	pendMu  sync.Mutex
	pending map[*sql.Tx]*outbox // events of AddManualDevice calls whose caller transaction is still open

	retMu sync.Mutex
	ret   retention // the prune job's unbroken-run state (retention.go)
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil {
		return nil, errors.New("inventory: New needs DB and Audit")
	}
	s := &Service{db: cfg.DB, audit: cfg.Audit, events: cfg.Events, kev: cfg.KEV, box: cfg.Box, findings: cfg.Findings, modules: cfg.Modules, boxOwned: cfg.BoxOwnedIPs, boxMACs: cfg.BoxOwnedMACs, decoyMAC: cfg.BoxDecoyMACs, clock: cfg.Clock, log: cfg.Log}
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
	var decoys map[netip.Addr]string
	asked, freshAsked := false, false
	load := func(fresh bool) {
		macs, decoys = nil, nil
		if list, err := s.boxMACs(ctx, fresh); err == nil {
			macs = map[string]bool{}
			for _, m := range list {
				if n, ok := normMAC(m); ok {
					macs[n] = true
				}
			}
		}
		if s.decoyMAC != nil {
			if m, err := s.decoyMAC(ctx, fresh); err == nil {
				decoys = m
			}
		}
	}
	return func(ip netip.Addr, mac string) bool {
		if !ip.IsValid() && mac != "" && s.decoyMAC != nil { // a frame with a MAC and no IPv4 (B2 lab): a decoy's own MAC is the box
			if !asked {
				asked = true
				load(false)
			}
			return isDecoyMAC(decoys, mac)
		}
		if !ip.IsValid() || !owned[ip] {
			return false
		}
		if mac == "" || s.boxMACs == nil {
			return true
		}
		if !asked {
			asked = true
			load(false)
		}
		if macs != nil && !macs[mac] && !freshAsked { // not the box's by the cached answer: ask the host before calling it a device
			freshAsked = true
			load(true)
		}
		if macs == nil || macs[mac] {
			return true
		}
		// A foreign MAC is another machine only where the host holds a decoy with another MAC; where it holds none yet, the frame is
		// the box's own link coming up (B2 lab), not a device.
		if decoys != nil {
			if m, held := decoys[ip]; !held || m == mac {
				return true
			}
		}
		return false
	}
}

func isDecoyMAC(decoys map[netip.Addr]string, mac string) bool {
	for _, m := range decoys {
		if n, ok := normMAC(m); ok && n == mac {
			return true
		}
	}
	return false
}

// ForgetBoxOwned deletes the device rows the sensors made of the box's own decoys before the inventory knew them (B2 lab: a Trap
// IP's address seen before it was box-owned, a decoy's MAC seen with no IPv4): unapproved, not added by hand, not the box, and
// either at a box-owned address with no MAC or one of the box's MACs, or with no address and a decoy's MAC. Each goes through
// DeleteDevice (audit "inventory.delete" by "system", event, findings). The honeypot asks at every Apply; it returns how many went.
func (s *Service) ForgetBoxOwned(ctx context.Context) (int, error) {
	owned := s.ownedIPs(ctx)
	if owned == nil || s.boxMACs == nil {
		return 0, nil
	}
	type row struct {
		id, mac string
		ip      netip.Addr
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, ifnull(ip, ''), ifnull(mac, '') FROM inv_asset WHERE is_box = 0 AND approved = 0 AND origin != 'manual'`)
	if err != nil {
		return 0, fmt.Errorf("inventory: read devices: %w", err)
	}
	var cand []row // only these need the host's MACs: a read of them is skipped when there is none
	for rows.Next() {
		var r row
		var ipS string
		if err := rows.Scan(&r.id, &ipS, &r.mac); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("inventory: read devices: %w", err)
		}
		r.ip, _ = netip.ParseAddr(ipS)
		if r.ip.IsValid() && owned[r.ip] || !r.ip.IsValid() && r.mac != "" {
			cand = append(cand, r)
		}
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, fmt.Errorf("inventory: read devices: %w", err)
	}
	if len(cand) == 0 {
		return 0, nil
	}
	list, err := s.boxMACs(ctx, false)
	if err != nil {
		return 0, nil // unknown: nothing is a ghost yet
	}
	macs := map[string]bool{}
	for _, m := range list {
		if n, ok := normMAC(m); ok {
			macs[n] = true
		}
	}
	var decoys map[netip.Addr]string
	if s.decoyMAC != nil {
		decoys, _ = s.decoyMAC(ctx, false)
	}
	n := 0
	for _, r := range cand {
		if r.ip.IsValid() && (r.mac == "" || macs[r.mac]) || !r.ip.IsValid() && isDecoyMAC(decoys, r.mac) {
			if err := s.DeleteDevice(ctx, "system", r.id); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
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
