package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/store"
)

// systemActor is the audit user of changes nobody asked for in the interface (sensors, agents).
const systemActor = "system"

// Config is what New needs. DB and Audit are required; everything else is optional and degrades:
// no Events means nothing is announced, no KEV means the catalog has only curated products and no CVE
// matching, no Findings means findings_count is 0.
type Config struct {
	// Zone is the organization's time zone the days in notes people read are written in (orgtime); nil: UTC.
	Zone     orgtime.Source
	DB       *store.DB
	Audit    *audit.Log
	Events   Publisher
	KEV      KEV
	Box      BoxPackages
	Findings FindingCounter
	// Risk says which devices carry risk: their open exploited findings and their Recommended updates, owned by findings; nil
	// means none (no marker, every device "clean").
	Risk    RiskSource
	Modules ModuleGate // to tell whether notify is on (notify_available)
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
	// BoxDecoyMACs says, per box-owned address, the MAC its decoy has or will have (vedette-host state/net, completed by the
	// honeypot's ExpectedMACs); "" = being added, its MAC not known yet: any MAC there is the box for that moment (B2 lab: a Trap
	// IP added a second ago became a device and then a conflict of itself). At a box-owned address only no MAC, a box MAC or this
	// one is the box; any other MAC is a machine on the address. nil = not known: the rule of BoxOwnedMACs alone.
	BoxDecoyMACs func(ctx context.Context, fresh bool) (map[netip.Addr]string, error)
	// Gateway is the box's IPv4 default gateway (vedette-host state/net), one signal of the identification rules: the
	// zero address when it is not known (no host, or the host did not answer). nil means never known.
	Gateway func(ctx context.Context) netip.Addr
	// WazuhAgents lists the addresses and MACs of the agents the saved Wazuh connection delivered (agent-intake): a device at one of
	// them with data of source agent is reported by Wazuh (#849 DeviceRow.sources). nil means none; an error is logged and means none.
	WazuhAgents func(ctx context.Context) (ips, macs []string, err error)
	// BoxPorts lists the ports the box itself listens on from outside (vedette-host GET /v1/state/ports): its device's open services,
	// source agent (INV-3, INV-23). A nil list (a host older than the read) keeps what is stored. nil: none (a container-only install).
	BoxPorts func(ctx context.Context) ([]observe.Service, error)
	// DeclaredOS is the matcher's choice of the device's OS among the rows a person declared as one (findings.DeclaredOSRow, INV-45):
	// of candidates (row ids, the preferred first) the one it reads as the device's OS and its version as it reads it; "" when none.
	// The device page shows that choice, so it never names another OS than the one findings are decided on. nil: a declared row only
	// fills an OS no source gives. It is asked only when a source the matcher may prefer reads the device (outranking); an error
	// leaves the device with what its sources read.
	DeclaredOS func(d MatchDevice, candidates []string) (id, version string, err error)
	// OSVersion reads a declared version as the matcher does (findings.OSVersion: "v7.2.13" -> "7.2.13"), for a row the matcher is not
	// asked about. nil: trimmed.
	OSVersion func(v string) string
	// SNMPOf is what sensor-active says of a device's SNMP (its state and last answer), for the device's source rows. nil: not known
	// (the row says unavailable); an error is logged and says the same.
	SNMPOf func(ctx context.Context, id string) (SNMPFact, error)
	// AgentOf is what agent-intake says of the agent that reads a device, for the device's source rows. nil: not known.
	AgentOf func(ctx context.Context, id string) (AgentFact, error)
	// AskAgent asks the device's agent to send its data now, after a person turned the agent on again (ChangeSources): best effort,
	// after the commit, the actor is the person. nil: the agent's next report brings it.
	AskAgent func(ctx context.Context, actor, id string)
	// Lifecycle are the other modules' parts of a device merge or delete, called inside the inventory's write (core/lifecycle). nil:
	// none (the inventory alone).
	Lifecycle *lifecycle.Hooks
	Clock     func() time.Time
	Log       *slog.Logger
}

// Service is the only writer of the inv_* tables (INV-2). Create it with New.
type Service struct {
	// scopeCost is active discovery's estimate of a pass (SetScopeCost); nil: no scope is refused for its size.
	scopeMu     sync.Mutex
	scopeCost   func(ctx context.Context, st Settings) ScopeCost
	zone        orgtime.Source
	db          *store.DB
	audit       *audit.Log
	events      Publisher
	kev         KEV
	box         BoxPackages
	boxPorts    func(ctx context.Context) ([]observe.Service, error)
	findings    FindingCounter
	risk        RiskSource
	modules     ModuleGate
	boxOwned    func(ctx context.Context) []netip.Addr
	boxMACs     func(ctx context.Context, fresh bool) ([]string, error)
	decoyMAC    func(ctx context.Context, fresh bool) (map[netip.Addr]string, error)
	gateway     func(ctx context.Context) netip.Addr
	wazuh       func(ctx context.Context) (ips, macs []string, err error)
	declared    func(d MatchDevice, candidates []string) (id, version string, err error)
	readVersion func(v string) string
	snmpOf      func(ctx context.Context, id string) (SNMPFact, error)
	agentOf     func(ctx context.Context, id string) (AgentFact, error)
	askAgent    func(ctx context.Context, actor, id string)
	lifecycle   *lifecycle.Hooks
	ownedHit    atomic.Int64 // observations ignored because their address is box-owned
	clock       func() time.Time
	log         *slog.Logger
	cat         catalogCache

	pendMu  sync.Mutex
	pending map[*sql.Tx]*outbox // events of AddManualDevice calls whose caller transaction is still open

	retMu sync.Mutex
	ret   retention // the prune job's unbroken-run state (retention.go)

	staleMu sync.Mutex
	stale   map[string]time.Time // device → when staleLog last logged it
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil {
		return nil, errors.New("inventory: New needs DB and Audit")
	}
	s := &Service{db: cfg.DB, audit: cfg.Audit, events: cfg.Events, kev: cfg.KEV, box: cfg.Box, boxPorts: cfg.BoxPorts, findings: cfg.Findings, risk: cfg.Risk, modules: cfg.Modules, boxOwned: cfg.BoxOwnedIPs, boxMACs: cfg.BoxOwnedMACs, decoyMAC: cfg.BoxDecoyMACs, gateway: cfg.Gateway, wazuh: cfg.WazuhAgents, declared: cfg.DeclaredOS, readVersion: cfg.OSVersion, snmpOf: cfg.SNMPOf, agentOf: cfg.AgentOf, askAgent: cfg.AskAgent, lifecycle: cfg.Lifecycle, clock: cfg.Clock, zone: cfg.Zone, log: cfg.Log}
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
		// The MAC the decoy at this address has or will have ("": being added, its MAC not known yet) is the box; any other MAC is a
		// machine on the address, held by the host or not (a refused or failed Trap IP must not hide a real device; B2 review round 2).
		if m, ok := decoys[ip]; ok && (m == "" || m == mac) {
			return true
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

// ForgetBoxOwned deletes the device rows the sensors made of the box's own decoys (B2 lab): first seen after the Trap IP at that
// address was switched on (since, from the honeypot: a row from before is a real machine and stays), unapproved, not added by
// hand, not the box, and either at that address with no MAC or one of the box's MACs, or with no address and that decoy's MAC.
// The condition is checked again in the deleting transaction, so a row approved in between stays. Each deletion is audited
// ("inventory.delete" by "system") and announced as DeleteDevice does. It returns how many went.
func (s *Service) ForgetBoxOwned(ctx context.Context, since map[netip.Addr]time.Time) (int, error) {
	if len(since) == 0 || s.boxMACs == nil {
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
		if _, trap := since[r.ip]; r.ip.IsValid() && trap || !r.ip.IsValid() && r.mac != "" {
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
		var from time.Time
		switch {
		case r.ip.IsValid() && (r.mac == "" || macs[r.mac]):
			from = since[r.ip]
		case !r.ip.IsValid():
			for ip, m := range decoys {
				if t, trap := since[ip]; trap && m != "" && m == r.mac {
					from = t
				}
			}
		}
		if from.IsZero() {
			continue
		}
		gone, err := s.forgetGhost(ctx, r.id, store.FormatTS(from))
		if err != nil {
			return n, err
		}
		if gone {
			n++
		}
	}
	return n, nil
}

// forgetGhost deletes one row of ForgetBoxOwned when it is still unapproved, not by hand, not the box and first seen at or after
// from, in the deleting transaction; false when it no longer is.
func (s *Service) forgetGhost(ctx context.Context, id, from string) (bool, error) {
	counts, err := s.findingCounts(ctx)
	if err != nil {
		return false, err
	}
	gone := false
	err = s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		gone = false
		name := deviceName(ctx, tx, id)
		var still bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM inv_asset WHERE id = ? AND is_box = 0 AND approved = 0 AND origin != 'manual' AND first_seen >= ?)`,
			id, from).Scan(&still); err != nil {
			return fmt.Errorf("inventory: read device: %w", err)
		}
		if !still {
			return nil
		}
		if err := s.deleteDeviceTx(ctx, tx, o, lifecycle.Delete{Device: id, Name: name}); err != nil {
			return err
		}
		gone = true
		detail := id + "; made of a Trap IP of the box itself"
		if k := counts[id]; k > 0 {
			detail = fmt.Sprintf("%s; removed %d findings of the device", detail, k)
		}
		o.add(EventAssetDeleted, AssetEvent{AssetID: id})
		return s.auditTx(ctx, tx, "system", "inventory.delete", name, detail)
	})
	return gone, err
}

// BoxOwnedSkipped counts the observations ignored since start because they came from a box-owned address.
func (s *Service) BoxOwnedSkipped() int { return int(s.ownedHit.Load()) }

func (s *Service) now() string { return store.FormatTS(s.clock()) }

// outbox collects the events of one transaction; they go out only after it commits.
type outbox struct {
	events []Event
	// readdressed are the devices whose address this write took away or changed (claimIP). write announces each one updated first
	// (readdressedEvents): a job holding the old address (an SNMP batch, an nmap run) stops when
	// its device leaves it, so a device that took the address mid-run is never sent a credential.
	readdressed []string
	// after run once the transaction has committed, to compute events that need data from other modules
	// (the CVEs feeds knows) which must not be read while the write transaction holds the database.
	after []func(ctx context.Context) []Event
}

func (o *outbox) add(name string, data any) {
	o.events = append(o.events, Event{Name: name, Data: data})
}

// readdress records that device id lost or changed its address in this write.
func (o *outbox) readdress(id string) {
	if !slices.Contains(o.readdressed, id) {
		o.readdressed = append(o.readdressed, id)
	}
}

// readdressedEvents is inventory.asset.updated for each readdressed device the write does not announce discovered (created in it: no job
// holds it) or deleted. They go out before the write's other events (review r1 L2 of #881): a job holding the old address stops before
// the newcomer's discovered handlers and the post-commit reads run (write publishes them on their own, first). A device the write also announces updated gets both.
func (o *outbox) readdressedEvents() []Event {
	var out []Event
	for _, id := range o.readdressed {
		told := slices.ContainsFunc(o.events, func(e Event) bool {
			a, ok := e.Data.(AssetEvent)
			return ok && a.AssetID == id && (e.Name == EventAssetDiscovered || e.Name == EventAssetDeleted)
		})
		if !told {
			out = append(out, Event{Name: EventAssetUpdated, Data: AssetEvent{AssetID: id}})
		}
	}
	return out
}

// write runs fn in one write transaction and announces its events after the commit.
func (s *Service) write(ctx context.Context, fn func(tx *sql.Tx, o *outbox) error) error {
	var o outbox
	if err := s.db.Write(ctx, func(tx *sql.Tx) error { return fn(tx, &o) }); err != nil {
		return err
	}
	s.publish(ctx, o.readdressedEvents()) // first, before the post-commit reads (review r2 L1 of #881): a job holding the old address stops now
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
