package honeypot

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
)

// Config is what New needs. DB, Audit, Secrets, Inventory and Host are required.
type Config struct {
	DB        *store.DB
	Audit     *audit.Log
	Secrets   *secrets.Store // the bait password of a credential token (core_secret)
	Inventory Inventory
	Host      Host
	Logs      Logs      // optional: other sources' lines around a hit (the logs module)
	Events    Publisher // optional: nil publishes nothing
	Modules   ModuleGate

	// ConfigDir is the folder core writes opencanary.conf and honeytokens.json into. It belongs to core: the honeypot
	// container mounts it read-only (WP-08), and core never reads a file back from it (D-89, amendment of the WP-14 review).
	// Empty means the module is not wired to a container: nothing is written, no trap can listen.
	ConfigDir string
	// LogDir is the folder the container writes the JSON-lines log opencanary.jsonl into (writable for the container,
	// read-only use for core). Everything in it is hostile: core opens the log through os.Root, without following
	// symlinks and without blocking. Empty means no log is read.
	LogDir string

	Clock    func() time.Time
	Log      *slog.Logger
	Location func(ctx context.Context) *time.Location // organization time zone for "today" and the daily ignored count; nil means UTC
	// BoxURL is the Box address as https://host[:port] (D-465), the start of a URL token; asked at every create. nil or "": the
	// box's IP from the inventory on port 8443; neither known: a URL token cannot be made (409 no_box_address).
	BoxURL func() string

	PollEvery time.Duration // log poll pace; default 1 s
	MaxLine   int           // default MaxLine
}

// Service is the honeypot module. Create it with New.
type Service struct {
	cfg Config
	db  *store.DB

	kick chan struct{} // capacity 1: "the state changed, apply it to the host"

	mu        sync.Mutex // guards host, tl's counters (copied into stats), stats, lastWarn, hourStart, hourNew
	host      hostCache
	kickGen   uint64 // bumped by Kick; doneGen is the kickGen the last finished Apply started with: kickGen > doneGen = a change the host has not confirmed (state starting/stopping)
	doneGen   uint64
	tl        *tailer
	stats     Stats
	lastWarn  map[string]time.Time
	hourStart time.Time // the clock hour hourNew counts
	hourNew   int       // new hits stored in that hour (per-hour cap, ingest.go)

	applyMu sync.Mutex                   // one Apply or teardown at a time (they rewrite "applied" and talk to the host)
	written map[string][sha256.Size]byte // hash of what Apply last wrote to ConfigDir, by file name (guarded by applyMu)
	// restartDue: a configuration file was written and no start of the container was acknowledged since (guarded by
	// applyMu). Memory only (INV-15: nothing in config/ is read back), so the first Apply after core starts asks for one
	// restart. ponytail: one restart per core start, an upgrade is a hash of the file the container last read.
	restartDue bool
	// refusals is what the host refused per address, for the back-off (guarded by applyMu); sig is the wanted set it belongs to.
	refusals map[netip.Addr]*refusal
	sig      string
	pollMu   sync.Mutex // one Poll at a time
	// touches is when each source last touched each Trap IP, for the sweep detection (ingest.go sweep; guarded by pollMu).
	touches map[netip.Addr]map[netip.Addr]time.Time
}

// New returns the service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Secrets == nil || cfg.Inventory == nil || cfg.Host == nil {
		return nil, errors.New("honeypot: New needs DB, Audit, Secrets, Inventory and Host")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.PollEvery <= 0 {
		cfg.PollEvery = time.Second
	}
	if cfg.MaxLine <= 0 || cfg.MaxLine > MaxLine {
		cfg.MaxLine = MaxLine
	}
	s := &Service{cfg: cfg, db: cfg.DB, kick: make(chan struct{}, 1), written: map[string][sha256.Size]byte{}}
	s.host.reason = "the host has not been asked yet"
	s.kickGen = 1 // the first Apply has not run: the traps are "starting", not "failed"
	return s, nil
}

func (s *Service) now() time.Time { return s.cfg.Clock().UTC() }

func (s *Service) loc(ctx context.Context) *time.Location {
	if s.cfg.Location != nil {
		if l := s.cfg.Location(ctx); l != nil {
			return l
		}
	}
	return time.UTC
}

func (s *Service) on() bool { return s.cfg.Modules == nil || s.cfg.Modules.Enabled("honeypot") }

// Kick is for a change the owner made (a setting, a switch, the module turned on): the traps are "starting" or "stopping"
// until an Apply that began after it has answered.
func (s *Service) Kick() {
	s.mu.Lock()
	s.kickGen++
	s.mu.Unlock()
	s.hint()
}

// hint asks the run loop to apply the state soon without claiming anything changed for the owner: an inventory event
// on a busy LAN must not keep the traps "starting" while an Apply is failing.
func (s *Service) hint() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, actor, action, target, detail string) error {
	if actor == "" {
		actor = "system"
	}
	if target == "" {
		target = "-"
	}
	if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: action, Target: target, Detail: detail}); err != nil {
		return fmt.Errorf("honeypot: audit: %w", err)
	}
	return nil
}

func ptr(s string) *string { return &s }

// ---- stored state ----

func loadJSON(ctx context.Context, q querier, key string, out any) error {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT value FROM hp_config WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("honeypot: read %s: %w", key, err)
	}
	if err := jsonUnmarshal(raw, out); err != nil {
		return fmt.Errorf("honeypot: read %s: %w", key, err)
	}
	return nil
}

func (s *Service) saveJSON(ctx context.Context, tx *sql.Tx, key string, v any, actor string) error {
	raw, err := jsonMarshal(v)
	if err != nil {
		return err
	}
	if actor == "" {
		actor = "system"
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO hp_config (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		key, raw, store.FormatTS(s.now()), actor)
	if err != nil {
		return fmt.Errorf("honeypot: write %s: %w", key, err)
	}
	return nil
}

type trapIPRow struct {
	TrapIP
	ip netip.Addr
}

func (d trapIPRow) has(svc ServiceName) bool { return slices.Contains(d.Services, svc) }

// spec is how the host builds the address: the vendor's MAC prefix and the ports of its services (D-466).
func (d trapIPRow) spec() DecoySpec {
	var oui string
	if d.Vendor != nil {
		oui, _ = vendorOUI(*d.Vendor)
	}
	return DecoySpec{OUI: oui, Ports: ports(d.Services)}
}

const trapIPCols = `id, name, ip, preset, vendor, services, enabled, created_at`

// loadTrapIPs reads the Trap IPs in creation order, the order that decides which one names the SMB share (D-466 (4)).
func loadTrapIPs(ctx context.Context, q querier) ([]trapIPRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+trapIPCols+` FROM hp_trap_ips ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("honeypot: read trap IPs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []trapIPRow
	for rows.Next() {
		var d trapIPRow
		var vendor sql.NullString
		var services string
		if err := rows.Scan(&d.ID, &d.Name, &d.IP, &d.Preset, &vendor, &services, &d.Enabled, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("honeypot: read trap IPs: %w", err)
		}
		if vendor.Valid {
			d.Vendor = ptr(vendor.String)
		}
		var l []ServiceName
		if err := jsonUnmarshal(services, &l); err != nil {
			return nil, fmt.Errorf("honeypot: read trap IP services: %w", err)
		}
		d.Services = inOrder(l)
		d.ip, _ = netip.ParseAddr(d.IP)
		out = append(out, d)
	}
	return out, rows.Err()
}

// world is everything a decision reads: the module's own tables and the inventory.
type world struct {
	trapIPs []trapIPRow // creation order
	devices []Device
	lan     netip.Prefix // zero when no IPv4 range is declared
	box     Box
}

func (s *Service) load(ctx context.Context) (*world, error) {
	w := &world{}
	db := s.db.Reader()
	var err error
	if w.trapIPs, err = loadTrapIPs(ctx, db); err != nil {
		return nil, err
	}
	if w.devices, err = s.cfg.Inventory.Devices(ctx); err != nil {
		return nil, fmt.Errorf("honeypot: read inventory: %w", err)
	}
	ranges, err := s.cfg.Inventory.LANRanges(ctx)
	if err != nil {
		return nil, fmt.Errorf("honeypot: read lan ranges: %w", err)
	}
	if w.box, err = s.cfg.Inventory.Box(ctx); err != nil {
		return nil, fmt.Errorf("honeypot: read box: %w", err)
	}
	w.lan = pickLAN(ranges, w.box.IP)
	return w, nil
}

// pickLAN is the network of the box: the declared range that holds its IP, else the first IPv4 range.
func pickLAN(ranges []netip.Prefix, boxIP netip.Addr) netip.Prefix {
	var first netip.Prefix
	for _, r := range ranges {
		if !r.IsValid() || !r.Addr().Is4() {
			continue
		}
		r = r.Masked()
		if boxIP.IsValid() && r.Contains(boxIP) {
			return r
		}
		if !first.IsValid() {
			first = r
		}
	}
	return first
}

// deviceAt is the inventory device (not the box) that has this IP.
func (w *world) deviceAt(ip netip.Addr) *Device {
	if !ip.IsValid() {
		return nil
	}
	for i := range w.devices {
		if d := &w.devices[i]; !d.IsBox && d.IP == ip {
			return d
		}
	}
	return nil
}

// byIP maps an address to the device that has it (INV-8), the box excluded.
func (w *world) byIP(ip string) *Device {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	return w.deviceAt(a)
}

// ipProblem says why the box must not hand this Trap IP address to the host now, "" when it may (INV-5,
// FORBID-1). The state can change after the address was accepted: a device took it, the box got it, the LAN range
// changed.
func (w *world) ipProblem(ip netip.Addr) string {
	switch {
	case !ip.IsValid():
		return "no address"
	case ip == w.box.IP:
		return "this is the address of the Vedette box itself"
	case !w.lan.IsValid():
		return "no LAN range is declared any more"
	case !usable(w.lan, ip):
		return "the address is no longer inside the box's network (" + w.lan.String() + ")"
	case w.deviceAt(ip) != nil:
		return "a device of the inventory has this address"
	}
	return ""
}

func (w *world) usedIPs() map[netip.Addr]bool {
	used := map[netip.Addr]bool{w.box.IP: true}
	for _, d := range w.devices {
		used[d.IP] = true
	}
	for _, d := range w.trapIPs {
		used[d.ip] = true
	}
	return used
}

// ---- overview ----

// Overview is GET /honeypot.
func (s *Service) Overview(ctx context.Context) (Overview, error) {
	w, err := s.load(ctx)
	if err != nil {
		return Overview{}, err
	}
	return s.overview(ctx, w)
}

func (s *Service) overview(ctx context.Context, w *world) (Overview, error) {
	db := s.db.Reader()
	now := s.now()
	weekAgo := store.FormatTS(now.Add(-7 * 24 * time.Hour))
	type agg struct {
		week int
		last string
	}
	per := map[ServiceName]agg{}
	rows, err := db.QueryContext(ctx, `SELECT service, ifnull(sum(ts >= ?), 0), max(ts) FROM hp_hits
		WHERE is_test = 0 AND kind = 'service' AND service IS NOT NULL GROUP BY service`, weekAgo)
	if err != nil {
		return Overview{}, fmt.Errorf("honeypot: count hits: %w", err)
	}
	for rows.Next() {
		var svc, last string
		var a agg
		if err := rows.Scan(&svc, &a.week, &last); err != nil {
			_ = rows.Close()
			return Overview{}, fmt.Errorf("honeypot: count hits: %w", err)
		}
		a.last = last
		per[ServiceName(svc)] = a
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return Overview{}, fmt.Errorf("honeypot: count hits: %w", err)
	}
	hv := s.hostView()
	out := Overview{UpdatedAt: store.FormatTS(now), Traps: make([]Trap, 0, len(Services))}
	if w.lan.IsValid() {
		out.LAN = ptr(w.lan.String())
	}
	out.Box = BoxRef{Name: w.box.Name}
	if w.box.IP.IsValid() {
		out.Box.IP = ptr(w.box.IP.String())
	}
	states := make(map[string]TrapIP, len(w.trapIPs))
	for _, d := range w.trapIPs {
		v := w.withState(d, hv)
		states[d.ID] = v
		out.TrapIPs.Total++
		if d.Enabled {
			out.TrapIPs.Enabled++
		}
		switch {
		case v.State == StateListening:
			out.TrapIPs.Listening++
		case d.Enabled && (v.State == StateFailed || v.State == StateConflict):
			out.TrapIPs.Failing++
		}
	}
	smb, http := w.boxWide()
	if smb != nil {
		out.SMBName = ptr(smb.Name)
	}
	out.HTTPPage = httpPage(http)
	// The traps cannot listen at all (the host, the container): one reason for the page. A Trap IP's own trouble is its reason.
	if ips, _, _ := w.desired(); len(ips) > 0 && !hv.pending && (!hv.available || !hv.running) {
		out.Problem = ptr(reasonOrDefault(hv.reason))
	}
	for _, svc := range Services {
		t := Trap{Service: svc, Port: svc.Port(), TrapIPs: []string{}, Hits7d: per[svc].week, State: StateOff}
		if l := per[svc].last; l != "" {
			t.LastHitAt = ptr(l)
		}
		for _, d := range w.trapIPs {
			if !d.Enabled || !d.has(svc) {
				continue
			}
			t.Enabled = true
			t.TrapIPs = append(t.TrapIPs, d.Name)
			if st := states[d.ID].State; stateRank[st] > stateRank[t.State] {
				t.State = st
			}
		}
		if !t.Enabled && hv.pending && hv.services[svc] {
			t.State = StateStopping // the container still runs with it until the host has been told
		}
		out.Traps = append(out.Traps, t)
	}
	day := s.dayOf(ctx, now)
	from := s.dayOf(ctx, now.AddDate(0, 0, -6))
	if err := db.QueryRowContext(ctx, `SELECT ifnull(sum(count), 0) FROM hp_ignored_day WHERE day >= ? AND day <= ?`, from, day).Scan(&out.Ignored7d); err != nil {
		return Overview{}, fmt.Errorf("honeypot: count ignored: %w", err)
	}
	startToday := store.FormatTS(startOfDay(now.In(s.loc(ctx))))
	if err := db.QueryRowContext(ctx, `SELECT ifnull(sum(ts >= ?), 0), ifnull(sum(ts >= ?), 0) FROM hp_hits WHERE is_test = 0`, startToday, weekAgo).Scan(&out.Summary.Today, &out.Summary.Week); err != nil {
		return Overview{}, fmt.Errorf("honeypot: count hits: %w", err)
	}
	var lastTS, lastIP string
	switch err := db.QueryRowContext(ctx, `SELECT ts, src_ip FROM hp_hits WHERE is_test = 0 ORDER BY ts DESC, id DESC LIMIT 1`).Scan(&lastTS, &lastIP); {
	case err == nil:
		out.Summary.LastHitAt = ptr(lastTS)
		name := lastIP
		if d := w.byIP(lastIP); d != nil {
			name = d.Name
		}
		out.Summary.LastSrc = ptr(name)
	case !errors.Is(err, sql.ErrNoRows):
		return Overview{}, fmt.Errorf("honeypot: last hit: %w", err)
	}
	return out, nil
}

// stateRank orders the states for a service across its Trap IPs: it shows the best one (listening when one listens).
var stateRank = map[string]int{StateOff: 0, StateConflict: 1, StateFailed: 2, StateStopping: 3, StateStarting: 4, StateListening: 5}

// boxWide are the Trap IPs that decide what the whole box shows (D-466 (4)): of those handed to the host, in creation order,
// the first with SMB names the share and the first with HTTP picks the login page. nil when none has it.
func (w *world) boxWide() (smb, http *trapIPRow) {
	ips, _, _ := w.desired()
	for i := range w.trapIPs {
		d := &w.trapIPs[i]
		if !slices.Contains(ips, d.ip) {
			continue
		}
		if smb == nil && d.has(SMB) {
			smb = d
		}
		if http == nil && d.has(HTTP) {
			http = d
		}
	}
	return smb, http
}

// httpPage is the login page the box shows: "nas" when the Trap IP that decides it looks like a NAS.
func httpPage(d *trapIPRow) *string {
	switch {
	case d == nil:
		return nil
	case d.Preset == NAS:
		return ptr("nas")
	}
	return ptr("login")
}

// notConfirmed is the reason shown for an address the host has not confirmed it holds (an unknown outcome: no answer,
// busy); the next Apply asks again.
const notConfirmed = "the host has not confirmed it holds the address yet; the box asks again"

// reasonOrDefault is the reason shown for a trap that is on but cannot listen when the host gave none.
func reasonOrDefault(r string) string {
	if r == "" {
		return "the host gave no reason"
	}
	return r
}

func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func (s *Service) dayOf(ctx context.Context, t time.Time) string {
	return t.In(s.loc(ctx)).Format("2006-01-02")
}
