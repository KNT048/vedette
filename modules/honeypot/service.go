package honeypot

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
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
	pollMu     sync.Mutex // one Poll at a time
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

// Kick asks the run loop to apply the state to the host soon (a device appeared, a setting changed).
func (s *Service) Kick() {
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

type configRow struct {
	SecondaryIP string `json:"secondary_ip"`
	Hostname    string `json:"hostname"`
}

func (c configRow) has() bool { return c.SecondaryIP != "" }

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

type trapRow struct {
	enabled bool
	since   *string
}

func loadTraps(ctx context.Context, q querier) (map[ServiceName]trapRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT service, enabled, since FROM hp_trap`)
	if err != nil {
		return nil, fmt.Errorf("honeypot: read traps: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[ServiceName]trapRow{}
	for rows.Next() {
		var svc string
		var en bool
		var since sql.NullString
		if err := rows.Scan(&svc, &en, &since); err != nil {
			return nil, fmt.Errorf("honeypot: read traps: %w", err)
		}
		t := trapRow{enabled: en}
		if since.Valid {
			t.since = ptr(since.String)
		}
		out[ServiceName(svc)] = t
	}
	return out, rows.Err()
}

type decoyRow struct {
	Decoy
	ip netip.Addr
}

func loadDecoys(ctx context.Context, q querier) ([]decoyRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, personality, name, ip, enabled, created_at FROM hp_decoys ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("honeypot: read decoys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []decoyRow
	for rows.Next() {
		var d decoyRow
		if err := rows.Scan(&d.ID, &d.Personality, &d.Name, &d.IP, &d.Enabled, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("honeypot: read decoys: %w", err)
		}
		d.ip, _ = netip.ParseAddr(d.IP)
		d.Services = personalityServices(d.Personality)
		out = append(out, d)
	}
	return out, rows.Err()
}

// world is everything a decision reads: the module's own tables and the inventory.
type world struct {
	cfg     configRow
	secIP   netip.Addr
	traps   map[ServiceName]trapRow
	decoys  []decoyRow
	devices []Device
	lan     netip.Prefix // zero when no IPv4 range is declared
	box     Box
}

func (s *Service) load(ctx context.Context) (*world, error) {
	w := &world{}
	db := s.db.Reader()
	if err := loadJSON(ctx, db, "config", &w.cfg); err != nil {
		return nil, err
	}
	w.secIP, _ = netip.ParseAddr(w.cfg.SecondaryIP)
	var err error
	if w.traps, err = loadTraps(ctx, db); err != nil {
		return nil, err
	}
	if w.decoys, err = loadDecoys(ctx, db); err != nil {
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

// ipProblem says why the box must not hand this secondary or decoy address to the host now, "" when it may (INV-5,
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
	used := map[netip.Addr]bool{w.secIP: true, w.box.IP: true}
	for _, d := range w.devices {
		used[d.IP] = true
	}
	for _, d := range w.decoys {
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
	conflict := w.deviceAt(w.secIP)
	secConflict := w.secIP.IsValid() && (w.ipProblem(w.secIP) != "" || s.refused(w.secIP) != "")
	out := Overview{Hostname: w.cfg.Hostname, UpdatedAt: store.FormatTS(now), Traps: make([]Trap, 0, len(Services))}
	if w.secIP.IsValid() {
		out.SecondaryIP = ptr(w.secIP.String())
	}
	if w.lan.IsValid() {
		out.LAN = ptr(w.lan.String())
	}
	out.Box = BoxRef{Name: w.box.Name}
	if w.box.IP.IsValid() {
		out.Box.IP = ptr(w.box.IP.String())
	}
	if conflict != nil {
		out.ConflictAsset = &AssetRef{ID: conflict.ID, Name: conflict.Name}
	}
	for _, svc := range Services {
		tr := w.traps[svc]
		t := Trap{Service: svc, Port: svc.Port(), Enabled: tr.enabled, Since: tr.since, Hits7d: per[svc].week}
		if l := per[svc].last; l != "" {
			t.LastHitAt = ptr(l)
		}
		switch {
		case !tr.enabled:
			t.State = StateOff
		case secConflict:
			t.State = StateConflict
		case s.listening(svc):
			t.State = StateListening
		default:
			t.State = StateOff
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

func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func (s *Service) dayOf(ctx context.Context, t time.Time) string {
	return t.In(s.loc(ctx)).Format("2006-01-02")
}
