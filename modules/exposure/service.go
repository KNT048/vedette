package exposure

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
)

// Config is what NewService needs. Publisher, Runner, TwoStep, Gateway, Services, Templates, Web, Greenbone, Probes, Matcher, Outside, Location and Clock may be nil.
type Config struct {
	DB        *store.DB
	Audit     *audit.Log
	Resolver  Resolver         // DNS TXT lookups of domain verification
	Prober    EgressProber     // the three public IP services (PublicServiceProber); tests pass a fake
	Publisher Publisher        // nil: no events
	Runner    Runner           // nil: scanning answers 501 until the scan module registers one
	TwoStep   TwoStep          // nil: nobody has two-step sign-in, so no first scan can record the commitment (D-473)
	Gateway   Gateway          // nil: the page makes no claim about which device answers the open ports (D-492)
	Services  ServiceScanner   // nil: every scan of an IP says service identification is not set up (INV-19)
	Templates TemplateScanner  // nil: every scan of an IP says the safe exploited-vulnerability templates are not set up (INV-23)
	Web       WebScanner       // nil: every scan says the passive web scan (ZAP) is not set up (INV-24)
	Greenbone GreenboneHost    // nil: the setting and every scan of an IP say "Greenbone is not available on this box" (INV-25)
	DataDir   string           // the box data directory: Greenbone's preflight measures the free space of its filesystem (INV-25)
	Probes    ProbeLog         // nil: the template and web steps do not run (nothing is sent without a probe log row, LEGAL §3)
	Matcher   Matcher          // nil: identified services are not compared with exploited CVEs, and the page says so (INV-20)
	Outside   *InternetDB      // nil: "Check what Shodan has seen" answers 501 (INV-21); cmd/vedette wires Shodan InternetDB
	Location  *time.Location   // the day of a snapshot (nil: time.Local)
	Log       *slog.Logger     //
	Clock     func() time.Time // nil: time.Now
}

// Service owns the exp_ tables. Every mutation runs in one transaction with its core_audit row (SYS-3);
// events go out after the commit.
type Service struct {
	cfg Config
	now func() time.Time

	detectMu sync.Mutex // one detection at a time: they probe the network and write the same rows

	mu     sync.RWMutex
	runner Runner

	runMu       sync.Mutex           // guards run, its view, lastScan, lastOutside, off, closed, feedSync and feedSyncAt
	feedSync    bool                 // Greenbone's weekly feed update holds the box's one scan slot (D-564 G6): begin refuses
	feedSyncAt  time.Time            // when that feed update started (the busy answer says it)
	off         bool                 // the module is switched off (ModuleSwitched): begin refuses
	closed      bool                 // the box is shutting down (Close)
	run         *scanRun             // the scan that runs now, or the last one (INV-18); one at a time on the box (D-229): a second one is 409 busy; a restart forgets it
	lastScan    map[string]time.Time // when each target's last scan started (ScanEvery; kept in memory, a restart forgets it)
	lastOutside time.Time            // when the box last asked Shodan (OutsideEvery; kept in memory, a restart forgets it)

	gbOnce sync.Once
	gbs    *gbState // Greenbone's state in memory (INV-25); made by gb()

	bg context.Context // FULL-2 (Trưởng), for Mlee: the service's own context for work the registry's module switch starts (it has none)
}

// NewService returns the service. DB, Audit, Resolver, Prober and Log are required.
func NewService(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Resolver == nil || cfg.Prober == nil || cfg.Log == nil {
		return nil, errors.New("exposure: creating service: DB, Audit, Resolver, Prober and Log are required")
	}
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	return &Service{cfg: cfg, now: now, runner: cfg.Runner, lastScan: map[string]time.Time{}, bg: context.Background()}, nil
}

// SetRunner registers the scanner (the scan module does it at start-up). Nil removes it.
func (s *Service) SetRunner(r Runner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runner = r
}

func (s *Service) scanRunner() Runner {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runner
}

// clock returns the time of a change, in UTC at the precision the database stores.
func (s *Service) clock() time.Time { return s.now().UTC().Truncate(time.Millisecond) }

const publishTimeout = 5 * time.Second

type pending struct {
	name    string
	payload any
}

// write runs fn in a write transaction, then publishes the events fn collected.
func (s *Service) write(ctx context.Context, fn func(tx *sql.Tx, emit func(name string, payload any)) error) error {
	var evs []pending
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		evs = evs[:0]
		return fn(tx, func(name string, payload any) { evs = append(evs, pending{name, payload}) })
	})
	if err != nil {
		return err
	}
	if s.cfg.Publisher == nil || len(evs) == 0 {
		return nil
	}
	// The change is committed: the events go out even if the caller has hung up, within a short deadline.
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), publishTimeout)
	defer cancel()
	for _, e := range evs {
		if err := s.cfg.Publisher.Publish(pctx, events.Event{Name: e.name, Data: e.payload}); err != nil {
			s.cfg.Log.ErrorContext(pctx, "publishing an exposure event failed", "event", e.name, "error", err)
		}
	}
	return nil
}

func (s *Service) audit(ctx context.Context, tx *sql.Tx, user, action, target, detail string) error {
	return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: action, Target: target, Detail: detail})
}

// ---- how a target looks (INV-1, INV-4) ----

// dayText and momentText are the one human date format of every message the API sends: "9 Nov 2026" and "9 Nov 2026, 17:00",
// in the box time zone (never ISO, never "UTC").
func (s *Service) dayText(t time.Time) string { return t.In(s.cfg.Location).Format("2 Jan 2006") }
func (s *Service) momentText(t time.Time) string {
	return t.In(s.cfg.Location).Format("2 Jan 2006, 15:04")
}

// clockSlack is how far into the future a stored time may lie before it is taken as written by a clock that was ahead.
const clockSlack = 5 * time.Minute

// clampTS returns t, or now when t lies more than clockSlack after now: a time written while the clock was ahead (a wrong RTC
// that NTP corrected) must neither keep an IP valid for longer than 30 days nor stop a check from being due.
func clampTS(t, now time.Time) time.Time {
	if t.After(now.Add(clockSlack)) {
		return now
	}
	return t
}

func (t Target) expiresAt(now time.Time) time.Time {
	if t.Kind != KindIP || t.VerifiedAt.IsZero() {
		return time.Time{}
	}
	return clampTS(t.VerifiedAt, now).Add(ValidDays * 24 * time.Hour)
}

// validity of an IP at now; the empty string for a domain or an IP that was never verified.
func (t Target) validity(now time.Time) string {
	exp := t.expiresAt(now)
	switch {
	case exp.IsZero():
		return ""
	case exp.Before(now):
		return validityExpired
	case daysLeft(exp, now) <= ExpiringDays:
		return validityExpiring
	}
	return validityValid
}

func daysLeft(exp, now time.Time) int {
	d := exp.Sub(now)
	n := int(d / (24 * time.Hour))
	if d%(24*time.Hour) > 0 {
		n++
	}
	return n
}

func (t Target) status(now time.Time) string {
	switch {
	case t.VerifiedAt.IsZero():
		return statusUnverified
	case t.validity(now) == validityExpired:
		return statusExpired
	}
	return statusVerified
}

// blocked says why the target cannot be scanned now; empty when it can (INV-1). It judges the stored
// state: the DNS TXT record is looked up again by CheckScannable and Scan, right before a scan.
func (t Target) blocked(now time.Time) BlockedReason {
	switch {
	case t.VerifiedAt.IsZero():
		return BlockedUnverified
	case t.validity(now) == validityExpired:
		return BlockedExpired
	case t.Kind == KindDomain && (t.LastCheck == nil || !t.LastCheck.OK):
		return BlockedTxtMissing
	case !t.Commitment.current():
		return BlockedNoCommitment
	}
	return ""
}

func (s *Service) view(t Target, latest map[string]latestResult, c checks, now time.Time) TargetView {
	v := TargetView{
		ID: t.ID, Kind: t.Kind, Value: t.Value, Status: t.status(now), Token: t.Token,
		LastCheck: t.LastCheck, Commitment: t.Commitment, CreatedAt: store.FormatTS(t.CreatedAt),
	}
	if t.Method != "" {
		m := t.Method
		v.Method = &m
	}
	if !t.VerifiedAt.IsZero() {
		x := store.FormatTS(t.VerifiedAt)
		v.VerifiedAt = &x
	}
	if e := t.expiresAt(now); !e.IsZero() {
		x := store.FormatTS(e)
		v.ExpiresAt = &x
	}
	if val := t.validity(now); val != "" {
		v.Validity = &val
	}
	if !t.Commitment.current() {
		n := noticeFor(t.Value)
		v.CommitmentNotice = &n
	}
	v.Terms, v.TermsNotice, v.FullScan = t.Terms, termsFor(t.Value), t.mode().Full
	b := t.blocked(now)
	if b == "" && t.Kind == KindIP && c.paused(t) {
		b = BlockedNotCurrent // the latest full check did not see this IP (INV-13): the same answer the scan gate gives
	}
	if b != "" {
		v.BlockedReason = &b
	} else {
		v.Scannable = true
	}
	if !t.LastScanAt.IsZero() {
		x := store.FormatTS(t.LastScanAt)
		v.LastScanAt = &x
	}
	if r, ok := latest[t.ID]; ok {
		v.Latest, v.OpenPorts = &r.Counts, r.Ports
		if v.OpenPorts == nil {
			v.OpenPorts = []PortRow{}
		}
	}
	return v
}

// Targets returns every target, oldest first (GET /exposure/targets). The scan module reads the
// scannable ones from here.
func (s *Service) Targets(ctx context.Context) ([]TargetView, error) {
	db := s.cfg.DB.Reader()
	ts, err := listTargets(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("exposure: listing targets: %w", err)
	}
	latest, err := latestResults(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("exposure: listing targets: %w", err)
	}
	c, err := s.loadChecks(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("exposure: listing targets: %w", err)
	}
	out := make([]TargetView, 0, len(ts))
	for _, t := range ts {
		out = append(out, s.view(t, latest, c, c.now))
	}
	return out, nil
}

// Target returns one target, or an error wrapping ErrNotFound.
func (s *Service) Target(ctx context.Context, id string) (TargetView, error) {
	v, err := s.targetView(ctx, s.cfg.DB.Reader(), id)
	if err != nil || v.Kind != KindIP {
		return v, err
	}
	t, err := loadTarget(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: reading target: %w", err)
	}
	if w := s.sharedAddress(ctx, t); w != "" { // D-566 review r1 M2: on the one target page only, not on every list
		v.TermsWarning = &w
	}
	return v, nil
}

func (s *Service) targetView(ctx context.Context, q querier, id string) (TargetView, error) {
	t, err := loadTarget(ctx, q, id)
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: reading target: %w", err)
	}
	latest, err := latestResults(ctx, q)
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: reading target: %w", err)
	}
	c, err := s.loadChecks(ctx, q)
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: reading target: %w", err)
	}
	return s.view(t, latest, c, c.now), nil
}

// ---- adding, deleting, committing ----

func newToken() string {
	b := make([]byte, tokenBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+)
	return hex.EncodeToString(b)
}

// AddDomain adds a domain to prove (POST /exposure/targets, PRE-4). A public IP is never added here (INV-2).
func (s *Service) AddDomain(ctx context.Context, user, raw string) (TargetView, error) {
	value, err := normalizeDomain(raw)
	if err != nil {
		return TargetView{}, err
	}
	var id string
	err = s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		if _, dup, err := loadTargetByValue(ctx, tx, value); err != nil {
			return err
		} else if dup {
			return duplicate(value)
		}
		if n, err := countTargets(ctx, tx); err != nil {
			return err
		} else if n >= MaxTargets {
			return ErrTooMany
		}
		id = store.NewID("xt")
		if err := insertTarget(ctx, tx, Target{ID: id, Kind: KindDomain, Value: value, Token: newToken(), CreatedAt: s.clock()}); err != nil {
			return err
		}
		return s.audit(ctx, tx, user, "exposure.target_add", value, "")
	})
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: adding domain: %w", err)
	}
	return s.Target(ctx, id)
}

// Delete removes a target with its snapshots and its commitment; the audit log stays (INV-7). For an
// IP it is how a customer takes it out of the inventory (INV-11); auto-detect adds it again when the box still uses it.
func (s *Service) Delete(ctx context.Context, user, id string) error {
	return s.Remove(ctx, user, id, false)
}

// Remove is Delete, and with ignore an IP also goes on the Ignored list in the same transaction (DELETE …?ignore=true,
// INV-14): detection never adds it again and nothing scans it, until somebody restores it. Only an IP can be ignored; a
// full list (MaxIgnored) refuses. Both changes are audited as the person.
func (s *Service) Remove(ctx context.Context, user, id string, ignore bool) error {
	err := s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		t, err := loadTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		if ignore {
			if t.Kind != KindIP {
				return ErrOnlyIPCanBeIgnored
			}
			if n, err := countIgnored(ctx, tx); err != nil {
				return err
			} else if n >= MaxIgnored {
				return ErrIgnoredFull
			}
		}
		if err := deleteTarget(ctx, tx, id); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, user, "exposure.target_delete", t.Value, ""); err != nil {
			return err
		}
		if !ignore {
			return nil
		}
		if err := insertIgnored(ctx, tx, t.Value, user, s.clock()); err != nil {
			return err
		}
		return s.audit(ctx, tx, user, "exposure.ip_ignore", t.Value, "removed; detection will not add it again and it will not be scanned")
	})
	if err != nil {
		return fmt.Errorf("exposure: deleting target: %w", err)
	}
	return nil
}

// Ignored returns the Ignored list, newest first (GET /exposure/targets, ignored).
func (s *Service) Ignored(ctx context.Context) ([]IgnoredIP, error) {
	l, err := loadIgnored(ctx, s.cfg.DB.Reader())
	if err != nil {
		return nil, fmt.Errorf("exposure: reading the ignored list: %w", err)
	}
	return l, nil
}

// Restore takes an IP off the Ignored list (DELETE /exposure/box-ip/ignored/{ip}, INV-14). It only lets detection add the
// IP again: nothing is added here, and the list never allows anything (D-25), so a restored IP that the box sees comes back
// as a new target that needs its commitment. ip must be a canonical IPv4 address (400 bad_value); one that is not on the
// list is 404.
func (s *Service) Restore(ctx context.Context, user, ip string) error {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() || a.String() != ip {
		return fmt.Errorf("exposure: restoring an ignored IP: %w", ErrBadIP)
	}
	err = s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		ok, err := deleteIgnored(ctx, tx, ip)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotIgnored
		}
		return s.audit(ctx, tx, user, "exposure.ip_restore", ip, "detection may add it again")
	})
	if err != nil {
		return fmt.Errorf("exposure: restoring an ignored IP: %w", err)
	}
	return nil
}
