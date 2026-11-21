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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/store"
)

// Config is what NewService needs. IPFetch, Publisher, Runner, TwoStep, Gateway, Appliances, Services, Templates, Web, Greenbone, DomainFence, Probes, Matcher, Outside, Location and Clock may be nil.
type Config struct {
	DB        *store.DB
	Schedules SchedulePort // keeps the public IP detection's schedule in step with the box-ip form; nil: that form cannot be saved
	Audit     *audit.Log
	Resolver  Resolver     // DNS TXT lookups of domain verification
	Prober    EgressProber // the three public IP services (PublicServiceProber); tests pass a fake
	Publisher Publisher    // nil: no events
	Runner    Runner       // nil: scanning answers 501 until the scan module registers one
	TwoStep   TwoStep      // nil: nobody has two-step sign-in, so no first scan can record the commitment
	Gateway   Gateway      // nil: the page makes no claim about which device answers the open ports
	// Appliances nil: an appliance a port names (appliance.go) is not tied to inventory devices; its Devices stay null.
	Appliances Appliances
	Services   ServiceScanner  // nil: every scan of an IP says service identification is not set up (INV-19)
	Templates  TemplateScanner // nil: every scan of an IP says the safe exploited-vulnerability templates are not set up (INV-23)
	Web        WebScanner      // nil: every scan says the passive web scan (ZAP) is not set up (INV-24)
	Greenbone  GreenboneHost   // nil: the setting and every scan of an IP say NotAvailableGreenbone, "OpenVAS is not available on this box." (INV-25)
	// DomainFence nil: a domain's deep scan reaches only the box's own verified IP; every other public address of its names
	// gets a "needs the domain fence" line and nothing more than the by-name checks.
	DomainFence DomainFence
	// IPFetch gets the proof file of a typed IP (INV-35); nil: the real one (no proxy, no redirect off the IP, a capped body).
	IPFetch IPFetcher
	DataDir string      // the box data directory: Greenbone's preflight measures the free space of its filesystem (INV-25)
	Probes  ProbeLog    // nil: the template and web steps do not run (nothing is sent without a probe log row, LEGAL §3)
	Matcher Matcher     // nil: identified services are not compared with exploited CVEs, and the page says so (INV-20)
	Outside *InternetDB // nil: "Check what Shodan has seen" answers 501 (INV-21); cmd/vedette wires Shodan InternetDB
	Safety  ScanSafety  // nil: the module's own rates and no exclusion; cmd/vedette wires the scan module's shared safety block (INV-31, #850)
	// Window nil: scheduled scans may start at any time; cmd/vedette wires the scan window of the shared safety block (INV-36).
	Window ScanWindow
	// Alert sends what a scheduled scan found new to the alert channels (INV-36); nil: nothing is sent. cmd/vedette wires notify's
	// system notice path.
	Alert    func(ctx context.Context, a Alert) error
	Location *time.Location // the day of a snapshot and the times of messages when Zone gives none (nil: time.Local)
	// Zone is the organization's time zone, read at every use (a change applies at once); nil, or a nil answer, is Location. The day of
	// a snapshot is a day of the customer's calendar: two scans of one local day are one snapshot, never two that read as the same day.
	Zone  func(ctx context.Context) *time.Location
	Log   *slog.Logger     //
	Clock func() time.Time // nil: time.Now
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
	feedSync    bool                 // Greenbone's weekly feed update holds the box's one scan slot: begin refuses
	feedSyncAt  time.Time            // when that feed update started (the busy answer says it)
	off         bool                 // the module is switched off (ModuleSwitched): begin refuses
	closed      bool                 // the box is shutting down (Close)
	run         *scanRun             // the scan that runs now, or the last one (INV-18); one at a time on the box: a second one is 409 busy; a restart forgets it
	lastScan    map[string]time.Time // when each target's last scan started (ScanEvery; kept in memory, a restart forgets it)
	lastOutside time.Time            // when the box last asked Shodan (OutsideEvery; kept in memory, a restart forgets it)
	queue       []*queuedScan        // INV-36: the scans that wait for the one that runs, in order (in memory, a restart forgets it)
	dispatching bool                 // the checks of the first queued scan run now (startQueued)

	checkMu    sync.Mutex           // guards lastCheck
	lastCheck  map[string]time.Time // when each domain target's ownership was last checked by a person (DomainCheckEvery; in memory, a restart forgets it)
	bucketFull time.Time            // the box-wide bound of those checks: when the bucket would be full again (zero: it is), guarded by checkMu

	liveMu   sync.Mutex
	ipListed map[string]bool      // typed IPs the host listed for the executors in this run, guarded by liveMu
	live     map[string]liveEntry // the last live result of each typed IP's proof (liveFor), guarded by liveMu

	gbOnce sync.Once
	gbs    *gbState // Greenbone's state in memory (INV-25); made by gb()

	bg context.Context // the service's own context for work the registry's module switch starts (it has none)

	appliances applianceCache // the inventory's last answer about the appliance families (INV-33)

	spawn func(func()) // starts the checks of a queued scan in the background (tests run them in place)
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
	return &Service{cfg: cfg, now: now, runner: cfg.Runner, lastScan: map[string]time.Time{}, lastCheck: map[string]time.Time{}, live: map[string]liveEntry{}, ipListed: map[string]bool{}, bg: context.Background(),
		spawn: func(f func()) { go f() }}, nil
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
// in the organization's time zone (loc; never ISO, never "UTC").
func (s *Service) dayText(t time.Time) string { return orgtime.Day(t, s.loc()) }
func (s *Service) momentText(t time.Time) string {
	return orgtime.Stamp(t, s.loc())
}

// loc is the time zone of a snapshot's day and of the API's messages: the organization's (Zone, read on the Service's own context,
// so a caller that hangs up never changes a snapshot's day), else Location.
func (s *Service) loc() *time.Location {
	if s.cfg.Zone != nil {
		if l := s.cfg.Zone(s.bg); l != nil {
			return l
		}
	}
	return s.cfg.Location
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
	case t.Typed && (t.LastCheck == nil || !t.LastCheck.OK):
		return BlockedProofMissing
	case !t.Commitment.current():
		return BlockedNoCommitment
	}
	return ""
}

func (s *Service) view(t Target, all []Target, latest map[string]latestResult, c checks, now time.Time) TargetView {
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
		n := noticeOf(t)
		v.CommitmentNotice = &n
	}
	v.Terms, v.TermsNotice, v.FullScan = t.Terms, termsOf(t), t.mode().Full
	v.Proof = proofHint(t, all)
	v.Origin = "person"
	if t.Kind == KindIP && !t.Typed {
		v.Origin = "box"
	}
	v.IPProof = ipProofHintOf(t, all)
	if n := t.ipNext(now); !n.IsZero() {
		x := store.FormatTS(n)
		v.NextCheckAt = &x
	}
	b := t.blocked(now)
	if b == "" && t.Kind == KindIP && !t.Typed && c.paused(t) {
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
		v.Latest, v.OpenPorts, v.LastScanFinishedAt = &r.Counts, r.Ports, r.FinishedAt
		if v.OpenPorts == nil {
			v.OpenPorts = []PortRow{}
		}
		v.OpenExposures = r.Counts.Ports
	}
	v.ScanState = s.scanState(t, v)
	return v
}

// scanState says where a target stands for scanning (TargetView.scan_state): scanning while a scan of it runs, then why it cannot be
// scanned (unproved: no proof now, expired: its 30 days ran out, paused: the box no longer goes out through the IP, needs_terms: the
// scan confirmation is missing), else ready.
func (s *Service) scanState(t Target, v TargetView) string {
	s.runMu.Lock()
	running := s.run != nil && s.run.view.TargetID == t.ID && s.run.view.Status == RunRunning
	queued := s.queuedLocked(t.ID)
	s.runMu.Unlock()
	switch {
	case running:
		return "scanning"
	case queued:
		return "queued"
	case v.BlockedReason == nil:
		return "ready"
	}
	switch *v.BlockedReason {
	case BlockedExpired:
		return "expired"
	case BlockedNotCurrent:
		return "paused"
	case BlockedNoCommitment:
		return "needs_terms"
	}
	return "unproved"
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
	s.tieLatest(ctx, latest)
	c, err := s.loadChecks(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("exposure: listing targets: %w", err)
	}
	out := make([]TargetView, 0, len(ts))
	for _, t := range ts {
		out = append(out, s.view(t, ts, latest, c, c.now))
	}
	if err := s.scheduleViews(ctx, db, ts, out, c); err != nil {
		return nil, fmt.Errorf("exposure: listing targets: %w", err)
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
	if w := s.sharedAddress(ctx, t); w != "" { // On the one target page only, not on every list
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
	if r, ok := latest[id]; ok {
		s.tieAppliances(ctx, r.Ports, nil)
	}
	c, err := s.loadChecks(ctx, q)
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: reading target: %w", err)
	}
	all, err := listTargets(ctx, q)
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: reading target: %w", err)
	}
	out := []TargetView{s.view(t, all, latest, c, c.now)}
	if err := s.scheduleViews(ctx, q, []Target{t}, out, c); err != nil {
		return TargetView{}, fmt.Errorf("exposure: reading target: %w", err)
	}
	return out[0], nil
}

// ---- adding, deleting, committing ----

func newToken() string {
	b := make([]byte, tokenBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+)
	return hex.EncodeToString(b)
}

// domainToken is the TXT token a new domain gets and whether it came from the host (fromHost: the host
// listed the domain, so a failed add must give the slot back). With a DomainFence: the box-bound token, so the executors' fence can
// derive it themselves and the domain's deep scan of addresses that are not the box's can run; the host's own refusal (its cap) and a
// transient error (busy, no answer: ErrFenceDown, "try again") are answered as they are; any other failure (an older host without the
// op, a damaged key or list) falls back to a random token, logged with the reason: the domain is added and verified as
// on a container-only install, its passive scan works on any verified token, and its deep steps to addresses that are not the box's
// say they need the box-bound TXT value. Without a fence (a container-only install) a random one, as before.
func (s *Service) domainToken(ctx context.Context, domain string) (tok string, fromHost bool, err error) {
	if s.cfg.DomainFence == nil {
		return newToken(), false, nil
	}
	tok, err = s.cfg.DomainFence.Token(ctx, domain)
	var ae *APIError
	switch {
	case errors.As(err, &ae):
		return "", false, err
	case err == nil && fenceTokenRE.MatchString(tok):
		return tok, true, nil
	}
	s.cfg.Log.ErrorContext(ctx, "exposure: the domain fence gave no token; the domain gets a random one, so its deep scan of addresses that are not the box's needs the box fixed", "domain", domain, "error", err)
	return newToken(), false, nil
}

// DomainFenceForget is implemented by a DomainFence that can give a domain's slot back to the host (exposure.token_forget):
// a deleted domain target, or an add that failed after the host issued the token.
type DomainFenceForget interface {
	Forget(ctx context.Context, domain string) error
}

// forgetDomain gives domain's slot back to the host, best effort (logged: the slot stays taken until the next delete of it).
func (s *Service) forgetDomain(ctx context.Context, domain string) {
	f, ok := s.cfg.DomainFence.(DomainFenceForget)
	if !ok {
		return
	}
	if err := f.Forget(context.WithoutCancel(ctx), domain); err != nil {
		s.cfg.Log.ErrorContext(ctx, "exposure: the host did not give the domain's fence slot back", "domain", domain, "error", err)
	}
}

// addChecks are AddDomain's checks of the list (a duplicate, the cap of targets), run once in a read before the host is asked for a
// token, so a doomed add takes no host slot, and again in the write.
func addChecks(ctx context.Context, q querier, value string) error {
	if _, dup, err := loadTargetByValue(ctx, q, value); err != nil {
		return err
	} else if dup {
		return duplicate(value)
	}
	if n, err := countTargets(ctx, q); err != nil {
		return err
	} else if n >= MaxTargets {
		return ErrTooMany
	}
	return nil
}

// AddTarget adds a target to prove (POST /exposure/targets, PRE-4): a domain, or a public IP typed in (INV-35). An empty kind is
// taken from the value: an IPv4 address is an IP, anything else a domain. A typed IP is accepted into the list at once and is never
// scanned until it is proved (token file or reverse DNS); the box does not look for the proof here, the person places it first.
func (s *Service) AddTarget(ctx context.Context, user string, kind Kind, raw string) (TargetView, error) {
	if kind == "" {
		kind = KindDomain
		if a, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil && a.Is4() {
			kind = KindIP
		}
	}
	switch kind {
	case KindDomain:
		return s.AddDomain(ctx, user, raw)
	case KindIP:
		return s.addIP(ctx, user, raw)
	}
	return TargetView{}, ErrKind
}

func (s *Service) addIP(ctx context.Context, user, raw string) (TargetView, error) {
	value, err := normalizeIP(raw)
	if err != nil {
		return TargetView{}, err
	}
	if err := addChecks(ctx, s.cfg.DB.Reader(), value); err != nil {
		return TargetView{}, fmt.Errorf("exposure: adding public IP: %w", err)
	}
	// With a domain fence the IP's token is the one the host binds to this box for the address (listed like a domain), so the executors
	// derive it themselves and check the IP's own proof; without one it is random and the deep steps say they need the fence.
	token, fromHost, err := s.domainToken(ctx, value)
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: adding public IP: %w", err)
	}
	var id string
	dupNow := false
	err = s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		if err := addChecks(ctx, tx, value); err != nil {
			var ae *APIError
			dupNow = errors.As(err, &ae) && ae.Code == "duplicate"
			return err
		}
		if ign, err := ignoredSet(ctx, tx); err != nil {
			return err
		} else if ign[value] {
			return apiErr(400, "bad_value", "%s is on your Ignored list. Restore it in Settings first.", value)
		}
		id = store.NewID("xt")
		if err := insertTarget(ctx, tx, Target{ID: id, Kind: KindIP, Typed: true, Value: value, Token: token, CreatedAt: s.clock()}); err != nil {
			return err
		}
		return s.audit(ctx, tx, user, "exposure.target_add", value, "public IP, typed in; not scanned until proved")
	})
	if err != nil {
		if fromHost && !dupNow {
			s.forgetDomain(ctx, value)
		}
		return TargetView{}, fmt.Errorf("exposure: adding public IP: %w", err)
	}
	return s.Target(ctx, id)
}

// AddDomain adds a domain to prove (PRE-4); AddTarget is the entry of the API.
func (s *Service) AddDomain(ctx context.Context, user, raw string) (TargetView, error) {
	value, err := normalizeDomain(raw)
	if err != nil {
		return TargetView{}, err
	}
	if err := addChecks(ctx, s.cfg.DB.Reader(), value); err != nil {
		return TargetView{}, fmt.Errorf("exposure: adding domain: %w", err)
	}
	token, fromHost, err := s.domainToken(ctx, value)
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: adding domain: %w", err)
	}
	var id string
	dupNow := false
	err = s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		if err := addChecks(ctx, tx, value); err != nil {
			var ae *APIError
			dupNow = errors.As(err, &ae) && ae.Code == "duplicate"
			return err
		}
		id = store.NewID("xt")
		if err := insertTarget(ctx, tx, Target{ID: id, Kind: KindDomain, Value: value, Token: token, CreatedAt: s.clock()}); err != nil {
			return err
		}
		return s.audit(ctx, tx, user, "exposure.target_add", value, "")
	})
	if err != nil {
		if fromHost && !dupNow { // a failed add never takes a slot (a target added meanwhile keeps its own)
			s.forgetDomain(ctx, value)
		}
		return TargetView{}, fmt.Errorf("exposure: adding domain: %w", err)
	}
	s.coverAdded(ctx, user, id, value)
	return s.Target(ctx, id)
}

// coverAdded checks a name just added when the proof of another target of the box already covers it (reuseCands): the person put no
// record for it and is asked for none. The check looks the record up again (DNS only); if it is gone the target stays unverified with the
// usual explanation. It is the box's own check, not an attempt of a person, and never fails the add.
func (s *Service) coverAdded(ctx context.Context, user, id, value string) {
	all, err := listTargets(ctx, s.cfg.DB.Reader())
	if err == nil {
		// Only a lookup is saved here, never a decision: the record decides at the check. A name no target of the box that was ever
		// verified could cover is left for the person's own check.
		t := Target{ID: id, Kind: KindDomain, Value: value}
		maybe := func(o Target) bool { return o.Kind == KindDomain && !o.VerifiedAt.IsZero() }
		if slices.ContainsFunc(reuseCands(t, proofChain(value), all), func(c candidate) bool { return maybe(c.t) }) ||
			slices.ContainsFunc(all, func(o Target) bool { return o.ID != id && maybe(o) && under(value, o.Value) }) {
			_, err = s.verify(ctx, user, id, false)
		}
	}
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: checking a name an earlier proof covers", "domain", value, "error", err)
	}
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
	var kind Kind
	var value string
	typed := false
	err := s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		t, err := loadTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		kind, value, typed = t.Kind, t.Value, t.Typed
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
		// INV-30: Settings › Scanning no longer names the target as an engine's last run (#863 r1 L4)
		if _, err := tx.ExecContext(ctx, `DELETE FROM exp_engine_run WHERE target = ?`, t.Value); err != nil {
			return fmt.Errorf("exposure: removing the target's engine runs: %w", err)
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
	if kind == KindDomain || typed { // the deleted domain's (or typed IP's) fence slot goes back to the host
		if typed {
			s.liveMu.Lock()
			delete(s.ipListed, value)
			s.liveMu.Unlock()
		}
		s.forgetDomain(ctx, value)
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
// IP again: nothing is added here, and the list never allows anything, so a restored IP that the box sees comes back
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
