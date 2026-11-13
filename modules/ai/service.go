package ai

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/ai/provider"
)

// ModuleID is the id of this module in the registry.
const ModuleID = "ai"

// secretPurpose is the core_secret purpose of an API key (DATA_MODEL 5.7).
const secretPurpose = "ai_profile.api_key"

// MaxProfiles is how many AI profiles a box holds.
const MaxProfiles = 12

// Settings are the shared token settings (`ai_setting` key config, INV-4).
type Settings struct {
	Tier          Tier `json:"tier"`
	MonthlyBudget int  `json:"monthly_budget"`
	RedactPII     bool `json:"redact_pii"`
}

// hookTimeout is the time one after_ai pass or one hook test may take.
func (s *Service) hookTimeout() time.Duration {
	if s.cfg.HookTimeout > 0 {
		return s.cfg.HookTimeout
	}
	return 5 * time.Second
}

// DefaultSettings is what a fresh box starts with. The budget is 6,000,000 tokens a month (D-531: the 200,000 a day of D-482 times 30):
// a few dollars with a Haiku-class model, and no single day of an incident is cut short by a daily cap.
func DefaultSettings() Settings {
	return Settings{Tier: TierMed, MonthlyBudget: DefaultMonthlyBudget, RedactPII: true}
}

func (s Settings) validate() error {
	if !s.Tier.Valid() {
		return perr("invalid_tier", "Pick a tier: minimum, medium or maximum.")
	}
	if !ValidMonthlyBudget(s.MonthlyBudget) {
		return perr("invalid_cap", "The monthly AI budget must be a whole number of tokens from %d to %d.", MinMonthlyBudget, MaxMonthlyBudget)
	}
	return nil
}

// Config wires a Service. DB, Secrets and Audit are required.
type Config struct {
	DB      *store.DB
	Secrets *secrets.Store
	Audit   *audit.Log
	Log     *slog.Logger

	Clock func() time.Time // nil = time.Now
	// Zone returns the IANA name of the box time zone (core_org.timezone). The meter reads it once when the service starts: a
	// change of zone applies after a restart. nil or empty or unknown = DefaultTimeZone.
	Zone func(context.Context) string
	// Factory builds the client of a profile; nil = Profile.Provider with BoxAddrs. Tests inject fakes: no test calls a real provider.
	Factory func(Profile) (provider.Provider, error)
	// BoxAddrs is the machine's addresses (vedette-host, the container's gateway): no profile reaches Vedette's own ports there, at
	// save and at every connection (D-446; loopback and core's own interfaces are refused on every port). known=false or nil:
	// those ports are refused on every address.
	BoxAddrs func() (addrs []netip.Addr, known bool)
	// SelfAddrs lists more addresses that are Vedette itself (the honeypot's decoys): no profile there on any port (D-446). nil: none.
	SelfAddrs func() []netip.Addr
	// Facts is what the box knows about a CVE and the devices it matches (feeds, findings, inventory), read through the ports of
	// those modules. nil = explaining a CVE answers 409 ai_unavailable.
	Facts Facts
	// Modules says whether the ai module is on (the module registry); nil = on. It is asked by the doors other modules use.
	Modules interface{ Enabled(id string) bool }
	// ChainPruner moves the anchor and the head of a hash chain when old rows are removed, in the caller's transaction. Core owns those
	// tables (core_chain_anchor, core_chain_head) and offers the helper (chainhead.Prune, issue #194); until then it is nil and
	// the retention prune is off: the setting is saved, nothing is removed.
	ChainPruner ChainPruner
	// Data is what the read tools of "Ask your data" search (inventory, findings, feeds); nil = those tools are not offered.
	Data Data
	// Conns lists and calls the read tools of the connections (core/conn/read); nil = no connection tools.
	Conns ConnReader
	// ConnTargets returns the address of each connection by id (core/conn List). While the privacy rule is on, only the tools of a
	// connection whose address is inside the network are offered; nil = none are (fail closed, D-212).
	ConnTargets func(ctx context.Context) (map[string]string, error)
	// LogDigest reads the digest of the logs (kinds of line, counts, spikes, bad connections, never a line); the bool is false while the
	// logs module is off. nil = the log digest answers 409 ai_unavailable. The adapter is in cmd/vedette; ai never imports logs.
	LogDigest func(ctx context.Context) (LogDigestData, bool, error)
	// LogAround reads what the logs counted about one address from from to to (kinds of line and counts, connections to listed
	// destinations, never a line; D-223): the events_around tool of log investigation. The bool is false while the logs module is off.
	// nil = the tool is not offered.
	LogAround func(ctx context.Context, ip netip.Addr, from, to time.Time) (LogAroundData, bool, error)
	// Alert raises an incident notice (notify: every enabled channel whose minimum severity it meets). The daily verify of the
	// activity log calls it when the chain is broken (S-AI-8, D-430), the budget watch at 80 % and 100 % of a monthly budget (D-531); high
	// = severity high, otherwise medium. nil = neither job is offered. The adapter is in cmd/vedette.
	Alert func(ctx context.Context, id, title, text string, high bool) error
	// AskTimeout bounds one question in all: every model turn and every tool call. 0 = 2 minutes. Tests set a tiny one.
	AskTimeout time.Duration
	// HookTimeout bounds the after_ai hooks of one call and one hook test. 0 = 5 seconds. Tests set a tiny one to run out of time.
	HookTimeout time.Duration
}

// stored is a profile as the service holds it: the library profile (with its key opened) and the id of its sealed key.
type stored struct {
	Profile
	secretID string
	lastTest *LastTest // the last connection test of the profile as saved; nil = not tested since it was added or its connection changed
}

// snapshot is one immutable generation of the saved settings. A change builds the next one, writes it, then swaps it in.
type snapshot struct {
	profiles []stored // creation order
	assign   Assignments
	cfg      Settings
}

func (sn *snapshot) find(id string) (stored, bool) {
	for _, p := range sn.profiles {
		if p.ID == id {
			return p, true
		}
	}
	return stored{}, false
}

func (sn *snapshot) libProfiles() []Profile {
	out := make([]Profile, len(sn.profiles))
	for i, p := range sn.profiles {
		out[i] = p.Profile
	}
	return out
}

func (sn *snapshot) byID() map[string]Profile {
	m := make(map[string]Profile, len(sn.profiles))
	for _, p := range sn.profiles {
		m[p.ID] = p.Profile
	}
	return m
}

// check is the rule set of the router applied before anything is written: a state that fails here is never saved.
func (sn *snapshot) check() error {
	for _, p := range sn.profiles {
		if err := p.Validate(); err != nil {
			return err
		}
	}
	return sn.assign.Validate(sn.byID())
}

func cloneAssign(a Assignments) Assignments {
	out := Assignments{InternalOnly: a.InternalOnly, Jobs: make(map[Job]Slot, len(Jobs()))}
	maps.Copy(out.Jobs, a.Jobs)
	return out
}

// Service holds the saved AI settings (profiles, keys, assignments, token settings) and the router and meter built from them.
// Every change is validated against the router's rules first, then written with its audit row in one transaction, and only then
// handed to the router, so the router never runs a state the rules forbid (INV-3).
type Service struct {
	modelsMu   sync.Mutex             // guards modelsAt (the rate limit of ListModels)
	modelsAt   map[string][]time.Time // per admin: when the last model-list calls started
	cfg        Config
	router     *Router
	meter      *Meter
	loc        *time.Location                  // the box time zone: the day of the meter and of "today" in the usage view
	harness    atomic.Pointer[harness]         // the rules, the hooks and the switches of the built-in hooks in force (slice 4a)
	skillsOff  atomic.Pointer[map[string]bool] // the skills switched off (slice 4b); never nil after New
	degraded   string                          // why the saved settings could not be loaded; "" = loaded
	mu         sync.Mutex                      // serialises changes
	testSlot   chan struct{}                   // one place: a hook test runs while it holds it, so tests cannot pile up work
	indexSlot  chan struct{}                   // one place: the documents of the knowledge base are read one at a time (slice 4c)
	digestSlot chan struct{}                   // one place: a log digest is made by one caller at a time, the next one finds it stored (no tokens twice)
	queued     atomic.Int64                    // uploads that hold their bytes in memory until they are read
	indexing   sync.WaitGroup                  // the readers in flight: a test waits for them
	snap       atomic.Pointer[snapshot]
	drafts     map[string]draftTest   // per admin, the last test of settings not saved yet, kept for the profile saved with them (D-445); under mu
	alerted    atomic.Pointer[string] // the break the last alert named (its first bad row, or "tail"): the same break is not raised again until a restart
	news       *newsFetcher           // the box's own fetcher of public pages for CVE news (S-AI-3)
	fuseMu     sync.Mutex             // guards fuse
	fuse       map[Job]*fuseWindow    // calls of each job in the current minute (the runaway fuse, D-531)
	pauseMonth string                 // the month the reasons in pauseNoted belong to (fuseMu)
	pauseNoted map[string]bool        // the reasons of scheduled-job stops already logged this month (fuseMu): one line a month per reason
}

// New loads the settings and builds the router and the meter. A saved state that the rules refuse is an error: the service does
// not start with it (fail closed).
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Secrets == nil || cfg.Audit == nil {
		return nil, errors.New("ai: service needs DB, Secrets and Audit")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	zone := ""
	if cfg.Zone != nil {
		zone = cfg.Zone(ctx)
	}
	loc, err := LoadLocation(zone)
	if err != nil {
		cfg.Log.WarnContext(ctx, "ai: unknown time zone; using the default", "zone", zone)
		if loc, err = LoadLocation(""); err != nil {
			return nil, err
		}
	}
	// Until the saved harness is loaded (and if it cannot be): no custom rules or hooks, every built-in hook on.
	h0, err := newHarness(nil, nil, nil)
	if err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, loc: loc, testSlot: make(chan struct{}, 1), indexSlot: make(chan struct{}, 1), digestSlot: make(chan struct{}, 1), news: newNewsFetcher(cfg.Clock)}
	s.harness.Store(h0)
	none := map[string]bool{}
	s.skillsOff.Store(&none)
	sn, err := s.load(ctx)
	if err == nil {
		err = s.build(sn, loc)
	}
	if err == nil {
		var h *harness
		if h, err = s.loadHarness(ctx); err == nil {
			s.harness.Store(h)
			if !sn.cfg.RedactPII && h.builtin[HookBlockPII] {
				// Before the switch existed, redact_pii=false was saved but nothing enforced it, so migration 0003 starts the switch on.
				cfg.Log.InfoContext(ctx, "ai: the saved redact_pii setting is off, but it was never enforced before; Block personal data is on. Turn it off in Settings, AI assistant, if you want that")
			}
		} else {
			err = fmt.Errorf("load rules and hooks: %w", err)
		}
	}
	if err == nil {
		var off map[string]bool
		if off, err = s.loadSkills(ctx); err == nil {
			s.skillsOff.Store(&off)
		}
	}
	if err == nil {
		// today's usage comes back from ai_activity, so the level in force and the caps survive a restart (INV-4)
		if err = s.seedMeter(ctx); err != nil {
			err = fmt.Errorf("load today's usage: %w", err)
		}
	}
	if err != nil {
		// A saved state that cannot be loaded (a key that cannot be opened, a profile that a newer rule refuses) must not stop the
		// box from starting: the AI module starts with no profiles, says so in the log, reports itself as degraded, and refuses
		// every change, so the rows that could not be read are not overwritten blind.
		s.degraded = err.Error()
		cfg.Log.ErrorContext(ctx, "ai: the saved AI settings could not be loaded; the module starts without profiles and refuses changes until this is fixed", "error", err)
		empty := &snapshot{cfg: DefaultSettings(), assign: Assignments{Jobs: make(map[Job]Slot, len(Jobs()))}}
		if err := s.build(empty, loc); err != nil {
			return nil, err
		}
	}
	if err := s.checkFTS(ctx); err != nil {
		cfg.Log.WarnContext(ctx, "ai: could not check the knowledge index", "error", err)
	}
	if err := s.recoverKnowledge(ctx); err != nil {
		cfg.Log.WarnContext(ctx, "ai: could not end the documents a restart cut off; they stay unfinished until the next start", "error", err)
	}
	return s, nil
}

// own is where the D-446 rule reads the addresses of Vedette itself.
func (s *Service) own() provider.OwnSources {
	return provider.OwnSources{Machine: s.cfg.BoxAddrs, Self: s.cfg.SelfAddrs}
}

// build makes the meter and the router of a snapshot and publishes it.
func (s *Service) build(sn *snapshot, loc *time.Location) error {
	meter, err := NewMeter(MeterConfig{Clock: s.cfg.Clock, Location: loc, GlobalCap: sn.cfg.MonthlyBudget, Tier: sn.cfg.Tier})
	if err != nil {
		return err
	}
	factory := s.cfg.Factory
	if factory == nil {
		factory = func(p Profile) (provider.Provider, error) { return p.provider(s.own()) }
	}
	router, err := NewRouter(RouterConfig{Profiles: sn.libProfiles(), Assignments: sn.assign, Meter: meter, Factory: factory})
	if err != nil {
		return fmt.Errorf("saved settings: %w", err)
	}
	s.meter, s.router = meter, router
	s.snap.Store(sn)
	return nil
}

// Degraded is empty when the saved settings were loaded. Otherwise it says why they were not (no secret in it), and the service has
// no profiles and refuses every change.
func (s *Service) Degraded() string { return s.degraded }

func (s *Service) errDegraded() error {
	return apierr.New(http.StatusConflict, "ai_unavailable", "The saved AI settings could not be loaded, so nothing can be changed until that is fixed. The box log says why.")
}

func (s *Service) load(ctx context.Context) (*snapshot, error) {
	q := s.cfg.DB.Reader()
	sn := &snapshot{cfg: DefaultSettings(), assign: Assignments{Jobs: make(map[Job]Slot, len(Jobs()))}}

	var tests map[string]LastTest
	rows, err := q.QueryContext(ctx, `SELECT key, value FROM ai_setting WHERE key IN ('config', 'assign', 'profile_tests')`)
	if err != nil {
		return nil, fmt.Errorf("settings: %w", err)
	}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("settings: %w", err)
		}
		switch key {
		case "config":
			if err := json.Unmarshal([]byte(value), &sn.cfg); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("settings config: %w", err)
			}
		case "assign":
			var v struct {
				InternalOnly bool `json:"internal_only"`
			}
			if err := json.Unmarshal([]byte(value), &v); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("settings assign: %w", err)
			}
			sn.assign.InternalOnly = v.InternalOnly
		case "profile_tests":
			// what only a row shows: a value that cannot be read leaves every profile "not tested", it does not stop the module
			if json.Unmarshal([]byte(value), &tests) != nil {
				tests = nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("settings: %w", err)
	}
	_ = rows.Close()
	if err := sn.cfg.validate(); err != nil {
		return nil, err
	}

	prof, err := q.QueryContext(ctx, `SELECT id, name, kind, api_style, base_url, model, secret_id, location, monthly_budget FROM ai_profile ORDER BY rowid`)
	if err != nil {
		return nil, fmt.Errorf("profiles: %w", err)
	}
	type raw struct {
		p        Profile
		secretID sql.NullString
	}
	var raws []raw
	for prof.Next() {
		var r raw
		var style, loc string
		if err := prof.Scan(&r.p.ID, &r.p.Name, &r.p.Kind, &style, &r.p.BaseURL, &r.p.Model, &r.secretID, &loc, &r.p.MonthlyBudget); err != nil {
			_ = prof.Close()
			return nil, fmt.Errorf("profiles: %w", err)
		}
		r.p.APIStyle, r.p.Location = provider.APIStyle(style), Location(loc)
		raws = append(raws, r)
	}
	if err := prof.Err(); err != nil {
		_ = prof.Close()
		return nil, fmt.Errorf("profiles: %w", err)
	}
	_ = prof.Close()
	for _, r := range raws {
		st := stored{Profile: r.p}
		if t, ok := tests[r.p.ID]; ok {
			st.lastTest = &t
		}
		if r.secretID.Valid {
			key, err := s.cfg.Secrets.Open(ctx, q, r.secretID.String, secretPurpose)
			if err != nil {
				return nil, fmt.Errorf("profile %s: key: %w", r.p.ID, err)
			}
			st.APIKey, st.secretID = provider.NewSecret(string(key)), r.secretID.String
		}
		sn.profiles = append(sn.profiles, st)
	}

	asg, err := q.QueryContext(ctx, `SELECT job, primary_profile_id, fallback_profile_id FROM ai_assignment`)
	if err != nil {
		return nil, fmt.Errorf("assignments: %w", err)
	}
	defer func() { _ = asg.Close() }()
	for asg.Next() {
		var job string
		var pri, fb sql.NullString
		if err := asg.Scan(&job, &pri, &fb); err != nil {
			return nil, fmt.Errorf("assignments: %w", err)
		}
		sn.assign.Jobs[Job(job)] = Slot{Primary: pri.String, Fallback: fb.String}
	}
	if err := asg.Err(); err != nil {
		return nil, fmt.Errorf("assignments: %w", err)
	}
	return sn, nil
}

// apply hands a committed snapshot to the router and publishes it. The state was checked before it was written, so SetConfig
// cannot refuse it; if it does anyway the box keeps the previous router state, logs, and the caller reports an internal error.
func (s *Service) apply(ctx context.Context, next *snapshot) error {
	if err := s.router.SetConfig(next.libProfiles(), next.assign); err != nil {
		s.cfg.Log.ErrorContext(ctx, "ai: a saved state was refused by the router", "error", err)
		return fmt.Errorf("ai: apply settings: %w", err)
	}
	s.snap.Store(next)
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func upsertSetting(ctx context.Context, tx *sql.Tx, key string, v any, now time.Time, who string) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("ai: encode setting %s: %w", key, err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ai_setting (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		key, string(raw), store.FormatTS(now), who)
	if err != nil {
		return fmt.Errorf("ai: save setting %s: %w", key, err)
	}
	return nil
}

func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, who, action, target, detail string) error {
	return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: who, Action: action, Target: target, Detail: detail})
}
