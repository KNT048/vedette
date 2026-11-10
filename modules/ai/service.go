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
	Tier      Tier `json:"tier"`
	DailyCap  int  `json:"daily_cap"`
	RedactPII bool `json:"redact_pii"`
}

// DefaultSettings is what a fresh box starts with (the mock's defaults).
func DefaultSettings() Settings { return Settings{Tier: TierMed, DailyCap: 60_000, RedactPII: true} }

func (s Settings) validate() error {
	if !s.Tier.Valid() {
		return perr("invalid_tier", "Pick a tier: minimum, medium or maximum.")
	}
	if !ValidDailyCap(s.DailyCap) {
		return perr("invalid_cap", "The daily token cap must be a whole number from %d to %d.", MinDailyCap, MaxDailyCap)
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
	// Factory builds the client of a profile; nil = Profile.Provider. Tests inject fakes: no test calls a real provider.
	Factory func(Profile) (provider.Provider, error)
}

// stored is a profile as the service holds it: the library profile (with its key opened) and the id of its sealed key.
type stored struct {
	Profile
	secretID string
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
	cfg      Config
	router   *Router
	meter    *Meter
	degraded string     // why the saved settings could not be loaded; "" = loaded
	mu       sync.Mutex // serialises changes
	snap     atomic.Pointer[snapshot]
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
	s := &Service{cfg: cfg}
	sn, err := s.load(ctx)
	if err == nil {
		err = s.build(sn, loc)
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
	return s, nil
}

// build makes the meter and the router of a snapshot and publishes it.
func (s *Service) build(sn *snapshot, loc *time.Location) error {
	meter, err := NewMeter(MeterConfig{Clock: s.cfg.Clock, Location: loc, GlobalCap: sn.cfg.DailyCap, Tier: sn.cfg.Tier})
	if err != nil {
		return err
	}
	router, err := NewRouter(RouterConfig{Profiles: sn.libProfiles(), Assignments: sn.assign, Meter: meter, Factory: s.cfg.Factory})
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

	rows, err := q.QueryContext(ctx, `SELECT key, value FROM ai_setting WHERE key IN ('config', 'assign')`)
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

	prof, err := q.QueryContext(ctx, `SELECT id, name, kind, api_style, base_url, model, secret_id, location, daily_cap FROM ai_profile ORDER BY rowid`)
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
		if err := prof.Scan(&r.p.ID, &r.p.Name, &r.p.Kind, &style, &r.p.BaseURL, &r.p.Model, &r.secretID, &loc, &r.p.DailyCap); err != nil {
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
