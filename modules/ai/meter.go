package ai

import (
	"fmt"
	"sync"
	"time"
)

// DefaultTimeZone is the box time zone unless the administrator picks another (`core_org.timezone`).
const DefaultTimeZone = "Asia/Ho_Chi_Minh"

// LoadLocation resolves an IANA zone name for the meter. An empty name means DefaultTimeZone; if the
// system has no tz database, that default falls back to a fixed UTC+7 (Vietnam has no daylight saving).
func LoadLocation(name string) (*time.Location, error) {
	if name == "" {
		name = DefaultTimeZone
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		if name == DefaultTimeZone {
			return time.FixedZone("ICT", 7*3600), nil
		}
		return nil, fmt.Errorf("ai: time zone %q: %w", name, err)
	}
	return loc, nil
}

// Downgrade records one automatic drop of the token level (INV-4, `ai_downgrades`, `ai.downgrade`).
type Downgrade struct {
	At       time.Time
	From, To Tier
	Reason   string
}

// MeterConfig configures a Meter. Clock and Location are injected: the day boundary is local midnight
// in Location, the box time zone, so "today" matches what the administrator sees on the wall clock.
type MeterConfig struct {
	Clock     func() time.Time
	Location  *time.Location
	GlobalCap int
	Tier      Tier
}

// Meter counts tokens per day, globally and per profile, and lowers the effective level when the shared
// cap is passed. It is safe for concurrent use. Usage lives in memory; WP-25 rebuilds it from ai_activity
// at start-up with Seed.
type Meter struct {
	mu     sync.Mutex
	clock  func() time.Time
	loc    *time.Location
	cap    int
	tier   Tier // configured level
	eff    Tier // effective level today; never above tier
	day    string
	total  int
	byProf map[string]int
}

// NewMeter validates the configuration.
func NewMeter(c MeterConfig) (*Meter, error) {
	if c.Clock == nil || c.Location == nil {
		return nil, fmt.Errorf("ai: meter needs a clock and a time zone")
	}
	m := &Meter{clock: c.Clock, loc: c.Location, byProf: map[string]int{}}
	if err := m.set(c.Tier, c.GlobalCap); err != nil {
		return nil, err
	}
	m.day = m.today()
	return m, nil
}

func (m *Meter) today() string { return m.clock().In(m.loc).Format("2006-01-02") }

func (m *Meter) set(t Tier, capTokens int) error {
	if !t.Valid() {
		return fmt.Errorf("ai: unknown token level %q", t)
	}
	if !ValidDailyCap(capTokens) {
		return fmt.Errorf("ai: the daily token cap must be a whole number from %d to %d", MinDailyCap, MaxDailyCap)
	}
	m.tier, m.eff, m.cap = t, t, capTokens
	return nil
}

// roll starts a new day: counters reset and the effective level returns to the configured one, because a
// downgrade is a reaction to today's cap only. Callers hold m.mu.
func (m *Meter) roll() {
	if d := m.today(); d != m.day {
		m.day, m.total, m.byProf, m.eff = d, 0, map[string]int{}, m.tier
	}
}

// SetConfig changes the configured level and shared cap (admin action); the effective level restarts from t.
func (m *Meter) SetConfig(t Tier, capTokens int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.set(t, capTokens)
}

// Seed loads today's usage after a restart. It replaces the counters; usage from other days is ignored by the caller.
func (m *Meter) Seed(perProfile map[string]int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	m.total, m.byProf = 0, map[string]int{}
	for id, n := range perProfile {
		if n > 0 {
			m.byProf[id] = n
			m.total += n
		}
	}
}

// Tier returns the effective level now.
func (m *Meter) Tier() Tier {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.eff
}

// Used returns today's shared total.
func (m *Meter) Used() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.total
}

// ProfileUsed returns today's tokens for one profile.
func (m *Meter) ProfileUsed(id string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.byProf[id]
}

// Exhausted reports that the shared cap is used up and there is no lower level left to fall back to, so
// no further call may be made today (the mock's `capped` outcome).
func (m *Meter) Exhausted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.total >= m.cap && m.eff == TierMin
}

// Record adds a finished call. When the shared total passes the cap and the level is above min, it lowers
// the effective level by one step (max -> med -> min, never up) and returns the record to store and audit.
func (m *Meter) Record(profileID string, tokensIn, tokensOut int) *Downgrade {
	n := max(tokensIn, 0) + max(tokensOut, 0)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	m.total += n
	m.byProf[profileID] += n
	if m.total <= m.cap || m.eff == TierMin {
		return nil
	}
	d := &Downgrade{At: m.clock().UTC(), From: m.eff, To: m.eff.Lower(), Reason: fmt.Sprintf("Over the %d tokens/day cap", m.cap)}
	m.eff = d.To
	return d
}
