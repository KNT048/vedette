package ai

import (
	"errors"
	"fmt"
	"math"
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

// ErrProfileCapped means a profile has used its own daily cap; the router moves on to the fallback.
var ErrProfileCapped = errors.New("ai: the profile's daily token cap is used up")

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
//
// The effective level is a pure function of today's total and the cap: one level down for every started cap
// beyond the first (total <= cap: configured level; <= 2 x cap: one down; <= 3 x cap: two down; never below min).
// So it only ever falls during a day, a restart that reloads the usage lands on the same level, and one call
// that overshoots by a lot can drop several levels at once.
type Meter struct {
	mu       sync.Mutex
	clock    func() time.Time
	loc      *time.Location
	cap      int
	tier     Tier // configured level
	eff      Tier // effective level today
	day      string
	total    int
	pending  int // tokens reserved by calls in flight
	byProf   map[string]int
	pendProf map[string]int
}

// NewMeter validates the configuration.
func NewMeter(c MeterConfig) (*Meter, error) {
	if c.Clock == nil || c.Location == nil {
		return nil, fmt.Errorf("ai: meter needs a clock and a time zone")
	}
	m := &Meter{clock: c.Clock, loc: c.Location, byProf: map[string]int{}, pendProf: map[string]int{}}
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
	m.tier, m.cap = t, capTokens
	m.eff = m.levelFor()
	return nil
}

// levelFor derives the effective level from the configured one and today's total.
func (m *Meter) levelFor() Tier {
	t := m.tier
	if m.total <= m.cap {
		return t
	}
	for steps := (m.total - 1) / m.cap; steps > 0 && t != TierMin; steps-- {
		t = t.Lower()
	}
	return t
}

// roll starts a new day when the local date has moved forward: counters reset and the level returns to the
// configured one. A clock that steps back (NTP, an administrator) never starts a new day. Callers hold m.mu.
func (m *Meter) roll() {
	if d := m.today(); d > m.day { // ISO dates compare in calendar order
		m.day, m.total, m.pending, m.byProf, m.pendProf = d, 0, 0, map[string]int{}, map[string]int{}
		m.eff = m.tier
	}
}

// SetConfig changes the configured level and shared cap (admin action); the effective level is recomputed.
func (m *Meter) SetConfig(t Tier, capTokens int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.set(t, capTokens)
}

// Seed loads today's usage after a restart. It replaces the counters and recomputes the effective level from
// them, so a day that was already downgraded stays downgraded. Usage from other days is the caller's to leave out.
func (m *Meter) Seed(perProfile map[string]int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	m.total, m.byProf = 0, map[string]int{}
	for id, n := range perProfile {
		if n > 0 {
			m.byProf[id] = satAdd(m.byProf[id], n)
			m.total = satAdd(m.total, n)
		}
	}
	m.eff = m.levelFor()
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

// Exhausted reports that the shared cap is used up and there is no lower level left to fall back to, so no
// further call may be made today (the mock's `capped` outcome). Calls in flight count as used.
func (m *Meter) Exhausted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.exhausted()
}

func (m *Meter) exhausted() bool { return satAdd(m.total, m.pending) >= m.cap && m.eff == TierMin }

func satAdd(a, b int) int {
	if b > 0 && a > math.MaxInt-b {
		return math.MaxInt
	}
	return a + b
}

// Reservation is the share of the caps held for one call in flight. Settle it with the real usage or Cancel it.
type Reservation struct {
	m       *Meter
	profile string
	tokens  int
	done    bool
}

// Reserve is the check before a call and the first half of metering. Under one lock it refuses the call when the
// shared cap is used up at the minimum level (ErrCapped) or when the profile has used its own cap
// (ErrProfileCapped), counting calls already in flight, and otherwise holds estimate tokens against both. N
// concurrent calls therefore cannot all pass the check: the first holds the tokens the next one would need.
func (m *Meter) Reserve(profileID string, profileCap, estimate int) (*Reservation, error) {
	estimate = max(estimate, 0)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	if m.exhausted() {
		return nil, ErrCapped
	}
	if satAdd(m.byProf[profileID], m.pendProf[profileID]) >= profileCap {
		return nil, ErrProfileCapped
	}
	m.pending = satAdd(m.pending, estimate)
	m.pendProf[profileID] = satAdd(m.pendProf[profileID], estimate)
	return &Reservation{m: m, profile: profileID, tokens: estimate}, nil
}

// Settle releases the hold and counts what the call really used (also for a failed call whose usage is known,
// such as a refusal). It returns the downgrade record if the level fell.
func (r *Reservation) Settle(tokensIn, tokensOut int) *Downgrade {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	if r.done {
		return nil
	}
	r.done = true
	r.m.pending = max(r.m.pending-r.tokens, 0)
	r.m.pendProf[r.profile] = max(r.m.pendProf[r.profile]-r.tokens, 0)
	return r.m.add(r.profile, tokensIn, tokensOut)
}

// Cancel releases the hold without counting anything (the call never reached the provider).
func (r *Reservation) Cancel() { r.Settle(0, 0) }

// Record adds a call that was not reserved (a profile test). Counts are added with saturation.
func (m *Meter) Record(profileID string, tokensIn, tokensOut int) *Downgrade {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.add(profileID, tokensIn, tokensOut)
}

func (m *Meter) add(profileID string, tokensIn, tokensOut int) *Downgrade {
	n := satAdd(max(tokensIn, 0), max(tokensOut, 0))
	m.total = satAdd(m.total, n)
	m.byProf[profileID] = satAdd(m.byProf[profileID], n)
	to := m.levelFor()
	if to == m.eff {
		return nil
	}
	d := &Downgrade{At: m.clock().UTC(), From: m.eff, To: to, Reason: fmt.Sprintf("Over the %d tokens/day cap", m.cap)}
	m.eff = to
	return d
}
