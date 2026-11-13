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

// Downgrade records one automatic drop of the token level (INV-4, `ai_downgrades`, `ai.downgrade`). Since D-531 the monthly budget
// stops calls at 100 % instead of lowering the level, so the meter writes none; the type stays for the rows of earlier days, which
// Usage still lists.
type Downgrade struct {
	At       time.Time
	From, To Tier
	Reason   string
}

// ErrProfileCapped means a profile has used its own monthly budget; the router moves on to the fallback.
var ErrProfileCapped = errors.New("ai: the profile's monthly token budget is used up")

// MeterConfig configures a Meter. Clock and Location are injected: the month starts at local midnight of its first day in Location,
// the box time zone, so "this month" matches what the administrator sees on the wall clock.
type MeterConfig struct {
	Clock     func() time.Time
	Location  *time.Location
	GlobalCap int // the shared monthly budget in tokens
	Tier      Tier
}

// Meter counts tokens per calendar month, for the whole box and per profile (D-531). It is safe for concurrent use. Usage lives in
// memory; the service rebuilds it from ai_activity at start-up with Seed.
//
// The budget is a plain stop rule: below it every call may go, at it (counting the holds of calls in flight) none may, until the
// month turns or an administrator raises it. There is no daily cap and no level drop on the way: the warnings at 80 % and 100 % are
// the service's (budget.go).
type Meter struct {
	mu       sync.Mutex
	clock    func() time.Time
	loc      *time.Location
	cap      int
	tier     Tier
	month    string // "2006-01" in the box time zone
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
	m.month = m.thisMonth()
	return m, nil
}

func (m *Meter) thisMonth() string { return m.clock().In(m.loc).Format("2006-01") }

// MonthStart is the first instant of the month that contains now, in the box time zone.
func MonthStart(now time.Time, loc *time.Location) time.Time {
	y, mo, _ := now.In(loc).Date()
	return time.Date(y, mo, 1, 0, 0, 0, 0, loc)
}

// Renews is when the current month's budget starts again: local midnight of the first day of the next month.
func (m *Meter) Renews() time.Time { return MonthStart(m.clock(), m.loc).AddDate(0, 1, 0) }

func (m *Meter) set(t Tier, capTokens int) error {
	if !t.Valid() {
		return fmt.Errorf("ai: unknown token level %q", t)
	}
	if !ValidMonthlyBudget(capTokens) {
		return fmt.Errorf("ai: the monthly token budget must be a whole number from %d to %d", MinMonthlyBudget, MaxMonthlyBudget)
	}
	m.tier, m.cap = t, capTokens
	return nil
}

// roll starts a new month when the local month has moved forward: the counters reset. A clock that steps back (NTP, an
// administrator) never starts a new month. Callers hold m.mu.
func (m *Meter) roll() {
	if d := m.thisMonth(); d > m.month { // "2006-01" compares in calendar order
		m.month, m.total, m.pending, m.byProf, m.pendProf = d, 0, 0, map[string]int{}, map[string]int{}
	}
}

// SetConfig changes the level and the shared budget (admin action).
func (m *Meter) SetConfig(t Tier, capTokens int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.set(t, capTokens)
}

// Seed loads this month's usage after a restart. It replaces the counters. Usage from other months is the caller's to leave out.
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
}

// Tier returns the level in force: the configured one (the budget never lowers it, D-531).
func (m *Meter) Tier() Tier {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tier
}

// Used returns this month's shared total.
func (m *Meter) Used() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.total
}

// ProfileUsed returns this month's tokens for one profile.
func (m *Meter) ProfileUsed(id string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.byProf[id]
}

// Exhausted reports that the shared budget is used up, so no further call may be made this month (the `capped` outcome). Calls in
// flight count as used.
func (m *Meter) Exhausted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.exhausted()
}

// UsedUp reports that the tokens already spent this month, without the holds of calls in flight, have used up the shared budget: what
// a call that has just failed may call "used up" (another call's hold may still be given back).
func (m *Meter) UsedUp() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	return m.total >= m.cap
}

func (m *Meter) exhausted() bool { return satAdd(m.total, m.pending) >= m.cap }

func satAdd(a, b int) int {
	if b > 0 && a > math.MaxInt-b {
		return math.MaxInt
	}
	return a + b
}

// Reservation is the share of the budgets held for one call in flight. Settle it with the real usage or Cancel it.
type Reservation struct {
	m       *Meter
	profile string
	tokens  int
	done    bool
}

// Reserve is the check before a call and the first half of metering. Under one lock it refuses the call when the shared budget is
// used up (ErrCapped) or when the profile has used its own budget (ErrProfileCapped), counting calls already in flight, and otherwise
// holds estimate tokens against both. N concurrent calls therefore cannot all pass the check: the first holds the tokens the next one
// would need.
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

// Settle releases the hold and counts what the call really used (also for a failed call whose usage is known, such as a refusal).
// It returns nil: the budget lowers no level (D-531); the result is kept for the callers that write a downgrade row when there is one.
func (r *Reservation) Settle(tokensIn, tokensOut int) *Downgrade {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	if r.done {
		return nil
	}
	r.done = true
	r.m.pending = max(r.m.pending-r.tokens, 0)
	r.m.pendProf[r.profile] = max(r.m.pendProf[r.profile]-r.tokens, 0)
	r.m.add(r.profile, tokensIn, tokensOut)
	return nil
}

// Cancel releases the hold without counting anything (the call never reached the provider).
func (r *Reservation) Cancel() { r.Settle(0, 0) }

// Record adds a call that was not reserved (a profile test). Counts are added with saturation.
func (m *Meter) Record(profileID string, tokensIn, tokensOut int) *Downgrade {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll()
	m.add(profileID, tokensIn, tokensOut)
	return nil
}

func (m *Meter) add(profileID string, tokensIn, tokensOut int) {
	n := satAdd(max(tokensIn, 0), max(tokensOut, 0))
	m.total = satAdd(m.total, n)
	m.byProf[profileID] = satAdd(m.byProf[profileID], n)
}
