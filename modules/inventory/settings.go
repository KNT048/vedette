package inventory

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/core/apierr"
)

// ActiveWindow is when and how fast the box may scan actively (INV-7). Since #850 it is the one store of the safety settings every
// LAN engine shares (INV-32): the window and the exclusions bind the vulnerability checks of the scan module too, and CheckRate is
// their speed.
type ActiveWindow struct {
	Enabled    bool     `json:"enabled"`
	Days       []int    `json:"days"` // 1 = Monday ... 7 = Sunday
	From       string   `json:"from"`
	To         string   `json:"to"` // earlier than From means the window crosses midnight
	Rate       int      `json:"rate"`
	Exclusions []string `json:"exclusions"` // IPv4 or CIDR
	// CheckRate is the speed of the vulnerability checks (nuclei) on LAN devices, in requests per second (1..MaxCheckRate). 0:
	// nobody saved it yet, read as DefaultCheckRate. Not part of GET/PUT
	// /inventory/settings (the handlers leave it out): /scanning/safety and /scans/config carry it.
	CheckRate int `json:"check_rate,omitempty"`
}

// Limits of the vulnerability checks' speed and of the shared exclusions (#850, INV-32).
const (
	DefaultCheckRate = 5  // the scan module's default (scan migration 0001)
	MaxCheckRate     = 20 // scan INV-5
	MaxExclusions    = 200
)

// Checks is the check rate, DefaultCheckRate until it was stored.
func (a ActiveWindow) Checks() int {
	if a.CheckRate == 0 {
		return DefaultCheckRate
	}
	return a.CheckRate
}

// Settings is the scan scope of the box (contract.ts InventorySettings).
type Settings struct {
	LANRanges        []string     `json:"lan_ranges"`
	Active           ActiveWindow `json:"active"`
	FragileKinds     []string     `json:"fragile_kinds"`
	RegularScanKinds []string     `json:"regular_scan_kinds"`
	ScopeConfirmedAt *string      `json:"scope_confirmed_at"`
	ScopeConfirmedBy *string      `json:"scope_confirmed_by"`
	// Version names the stored safety block (INV-32, review #860 M1): every read sets it (SafetyVersion), a writer given one
	// refuses with 409 safety_changed when the block changed since. In SettingsInput it is the version the page read ("" = none).
	Version string `json:"version"`
}

// SettingsInput is PUT /inventory/settings.
type SettingsInput struct {
	Settings
	ScopeConfirmed bool `json:"scope_confirmed"` // the person's scan-scope attestation
}

// SafetyVersion names the safety block's stored values (INV-32): the ranges and their attestation, the switch of active discovery
// (review #860 r2 L1: a stale Devices › Scope save would turn it back on), the window, both speeds, the exclusions and the fragile
// types. The merge stamp is not part of it. Equal values give the same version, so a version names what a person saw, not when.
func SafetyVersion(st Settings) string {
	raw, err := json.Marshal([]any{
		st.LANRanges, st.ScopeConfirmedAt, st.ScopeConfirmedBy, st.Active.Enabled, st.Active.Days, st.Active.From, st.Active.To, st.Active.Rate,
		st.Active.Checks(), st.Active.Exclusions, st.FragileKinds, st.RegularScanKinds,
	})
	if err != nil { // only plain values: cannot happen
		panic("inventory: encode the safety version: " + err.Error())
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// Changed refuses a write built on values that changed since the person read them (409 safety_changed or scope_changed, review
// #860 H1/M1): nothing was stored. Current is the block as it is now, for the page to show again. It unwraps to its *apierr.Error.
type Changed struct {
	API     *apierr.Error
	Current Settings
}

func (e *Changed) Error() string { return "inventory: " + e.API.Code }
func (e *Changed) Unwrap() error { return e.API }

func safetyChanged(cur Settings) *Changed {
	return &Changed{API: apierr.New(http.StatusConflict, "safety_changed", "These safety settings changed since you opened the page (another admin, another tab, or a range or exclusion added elsewhere). Review the current values and save again."), Current: cur}
}

type scopeValue struct {
	ConfirmedAt *string `json:"confirmed_at"`
	ConfirmedBy *string `json:"confirmed_by"`
}

// InScope reports whether ip is inside lan_ranges and outside the exclusions (INV-7, SYS-7).
func (st Settings) InScope(ip netip.Addr) bool {
	ip = ip.Unmap()
	inRange := false
	for _, r := range st.LANRanges {
		if p, err := netip.ParsePrefix(r); err == nil && p.Contains(ip) {
			inRange = true
			break
		}
	}
	return inRange && !st.Excluded(ip)
}

// Excluded reports whether ip is on the exclusion list ("never touch"): nothing active goes there, not discovery, not a scan, not an
// SNMP read (outside lan_ranges SNMP reads a device a person turned SNMP on for, never an excluded one).
func (st Settings) Excluded(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, x := range st.Active.Exclusions {
		if a, err := netip.ParseAddr(x); err == nil && a == ip {
			return true
		}
		if p, err := netip.ParsePrefix(x); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

func loadSetting[T any](ctx context.Context, q querier, key string, into *T) error {
	var raw string
	if err := q.QueryRowContext(ctx, `SELECT value FROM inv_setting WHERE key = ?`, key).Scan(&raw); err != nil {
		return fmt.Errorf("inventory: read setting %s: %w", key, err)
	}
	if err := json.Unmarshal([]byte(raw), into); err != nil {
		return fmt.Errorf("inventory: decode setting %s: %w", key, err)
	}
	return nil
}

func loadSettings(ctx context.Context, q querier) (Settings, error) {
	var st Settings
	var sc scopeValue
	for _, l := range []func() error{
		func() error { return loadSetting(ctx, q, "lan_ranges", &st.LANRanges) },
		func() error { return loadSetting(ctx, q, "active", &st.Active) },
		func() error { return loadSetting(ctx, q, "fragile_kinds", &st.FragileKinds) },
		func() error { return loadSetting(ctx, q, "regular_scan_kinds", &st.RegularScanKinds) },
		func() error { return loadSetting(ctx, q, "scope", &sc) },
	} {
		if err := l(); err != nil {
			return Settings{}, err
		}
	}
	st.ScopeConfirmedAt, st.ScopeConfirmedBy = sc.ConfirmedAt, sc.ConfirmedBy
	for _, p := range []*[]string{&st.LANRanges, &st.FragileKinds, &st.RegularScanKinds, &st.Active.Exclusions} {
		if *p == nil {
			*p = []string{}
		}
	}
	if st.Active.Days == nil {
		st.Active.Days = []int{}
	}
	st.Version = SafetyVersion(st)
	return st, nil
}

func putSetting(ctx context.Context, tx *sql.Tx, key string, v any, now, actor string) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO inv_setting (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`, key, string(raw), now, actor)
	if err != nil {
		return fmt.Errorf("inventory: write setting %s: %w", key, err)
	}
	return nil
}

// Settings returns the scan scope.
func (s *Service) Settings(ctx context.Context) (Settings, error) {
	return loadSettings(ctx, s.db.Reader())
}

// InScope reports whether ip may be scanned: inside lan_ranges and outside the exclusions (INV-7).
func (s *Service) InScope(ctx context.Context, ip netip.Addr) (bool, error) {
	st, err := s.Settings(ctx)
	if err != nil {
		return false, err
	}
	return st.InScope(ip), nil
}

// SavedSettings is the answer of a PUT: the stored settings and the ranges that were reduced to their network.
type SavedSettings struct {
	Settings
	Adjusted []Adjustment `json:"adjusted"`
}

// checkSettings validates a PUT in the order the mock does, so the first problem a person sees is the
// same one. It returns the cleaned input and the adjusted ranges. Exclusions stay strict: an exclusion with
// host bits is refused, not reduced (the mock does the same).
func checkSettings(in SettingsInput) (SettingsInput, []Adjustment, error) {
	ranges, adjusted, aerr := checkRanges(in.LANRanges)
	if aerr != nil {
		return in, nil, aerr
	}
	act := in.Active
	for _, d := range act.Days {
		if d < 1 || d > 7 {
			return in, nil, badRequest("bad_days", "Scan days must be Monday to Sunday.")
		}
	}
	if !hhmmRE.MatchString(act.From) || !hhmmRE.MatchString(act.To) {
		return in, nil, badRequest("bad_time", "Time must look like 23:00.")
	}
	if act.From == act.To {
		return in, nil, badRequest("bad_window", "Start and end time cannot be the same.")
	}
	if act.Rate < 1 || act.Rate > 1000 {
		return in, nil, badRequest("bad_rate", "Scan rate is 1 to 1000 packets per second.")
	}
	if act.CheckRate != 0 && (act.CheckRate < 1 || act.CheckRate > MaxCheckRate) {
		return in, nil, badRequest("bad_rate", "The vulnerability check rate is 1 to 20 requests per second.")
	}
	var excl []string
	for _, raw := range act.Exclusions {
		x, aerr := checkExclusion(raw)
		if aerr != nil {
			return in, nil, aerr
		}
		if !slices.Contains(excl, x) {
			excl = append(excl, x)
		}
	}
	days := slices.Clone(act.Days)
	slices.Sort(days)
	days = slices.Compact(days)
	if act.Enabled && len(days) == 0 {
		return in, nil, badRequest("no_days", "Choose at least one day for the scan window, or turn active scanning off.")
	}
	if act.Enabled && len(ranges) == 0 {
		return in, nil, badRequest("no_ranges", "Active scanning needs at least one network range.")
	}
	if act.Enabled && !in.ScopeConfirmed {
		return in, nil, badRequest("scope_not_confirmed", "Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only scans within the confirmed scope.")
	}
	for _, k := range in.FragileKinds { // the 13 kinds behaviour is keyed on; every device type acts as one of them
		if !slices.Contains(Kinds, k) {
			return in, nil, badRequest("bad_kinds", "The list of fragile device types is not valid.")
		}
	}
	for _, k := range in.RegularScanKinds {
		if !slices.Contains(Kinds, k) {
			return in, nil, badRequest("bad_kinds", "The list of device types for regular scans is not valid.")
		}
	}
	fragile := dedupe(in.FragileKinds)
	regular := slices.DeleteFunc(dedupe(in.RegularScanKinds), func(k string) bool { return !slices.Contains(fragile, k) })
	if excl == nil {
		excl = []string{}
	}
	out := in
	out.LANRanges = ranges
	out.Active = ActiveWindow{Enabled: act.Enabled, Days: days, From: act.From, To: act.To, Rate: act.Rate, Exclusions: excl, CheckRate: act.CheckRate}
	out.FragileKinds, out.RegularScanKinds = fragile, regular
	return out, adjusted, nil
}

// checkExclusion is one exclusion as PUT /inventory/settings and PUT /scanning/safety accept it: an IPv4 address or an IPv4 range
// without host bits (strict: 192.168.10.5/28 is refused, not reduced).
func checkExclusion(raw string) (string, *apierr.Error) {
	x := strings.TrimSpace(raw)
	if _, isIP := ipv4(x); isIP {
		return x, nil
	}
	if p, err := netip.ParsePrefix(x); err == nil && p.Addr().Is4() && p.Masked() == p {
		return x, nil
	}
	return "", badRequest("bad_exclusion", `Exclusion "`+clip(x, 30)+`" is not valid. Enter an IP (192.168.10.10) or a valid range (192.168.10.0/28).`)
}

func dedupe(in []string) []string {
	out := []string{}
	for _, k := range in {
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// ScopeCost is what one pass of active discovery over a scope costs (the estimate of the range form): the addresses it walks, the
// time one pass takes at the scan rate (a floor), one window's length, and how many windows one pass needs against the windows of a
// week.
type ScopeCost struct {
	Addresses   int
	Pass        time.Duration
	Window      time.Duration // 0: no window is set
	Windows     int           // windows one pass needs (1: it fits one)
	WeekWindows int           // windows in a week (the window's days)
}

// FitsWeek says one pass ends within a week of windows (or there is nothing to sweep, or no window to measure against).
func (c ScopeCost) FitsWeek() bool {
	return c.Addresses == 0 || c.Window <= 0 || c.WeekWindows == 0 || c.Windows <= c.WeekWindows
}

// SetScopeCost gives the inventory the estimate of a pass over a scope (active discovery's: it knows the probes an address costs and
// the box's own networks). A save of the scan scope, window or rate that active discovery could not sweep within a week is refused
// with the numbers (scope_too_large); without an estimate nothing is refused.
func (s *Service) SetScopeCost(fn func(ctx context.Context, st Settings) ScopeCost) {
	s.scopeMu.Lock()
	defer s.scopeMu.Unlock()
	s.scopeCost = fn
}

// checkCost refuses next when one pass over its scope does not end within a week of its windows (scope_too_large).
func (s *Service) checkCost(ctx context.Context, next Settings) error {
	s.scopeMu.Lock()
	fn := s.scopeCost
	s.scopeMu.Unlock()
	if fn == nil || len(next.LANRanges) == 0 {
		return nil
	}
	c := fn(ctx, next)
	if c.FitsWeek() {
		return nil
	}
	return badRequest("scope_too_large", fmt.Sprintf("One pass over these ranges covers %d addresses and takes at least %s at %d packets per second, "+
		"which is %d scan windows of %s; a week has %d. Vedette never takes a scope it cannot sweep within a week: raise the scan rate, "+
		"widen the window or add days, or narrow the ranges.", c.Addresses, durationWords(c.Pass), next.Active.Rate, c.Windows, durationWords(c.Window), c.WeekWindows))
}

// durationWords writes d as "6 h 12 min" or "40 min".
func durationWords(d time.Duration) string {
	m := int(d.Round(time.Minute) / time.Minute)
	if m < 60 {
		return fmt.Sprintf("%d min", max(m, 1))
	}
	if m%60 == 0 {
		return fmt.Sprintf("%d h", m/60)
	}
	return fmt.Sprintf("%d h %d min", m/60, m%60)
}

// SaveSettings stores the scan scope (PRE-5, INV-6, INV-7). scope_confirmed_at stays when the ranges did
// not change (POST-5). The fragile flag of every device without a manual override follows the new kinds.
func (s *Service) SaveSettings(ctx context.Context, actor string, in SettingsInput) (SavedSettings, error) {
	return s.saveSettings(ctx, actor, in, saveOpts{})
}

// saveOpts are the rules of PUT /scanning/safety on top of SaveSettings' (INV-32).
type saveOpts struct {
	keepEnabled    bool // the switch of active discovery is not part of the input: the stored one, read in the transaction, stays (L8)
	capExclusions  bool // more than MaxExclusions exclusions only when the list does not grow (L7)
	requireVersion bool // the input names the version it was built on (PUT /scanning/safety); without it, only when one is given
}

func (s *Service) saveSettings(ctx context.Context, actor string, in SettingsInput, opt saveOpts) (SavedSettings, error) {
	if !opt.keepEnabled { // checked before the transaction as before; with keepEnabled it needs the stored switch
		if _, _, err := checkSettings(in); err != nil {
			return SavedSettings{}, err
		}
	}
	var saved Settings
	var adjusted []Adjustment
	err := s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		prev, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		// review #860 M1: a page read before another change (an inline add, another admin) would replace it: refused, nothing stored
		if (opt.requireVersion || in.Version != "") && in.Version != prev.Version {
			return safetyChanged(prev)
		}
		if opt.keepEnabled {
			in.Active.Enabled = prev.Active.Enabled
		}
		if in, adjusted, err = checkSettings(in); err != nil {
			return err
		}
		if opt.capExclusions && len(in.Active.Exclusions) > MaxExclusions && len(in.Active.Exclusions) > len(prev.Active.Exclusions) {
			return badRequest("too_many_exclusions", "The exclusion list can have at most 200 lines.")
		}
		if err := s.checkCost(ctx, in.Settings); err != nil {
			return err
		}
		now := s.now()
		next := in.Settings
		if next.Active.CheckRate == 0 { // PUT /inventory/settings does not carry it: the stored value stays
			next.Active.CheckRate = prev.Active.CheckRate
		}
		next.ScopeConfirmedAt, next.ScopeConfirmedBy = nil, nil
		if in.ScopeConfirmed {
			at, by := now, actor
			if prev.ScopeConfirmedAt != nil && slices.Equal(sortedCopy(prev.LANRanges), sortedCopy(in.LANRanges)) {
				at, by = *prev.ScopeConfirmedAt, ""
				if prev.ScopeConfirmedBy != nil {
					by = *prev.ScopeConfirmedBy
				}
			}
			next.ScopeConfirmedAt = &at
			if by != "" {
				next.ScopeConfirmedBy = &by
			}
		}
		for key, v := range map[string]any{
			"lan_ranges": next.LANRanges, "active": next.Active, "fragile_kinds": next.FragileKinds, "regular_scan_kinds": next.RegularScanKinds,
			"scope": scopeValue{ConfirmedAt: next.ScopeConfirmedAt, ConfirmedBy: next.ScopeConfirmedBy},
		} {
			if err := putSetting(ctx, tx, key, v, now, actorOrSystem(actor)); err != nil {
				return err
			}
		}
		if err := applyFragilePolicy(ctx, tx, next.FragileKinds); err != nil {
			return err
		}
		state := "off"
		if next.Active.Enabled {
			state = "on"
		}
		if err := s.auditTx(ctx, tx, actor, "inventory.settings", "scan scope", strconv.Itoa(len(next.LANRanges))+" ranges, active scanning "+state); err != nil {
			return err
		}
		o.add(EventSettingsChanged, SettingsEvent{Scope: "scan"})
		saved, err = loadSettings(ctx, tx) // as stored, with its new version
		return err
	})
	return SavedSettings{Settings: saved, Adjusted: adjusted}, err
}

// SetupScope stores the LAN ranges and the scan commitment of first-run setup (core INV-15, S-CORE-1) inside the caller's write
// transaction tx, so that they are the scope of Devices -> Scope and sensors from the first page on (#350): the ranges pass INV-6
// (an error is an *apierr.Error and the caller's setup fails with it), lan_ranges is replaced, and the scope is confirmed by actor
// now when confirmed is true and cleared otherwise. The other settings keep their values. No audit row of its own: the caller's
// core.setup row counts the ranges. inventory.settings.changed goes out at Settle, when the caller's transaction committed.
func (s *Service) SetupScope(ctx context.Context, tx *sql.Tx, actor string, ranges []string, confirmed bool) error {
	clean, _, aerr := checkRanges(ranges)
	if aerr != nil {
		return aerr
	}
	now := s.now()
	var sc scopeValue
	if confirmed {
		at, by := now, actor
		sc = scopeValue{ConfirmedAt: &at, ConfirmedBy: &by}
	}
	if err := putSetting(ctx, tx, "lan_ranges", clean, now, actorOrSystem(actor)); err != nil {
		return err
	}
	if err := putSetting(ctx, tx, "scope", sc, now, actorOrSystem(actor)); err != nil {
		return err
	}
	// The commitment ticked at setup is the consent to scan these ranges, so active scanning goes on with it, as the setup
	// page says. Unticked leaves the setting as it was (off on a new box).
	if confirmed {
		var act ActiveWindow
		if err := loadSetting(ctx, tx, "active", &act); err != nil {
			return err
		}
		act.Enabled = true
		if act.Exclusions == nil {
			act.Exclusions = []string{}
		}
		if err := putSetting(ctx, tx, "active", act, now, actorOrSystem(actor)); err != nil {
			return err
		}
	}
	var o outbox
	o.add(EventSettingsChanged, SettingsEvent{Scope: "scan"})
	s.keep(tx, &o)
	return nil
}

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

func actorOrSystem(a string) string {
	if a == "" {
		return systemActor
	}
	return a
}

// kindList is "(?,?,?)" for the kinds, and its arguments. SQLite accepts the empty list "()".
func kindList(kinds []string) (string, []any) {
	args := make([]any, len(kinds))
	for i, k := range kinds {
		args[i] = k
	}
	return "(" + strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",") + ")", args
}

// applyFragilePolicy sets fragile on every device whose flag was not set by hand: a device whose type acts as one of kinds.
func applyFragilePolicy(ctx context.Context, tx *sql.Tx, kinds []string) error {
	list, args := kindList(devicetypes.ActingAs(kinds))
	_, err := tx.ExecContext(ctx, `UPDATE inv_asset SET fragile = (kind IN `+list+`) WHERE fragile_manual = 0 AND fragile <> (kind IN `+list+`)`, append(args, args...)...) //nolint:gosec // list is only "?" placeholders, the kinds travel as arguments
	if err != nil {
		return fmt.Errorf("inventory: apply fragile policy: %w", err)
	}
	return nil
}

// NotifyNew returns the notify_new switch.
func (s *Service) NotifyNew(ctx context.Context) (bool, error) {
	return notifyNew(ctx, s.db.Reader())
}

func notifyNew(ctx context.Context, q querier) (bool, error) {
	var v struct {
		Enabled bool `json:"enabled"`
	}
	if err := loadSetting(ctx, q, "notify_new", &v); err != nil {
		return false, err
	}
	return v.Enabled, nil
}

// SetNotifyNew turns the alert for new devices on or off.
func (s *Service) SetNotifyNew(ctx context.Context, actor string, enabled bool) error {
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		if err := putSetting(ctx, tx, "notify_new", map[string]bool{"enabled": enabled}, s.now(), actorOrSystem(actor)); err != nil {
			return err
		}
		state := "off"
		if enabled {
			state = "on"
		}
		if err := s.auditTx(ctx, tx, actor, "inventory.notify_new", state, ""); err != nil {
			return err
		}
		o.add(EventSettingsChanged, SettingsEvent{Scope: "notify_new"})
		return nil
	})
}
