package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// ActiveWindow is when and how fast the box may scan actively (INV-7).
type ActiveWindow struct {
	Enabled    bool     `json:"enabled"`
	Days       []int    `json:"days"` // 1 = Monday ... 7 = Sunday
	From       string   `json:"from"`
	To         string   `json:"to"` // earlier than From means the window crosses midnight
	Rate       int      `json:"rate"`
	Exclusions []string `json:"exclusions"` // IPv4 or CIDR
}

// Settings is the scan scope of the box (contract.ts InventorySettings).
type Settings struct {
	LANRanges        []string     `json:"lan_ranges"`
	Active           ActiveWindow `json:"active"`
	FragileKinds     []string     `json:"fragile_kinds"`
	RegularScanKinds []string     `json:"regular_scan_kinds"`
	ScopeConfirmedAt *string      `json:"scope_confirmed_at"`
	ScopeConfirmedBy *string      `json:"scope_confirmed_by"`
}

// SettingsInput is PUT /inventory/settings.
type SettingsInput struct {
	Settings
	ScopeConfirmed bool `json:"scope_confirmed"` // the attestation of D-26
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
	if !inRange {
		return false
	}
	for _, x := range st.Active.Exclusions {
		if a, err := netip.ParseAddr(x); err == nil && a == ip {
			return false
		}
		if p, err := netip.ParsePrefix(x); err == nil && p.Contains(ip) {
			return false
		}
	}
	return true
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
	var excl []string
	for _, raw := range act.Exclusions {
		x := strings.TrimSpace(raw)
		ok := false
		if _, isIP := ipv4(x); isIP {
			ok = true
		} else if p, err := netip.ParsePrefix(x); err == nil && p.Addr().Is4() && p.Masked() == p {
			ok = true
		}
		if !ok {
			return in, nil, badRequest("bad_exclusion", `Exclusion "`+clip(x, 30)+`" is not valid. Enter an IP (192.168.10.10) or a valid range (192.168.10.0/28).`)
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
	for _, k := range in.FragileKinds {
		if !validKind(k) {
			return in, nil, badRequest("bad_kinds", "The list of fragile device types is not valid.")
		}
	}
	for _, k := range in.RegularScanKinds {
		if !validKind(k) {
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
	out.Active = ActiveWindow{Enabled: act.Enabled, Days: days, From: act.From, To: act.To, Rate: act.Rate, Exclusions: excl}
	out.FragileKinds, out.RegularScanKinds = fragile, regular
	return out, adjusted, nil
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

// SaveSettings stores the scan scope (PRE-5, INV-6, INV-7). scope_confirmed_at stays when the ranges did
// not change (POST-5). The fragile flag of every device without a manual override follows the new kinds.
func (s *Service) SaveSettings(ctx context.Context, actor string, in SettingsInput) (SavedSettings, error) {
	in, adjusted, err := checkSettings(in)
	if err != nil {
		return SavedSettings{}, err
	}
	var saved Settings
	err = s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		prev, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		now := s.now()
		next := in.Settings
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
		saved = next
		return nil
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

// applyFragilePolicy sets fragile on every device whose flag was not set by hand (D-45).
func applyFragilePolicy(ctx context.Context, tx *sql.Tx, kinds []string) error {
	list, args := kindList(kinds)
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
