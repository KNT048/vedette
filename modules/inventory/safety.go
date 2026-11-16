package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// The shared safety settings of Settings › Scanning (#850, INV-32). The inventory's `active` setting is their one store: the window,
// the exclusions and the check rate bind every LAN engine (discovery, version scans, SNMP rounds and the scan module's vulnerability
// checks). Three writers reach it: PUT /scanning/safety (SaveSafety, through core's Scanning port), PUT /inventory/settings
// (SaveSettings) and PUT /scans/config (SaveChecks inside the scan module's transaction). Each publishes inventory.settings.changed.

// SafetyInput is PUT /scanning/safety as the inventory stores it: the whole shared block. Whether active discovery is on is not part
// of it (the nmap-discovery switch is, SetDiscovery), so a save keeps the stored switch.
type SafetyInput struct {
	LANRanges        []string
	Confirmed        bool // the attestation of D-26
	Days             []int
	From, To         string
	PacketsPerS      int // discovery and SNMP, 1..1000
	RequestsPerS     int // the vulnerability checks, 1..MaxCheckRate
	Exclusions       []string
	FragileKinds     []string
	RegularScanKinds []string
}

// SaveSafety stores the shared block (PRE-5 and INV-6/7 as SaveSettings; at least one day, the check rate 1..20 and at most
// MaxExclusions exclusions on top). The switch of active discovery keeps its stored value; scope_not_confirmed when it is on and the
// attestation is not ticked.
func (s *Service) SaveSafety(ctx context.Context, actor string, in SafetyInput) (SavedSettings, error) {
	if len(in.Exclusions) > MaxExclusions {
		return SavedSettings{}, badRequest("too_many_exclusions", "The exclusion list can have at most 200 lines.")
	}
	if len(in.Days) == 0 {
		return SavedSettings{}, badRequest("no_days", "Choose at least one day for the scan window.")
	}
	if in.RequestsPerS < 1 || in.RequestsPerS > MaxCheckRate {
		return SavedSettings{}, badRequest("bad_rate", "The vulnerability check rate is 1 to 20 requests per second.")
	}
	prev, err := s.Settings(ctx)
	if err != nil {
		return SavedSettings{}, err
	}
	return s.SaveSettings(ctx, actor, SettingsInput{
		Settings: Settings{
			LANRanges: in.LANRanges,
			Active: ActiveWindow{Enabled: prev.Active.Enabled, Days: in.Days, From: in.From, To: in.To, Rate: in.PacketsPerS,
				Exclusions: in.Exclusions, CheckRate: in.RequestsPerS},
			FragileKinds: in.FragileKinds, RegularScanKinds: in.RegularScanKinds,
		},
		ScopeConfirmed: in.Confirmed,
	})
}

// SetDiscovery turns active discovery (active.enabled, the nmap-discovery engine of Settings › Scanning) on or off; the other
// settings keep their values. On needs a range, a day and the confirmed scope (INV-7: 400 no_ranges, no_days, scope_not_confirmed).
// One audit row inventory.settings, then inventory.settings.changed: sensor-active stops a run that may no longer go on.
func (s *Service) SetDiscovery(ctx context.Context, actor string, enabled bool) error {
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		if enabled {
			switch {
			case len(st.LANRanges) == 0:
				return badRequest("no_ranges", "Active scanning needs at least one network range.")
			case len(st.Active.Days) == 0:
				return badRequest("no_days", "Choose at least one day for the scan window, or turn active scanning off.")
			case st.ScopeConfirmedAt == nil:
				return badRequest("scope_not_confirmed", "Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only scans within the confirmed scope.")
			}
		}
		act := st.Active
		act.Enabled = enabled
		if err := putSetting(ctx, tx, "active", act, s.now(), actorOrSystem(actor)); err != nil {
			return err
		}
		state := "off"
		if enabled {
			state = "on"
		}
		if err := s.auditTx(ctx, tx, actor, "inventory.settings", "scan scope", "active scanning "+state); err != nil {
			return err
		}
		o.add(EventSettingsChanged, SettingsEvent{Scope: "scan"})
		return nil
	})
}

// ChecksInput is the part of the shared block PUT /scans/config still writes (#850): the window, the check rate and the exclusions.
type ChecksInput struct {
	Days       []int
	From, To   string
	CheckRate  int
	Exclusions []string // IPv4 or CIDR; host bits are dropped (the scan module accepted them)
}

// SaveChecks writes the window, the check rate and the exclusions inside the caller's write transaction tx: the scan module's PUT
// /scans/config, whose own row and audit row share tx (INV-32). The input passes the rules of INV-7 (a day at least, HH:MM, from ≠
// to) and of the check rate (1..20), at most MaxExclusions exclusions, each an IPv4 address or an IPv4 range (host bits are dropped:
// 192.168.1.5/24 is 192.168.1.0/24, the same addresses). An error is an *apierr.Error. inventory.settings.changed goes out at
// Settle, when tx committed. No audit row of its own: the caller's scan.config row says what changed.
func (s *Service) SaveChecks(ctx context.Context, tx *sql.Tx, actor string, in ChecksInput) error {
	if len(in.Days) == 0 || slices.ContainsFunc(in.Days, func(d int) bool { return d < 1 || d > 7 }) {
		return badRequest("bad_days", "Scan days must be Monday to Sunday.")
	}
	if !hhmmRE.MatchString(in.From) || !hhmmRE.MatchString(in.To) {
		return badRequest("bad_time", "Time must look like 23:00.")
	}
	if in.From == in.To {
		return badRequest("bad_window", "Start and end time cannot be the same.")
	}
	if in.CheckRate < 1 || in.CheckRate > MaxCheckRate {
		return badRequest("bad_rate", "The vulnerability check rate is 1 to 20 requests per second.")
	}
	if len(in.Exclusions) > MaxExclusions {
		return badRequest("too_many_exclusions", "The exclusion list can have at most 200 lines.")
	}
	excl := []string{}
	for _, raw := range in.Exclusions {
		x, ok := normalExclusion(raw)
		if !ok {
			return badRequest("bad_exclusion", `Exclusion "`+clip(strings.TrimSpace(raw), 30)+`" is not valid. Enter an IP (192.168.10.10) or a valid range (192.168.10.0/28).`)
		}
		if !slices.Contains(excl, x) {
			excl = append(excl, x)
		}
	}
	var act ActiveWindow
	if err := loadSetting(ctx, tx, "active", &act); err != nil {
		return err
	}
	act.Days = slices.Compact(slices.Sorted(slices.Values(in.Days)))
	act.From, act.To, act.CheckRate, act.Exclusions = in.From, in.To, in.CheckRate, excl
	if err := putSetting(ctx, tx, "active", act, s.now(), actorOrSystem(actor)); err != nil {
		return err
	}
	var o outbox
	o.add(EventSettingsChanged, SettingsEvent{Scope: "scan"})
	s.keep(tx, &o)
	return nil
}

// normalExclusion is an exclusion as the inventory stores it: an IPv4 address, or an IPv4 range without host bits.
func normalExclusion(raw string) (string, bool) {
	x := strings.TrimSpace(raw)
	if a, ok := ipv4(x); ok {
		return a.String(), true
	}
	if p, err := netip.ParsePrefix(x); err == nil && p.Addr().Is4() {
		return p.Masked().String(), true
	}
	return "", false
}

// LegacyChecks is the scan module's own copy of the window, rate and exclusions (scan_setting) as it stood before #850.
type LegacyChecks struct {
	Days       []int
	From, To   string
	Rate       int // requests per second
	Exclusions []string
	SavedBy    string // who saved it last; "" when nobody did (the defaults of the install)
}

// MergeLegacyChecks is the one-time merge of the scan module's copy into the one store (#850, INV-32), run at every start by
// cmd/vedette and done once: it does nothing when the check rate is stored already. The check rate becomes the scan module's rate
// (DefaultCheckRate when that is out of range); the exclusions become the union of both lists, normalized (nothing that was excluded
// from any engine gets scanned: discovery now also skips what only the vulnerability checks skipped); the window stays the
// inventory's. When a person had saved a different window for the vulnerability checks, one audit row scanning.safety.merged
// names both windows, so the change is visible in the audit log. merged is true when it wrote.
func (s *Service) MergeLegacyChecks(ctx context.Context, in LegacyChecks) (merged bool, err error) {
	err = s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		var act ActiveWindow
		if err := loadSetting(ctx, tx, "active", &act); err != nil {
			return err
		}
		if act.CheckRate != 0 {
			return nil
		}
		act.CheckRate = in.Rate
		if act.CheckRate < 1 || act.CheckRate > MaxCheckRate {
			act.CheckRate = DefaultCheckRate
		}
		excl := slices.Clone(act.Exclusions)
		if excl == nil {
			excl = []string{}
		}
		for _, raw := range in.Exclusions {
			if x, ok := normalExclusion(raw); ok && !slices.Contains(excl, x) {
				excl = append(excl, x)
			}
		}
		added := len(excl) - len(act.Exclusions)
		act.Exclusions = excl
		if err := putSetting(ctx, tx, "active", act, s.now(), systemActor); err != nil {
			return err
		}
		days := slices.Compact(slices.Sorted(slices.Values(in.Days)))
		if in.SavedBy != "" && (!slices.Equal(days, act.Days) || in.From != act.From || in.To != act.To) {
			type window struct {
				Days []int  `json:"days"`
				From string `json:"from"`
				To   string `json:"to"`
			}
			detail, err := json.Marshal(struct {
				Kept      window `json:"kept"`
				Dropped   window `json:"dropped"`
				DroppedBy string `json:"dropped_by"`
				Added     int    `json:"exclusions_added"`
			}{window{act.Days, act.From, act.To}, window{days, in.From, in.To}, in.SavedBy, added})
			if err != nil {
				return fmt.Errorf("inventory: encode the merge detail: %w", err)
			}
			if err := s.auditTx(ctx, tx, systemActor, "scanning.safety.merged", "scan window", string(detail)); err != nil {
				return err
			}
		}
		o.add(EventSettingsChanged, SettingsEvent{Scope: "scan"})
		merged = true
		return nil
	})
	return merged, err
}

// FragileCount is how many devices are fragile now (by type or marked by hand): the count of Devices' fragile filter.
func (s *Service) FragileCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM inv_asset WHERE fragile = 1`).Scan(&n); err != nil {
		return 0, fmt.Errorf("inventory: count fragile devices: %w", err)
	}
	return n, nil
}
