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

// SaveSafety stores the shared block (PRE-5 and INV-6/7 as SaveSettings; at least one day, the check rate 1..20, and more than
// MaxExclusions exclusions only when the list does not grow). The switch of active discovery keeps the value stored when the
// transaction reads it (review #857 L8); scope_not_confirmed when it is on and the attestation is not ticked.
func (s *Service) SaveSafety(ctx context.Context, actor string, in SafetyInput) (SavedSettings, error) {
	if len(in.Days) == 0 {
		return SavedSettings{}, badRequest("no_days", "Choose at least one day for the scan window.")
	}
	if in.RequestsPerS < 1 || in.RequestsPerS > MaxCheckRate {
		return SavedSettings{}, badRequest("bad_rate", "The vulnerability check rate is 1 to 20 requests per second.")
	}
	return s.saveSettings(ctx, actor, SettingsInput{
		Settings: Settings{
			LANRanges: in.LANRanges,
			Active: ActiveWindow{Days: in.Days, From: in.From, To: in.To, Rate: in.PacketsPerS,
				Exclusions: in.Exclusions, CheckRate: in.RequestsPerS},
			FragileKinds: in.FragileKinds, RegularScanKinds: in.RegularScanKinds,
		},
		ScopeConfirmed: in.Confirmed,
	}, saveOpts{keepEnabled: true, capExclusions: true})
}

// AddRange adds one LAN range to the scope (POST /scanning/safety/ranges: "+ New range" where the person is, #842/#850, INV-32). It
// reads, appends and stores in one write transaction, so two adds at once both land and no other edit is overwritten. The range
// passes the rules of a PUT (INV-6: an internal IPv4 range, host bits dropped and reported in Adjusted, at most 16, no overlap);
// confirmed is the attestation of D-26 as a PUT's (400 scope_not_confirmed without it), recorded the same way: the ranges changed,
// so the scope is confirmed by actor now. A range a stored one already covers changes nothing (no audit row, no event) while the
// scope is confirmed; while it is not, the attestation is recorded for the stored ranges, as a PUT of the same ranges would. One
// audit row inventory.settings naming the range, then inventory.settings.changed.
func (s *Service) AddRange(ctx context.Context, actor, raw string, confirmed bool) (SavedSettings, error) {
	one, adjusted, aerr := checkRanges([]string{raw})
	if aerr != nil {
		return SavedSettings{}, aerr
	}
	if len(one) != 1 {
		return SavedSettings{}, badRequest("bad_cidr", "Enter a network range such as 192.168.10.0/24.")
	}
	if !confirmed {
		return SavedSettings{}, badRequest("scope_not_confirmed", "Tick the confirmation that these network ranges belong to your company and you are allowed to scan them. Vedette only scans within the confirmed scope.")
	}
	add := netip.MustParsePrefix(one[0]) // checkRanges returned it parsed and masked
	var saved Settings
	err := s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		prev, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		covered := slices.ContainsFunc(prev.LANRanges, func(r string) bool {
			p, err := netip.ParsePrefix(r)
			return err == nil && p.Bits() <= add.Bits() && p.Contains(add.Addr())
		})
		if covered && prev.ScopeConfirmedAt != nil {
			saved = prev
			return nil
		}
		next := prev
		detail := "confirmed the scope (" + one[0] + " is inside it)"
		if !covered {
			ranges, _, aerr := checkRanges(append(slices.Clone(prev.LANRanges), one[0]))
			if aerr != nil {
				return aerr
			}
			next.LANRanges = ranges
			detail = "added range " + one[0]
		}
		now := s.now()
		at := now
		next.ScopeConfirmedAt, next.ScopeConfirmedBy = &at, nil
		if actor != "" {
			next.ScopeConfirmedBy = &actor
		}
		if err := putSetting(ctx, tx, "lan_ranges", next.LANRanges, now, actorOrSystem(actor)); err != nil {
			return err
		}
		if err := putSetting(ctx, tx, "scope", scopeValue{ConfirmedAt: next.ScopeConfirmedAt, ConfirmedBy: next.ScopeConfirmedBy}, now, actorOrSystem(actor)); err != nil {
			return err
		}
		if err := s.auditTx(ctx, tx, actor, "inventory.settings", "scan scope", detail+": "+strconv.Itoa(len(next.LANRanges))+" ranges, active scanning "+onOff(next.Active.Enabled)); err != nil {
			return err
		}
		o.add(EventSettingsChanged, SettingsEvent{Scope: "scan"})
		saved = next
		return nil
	})
	return SavedSettings{Settings: saved, Adjusted: adjusted}, err
}

// AddExclusion adds one exclusion to the shared list (POST /scanning/safety/exclusions, #842/#850, INV-32) in one write transaction.
// The entry passes the rule of a PUT (an IPv4 address or an IPv4 range without host bits: 400 bad_exclusion); one an exclusion
// already stored covers changes nothing (no audit row, no event); growing the list past MaxExclusions is 409 too_many_exclusions.
// One audit row inventory.settings naming the entry, then inventory.settings.changed. It only narrows what is scanned, so it needs
// no attestation and keeps the scope's.
func (s *Service) AddExclusion(ctx context.Context, actor, raw string) (SavedSettings, error) {
	x, aerr := checkExclusion(raw)
	if aerr != nil {
		return SavedSettings{}, aerr
	}
	add := asPrefix(x)
	var saved Settings
	err := s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		prev, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		if slices.ContainsFunc(prev.Active.Exclusions, func(e string) bool {
			p := asPrefix(e)
			return p.IsValid() && p.Bits() <= add.Bits() && p.Contains(add.Addr())
		}) {
			saved = prev
			return nil
		}
		if len(prev.Active.Exclusions) >= MaxExclusions {
			return conflict("too_many_exclusions", "The exclusion list can have at most 200 lines. Remove one in Settings, Scanning, or exclude a range that covers several.")
		}
		next := prev
		next.Active.Exclusions = append(slices.Clone(prev.Active.Exclusions), x)
		now := s.now()
		if err := putSetting(ctx, tx, "active", next.Active, now, actorOrSystem(actor)); err != nil {
			return err
		}
		if err := s.auditTx(ctx, tx, actor, "inventory.settings", "scan scope", "added exclusion "+x+": "+strconv.Itoa(len(next.Active.Exclusions))+" exclusions"); err != nil {
			return err
		}
		o.add(EventSettingsChanged, SettingsEvent{Scope: "scan"})
		saved = next
		return nil
	})
	return SavedSettings{Settings: saved, Adjusted: []Adjustment{}}, err
}

// asPrefix is an exclusion as the addresses it covers: an address is its /32. The zero Prefix when it is neither.
func asPrefix(x string) netip.Prefix {
	if a, err := netip.ParseAddr(x); err == nil {
		return netip.PrefixFrom(a, a.BitLen())
	}
	p, _ := netip.ParsePrefix(x)
	return p.Masked()
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
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
	// CopySavedAt is the updated_at the caller wrote on its own copy (scan_setting) in the same transaction: the copy is taken in.
	CopySavedAt string
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
	if len(excl) > MaxExclusions && len(excl) > len(act.Exclusions) { // over the limit only when it does not grow (L7)
		return badRequest("too_many_exclusions", "The exclusion list can have at most 200 lines.")
	}
	act.Days = slices.Compact(slices.Sorted(slices.Values(in.Days)))
	act.From, act.To, act.CheckRate, act.Exclusions = in.From, in.To, in.CheckRate, excl
	from := in.CopySavedAt // the caller wrote back what it read, the union of both lists while unmerged, and this stamp (M1)
	act.ChecksMergedFrom = &from
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
	SavedAt    string // when (store timestamp); "" when nobody did
}

// MergeLegacyChecks takes the scan module's own copy into the one store (#850, INV-32). cmd/vedette runs it at every start and it does
// something whenever the copy is not the one last taken in (its updated_at differs from ChecksMergedFrom), or none was: the first start
// after #850, a merge that failed, or a version before #850 that wrote the copy after a rollback (review #857 M1: it can never be
// skipped for good; the union is safe to repeat). The stamps are compared for equality only, never for order (r2 L1). The check rate becomes the copy's (DefaultCheckRate when out of range); the
// exclusions become the union of both lists, normalized and each once (nothing either list excluded gets scanned: discovery also
// skips what only the vulnerability checks skipped); the window stays the inventory's. One audit row scanning.safety.merged names
// both windows and the exclusions added when that changed anything a person sees: a different window a person had saved, or
// exclusions added (L10). merged is true when it wrote.
func (s *Service) MergeLegacyChecks(ctx context.Context, in LegacyChecks) (merged bool, err error) {
	err = s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		var act ActiveWindow
		if err := loadSetting(ctx, tx, "active", &act); err != nil {
			return err
		}
		if act.ChecksMergedFrom != nil && *act.ChecksMergedFrom == in.SavedAt {
			return nil // this very copy was taken in already
		}
		rate := in.Rate
		if rate < 1 || rate > MaxCheckRate {
			rate = DefaultCheckRate
		}
		if act.CheckRate == 0 || in.SavedAt != "" { // a copy a person saved after the last merge is the newer speed
			act.CheckRate = rate
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
		from := in.SavedAt
		act.ChecksMergedFrom = &from
		if err := putSetting(ctx, tx, "active", act, s.now(), systemActor); err != nil {
			return err
		}
		days := slices.Compact(slices.Sorted(slices.Values(in.Days)))
		otherWindow := in.SavedBy != "" && (!slices.Equal(days, act.Days) || in.From != act.From || in.To != act.To)
		if otherWindow || added > 0 {
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
