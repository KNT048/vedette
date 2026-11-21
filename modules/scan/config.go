package scan

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
)

// Window is when scheduled scans may run (INV-5). Days are ISO weekdays, 1 = Monday ... 7 = Sunday.
type Window struct {
	Days []int  `json:"days"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Settings is the scan configuration (contract.ts ScanConfig).
type Settings struct {
	Window             Window   `json:"window"`
	Rate               int      `json:"rate"` // requests per second
	Exclusions         []string `json:"exclusions"`
	StopOnUnresponsive bool     `json:"stop_on_unresponsive"`
	UnresponsiveAfter  int      `json:"unresponsive_after"`
	AutoRescan         bool     `json:"auto_rescan"`
	// Version is the shared block's version read with the window, rate and exclusions above, in the same read (Checks; review #860
	// r2 L3); "" without SharedChecks. Not part of the stored row or of contract.ts ScanConfig.
	Version string `json:"-"`
}

// Patch is a partial PUT /scans/config: a nil field keeps the stored value (POST-3).
type Patch struct {
	Days               []int // nil: keep
	From, To           *string
	Rate               *int
	Exclusions         []string // nil: keep; empty: clear
	StopOnUnresponsive *bool
	UnresponsiveAfter  *int
	AutoRescan         *bool
	DangerousChecks    *bool
	Version            string // the shared block's version the page read (ConfigView.Version); "" = none, no check
}

// Limits of INV-5.
const (
	MaxRate         = 20
	MaxExclusions   = 200
	MinUnresponsive = 2
	MaxUnresponsive = 20
)

var hhmmRE = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

func (p Patch) apply(cur Settings) Settings {
	next := cur
	next.Window.Days = slices.Clone(cur.Window.Days)
	next.Exclusions = slices.Clone(cur.Exclusions)
	if p.Days != nil {
		// stored sorted and once each: [7, 1, 1] and [1, 7] are the same window
		next.Window.Days = slices.Compact(slices.Sorted(slices.Values(p.Days)))
	}
	set(&next.Window.From, p.From)
	set(&next.Window.To, p.To)
	set(&next.Rate, p.Rate)
	if p.Exclusions != nil {
		next.Exclusions = slices.Clone(p.Exclusions)
	}
	set(&next.StopOnUnresponsive, p.StopOnUnresponsive)
	set(&next.UnresponsiveAfter, p.UnresponsiveAfter)
	set(&next.AutoRescan, p.AutoRescan)
	return next
}

func set[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

// validate checks INV-5 on a whole configuration, in the order and with the words of the mock's validateConfig. had is how many
// exclusions the stored configuration held: a list over MaxExclusions passes when it does not grow (the merge of #850 can leave a
// longer one, and a save of something else must still go through: review #857 L7).
func (c Settings) validate(had int) error {
	w := c.Window
	if len(w.Days) == 0 || len(w.Days) > 7 || slices.ContainsFunc(w.Days, func(d int) bool { return d < 1 || d > 7 }) {
		return invalidConfig("Choose at least one day for the scan window.")
	}
	if !hhmmRE.MatchString(w.From) || !hhmmRE.MatchString(w.To) {
		return invalidConfig("Time must look like HH:MM, for example 22:00.")
	}
	if w.From == w.To {
		return invalidConfig("The start and end times must differ. To scan all day, set 00:00 to 23:59.")
	}
	if c.Rate < 1 || c.Rate > MaxRate {
		return invalidConfig("The rate must be 1 to 20 requests per second. A lower rate is safer for old devices.")
	}
	if len(c.Exclusions) > MaxExclusions && len(c.Exclusions) > had {
		return invalidConfig("The exclusion list can have at most 200 lines.")
	}
	for i, e := range c.Exclusions {
		if !validExclusion(e) {
			return invalidConfig("Line %d: \"%s\" is not an IP or network range. For example 192.168.10.5 or 192.168.20.0/24.", i+1, clip(e, 40))
		}
	}
	if c.UnresponsiveAfter < MinUnresponsive || c.UnresponsiveAfter > MaxUnresponsive {
		return invalidConfig("The number of non-responses before auto-stop must be 2 to 20.")
	}
	return nil
}

// validExclusion accepts one IPv4 address or one IPv4 CIDR range in dotted form (netip refuses leading zeros, so
// "010.0.0.1" cannot mean two things). The text is kept as the admin typed it.
func validExclusion(s string) bool {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Is4()
	}
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().Is4()
}

// clip cuts s to n runes for an error message.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// ---- storage ----

// Checks is the part of the settings every LAN engine shares (INV-16): the window, the check rate and the exclusions.
type Checks struct {
	Window     Window
	Rate       int // requests per second
	Exclusions []string
	// Version names the shared block as read (Checks); on SaveChecks it is the one the page read ("" = none: no check), and another
	// one refuses the save with 409 safety_changed (review #860 M1).
	Version string
}

// settings is scan_setting (the module's own: unresponsive limit, auto rescan) with the shared window, check rate and
// exclusions of the inventory, their one home (INV-16).
func (s *Service) settings(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (Settings, error) {
	c, err := loadSettings(ctx, q)
	if err != nil {
		return Settings{}, err
	}
	ch, err := s.cfg.Inventory.Checks(ctx)
	if err != nil {
		return Settings{}, fmt.Errorf("scan: reading the shared window, rate and exclusions: %w", err)
	}
	c.Version = ch.Version
	c.Window = Window{Days: slices.Clone(ch.Window.Days), From: ch.Window.From, To: ch.Window.To}
	c.Rate = ch.Rate
	c.Exclusions = slices.Clone(ch.Exclusions)
	if c.Exclusions == nil {
		c.Exclusions = []string{}
	}
	return c, nil
}

func loadSettings(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (Settings, error) {
	var c Settings
	err := q.QueryRowContext(ctx, `SELECT stop_on_unresponsive, unresponsive_after, auto_rescan
FROM scan_setting WHERE id = 1`).Scan(&c.StopOnUnresponsive, &c.UnresponsiveAfter, &c.AutoRescan)
	if err != nil {
		return Settings{}, fmt.Errorf("scan: reading the settings: %w", err)
	}
	return c, nil
}

func saveSettings(ctx context.Context, tx *sql.Tx, c Settings, user, at string) error {
	_, err := tx.ExecContext(ctx, `UPDATE scan_setting SET stop_on_unresponsive = ?, unresponsive_after = ?, auto_rescan = ?,
updated_at = ?, updated_by = ? WHERE id = 1`,
		c.StopOnUnresponsive, c.UnresponsiveAfter, c.AutoRescan, at, user)
	if err != nil {
		return fmt.Errorf("scan: saving the settings: %w", err)
	}
	return nil
}
