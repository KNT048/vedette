package exposure

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/core/store"
)

// The deep-scan settings of a target (exp_deep_setting): how hard the deep scan may hit it. A person turns groups of checks off,
// slows the scan down, and lists ports and web paths the engines leave alone. The settings only narrow: narrow runs after every
// rule of runMode (the terms, a scheduled scan, carrier-grade NAT), and the deep gate of a domain's address keeps its own rules
// (a typed IP, an address that is not the box's own) on top, so a setting can never turn a group on where those rules say no.
// No row means the defaults below. A value the box cannot read narrows: a toggle counts as off, the speed as gentle, and an
// exclusion list that cannot be parsed makes the run refuse at its check step (a scan never runs without the person's exclusions).

// The speeds of a deep scan.
const (
	SpeedNormal = "normal"
	SpeedGentle = "gentle"
)

// Limits of the exclusion lists (the API refuses more; a stored list over them is unreadable).
const (
	MaxSkipPorts   = 64
	MaxSkipPaths   = 20
	maxSkipPathLen = 200
)

// NotBySettings is the one sentence of a group or step that this target's settings turned off (the run page, every engine).
const NotBySettings = "Turned off in this target's settings."

const notSettings = NotBySettings

// DeepSettings is the deep-scan settings of one target. The toggles say a group may run (still only where the scan's rules allow
// it); SkipPorts and SkipPaths are what every engine, and the web scans, leave out.
type DeepSettings struct {
	DoS        bool     `json:"dos"`
	Logins     bool     `json:"logins"`
	WebActive  bool     `json:"web_active"`
	DataChange bool     `json:"data_change"`
	OpenVAS    bool     `json:"openvas"`
	Speed      string   `json:"speed"`
	SkipPorts  []int    `json:"skip_ports"`
	SkipPaths  []string `json:"skip_paths"`
	// UpdatedAt and UpdatedBy are who saved the row and when; nil while the target has the defaults (no row).
	UpdatedAt *string `json:"updated_at"`
	UpdatedBy *string `json:"updated_by"`
	// Problem says why the stored settings cannot be read as they are; the scan of the target refuses to run until they are saved
	// again. nil when they read fine.
	Problem *string `json:"problem"`
}

// DefaultDeepSettings are the settings of a target without a row: the denial-of-service checks off, everything else on.
func DefaultDeepSettings() DeepSettings {
	return DeepSettings{Logins: true, WebActive: true, DataChange: true, OpenVAS: true, Speed: SpeedNormal, SkipPorts: []int{}, SkipPaths: []string{}}
}

// Groups are the groups d allows.
func (d DeepSettings) Groups() Groups {
	var g Groups
	for _, x := range []struct {
		on bool
		g  Groups
	}{{d.DoS, GroupDoS}, {d.Logins, GroupLogins}, {d.DataChange, GroupChange}, {d.WebActive, GroupWebActive}, {d.OpenVAS, GroupOpenVAS}} {
		if x.on {
			g |= x.g
		}
	}
	return g
}

// Gentle says the scan runs at the gentle speed.
func (d DeepSettings) Gentle() bool { return d.Speed != SpeedNormal }

// deepColumns are the columns of exp_deep_setting d as scanDeep reads them, each in a form that cannot fail to scan: a toggle is
// 1 only when the stored value is exactly 1; the lists and the speed as text.
const deepColumns = `d.target_id IS NOT NULL, d.dos IS 1, d.logins IS 1, d.web_active IS 1, d.data_change IS 1, d.openvas IS 1,
	CAST(d.speed AS TEXT), CAST(d.skip_ports AS TEXT), CAST(d.skip_paths AS TEXT), CAST(d.updated_at AS TEXT), CAST(d.updated_by AS TEXT)`

// deepRow is one read of deepColumns.
type deepRow struct {
	has, dos, logins, web, change, openvas bool
	speed, ports, paths, at, by            sql.NullString
}

func (r *deepRow) dest() []any {
	return []any{&r.has, &r.dos, &r.logins, &r.web, &r.change, &r.openvas, &r.speed, &r.ports, &r.paths, &r.at, &r.by}
}

// settings is the row as settings, failing closed on what it cannot read (narrower, never wider).
func (r deepRow) settings() DeepSettings {
	if !r.has {
		return DefaultDeepSettings()
	}
	d := DeepSettings{DoS: r.dos, Logins: r.logins, WebActive: r.web, DataChange: r.change, OpenVAS: r.openvas, Speed: SpeedGentle,
		SkipPorts: []int{}, SkipPaths: []string{}}
	if r.speed.Valid && r.speed.String == SpeedNormal {
		d.Speed = SpeedNormal
	}
	if r.at.Valid {
		d.UpdatedAt = &r.at.String
	}
	if r.by.Valid {
		d.UpdatedBy = &r.by.String
	}
	var bad []string
	if ports, err := parseSkipPorts(r.ports.String); err != nil {
		bad = append(bad, "the ports to skip: "+err.Error())
	} else {
		d.SkipPorts = ports
	}
	if paths, err := parseSkipPaths(r.paths.String); err != nil {
		bad = append(bad, "the web paths to skip: "+err.Error())
	} else {
		d.SkipPaths = paths
	}
	if len(bad) > 0 {
		p := "The stored deep-scan settings cannot be read (" + strings.Join(bad, "; ") + "). Save them again."
		d.Problem = &p
	}
	return d
}

// parseSkipPorts reads a stored list of ports: a JSON array of whole numbers 1 to 65535, at most MaxSkipPorts.
func parseSkipPorts(raw string) ([]int, error) {
	var ports []int
	if err := json.Unmarshal([]byte(raw), &ports); err != nil {
		return nil, fmt.Errorf("not a list of port numbers")
	}
	return cleanPorts(ports)
}

// parseSkipPaths reads a stored list of web paths: a JSON array of paths validSkipPath accepts, at most MaxSkipPaths.
func parseSkipPaths(raw string) ([]string, error) {
	var paths []string
	if err := json.Unmarshal([]byte(raw), &paths); err != nil {
		return nil, fmt.Errorf("not a list of paths")
	}
	return cleanPaths(paths)
}

// cleanPorts checks a list of ports and returns it sorted, without repeats.
func cleanPorts(in []int) ([]int, error) {
	out := []int{}
	for _, p := range in {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("%d is not a port number (1 to 65535)", p)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if len(out) > MaxSkipPorts {
		return nil, fmt.Errorf("more than %d ports", MaxSkipPorts)
	}
	slices.Sort(out)
	return out, nil
}

// cleanPaths checks a list of paths and returns it without repeats, in its order.
func cleanPaths(in []string) ([]string, error) {
	out := []string{}
	for _, p := range in {
		if err := validSkipPath(p); err != nil {
			return nil, err
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if len(out) > MaxSkipPaths {
		return nil, fmt.Errorf("more than %d paths", MaxSkipPaths)
	}
	return out, nil
}

// validSkipPath accepts a URL path prefix as written: it starts with "/", has at most maxSkipPathLen characters, and holds only the
// characters of a URL path (letters, digits, - . _ ~ % ! & ' , ; = : @ /). It is matched literally, as a prefix, never as a pattern,
// so the characters of a pattern (* ? ^ $ ( ) [ ] { } + | \), a query, a fragment, spaces and control characters are refused.
func validSkipPath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/"):
		return fmt.Errorf("%q does not start with /", clipText(p, 40))
	case len(p) > maxSkipPathLen:
		return fmt.Errorf("a path is longer than %d characters", maxSkipPathLen)
	}
	for _, r := range p {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~%!&',;=:@/", r)
		if !ok {
			return fmt.Errorf("%q holds a character a path to skip cannot have (only letters, digits and - . _ ~ %% ! & ' , ; = : @ /; it is matched as written, not as a pattern)", clipText(p, 40))
		}
	}
	return nil
}

// ---- the groups and the one narrowing point ----

// Groups is a set of the deep-scan groups a target's settings can turn off.
type Groups uint8

// The groups.
const (
	GroupDoS       Groups = 1 << iota // denial-of-service and crash checks
	GroupLogins                       // password guessing and default logins
	GroupChange                       // exploit checks that may change data
	GroupWebActive                    // the active web scan (ZAP)
	GroupOpenVAS                      // OpenVAS for this target
)

// Has says g holds every group of x.
func (g Groups) Has(x Groups) bool { return g&x == x }

// groupNames are the groups in the words of the run page, in their order.
var groupNames = []struct {
	g    Groups
	name string
}{
	{GroupDoS, "denial-of-service checks"},
	{GroupLogins, "password guessing and default logins"},
	{GroupWebActive, "the active web scan"},
	{GroupChange, "exploit checks that may change data"},
	{GroupOpenVAS, "OpenVAS"},
}

// Names are the groups of g in words, in their order.
func (g Groups) Names() []string {
	var out []string
	for _, n := range groupNames {
		if g.Has(n.g) {
			out = append(out, n.name)
		}
	}
	return out
}

// narrow applies a target's deep-scan settings to m, the mode its rules allow: it only clears groups, recording in Off the ones the
// rules allowed and the settings removed, and then Disruptive is DoS || Logins || Change. It is the last step of runMode.
func narrow(m ScanMode, s DeepSettings) ScanMode {
	m = m.norm()
	drop := func(on *bool, keep bool, g Groups) {
		if *on && !keep {
			*on = false
			m.Off |= g
		}
	}
	drop(&m.DoS, s.DoS, GroupDoS)
	drop(&m.Logins, s.Logins, GroupLogins)
	drop(&m.Change, s.DataChange, GroupChange)
	drop(&m.WebActive, s.WebActive, GroupWebActive)
	drop(&m.OpenVAS, s.OpenVAS, GroupOpenVAS)
	return m.norm()
}

// intersect is the settings both targets allow: a domain's address that is also an IP target of the box takes both (the stricter
// of the two, like their terms). The exclusions add up; gentle wins; a problem of either stays.
func intersect(a, b DeepSettings) DeepSettings {
	out := DeepSettings{DoS: a.DoS && b.DoS, Logins: a.Logins && b.Logins, WebActive: a.WebActive && b.WebActive, DataChange: a.DataChange && b.DataChange,
		OpenVAS: a.OpenVAS && b.OpenVAS, Speed: SpeedNormal, Problem: a.Problem}
	if a.Gentle() || b.Gentle() {
		out.Speed = SpeedGentle
	}
	if out.Problem == nil {
		out.Problem = b.Problem
	}
	out.SkipPorts, _ = cleanPorts(append(slices.Clone(a.SkipPorts), b.SkipPorts...))
	if out.SkipPorts == nil { // more than MaxSkipPorts together: every one is still left out
		out.SkipPorts = append(slices.Clone(a.SkipPorts), b.SkipPorts...)
		slices.Sort(out.SkipPorts)
		out.SkipPorts = slices.Compact(out.SkipPorts)
	}
	out.SkipPaths = slices.Clone(a.SkipPaths)
	for _, p := range b.SkipPaths {
		if !slices.Contains(out.SkipPaths, p) {
			out.SkipPaths = append(out.SkipPaths, p)
		}
	}
	return out
}

// Skips says port is one this scan leaves out.
func (t ScanTarget) Skips(port int) bool { return slices.Contains(t.SkipPorts, port) }

// dropSkipped takes the ports this scan leaves out out of what an engine reported: they are not observed, so their stored rows stay
// as they are (no verdict, never closed or retired) and no later engine gets them.
func dropSkipped(st ScanTarget, c Content) Content {
	if len(st.SkipPorts) == 0 {
		return c
	}
	c.Ports = slices.DeleteFunc(c.Ports, func(p PortRow) bool { return st.Skips(p.Port) })
	c.Services = slices.DeleteFunc(c.Services, func(r ServiceRow) bool { return st.Skips(r.Port) })
	c.AdminPanels = slices.DeleteFunc(c.AdminPanels, func(a AdminRow) bool { return st.Skips(a.Port) })
	c.Scripts = slices.DeleteFunc(c.Scripts, func(r ScriptRow) bool { return st.Skips(r.Port) })
	c.webOK = slices.DeleteFunc(c.webOK, func(p WebPage) bool { return st.Skips(p.Port) })
	for ip, ps := range c.Probed {
		c.Probed[ip] = slices.DeleteFunc(slices.Clone(ps), st.Skips)
	}
	return c
}

// ---- the run page ----

// settingsNote is what the check step says of the settings a run uses: "" for the defaults.
func settingsNote(m ScanMode, d DeepSettings) string {
	var parts []string
	if off := m.Off.Names(); len(off) > 0 {
		parts = append(parts, "turned off: "+strings.Join(off, ", "))
	}
	if d.Gentle() {
		parts = append(parts, "speed gentle")
	}
	if len(d.SkipPorts) > 0 {
		ps := make([]string, len(d.SkipPorts))
		for i, p := range d.SkipPorts {
			ps[i] = strconv.Itoa(p)
		}
		parts = append(parts, "ports skipped: "+strings.Join(ps, ", "))
	}
	if len(d.SkipPaths) > 0 {
		parts = append(parts, "web paths skipped: "+strings.Join(d.SkipPaths, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return " This target's settings: " + strings.Join(parts, "; ") + "."
}

// settingsSummary is the settings a run used, as exp_scan.summary keeps them ("settings").
type settingsSummary struct {
	Off       []string `json:"off"`
	Speed     string   `json:"speed"`
	SkipPorts []int    `json:"skip_ports"`
	SkipPaths []string `json:"skip_paths"`
}

func summaryOf(m ScanMode, d DeepSettings) settingsSummary {
	return settingsSummary{Off: nz(m.Off.Names()), Speed: d.Speed, SkipPorts: nz(d.SkipPorts), SkipPaths: nz(d.SkipPaths)}
}

// errSettingsUnreadable refuses the scan of a target whose stored exclusions cannot be read.
func errSettingsUnreadable(t Target) *APIError {
	return apiErr(409, "settings_unreadable", "%s was not scanned: %s", t.Value, *t.Deep.Problem)
}

// ---- the API ----

// DeepSettingsEdit is the body of PUT /exposure/tree/{id}/deep-settings: the whole settings, as the dialog shows them.
type DeepSettingsEdit struct {
	DoS, Logins, WebActive, DataChange, OpenVAS bool
	Speed                                       string
	SkipPorts                                   []int
	SkipPaths                                   []string
}

// errDoSTwoStep refuses turning the denial-of-service checks on without two-step sign-in.
func errDoSTwoStep() *APIError {
	return apiErr(403, "twofa_required", "Turn on two-step sign-in for your account first (My account), then turn the denial-of-service checks on again.")
}

func errSettings(format string, a ...any) *APIError {
	return apiErr(400, "invalid_settings", format, a...)
}

// PutDeepSettings is PUT /exposure/tree/{id}/deep-settings (admin): it stores the target's deep-scan settings, with an
// exposure.deep_settings audit row that says what they were and what they are. Turning the denial-of-service checks on is the one
// change that adds risk over the defaults: it needs two-step sign-in, as the terms do. A scan that runs now takes a group turned
// off at its next engine step (ModeNow) and never one turned on (the run's own mode bounds it); the ports and web paths to skip and
// the speed are read once at its check step, so they apply from the next scan. Nothing is stopped.
func (s *Service) PutDeepSettings(ctx context.Context, who Actor, id string, e DeepSettingsEdit) error {
	if !who.Admin {
		return apiErr(403, "forbidden", "Only an administrator can change the deep-scan settings.")
	}
	if e.Speed != SpeedNormal && e.Speed != SpeedGentle {
		return errSettings("The speed is normal or gentle.")
	}
	ports, err := cleanPorts(e.SkipPorts)
	if err != nil {
		return errSettings("Ports to skip: %s.", err.Error())
	}
	paths, err := cleanPaths(e.SkipPaths)
	if err != nil {
		return errSettings("Web paths to skip: %s.", err.Error())
	}
	t, err := loadTarget(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return err
	}
	method := ""
	if e.DoS && !t.Deep.DoS { // the only change that adds risk: two-step sign-in, as for the terms
		if s.cfg.TwoStep == nil {
			return errDoSTwoStep()
		}
		if method, err = s.cfg.TwoStep(ctx, who.ID); err != nil {
			return fmt.Errorf("checking two-step sign-in: %w", err)
		}
		if method == "" {
			return errDoSTwoStep()
		}
	}
	pj, err := json.Marshal(ports)
	if err != nil {
		return err
	}
	hj, err := json.Marshal(paths)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		t, err := loadTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		if e.DoS && !t.Deep.DoS && method == "" { // turned off by another write meanwhile: this request did not check two-step
			return errDoSTwoStep()
		}
		now := store.FormatTS(s.clock())
		if _, err := tx.ExecContext(ctx, `INSERT INTO exp_deep_setting (target_id, dos, logins, web_active, data_change, openvas, speed, skip_ports, skip_paths, updated_at, updated_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (target_id) DO UPDATE SET dos = excluded.dos, logins = excluded.logins, web_active = excluded.web_active, data_change = excluded.data_change,
			openvas = excluded.openvas, speed = excluded.speed, skip_ports = excluded.skip_ports, skip_paths = excluded.skip_paths, updated_at = excluded.updated_at,
			updated_by = excluded.updated_by`,
			id, boolInt(e.DoS), boolInt(e.Logins), boolInt(e.WebActive), boolInt(e.DataChange), boolInt(e.OpenVAS), e.Speed, string(pj), string(hj), now, who.Email); err != nil {
			return fmt.Errorf("storing the deep-scan settings of %s: %w", t.Value, err)
		}
		after := DeepSettings{DoS: e.DoS, Logins: e.Logins, WebActive: e.WebActive, DataChange: e.DataChange, OpenVAS: e.OpenVAS, Speed: e.Speed, SkipPorts: ports, SkipPaths: paths}
		detail := "before: " + settingsWords(t.Deep) + "; after: " + settingsWords(after)
		if method != "" {
			detail += " (denial-of-service checks turned on with two-step sign-in: " + method + ", user " + who.ID + ")"
		}
		return s.audit(ctx, tx, who.Email, "exposure.deep_settings", t.Value, auditClip(detail))
	})
}

// settingsWords is a whole settings in words, for the audit trail.
func settingsWords(d DeepSettings) string {
	onOff := func(b bool) string { return map[bool]string{true: "on", false: "off"}[b] }
	ports := make([]string, len(d.SkipPorts))
	for i, p := range d.SkipPorts {
		ports[i] = strconv.Itoa(p)
	}
	w := fmt.Sprintf("denial of service %s, logins %s, active web scan %s, data change %s, OpenVAS %s, speed %s, ports skipped [%s], web paths skipped [%s]",
		onOff(d.DoS), onOff(d.Logins), onOff(d.WebActive), onOff(d.DataChange), onOff(d.OpenVAS), d.Speed, strings.Join(ports, " "), strings.Join(d.SkipPaths, " "))
	if d.Problem != nil {
		w += " (unreadable: " + *d.Problem + ")"
	}
	return w
}
