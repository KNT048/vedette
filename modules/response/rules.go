package response

import (
	"context"
	"database/sql"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Rules: WHEN (trigger with typed fields) -> IF (conditions, at most 10) -> THEN (1 to 6 catalog actions with typed
// parameters). Every new rule starts as a dry run (INV-14d).

const maxRules = 30

var (
	condValueRE = regexp.MustCompile(`^[\w .,:/@#-]{0,200}$`)
	triggerRef  = regexp.MustCompile(`\{\{\s*trigger\.([a-z_]+)\s*\}\}`)
	oneRef      = regexp.MustCompile(`^\{\{\s*trigger\.[a-z_]+\s*\}\}$`)
)

var conditionOps = []string{"eq", "in", "in_cidr", "gte", "lte", "device_type", "count_window", "first_time"}

// logMinWindow is the shortest window of a log_threshold rule: the logs counters are 5-minute buckets (logs.CountsMinWindow).
const logMinWindow = 5

// logSignature reports whether c is the counted signature of a log_threshold rule (D-287): its value is a signature of the
// Logs digest, compared and counted, never filled into an action.
func logSignature(trigger string, c Condition) bool {
	return trigger == "log_threshold" && c.Op == "count_window" && c.Field == "signature"
}

func refsIn(spec string) []string {
	var out []string
	for _, m := range triggerRef.FindAllStringSubmatch(spec, -1) {
		out = append(out, m[1])
	}
	return out
}

// resolveParam replaces each reference by the event value (empty when the event has none). Whatever comes out is
// checked by type afterwards: the event value is attacker-controlled.
func resolveParam(spec string, fields map[string]string) string {
	return triggerRef.ReplaceAllStringFunc(spec, func(m string) string {
		return fields[triggerRef.FindStringSubmatch(m)[1]]
	})
}

func invalid(msg string) error { return fail(http.StatusBadRequest, "invalid", msg) }

func compatible(p ParamType, fieldType string) bool { return fieldType == string(p) || p == PText }

// checkRule validates a rule a client sent. cats are the catalog actions by id, st the settings (the limit of the pre-approval).
func (s *Service) checkRule(b RuleInput, cats map[string]catRow, st Settings) (RuleInput, error) {
	if !catTextRE.MatchString(b.Name) {
		return b, invalid("Name: 1 to 80 letters, numbers, spaces and . , : ' ( ) / -")
	}
	trig := s.trigger(b.Trigger)
	switch {
	case trig == nil:
		return b, invalid("Choose a trigger (WHEN).")
	case b.Match != "all" && b.Match != "any":
		return b, invalid("Choose whether all or any of the conditions must match.")
	case b.MaxPerHour < 1 || b.MaxPerHour > 100:
		return b, invalid("Maximum actions per hour must be 1 to 100.")
	}
	if b.Trigger == "schedule" {
		if b.ScheduleMin == nil || *b.ScheduleMin < 15 || *b.ScheduleMin > 10080 {
			return b, invalid("Schedule: run every 15 minutes to 7 days.")
		}
	} else if b.ScheduleMin != nil {
		return b, invalid("Only the schedule trigger has a run interval.")
	}
	if len(b.Conditions) > 10 {
		return b, invalid("Up to 10 conditions.")
	}
	conds := make([]Condition, 0, len(b.Conditions))
	for _, c := range b.Conditions {
		if !slices.Contains(conditionOps, c.Op) {
			if c.Op == "" {
				return b, invalid("Each condition needs a field, a test and a value.")
			}
			return b, invalid("Unknown condition test.")
		}
		if c.Op == "device_type" {
			for k := range strings.SplitSeq(c.Value, ",") {
				if !s.isDeviceKind(strings.TrimSpace(k)) {
					return b, invalid("Device type: use device types such as camera, nvr, iot.")
				}
			}
		} else if !slices.ContainsFunc(trig.Fields, func(f TriggerField) bool { return f.Key == c.Field }) {
			return b, invalid("The field \"" + oneLine(c.Field, 30) + "\" does not exist for this trigger.")
		}
		if logSignature(b.Trigger, c) {
			c.Value = strings.TrimSpace(c.Value)                   // logs.Counts hashes the exact text: a pasted trailing space would never count
			if c.Value != oneLine(c.Value, 200) || c.Value == "" { // pasted from the Logs digest as it is (=, <ip>); only compared, never filled
				return b, invalid("Log signature: one line of up to 200 characters, as the Logs digest shows it.")
			}
		} else if !condValueRE.MatchString(c.Value) {
			return b, invalid("Condition values: letters, numbers and . , : / @ # - only.")
		}
		switch c.Op {
		case "in_cidr":
			if _, err := netip.ParsePrefix(c.Value); err != nil {
				return b, invalid("In range: give a CIDR range such as 192.168.10.0/24.")
			}
		case "gte", "lte":
			if _, err := strconv.ParseFloat(c.Value, 64); err != nil || c.Value == "" {
				return b, invalid("At least / at most: give a number.")
			}
		case "count_window":
			if c.N == nil || *c.N < 1 || *c.N > 1000 || c.WindowMin == nil || *c.WindowMin < 1 || *c.WindowMin > 1440 {
				return b, invalid("Count in window: give how many (1 to 1000) and the minutes (1 to 1440).")
			}
		case "first_time":
			if c.N == nil || *c.N < 1 || *c.N > 720 {
				return b, invalid("First time: give the hours (1 to 720).")
			}
		}
		x := Condition{Field: c.Field, Op: c.Op, Value: c.Value}
		if c.Op == "count_window" || c.Op == "first_time" {
			x.N = c.N
		}
		if c.Op == "count_window" {
			x.WindowMin = c.WindowMin
		}
		conds = append(conds, x)
	}
	if b.Trigger == "log_threshold" {
		var sigs []Condition
		for _, c := range conds {
			if logSignature(b.Trigger, c) {
				sigs = append(sigs, c)
			}
		}
		if b.Match != "all" {
			return b, invalid("A log rule matches all of its conditions: the counted signature always applies.")
		}
		if len(sigs) != 1 || *sigs[0].WindowMin < logMinWindow {
			return b, invalid("A log rule needs exactly one condition \"signature seen at least N times within W minutes\", with W from 5 to 1440 minutes (the log counters are 5 minutes wide).")
		}
	}
	if len(b.Actions) < 1 || len(b.Actions) > 6 {
		return b, invalid("Add 1 to 6 actions (THEN).")
	}
	acts := make([]RuleAction, 0, len(b.Actions))
	for _, a := range b.Actions {
		cat, ok := cats[a.ActionID]
		if !ok {
			return b, invalid("Choose an action from the catalog.")
		}
		params := map[string]string{}
		for _, p := range cat.params() {
			spec := strings.TrimSpace(a.Params[string(p)])
			if spec == "" || len(spec) > 200 {
				return b, invalid("Action \"" + cat.Name + "\": fill in {" + string(p) + "}.")
			}
			refs := refsIn(spec)
			for _, r := range refs {
				i := slices.IndexFunc(trig.Fields, func(f TriggerField) bool { return f.Key == r })
				if i < 0 {
					return b, invalid("Action \"" + cat.Name + "\": the trigger has no field \"" + oneLine(r, 30) + "\".")
				}
				if b.Trigger == "log_threshold" && r == "signature" { // a signature is device text (=, <ip>): compared, never sent (D-287)
					return b, invalid("Action \"" + cat.Name + "\": the log signature cannot be used in an action; use {{trigger.count}}, {{trigger.window}} or {{trigger.source_device}}.")
				}
				if ft := trig.Fields[i].Type; !compatible(p, ft) {
					return b, invalid("Action \"" + cat.Name + "\": {" + string(p) + "} needs a field of type " + string(p) + ", but " + r + " is " + ft + ".")
				}
			}
			switch {
			case len(refs) > 0:
				if p != PText && !oneRef.MatchString(spec) {
					return b, invalid("Action \"" + cat.Name + "\": {" + string(p) + "} must be exactly one trigger field or a fixed value, not a mix.")
				}
			default:
				v, ok := CheckValue(p, spec)
				if !ok {
					return b, invalid("Action \"" + cat.Name + "\": \"" + oneLine(spec, 40) + "\" is not a valid " + string(p) + " value.")
				}
				spec = v
			}
			params[string(p)] = spec
		}
		if a.TTLMin != nil && (*a.TTLMin < 5 || *a.TTLMin > 43200) {
			return b, invalid("Undo after: 5 minutes to 30 days.")
		}
		acts = append(acts, RuleAction{ActionID: cat.ID, Params: params, TTLMin: a.TTLMin})
	}
	if b.PreApproved {
		if bad := preApprovedProblem(acts, cats); bad != "" {
			return b, invalid(bad)
		}
		// A pre-approved rule is never one of two approvers (INV-2): refuse a rule whose request would already need two people.
		// A range that comes from the event is only known when the rule runs; fire refuses it then.
		items := make([]itemRec, len(acts))
		for i, a := range acts {
			n := 1
			if spec := a.Params[string(PCIDR)]; spec != "" && len(refsIn(spec)) == 0 {
				if c, ok := CheckValue(PCIDR, spec); ok {
					n = prefixSize(c)
				}
			}
			items[i] = itemRec{RequestItem: RequestItem{Risk: cats[a.ActionID].Risk, Targets: n}}
		}
		if n, why := requiredApprovals(items, st); n > 1 {
			return b, invalid("Pre-approved is only for a request that one person can approve. " + why)
		}
	}
	return RuleInput{Name: b.Name, Enabled: b.Enabled, Live: b.Live, Trigger: b.Trigger, Match: b.Match, Conditions: conds, Actions: acts,
		PreApproved: b.PreApproved, MaxPerHour: b.MaxPerHour, ScheduleMin: b.ScheduleMin}, nil
}

// preApprovedProblem is "" when a rule may be pre-approved: only low-risk, reversible actions with an undo time of 24
// hours or less (INV-5, FORBID-3). It is checked on save and again every time the rule runs.
func preApprovedProblem(acts []RuleAction, cats map[string]catRow) string {
	for _, a := range acts {
		c, ok := cats[a.ActionID]
		switch {
		case !ok:
			return "Pre-approved: an action is missing from the catalog."
		case c.Risk != RiskLow:
			return "Pre-approved is only for low-risk actions. \"" + c.Name + "\" is " + string(c.Risk) + " risk."
		case !c.reversible():
			return "Pre-approved is only for actions that can be undone. \"" + c.Name + "\" cannot."
		case a.TTLMin == nil || *a.TTLMin > 1440:
			return "Pre-approved needs an undo time of 24 hours or less for \"" + c.Name + "\"."
		}
	}
	return ""
}

func catMap(l []catRow) map[string]catRow {
	m := make(map[string]catRow, len(l))
	for _, c := range l {
		m[c.ID] = c
	}
	return m
}

// ---- conditions (IF) ----

func lc(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func csvList(v string) []string {
	var out []string
	for p := range strings.SplitSeq(v, ",") {
		if p = lc(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// evalCondition is the pure test of one condition. others are the other events of the same trigger (for the counting tests).
func evalCondition(c Condition, ev Det, others []Det) bool {
	f := ev.Fields[c.Field]
	switch c.Op {
	case "eq":
		return lc(f) == lc(c.Value)
	case "in":
		return slices.Contains(csvList(c.Value), lc(f))
	case "in_cidr":
		p, err := netip.ParsePrefix(c.Value)
		a, err2 := netip.ParseAddr(f)
		return err == nil && err2 == nil && p.Contains(a.Unmap())
	case "gte", "lte":
		x, e1 := strconv.ParseFloat(f, 64)
		y, e2 := strconv.ParseFloat(c.Value, 64)
		if f == "" || e1 != nil || e2 != nil {
			return false
		}
		return (c.Op == "gte" && x >= y) || (c.Op == "lte" && x <= y)
	case "device_type":
		return ev.DeviceKind != "" && slices.Contains(csvList(c.Value), lc(ev.DeviceKind))
	case "count_window":
		if logSignature(ev.Trigger, c) { // the event is the count itself, made by PollLogs for this signature, window and threshold
			return f != "" && f == c.Value && ev.Fields["window"] == itoa(intOr(c.WindowMin, 0)) && ev.Fields["threshold"] == itoa(intOr(c.N, 0))
		}
		end := parseTS(ev.TS)
		start := end.Add(-time.Duration(intOr(c.WindowMin, 0)) * time.Minute)
		same := 1
		for _, o := range others {
			if t := parseTS(o.TS); o.ID != ev.ID && lc(o.Fields[c.Field]) == lc(f) && !t.Before(start) && !t.After(end) {
				same++
			}
		}
		return f != "" && same >= intOr(c.N, 1)
	case "first_time":
		end := parseTS(ev.TS)
		start := end.Add(-time.Duration(intOr(c.N, 1)) * time.Hour)
		for _, o := range others {
			if t := parseTS(o.TS); o.ID != ev.ID && lc(o.Fields[c.Field]) == lc(f) && !t.Before(start) && t.Before(end) {
				return false
			}
		}
		return f != ""
	}
	return false
}

func intOr(p *int, d int) int {
	if p == nil {
		return d
	}
	return *p
}

func condText(c Condition) string {
	f := c.Field
	if f == "" {
		f = "device"
	}
	switch c.Op {
	case "eq":
		return f + " is " + c.Value
	case "in":
		return f + " is one of " + c.Value
	case "in_cidr":
		return f + " is inside " + c.Value
	case "gte":
		return f + " is at least " + c.Value
	case "lte":
		return f + " is at most " + c.Value
	case "device_type":
		return "device type is one of " + c.Value
	case "count_window":
		return f + " seen at least " + itoa(intOr(c.N, 0)) + " times within " + itoa(intOr(c.WindowMin, 0)) + " minutes"
	case "first_time":
		return "first time " + f + " is seen in " + itoa(intOr(c.N, 0)) + " hours"
	}
	return c.Op
}

func conditionsOK(r RuleInput, ev Det, all []Det) (bool, []SimCondition) {
	var others []Det
	for _, d := range all {
		if d.Trigger == r.Trigger {
			others = append(others, d)
		}
	}
	res := make([]SimCondition, len(r.Conditions))
	okAll, okAny := true, false
	for i, c := range r.Conditions {
		ok := evalCondition(c, ev, others)
		res[i] = SimCondition{Text: condText(c), OK: ok}
		okAll, okAny = okAll && ok, okAny || ok
	}
	if len(res) == 0 {
		return true, res
	}
	if r.Match == "all" {
		return okAll, res
	}
	return okAny, res
}

// ---- rules service ----

// Triggers is GET /response/triggers.
func (s *Service) Triggers(ctx context.Context) ([]TriggerInfo, error) {
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return nil, err
	}
	out := make([]TriggerInfo, len(s.triggers))
	for i, t := range s.triggers {
		out[i] = TriggerInfo{ID: t.ID, Name: t.Name, Description: t.Description, Fields: t.Fields, AIAllowed: slices.Contains(st.AI.Triggers, t.ID)}
	}
	return out, nil
}

// Rules is GET /response/rules.
func (s *Service) Rules(ctx context.Context) ([]Rule, error) {
	return loadRules(ctx, s.cfg.DB.Reader())
}

func (s *Service) cats(ctx context.Context, q dbq) (map[string]catRow, error) {
	l, err := loadCatalog(ctx, q)
	return catMap(l), err
}

// AddRule is POST /response/rules. A new rule always starts in dry run.
func (s *Service) AddRule(ctx context.Context, who Actor, in RuleInput) (Rule, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return Rule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out Rule
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		cats, err := s.cats(ctx, tx)
		if err != nil {
			return err
		}
		in.Live = false // INV-14d
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		c, err := s.checkRule(in, cats, st)
		if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM resp_rules`).Scan(&n); err != nil {
			return err
		}
		if n >= maxRules {
			return fail(http.StatusConflict, "limit", "Up to 30 rules.")
		}
		out = Rule{ID: newID("rule"), RuleInput: c}
		args := append([]any{out.ID}, ruleArgs(out)...)
		if _, err := tx.ExecContext(ctx, `INSERT INTO resp_rules (id, name, enabled, live, trigger, match, conditions, actions, pre_approved, max_per_hour, schedule_min) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...); err != nil {
			return err
		}
		return s.step(ctx, tx, "response.rule.add", out.ID, LogSettings, "Rule added in dry run: "+out.Name+" ("+out.Trigger+", "+itoa(len(out.Actions))+" action(s), "+onOff(out.Enabled, "on", "off")+flagIf(out.PreApproved, ", PRE-APPROVED")+")", who.Email)
	})
	if err != nil {
		return Rule{}, s.refuse(ctx, err, "response.rule", who.Email)
	}
	return out, nil
}

// ChangeRule is PUT /response/rules/{id}: change a rule, switch it on or off, or from dry run to live.
func (s *Service) ChangeRule(ctx context.Context, who Actor, id string, in RuleInput) (Rule, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return Rule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out Rule
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		old, ok, err := loadRule(ctx, tx, id)
		if err != nil {
			return err
		}
		if !ok {
			return fail(http.StatusNotFound, "not_found", "No such rule.")
		}
		cats, err := s.cats(ctx, tx)
		if err != nil {
			return err
		}
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		c, err := s.checkRule(in, cats, st)
		if err != nil {
			return err
		}
		out = Rule{ID: id, RuleInput: c, TemplateID: old.TemplateID, LastFired: old.LastFired}
		args := append(ruleArgs(out), id)
		if _, err := tx.ExecContext(ctx, `UPDATE resp_rules SET name = ?, enabled = ?, live = ?, trigger = ?, match = ?, conditions = ?, actions = ?, pre_approved = ?, max_per_hour = ?, schedule_min = ? WHERE id = ?`, args...); err != nil {
			return err
		}
		return s.step(ctx, tx, "response.rule.change", id, LogSettings, "Rule changed: "+out.Name+" ("+out.Trigger+", "+onOff(out.Live, "LIVE", "dry run")+", "+onOff(out.Enabled, "on", "off")+flagIf(out.PreApproved, ", PRE-APPROVED")+")", who.Email)
	})
	if err != nil {
		return Rule{}, s.refuse(ctx, err, id, who.Email)
	}
	return out, nil
}

// DeleteRule is DELETE /response/rules/{id}.
func (s *Service) DeleteRule(ctx context.Context, who Actor, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		old, ok, err := loadRule(ctx, tx, id)
		if err != nil {
			return err
		}
		if !ok {
			return fail(http.StatusNotFound, "not_found", "No such rule.")
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM resp_rules WHERE id = ?`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM resp_done WHERE rule_id = ?`, id); err != nil {
			return err
		}
		return s.step(ctx, tx, "response.rule.delete", id, LogSettings, "Rule deleted: "+old.Name, who.Email)
	})
	if err != nil {
		return s.refuse(ctx, err, id, who.Email)
	}
	return nil
}

// Templates is GET /response/templates.
func (s *Service) Templates(ctx context.Context) ([]Template, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return nil, err
	}
	cats, err := s.cats(ctx, s.cfg.DB.Reader())
	if err != nil {
		return nil, err
	}
	st, err := loadSettings(ctx, s.cfg.DB.Reader())
	if err != nil {
		return nil, err
	}
	out := make([]Template, len(s.templates))
	for i, t := range s.templates {
		var items []itemRec
		for _, a := range t.Rule.Actions {
			items = append(items, itemRec{RequestItem: RequestItem{Risk: cats[a.ActionID].Risk, Targets: 1}})
		}
		n, _ := requiredApprovals(items, st)
		out[i] = Template{ID: t.ID, Name: t.Name, Description: s.templateText(t), Trigger: t.Rule.Trigger, Risk: maxRisk(items), Approvals: n, Rule: t.Rule}
	}
	return out, nil
}

// templateText: a template that uses a not-yet-verified action says so in the gallery, like the action does.
func (s *Service) templateText(t templateDef) string {
	for _, a := range t.Rule.Actions {
		for _, b := range s.cat {
			if b.ID == a.ActionID && b.Unverified {
				return t.Description + " " + s.catNote + "."
			}
		}
	}
	return t.Description
}

// Clone is POST /response/templates/{id}/clone: a new rule that is switched off and in dry run.
func (s *Service) Clone(ctx context.Context, who Actor, id string) (Rule, error) {
	var tpl *templateDef
	for i := range s.templates {
		if s.templates[i].ID == id {
			tpl = &s.templates[i]
		}
	}
	if tpl == nil {
		return Rule{}, fail(http.StatusNotFound, "not_found", "No such template.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out Rule
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM resp_rules`).Scan(&n); err != nil {
			return err
		}
		if n >= maxRules {
			return fail(http.StatusConflict, "limit", "Up to 30 rules.")
		}
		r := tpl.Rule
		r.Enabled, r.Live, r.PreApproved = false, false, false
		out = Rule{ID: newID("rule"), RuleInput: r, TemplateID: &tpl.ID}
		args := append([]any{out.ID}, ruleArgs(out)...)
		args = append(args, tpl.ID)
		if _, err := tx.ExecContext(ctx, `INSERT INTO resp_rules (id, name, enabled, live, trigger, match, conditions, actions, pre_approved, max_per_hour, schedule_min, template_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...); err != nil {
			return err
		}
		return s.step(ctx, tx, "response.rule.add", out.ID, LogSettings, "Rule cloned from template \""+tpl.Name+"\": switched off, dry run", who.Email)
	})
	if err != nil {
		return Rule{}, s.refuse(ctx, err, "response.rule", who.Email)
	}
	return out, nil
}

// ---- never-touch list ----

const maxAllow = 100

// Allowlist is GET /response/allowlist: the declared entries plus the box's own addresses, which always count.
func (s *Service) Allowlist(ctx context.Context) ([]AllowEntry, error) {
	return s.neverTouch(ctx, s.cfg.DB.Reader())
}

// SetAllowlist is PUT /response/allowlist: replace the declared entries. The box's own addresses are not stored: they
// always count.
func (s *Service) SetAllowlist(ctx context.Context, who Actor, in []AllowEntry) ([]AllowEntry, error) {
	box := map[string]bool{}
	addrs, err := s.boxAddrs()
	if err != nil {
		return nil, err
	}
	for _, e := range boxEntries(addrs) {
		box[e.Value] = true
	}
	var clean []AllowEntry
	seen := map[string]bool{}
	if len(in) > maxAllow {
		err = invalid("Each entry needs an IP address, CIDR range or domain, and a label of up to 80 characters (up to 100 entries).")
	}
	for _, e := range in {
		v, ok := ValidAllowValue(e.Value)
		if !ok || len(e.Label) > 80 {
			err = invalid("Each entry needs an IP address, CIDR range or domain, and a label of up to 80 characters (up to 100 entries).")
			break
		}
		if seen[v] || box[v] {
			continue
		}
		seen[v] = true
		clean = append(clean, AllowEntry{Value: v, Label: oneLine(e.Label, 80)})
	}
	if err != nil {
		return nil, s.refuse(ctx, err, "response.allowlist", who.Email)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM resp_allowlist`); err != nil {
			return err
		}
		for _, e := range clean {
			if _, err := tx.ExecContext(ctx, `INSERT INTO resp_allowlist (value, label) VALUES (?, ?)`, e.Value, e.Label); err != nil {
				return err
			}
		}
		names := make([]string, len(clean))
		for i, e := range clean {
			names[i] = e.Value
		}
		return s.step(ctx, tx, "response.allowlist", "response", LogSettings, "Never-touch list saved: "+joinNonEmpty(names...)+onEmpty(len(clean), "empty"), who.Email)
	})
	if err != nil {
		return nil, err
	}
	return s.neverTouch(ctx, s.cfg.DB.Reader())
}

func onEmpty(n int, s string) string {
	if n == 0 {
		return s
	}
	return ""
}
