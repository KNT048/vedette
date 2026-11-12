package response

import (
	"context"
	"database/sql"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/events"
)

// The rule engine: events with typed fields -> WHEN/IF/THEN -> planned actions -> one bundled request. Trigger data is
// attacker-controlled: every parameter is resolved from the event and checked by type before it can reach a template.

const hour = time.Hour

// effects are the things to do after a transaction committed: events on the bus and notices to the alert channels.
type effects struct {
	ob    events.Outbox
	after []func(ctx context.Context)
}

func (e *effects) later(f func(ctx context.Context)) { e.after = append(e.after, f) }

func (s *Service) run(ctx context.Context, e *effects) {
	s.flush(ctx, &e.ob)
	for _, f := range e.after {
		f(context.WithoutCancel(ctx))
	}
}

// ---- how many approvers (INV-2) ----

// requiredApprovals is 2 when an item is high risk, or an item touches more targets than the limit, or all items together do.
func requiredApprovals(items []itemRec, st Settings) (int, string) {
	for _, i := range items {
		if i.Risk == RiskHigh {
			return 2, "High-risk actions need two different approvers."
		}
	}
	total := 0
	over := false
	for _, i := range items {
		total += i.Targets
		over = over || i.Targets > st.MultiTargetMax
	}
	if over || total > st.MultiTargetMax {
		return 2, "This request touches " + itoa(total) + " targets, more than the limit of " + itoa(st.MultiTargetMax) + ", so a second approver is needed."
	}
	return 1, ""
}

// ---- planning: resolve, validate, render ----

type planned struct {
	rec itemRec
	key string
}

type planFail struct{ code, msg, title string }

func (s *Service) planAction(a RuleAction, ev Det, why string, cats map[string]catRow, cs conns, never []AllowEntry) (planned, *planFail) {
	cat, ok := cats[a.ActionID]
	title := a.ActionID
	if ok {
		title = cat.Name
	}
	if !ok || !cat.Enabled {
		return planned{}, &planFail{"tool_not_allowed", "the action \"" + title + "\" is not enabled in the action catalog.", title}
	}
	raw := map[ParamType]string{}
	for _, p := range cat.params() {
		raw[p] = strings.TrimSpace(resolveParam(a.Params[string(p)], ev.Fields))
	}
	if ev.Trigger == "log_threshold" && raw[PIP] == "" && slices.Contains(refsIn(a.Params[string(PIP)]), "source_ip") {
		// no single address reached the threshold (D-288): the count is the log source's, spread over many addresses or naming none.
		// Not a bad value: nothing to act on. Other triggers keep INV-10: an empty address is invalid_target.
		n := "N"
		if v, err := strconv.Atoi(ev.Fields["threshold"]); err == nil && v > 0 {
			n = strconv.Itoa(v)
		}
		return planned{}, &planFail{"tool_unavailable", "Not available: no single address sent at least " + n + " lines of this signature in the window (they came from many addresses, or name none), so {{trigger.source_ip}} has no value. Nothing was changed.", title}
	}
	vals, bad := CheckValues(cat.params(), raw)
	if bad != "" {
		return planned{}, &planFail{"invalid_target", bad, title}
	}
	// Never touch the gateway, DNS servers, domain controllers, this box or management addresses. An action that names an
	// address (ip, cidr, domain) and nothing of a device (interface, MAC, VLAN, port) acts on that address only: blocking a bad
	// destination must not be refused because the device that talked to it is a router. An action that names a switch port,
	// a MAC, a VLAN or a port acts on the device the event is about, with or without an address, so the event's subject counts.
	acted := actedOf(vals)
	if !namesAnAddress(vals) || namesADevicePart(vals) {
		acted = dedupe(append(acted, subjectOf(ev.Fields)...))
	}
	if e, hit := firstTouched(never, acted); hit {
		return planned{}, &planFail{"never_touch", cleanLine(strings.Join(acted, " / ")+" matches the never-touch list ("+e.Label+", "+e.Value+").") + " Nothing was changed.", title}
	}
	if why2 := unavailable(cat, cs); why2 != "" {
		return planned{}, &planFail{"tool_unavailable", why2, title}
	}
	var conn *ConnectionInfo
	if c, ok := cs.get(cat.ConnectionID); ok && cat.device() {
		conn = &c
	}
	if cat.device() && cat.usesRuntime("expiry_s") && a.TTLMin == nil { // D-94 (4): {expiry_s} is the undo time in seconds
		return planned{}, &planFail{"tool_unavailable", "Not available: this action needs an undo time, and none is set.", title}
	}
	ch, err := s.buildChange(cat, vals, conn, why, a.TTLMin)
	if err != nil {
		return planned{}, &planFail{"invalid_target", "The action could not be rendered from its template. Nothing was changed.", title}
	}
	first := ""
	if ps := cat.params(); len(ps) > 0 {
		first = vals[ps[0]]
	}
	it := RequestItem{Risk: cat.Risk, Reversible: cat.reversible(), Tool: orStr(cat.Tool, cat.ID), Targets: targetCount(vals), Change: ch, TTLMin: a.TTLMin, Status: ItemPending, ActionID: cat.ID}
	switch cat.ID {
	case "blocklist_add":
		it.Title = "Add " + vals[PIP] + " to the block list"
	case "msg_send":
		it.Title = "Send a message to your alert channels"
	default:
		it.Title = cat.Name + ": " + first
	}
	rec := itemRec{RequestItem: it, Values: map[ParamType]string(vals), Acted: acted, RunTool: cat.Tool, RollbackTool: cat.RollbackTool, ActionFP: actionFP(cat)}
	if cat.device() {
		rec.ConnectorID, rec.Connection, rec.ConnFP, rec.ConnIdent = strp(cat.ConnectionID), strp(conn.Name), connFP(*conn), connIdent(*conn)
		if rec.Exec, err = s.buildExec(cat, vals, conn, a.TTLMin); err != nil {
			return planned{}, &planFail{"invalid_target", "The action could not be rendered from its template. Nothing was changed.", title}
		}
		rec.ExecHash = execHash(rec.Exec)
		if why := rec.Exec.addressProblem(*conn); why != "" { // an action that could never be sent is not available, with the reason (L6)
			return planned{}, &planFail{"tool_unavailable", why, title}
		}
	}
	return planned{rec: rec, key: planKey(rec.RequestItem)}, nil
}

// dedupe drops repeated strings, keeping the first of each.
func dedupe(l []string) []string {
	var out []string
	for _, x := range l {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// subjectOf is the device an event is about: its address (the field is named ip, src_ip or source_ip by trigger) and its MAC,
// as checked canonical values. Values that are not valid addresses are left out: they cannot be on the never-touch list.
func subjectOf(f map[string]string) []string {
	var out []string
	for _, k := range []string{"ip", "src_ip", "source_ip"} {
		if ip, ok := CheckValue(PIP, f[k]); ok {
			out = append(out, ip)
		}
	}
	if mac, ok := CheckValue(PMAC, f["mac"]); ok {
		out = append(out, mac)
	}
	return out
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// namesAnAddress says whether an action's checked values hold an address it acts on (ip, cidr or domain).
func namesAnAddress(v Values) bool {
	for _, p := range []ParamType{PIP, PCIDR, PDomain} {
		if _, ok := v[p]; ok {
			return true
		}
	}
	return false
}

// namesADevicePart says whether the values hold an interface, a MAC, a VLAN or a port: what a device owns, not an address.
func namesADevicePart(v Values) bool {
	for _, p := range []ParamType{PInterface, PMAC, PVLAN, PPort} {
		if _, ok := v[p]; ok {
			return true
		}
	}
	return false
}

func actedOf(v Values) []string {
	var out []string
	for _, p := range []ParamType{PIP, PCIDR, PDomain, PMAC, PInterface} {
		if x, ok := v[p]; ok {
			out = append(out, x)
		}
	}
	return out
}

func firstTouched(never []AllowEntry, acted []string) (AllowEntry, bool) {
	for _, e := range never {
		for _, v := range acted {
			if touches(e.Value, v) {
				return e, true
			}
		}
	}
	return AllowEntry{}, false
}

func targetCount(v Values) int {
	if c, ok := v[PCIDR]; ok {
		return prefixSize(c)
	}
	return 1
}

func planKey(i RequestItem) string {
	rest := ""
	if i.Change.Rest != nil {
		b := ""
		if i.Change.Rest.Body != nil {
			b = *i.Change.Rest.Body
		}
		rest = i.Change.Rest.Method + " " + i.Change.Rest.URL + " " + b
	}
	return i.ActionID + "|" + i.Change.CLI + "|" + rest
}

// openKeys are the (action, target) pairs that are open (pending or approved, not yet run) or in force (executed and not undone).
func openKeys(ctx context.Context, q dbq, now time.Time) (map[string]bool, error) {
	reqs, err := loadReqs(ctx, q, `WHERE status IN ('pending', 'approved', 'executed')`)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range reqs {
		for _, i := range r.recs {
			switch {
			case i.Status == ItemPending && (r.Status == StatusPending || r.Status == StatusApproved):
				out[planKey(i.RequestItem)] = true
			case i.Status == ItemExecuted && (i.RemoveAt == nil || parseTS(*i.RemoveAt).After(now)):
				out[planKey(i.RequestItem)] = true
			}
		}
	}
	return out, nil
}

func maintenanceNow(st Settings, now time.Time) *Window {
	for i, w := range st.Maintenance {
		if !parseTS(w.Start).After(now) && now.Before(parseTS(w.End)) {
			return &st.Maintenance[i]
		}
	}
	return nil
}

// ---- breaker (INV-12) ----

// actionsLastHour counts the actions requested in the last hour, rules and AI together (what the global breaker counts).
func actionsLastHour(ctx context.Context, q dbq, now time.Time) (int, error) {
	reqs, err := loadReqs(ctx, q, `WHERE requested_at >= ?`, now.Add(-hour).UTC().Format("2006-01-02T15:04:05.000Z"))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range reqs {
		n += len(r.recs)
	}
	return n, nil
}

// checkBreaker trips the global breaker when adding more actions would pass the hourly limit: everything pauses until an
// admin resets it. It returns true when the breaker is (now) open. The line and the notice are part of tx and fx.
func (s *Service) checkBreaker(ctx context.Context, tx *sql.Tx, st *Settings, adding int, fx *effects) (bool, error) {
	if st.BreakerTrippedAt != nil {
		return true, nil
	}
	n, err := actionsLastHour(ctx, tx, s.now())
	if err != nil {
		return false, err
	}
	if n+adding <= st.BreakerMaxPerHour {
		return false, nil
	}
	names := s.channelNames(ctx)
	st.BreakerTrippedAt, st.BreakerNotified = strp(s.ts()), names
	if err := s.saveSettings(ctx, tx, *st); err != nil {
		return false, err
	}
	detail := "Circuit breaker tripped: more than " + itoa(st.BreakerMaxPerHour) + " actions in one hour. All rules and AI requests are paused. Notified: " + strings.Join(names, ", ")
	if err := s.step(ctx, tx, "response.breaker", "response", LogBreaker, detail, "system"); err != nil {
		return false, err
	}
	fx.ob.Add(events.Event{Name: EventBreakerTripped, Data: BreakerEvent{MaxPerHour: st.BreakerMaxPerHour, TrippedAt: *st.BreakerTrippedAt}})
	fx.later(func(ctx context.Context) { s.message(ctx, "brk-"+*st.BreakerTrippedAt, "Response paused", detail) })
	return true, nil
}

// ---- firing a rule on an event ----

const breakerMsg = "The circuit breaker is open: too many actions in one hour, so everything is paused. An admin can resume it in Settings, AI response."

// fire runs one rule on one event inside tx. A refusal is a normal outcome: it is logged and counted, not returned.
// It returns the id of the request it created when the rule is live and pre-approved (the caller approves it after the
// commit), otherwise "".
func (s *Service) fire(ctx context.Context, tx *sql.Tx, rule Rule, ev Det, sum *RunSummary, fx *effects) (preID string, err error) {
	actor := "rule:" + oneLine(rule.Name, 80)
	if err := s.step(ctx, tx, "response.rule_fired", rule.ID, LogRuleFired, rule.Name+": "+ev.Summary, actor); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE resp_rules SET last_fired = ? WHERE id = ?`, s.ts(), rule.ID); err != nil {
		return "", err
	}
	no := func(code, msg string) (string, error) {
		sum.Refused++
		return "", s.step(ctx, tx, "response.refused", rule.ID, LogRefused, code+": "+rule.Name+": "+msg, actor)
	}
	st, err := loadSettings(ctx, tx)
	if err != nil {
		return "", err
	}
	if w := maintenanceNow(st, s.now()); w != nil {
		return no("maintenance", "held, maintenance window \""+oneLine(w.Name, 80)+"\" is active. Nothing was requested.")
	}
	if st.BreakerTrippedAt != nil {
		return no("circuit_open", breakerMsg)
	}
	cats, err := s.cats(ctx, tx)
	if err != nil {
		return "", err
	}
	cs, err := s.loadConns(ctx)
	if err != nil {
		return "", err
	}
	never, refusal, err := s.neverTouchOrRefusal(ctx, tx)
	if err != nil {
		return "", err
	}
	if refusal != nil {
		return no(refusal.Code, refusal.Message)
	}
	var plan []planned
	for _, a := range rule.Actions {
		p, f := s.planAction(a, ev, ev.Summary, cats, cs, never)
		if f != nil {
			return no(f.code, f.msg) // fail closed: one bad action refuses the whole run
		}
		plan = append(plan, p)
	}
	// The same target and action already open or in force: nothing new to ask. Duplicates inside one run merge into one.
	open, err := openKeys(ctx, tx, s.now())
	if err != nil {
		return "", err
	}
	seen := map[string]bool{}
	var fresh []planned
	for _, p := range plan {
		if open[p.key] || seen[p.key] {
			continue
		}
		seen[p.key] = true
		fresh = append(fresh, p)
	}
	if len(fresh) == 0 {
		sum.Deduped++
		return "", s.step(ctx, tx, "response.deduped", rule.ID, LogDeduped, rule.Name+": same target and action is already open or in force, merged: "+ev.Summary, actor)
	}
	var lastHour int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM resp_actions WHERE rule_id = ? AND requested_at >= ?`, rule.ID, store2(s.now().Add(-hour))).Scan(&lastHour); err != nil {
		return "", err
	}
	if lastHour >= rule.MaxPerHour {
		return no("rule_rate_limited", "limit of "+itoa(rule.MaxPerHour)+" runs per hour reached.")
	}
	if !rule.Live {
		sum.DryRun++
		var would []string
		for _, p := range fresh {
			would = append(would, p.rec.Title+" ("+firstLine(callFirstLine(p.rec.Change.Rest, p.rec.Change.CLI))+")")
		}
		return "", s.step(ctx, tx, "response.dry_run", rule.ID, LogDryRun, rule.Name+": dry run, nothing was requested or run. Would do: "+strings.Join(would, "; "), actor)
	}
	if open, err := s.checkBreaker(ctx, tx, &st, len(fresh), fx); err != nil {
		return "", err
	} else if open {
		return no("circuit_open", breakerMsg)
	}
	recs := make([]itemRec, len(fresh))
	for i, p := range fresh {
		p.rec.ID = newID("it")
		recs[i] = p.rec
	}
	// A pre-approved rule never stands in for one of two people: when the request needs two approvers (INV-2, for example the
	// limit was lowered after the rule was saved) it is a normal pending request.
	need, _ := requiredApprovals(recs, st)
	held := ""
	switch {
	case rule.PreApproved && need > 1:
		held = "; pre-approval not used, this request needs " + itoa(need) + " approvers"
	case rule.PreApproved && heldForAuto(ev, rule.Actions, recs) != "":
		held = "; pre-approval not used, " + heldForAuto(ev, rule.Actions, recs)
	}
	pre := rule.PreApproved && held == "" && preApprovedProblem(rule.Actions, cats) == ""
	title := rule.Name + ": " + itoa(len(recs)) + " actions"
	if len(recs) == 1 {
		title = recs[0].Title
	}
	name := firstNonEmpty(ev.Fields["device"], ev.Fields["source_device"], ev.Fields["ip"], ev.Fields["source_ip"], "Network")
	r, err := s.createRequest(ctx, tx, st, reqInit{Source: "rule", ProposalID: "rule:" + rule.ID + ":" + ev.ID, RuleID: rule.ID, RuleName: rule.Name, Trigger: rule.Trigger, TriggerSummary: ev.Summary,
		FindingID: ev.FindingID, CVE: ev.CVE, AssetID: ev.AssetID, AssetName: name, Title: title, Recs: recs, Held: held, Quiet: pre}, fx)
	if err != nil {
		return "", err
	}
	sum.Requests++
	if pre {
		return r.ID, nil
	}
	return "", nil
}

func firstNonEmpty(l ...string) string {
	for _, s := range l {
		if s != "" {
			return s
		}
	}
	return ""
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

func store2(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// heldForAuto says why a pre-approved rule must leave this request to a person ("" = it may run it). A port scan of a decoy is seen
// from a SYN alone, so any LAN host can make it name 1.1.1.1 (D-286 (4), review of #304). A known-bad connection is read from a syslog
// line, which a LAN host can forge too (D-213): a hit on a domain only (a DNS forwarder or a proxy is "the device" of every client
// behind it) waits for a person, and so does an action that names the device of the hit, whether the rule puts {{trigger.src_ip}},
// {{trigger.device}} or {{trigger.switch_port}} into any value (text included) or a fixed value equals one of them (D-336). A new
// port's address is the customer's own public address or whatever a name of theirs resolves to, so an action on that address
// (block it, ACL it) waits for a person; a message about it does not (D-384).
func heldForAuto(ev Det, specs []RuleAction, recs []itemRec) string {
	switch {
	case ev.Trigger == "honeypot" && ev.Fields["kind"] == "scan":
		return "the source address of a port scan can be forged, so a person approves it"
	case ev.Trigger == "ioc_connection" && ev.Fields["dest_kind"] != "ip":
		return "the hit names a domain only, so the device it names may be a DNS forwarder or a proxy: a person approves it"
	case ev.Trigger == "ioc_connection" && (namesSource(specs) || slices.ContainsFunc(recs, func(r itemRec) bool { return touchesSource(r.Values, ev) })):
		return "the action is on the device of a syslog line, which can be forged: a person approves it"
	case ev.Trigger == "new_port" && slices.ContainsFunc(recs, func(r itemRec) bool { return actsOnAddr(r.Values, ev.Fields["ip"]) }):
		return "the address of a new port is your own public address or one a name of yours points at (shared hosting, a dangling record): a person approves an action on it"
	}
	return ""
}

// actsOnAddr reports whether an action's address or range values cover addr (D-384): a message that only names it in text does not.
func actsOnAddr(vals map[ParamType]string, addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	if v := vals[PIP]; v != "" && addrOf(v) == a {
		return true
	}
	p, err := netip.ParsePrefix(vals[PCIDR])
	return err == nil && p.Contains(a)
}

// namesSource reports whether a rule's actions put a field of the hit's device into any value, alone or inside text.
func namesSource(specs []RuleAction) bool {
	for _, a := range specs {
		for _, spec := range a.Params {
			if slices.ContainsFunc(refsIn(spec), func(f string) bool { return f == "src_ip" || f == "device" || f == "switch_port" }) {
				return true
			}
		}
	}
	return false
}

// touchesSource reports whether an action's values name the device of a known-bad connection: its address, its name or its switch port.
func touchesSource(vals map[ParamType]string, ev Det) bool {
	for p, v := range vals {
		switch {
		case v == "":
		case p == PIP && v == ev.Fields["src_ip"],
			(p == PName || p == PText) && ev.Fields["device"] != "" && strings.EqualFold(v, ev.Fields["device"]),
			p == PInterface && ev.Fields["switch_port"] != "" && v == ev.Fields["switch_port"]:
			return true
		}
	}
	return false
}

// ---- evaluating events ----

// Evaluate runs the enabled rules on the events that no rule has seen yet. The evaluate job calls it; tests call it directly.
// Each (rule, event) pair is handled once. A pre-approved rule's request is approved after its own transaction committed.
func (s *Service) Evaluate(ctx context.Context) (RunSummary, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return RunSummary{}, err
	}
	var sum RunSummary
	rdb := s.cfg.DB.Reader()
	evs, err := loadEventsUnprocessed(ctx, rdb, 200)
	if err != nil {
		return sum, err
	}
	for _, ev := range evs {
		if err := s.evaluateOne(ctx, ev, &sum); err != nil {
			return sum, err
		}
	}
	return sum, nil
}

func loadEventsUnprocessed(ctx context.Context, q dbq, limit int) ([]Det, error) {
	// oldest first so a rule sees events in the order they happened
	rows, err := q.QueryContext(ctx, `SELECT `+evCols+` FROM resp_events WHERE processed = 0 ORDER BY seq LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Det
	for rows.Next() {
		d, err := scanEv(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Service) evaluateOne(ctx context.Context, ev Det, sum *RunSummary) error {
	rdb := s.cfg.DB.Reader()
	rules, err := loadRules(ctx, rdb)
	if err != nil {
		return err
	}
	var all []Det
	read := false
	for _, rule := range rules {
		if !rule.Enabled || rule.Trigger != ev.Trigger {
			continue
		}
		// The trigger's history only when a rule of that trigger is on: a flood of a trigger no rule watches (spoofed scans) would
		// otherwise read up to maxEvents events for each event of it.
		if !read {
			if all, err = loadEvents(ctx, rdb, `WHERE trigger = ?`, maxEvents, ev.Trigger); err != nil {
				return err
			}
			read = true
		}
		if ok, _ := conditionsOK(rule.RuleInput, ev, all); !ok || !s.storedCondsOK(rule.RuleInput) {
			continue
		}
		var pre string
		var fx effects
		handled := false
		s.mu.Lock()
		err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			fx = effects{}
			var err error
			pre, handled, err = s.handleInTx(ctx, tx, rule.ID, ev, all, sum, &fx)
			return err
		})
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if handled {
			sum.Matched++
		}
		s.run(ctx, &fx)
		if pre != "" {
			s.autoApprove(ctx, pre, rule, sum)
		}
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE resp_events SET processed = 1 WHERE id = ?`, ev.ID)
		return err
	})
}

// handleInTx runs one rule on one event inside tx. The rule may have changed since the caller read it, so its trigger, switch and
// conditions are tested again on the stored rule before anything is recorded: a rule that no longer matches is not run and the
// event is not marked handled for it. handled is true when the pair was new and the rule ran.
func (s *Service) handleInTx(ctx context.Context, tx *sql.Tx, ruleID string, ev Det, all []Det, sum *RunSummary, fx *effects) (pre string, handled bool, err error) {
	cur, ok, err := loadRule(ctx, tx, ruleID)
	if err != nil || !ok || !cur.Enabled || cur.Trigger != ev.Trigger {
		return "", false, err
	}
	if match, _ := conditionsOK(cur.RuleInput, ev, all); !match || !s.storedCondsOK(cur.RuleInput) {
		return "", false, nil
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO resp_done (rule_id, event_id, at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, ruleID, ev.ID, s.ts())
	if err != nil {
		return "", false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", false, nil // already handled
	}
	pre, err = s.fire(ctx, tx, cur, ev, sum, fx)
	return pre, true, err
}

// autoApprove carries out the request of a pre-approved rule (INV-5): no person, via auto. Every other gate still applies.
func (s *Service) autoApprove(ctx context.Context, reqID string, rule Rule, sum *RunSummary) {
	who := Actor{ID: "rule:" + rule.ID, Name: "Rule: " + rule.Name, Email: "rule@vedette", Via: ViaAuto}
	_, err := s.approve(ctx, who, reqID, nil, "", true, nil)
	if err != nil {
		sum.Refused++
		_ = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error { // the request must not stay open
			r, ok, err := loadReq(ctx, tx, reqID)
			if err != nil || !ok || r.Status != StatusPending {
				return err
			}
			r.Status, r.DecidedAt, r.Note = StatusRejected, strp(s.ts()), strp("Pre-approval refused by a safety gate (see the log).")
			for i := range r.recs {
				r.recs[i].Status = ItemSkipped
			}
			return updateReq(ctx, tx, r)
		})
		return
	}
	sum.Executed++
	_ = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE resp_actions SET pre_approved = 1 WHERE id = ?`, reqID)
		return err
	})
}

// RunSchedules fires the enabled schedule rules that are due: one synthetic event per due run.
func (s *Service) RunSchedules(ctx context.Context) error {
	rules, err := s.Rules(ctx)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if !r.Enabled || r.Trigger != "schedule" || r.ScheduleMin == nil {
			continue
		}
		every := time.Duration(*r.ScheduleMin) * time.Minute
		if r.LastFired != nil && s.now().Sub(parseTS(*r.LastFired)) < every {
			continue
		}
		d := Det{ID: "det-sch-" + r.ID + "-" + itoa(int(s.now().Unix()/int64(every.Seconds()))), Trigger: "schedule", TS: s.ts(), Summary: "Scheduled run of " + r.Name,
			Fields: map[string]string{"run_at": strings.Replace(s.ts()[:16], "T", " ", 1), "scope": "whole network"}}
		if err := s.StoreEvent(ctx, d); err != nil {
			return err
		}
		// stamp the rule so a failing run is not retried every tick
		if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE resp_rules SET last_fired = ? WHERE id = ?`, s.ts(), r.ID)
			return err
		}); err != nil {
			return err
		}
	}
	_, err = s.Evaluate(ctx)
	return err
}

// StoreEvent records an event for the triggers to watch. A second event with the same id changes nothing.
func (s *Service) StoreEvent(ctx context.Context, d Det) error {
	if d.Fields == nil {
		d.Fields = map[string]string{}
	}
	var dropped, unlogged int
	var logged bool
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var err error
		logged, unlogged = false, 0
		if _, dropped, err = insertEvent(ctx, tx, d, s.maxBacklog); err != nil || dropped == 0 {
			return err
		}
		// Never a silent loss: the metric counts every drop; the response log (append-only, never pruned) and the warning get one
		// line per dropDropLogEvery with the count since the last line, so a flood of trigger events cannot grow the log by one
		// row per event. ponytail: drops after the last line of a burst are in the metric and in the next line, not in a line of their own.
		s.dropMu.Lock()
		unlogged = s.dropUnlogged + dropped
		due := s.dropLoggedAt.IsZero() || s.now().Sub(s.dropLoggedAt) >= dropLogEvery
		s.dropMu.Unlock()
		if !due {
			return nil
		}
		logged = true
		return s.step(ctx, tx, "response.events_dropped", "response", LogRefused, "event_backlog: "+itoa(unlogged)+" unprocessed trigger event(s) were dropped, oldest first, because more than "+itoa(s.maxBacklog)+" were waiting. Rules did not see them.", "system")
	})
	if err != nil || dropped == 0 {
		return err
	}
	s.dropped.Add(int64(dropped))
	s.dropMu.Lock()
	s.dropUnlogged = unlogged
	if logged {
		s.dropUnlogged, s.dropLoggedAt = 0, s.now()
	}
	s.dropMu.Unlock()
	if logged {
		s.cfg.Log.WarnContext(ctx, "response: the event backlog is full, the oldest unprocessed events were dropped", "dropped", unlogged, "backlog", s.maxBacklog)
	}
	return nil
}

// dropLogEvery is the most often a backlog overflow adds a line to the response log.
const dropLogEvery = time.Minute

// RunManual is POST /response/rules/{id}/manual: run a manual-trigger rule on a chosen device. It still goes through every gate.
func (s *Service) RunManual(ctx context.Context, who Actor, ruleID, assetID string) (RunSummary, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return RunSummary{}, err
	}
	var sum RunSummary
	rule, ok, err := loadRule(ctx, s.cfg.DB.Reader(), ruleID)
	if err != nil {
		return sum, err
	}
	if !ok {
		return sum, fail(http.StatusNotFound, "not_found", "No such rule.")
	}
	if rule.Trigger != "manual" {
		return sum, s.refuse(ctx, fail(http.StatusConflict, "not_manual", "Only a rule with the manual trigger can be run on a chosen device."), rule.ID, who.Email)
	}
	if !rule.Enabled {
		return sum, s.refuse(ctx, fail(http.StatusConflict, "rule_off", "Switch the rule on first."), rule.ID, who.Email)
	}
	if s.cfg.Directory == nil {
		return sum, fail(http.StatusNotFound, "not_found", "No such device.")
	}
	d, ok, err := s.cfg.Directory.Device(ctx, assetID)
	if err != nil {
		return sum, err
	}
	if !ok {
		return sum, fail(http.StatusNotFound, "not_found", "No such device.")
	}
	ev := Det{ID: "det-man-" + rule.ID + "-" + d.ID + "-" + itoa(int(s.now().UnixMilli())), Trigger: "manual", TS: s.ts(), Summary: "Run by " + who.Email + " on " + d.Name,
		DeviceKind: d.Kind, AssetID: d.ID, Fields: map[string]string{"device": d.Name, "ip": d.IP, "mac": d.MAC, "switch_port": ""}}
	sum.Matched++
	var pre string
	var fx effects
	s.mu.Lock()
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		pre, err = s.fire(ctx, tx, rule, ev, &sum, &fx)
		return err
	})
	s.mu.Unlock()
	if err != nil {
		return sum, err
	}
	s.run(ctx, &fx)
	if pre != "" {
		s.autoApprove(ctx, pre, rule, &sum)
	}
	return sum, nil
}

// ---- reads ----

func (s *Service) eventView(d Det, done []string, names map[string]string) EventView {
	v := EventView{ID: d.ID, Trigger: d.Trigger, TS: d.TS, Summary: d.Summary, Fields: d.Fields, DeviceKind: ptrOrNil(d.DeviceKind), HandledBy: []string{}}
	for _, k := range done {
		rid, eid, _ := strings.Cut(k, "\x00")
		if eid == d.ID {
			n := names[rid]
			if n == "" {
				n = "a deleted rule"
			}
			v.HandledBy = append(v.HandledBy, n)
		}
	}
	return v
}

// Events is GET /response/events.
func (s *Service) Events(ctx context.Context) ([]EventView, error) {
	rdb := s.cfg.DB.Reader()
	evs, err := loadEvents(ctx, rdb, "", 60)
	if err != nil {
		return nil, err
	}
	done, err := doneKeys(ctx, rdb)
	if err != nil {
		return nil, err
	}
	rules, err := loadRules(ctx, rdb)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, r := range rules {
		names[r.ID] = r.Name
	}
	out := make([]EventView, len(evs))
	for i, d := range evs {
		out[i] = s.eventView(d, done, names)
	}
	return out, nil
}

// ---- simulation ----

func (s *Service) sampleEvent(trigger string) Det {
	f := map[string]string{}
	if t := s.trigger(trigger); t != nil {
		for _, x := range t.Fields {
			f[x.Key] = x.Example
		}
	}
	return Det{ID: "example-" + trigger, Trigger: trigger, TS: s.ts(), Summary: "Example values from the trigger catalog", Fields: f}
}

// Simulate is POST /response/rules/simulate: render exactly what a live run would do with the latest event of the trigger
// and execute nothing (executed is always 0). The rule can be saved or not.
func (s *Service) Simulate(ctx context.Context, who Actor, in RuleInput, eventID string) (Simulation, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return Simulation{}, err
	}
	rdb := s.cfg.DB.Reader()
	cats, err := s.cats(ctx, rdb)
	if err != nil {
		return Simulation{}, err
	}
	st, err := loadSettings(ctx, rdb)
	if err != nil {
		return Simulation{}, err
	}
	rule, err := s.checkRule(in, cats, st)
	if err != nil {
		return Simulation{}, s.refuse(ctx, err, "response.simulate", who.Email)
	}
	all, err := loadEvents(ctx, rdb, `WHERE trigger = ?`, maxEvents, rule.Trigger)
	if err != nil {
		return Simulation{}, err
	}
	var found *Det
	for i := range all {
		if eventID != "" && all[i].ID == eventID || eventID == "" {
			found = &all[i]
			break
		}
	}
	if eventID != "" && found == nil { // an event of another trigger does not match this rule, but the caller asked for it
		if d, err := loadEvents(ctx, rdb, `WHERE id = ?`, 1, eventID); err == nil && len(d) == 1 {
			found = &d[0]
		}
	}
	var notes []string
	ev := s.sampleEvent(rule.Trigger)
	if found != nil {
		ev = *found
	} else {
		notes = append(notes, "No event of this trigger yet, so the example values from the trigger catalog were used.")
	}
	ok, results := conditionsOK(rule, ev, all)
	if !ok {
		notes = append(notes, "The conditions do not match this event, so a live run would do nothing for it. The steps below show what would happen if it matched.")
	}
	cs, err := s.loadConns(ctx)
	if err != nil {
		return Simulation{}, err
	}
	never, nt, err := s.neverTouchOrRefusal(ctx, rdb)
	if err != nil {
		return Simulation{}, err
	}
	if nt != nil {
		return Simulation{}, s.refuse(ctx, nt, "response.simulate", who.Email)
	}
	steps := []SimStep{}
	var plan []planned
	for _, a := range rule.Actions {
		p, f := s.planAction(a, ev, ev.Summary, cats, cs, never)
		if f == nil {
			plan = append(plan, p)
			ch := p.rec.Change
			steps = append(steps, SimStep{Action: p.rec.Title, Risk: p.rec.Risk, OK: true, Change: &ch})
			continue
		}
		risk := RiskLow
		if c, ok := cats[a.ActionID]; ok {
			risk = c.Risk
		}
		steps = append(steps, SimStep{Action: f.title, Risk: risk, Error: strp(f.msg)})
	}
	if !rule.Live {
		notes = append(notes, "This rule is in dry run: a real match is only logged.")
	}
	if rule.PreApproved {
		if bad := preApprovedProblem(rule.Actions, cats); bad != "" {
			notes = append(notes, bad)
		} else {
			notes = append(notes, "Pre-approved: a live run would carry this out without asking a person.")
			var recs []itemRec
			for _, p := range plan {
				recs = append(recs, p.rec)
			}
			if why := heldForAuto(ev, rule.Actions, recs); why != "" {
				notes = append(notes, "Pre-approval is not used for this event: "+why+".")
			}
		}
	} else {
		notes = append(notes, "Every action needs approval before it runs.")
	}
	open, err := openKeys(ctx, rdb, s.now())
	if err != nil {
		return Simulation{}, err
	}
	if slices.ContainsFunc(plan, func(p planned) bool { return open[p.key] }) {
		notes = append(notes, "One of these actions is already open or in force for this target, so a live run would merge it instead of asking again.")
	}
	if w := maintenanceNow(st, s.now()); w != nil {
		notes = append(notes, "A maintenance window is active: "+oneLine(w.Name, 80)+". Nothing would be requested now.")
	}
	if st.BreakerTrippedAt != nil {
		notes = append(notes, "The circuit breaker is open: nothing would be requested now.")
	}
	recs := make([]itemRec, len(plan))
	for i, p := range plan {
		recs[i] = p.rec
	}
	need, why := requiredApprovals(recs, st)
	if why != "" {
		notes = append(notes, why)
	}
	var evv EventView
	{
		done, _ := doneKeys(ctx, rdb)
		evv = s.eventView(ev, done, nil)
	}
	out := Simulation{Event: &evv, Matched: ok, Conditions: results, Steps: steps, Notes: notes, Approvals: need, Executed: 0}
	if out.Conditions == nil {
		out.Conditions = []SimCondition{}
	}
	var line []string
	for _, st := range steps {
		if st.OK {
			line = append(line, st.Action)
		} else {
			line = append(line, "refused ("+*st.Error+")")
		}
	}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		return s.step(ctx, tx, "response.simulate", rule.Name, LogSimulated, "Simulated \""+rule.Name+"\" with "+ev.ID+": "+strings.Join(line, "; ")+". Nothing was executed.", who.Email)
	})
	return out, err
}
