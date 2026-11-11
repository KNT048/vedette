package response_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/response"
)

// fakeLogs is the logs module's read port: declared sources, a count per (source, signature) and the addresses behind it.
type fakeLogs struct {
	mu        sync.Mutex
	sources   []response.LogSource
	counts    map[string]int                   // source id + "|" + signature
	addrs     map[string][]response.LogAddress // the same key, most first (logs.TopAddresses)
	off       bool
	broken    bool
	topBroken bool
	topOff    bool // the Logs module turned off between Counts and TopAddresses
	windows   []time.Duration
	asked     []int // the n of every TopAddresses
}

func (f *fakeLogs) Sources(context.Context) ([]response.LogSource, error) {
	switch {
	case f.broken:
		return nil, errors.New("logs: reading sources: disk I/O error")
	case f.off: // the adapter answers no source while the module is off
		return nil, nil
	}
	return f.sources, nil
}

func (f *fakeLogs) Counts(_ context.Context, source, signature string, window time.Duration) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.windows = append(f.windows, window)
	return f.counts[source+"|"+signature], nil
}

func (f *fakeLogs) TopAddresses(_ context.Context, source, signature string, _ time.Duration, n int) ([]response.LogAddress, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, n)
	if f.topBroken {
		return nil, errors.New("logs: reading addresses: disk I/O error")
	}
	if f.topOff {
		return nil, response.ErrLogsOff
	}
	a := f.addrs[source+"|"+signature]
	return a[:min(n, len(a))], nil
}

func addr(s string, n int) response.LogAddress {
	return response.LogAddress{Addr: netip.MustParseAddr(s), Count: n}
}

func (e *env) logEvents() []string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT json_extract(fields, '$.source_ip') FROM resp_events WHERE trigger = 'log_threshold' ORDER BY id`)
	e.must(err)
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var ip string
		e.must(rows.Scan(&ip))
		out = append(out, ip)
	}
	e.must(rows.Err())
	slices.Sort(out)
	return out
}

const failedLogon = "4625: Failed logon"

// logRule counts failedLogon in a 5-minute window.
func logRule(n int) func(in *response.RuleInput) {
	win := 5
	return func(in *response.RuleInput) {
		in.Conditions = []response.Condition{{Field: "signature", Op: "count_window", Value: failedLogon, N: &n, WindowMin: &win}}
	}
}

func logEnv(t *testing.T) (*env, *fakeLogs) {
	t.Helper()
	l := &fakeLogs{sources: []response.LogSource{{ID: "ls-fw", Name: "FortiGate"}, {ID: "ls-dc", Name: "DC01"}}, counts: map[string]int{}, addrs: map[string][]response.LogAddress{}}
	return newEnv(t, func(c *response.Config) { c.LogCounts = l }), l
}

// #332, D-287, D-288: a log_threshold rule fires when a declared log source reached N lines of the signature in W minutes, once per
// burst; when no single address sent N of them (spread over many, or lines that name none) the event names the log source only,
// so an action that needs {{trigger.source_ip}} is not available.
func TestLogThresholdFiresFromTheLogCounts(t *testing.T) {
	e, l := logEnv(t)
	e.rule("Failed logons", "log_threshold", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "{{trigger.count}} failed logons on {{trigger.source_device}} in {{trigger.window}} min"}}}, logRule(10))
	e.rule("Ban", "log_threshold", []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.source_ip}}"}, TTLMin: intp(60)}}, logRule(10))
	l.counts["ls-fw|"+failedLogon] = 12
	l.counts["ls-dc|"+failedLogon] = 9 // under the threshold
	e.must(e.svc.PollLogs(e.ctx()))
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE trigger = 'log_threshold'`); n != 1 {
		t.Fatalf("%d log events, want 1 (FortiGate only)", n)
	}
	if len(l.windows) == 0 || l.windows[0] != 5*time.Minute {
		t.Fatalf("windows asked: %v", l.windows)
	}
	sum, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	acts := e.actions()
	if sum.Requests != 1 || sum.Refused != 1 || len(acts) != 1 || acts[0].Items[0].Change.CLI != "notify 12 failed logons on FortiGate in 5 min" {
		t.Fatalf("summary %+v, requests %+v", sum, acts)
	}
	lg, err := e.svc.Log(e.ctx())
	e.must(err)
	refused := false
	for _, l := range lg {
		refused = refused || l.Kind == "refused" && strings.Contains(l.Detail, "Not available: no single address sent at least 10 lines")
	}
	if !refused {
		t.Errorf("the ban was not refused as not available: %+v", lg)
	}
	// While the lines of that burst still count (the window and one 5-minute bucket), no second event, even when the count grows
	// or a fixed period boundary passes; after that, a new one.
	l.counts["ls-fw|"+failedLogon] = 40
	for _, step := range []time.Duration{2 * time.Minute, 4 * time.Minute, 3 * time.Minute} {
		e.clock.Advance(step)
		e.must(e.svc.PollLogs(e.ctx()))
		if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE trigger = 'log_threshold'`); n != 1 {
			t.Fatalf("%d log events for one burst, want 1", n)
		}
	}
	e.clock.Advance(2 * time.Minute)
	e.must(e.svc.PollLogs(e.ctx()))
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE trigger = 'log_threshold'`); n != 2 {
		t.Fatalf("%d log events after the burst left the window, want 2", n)
	}
}

// Two rules on the same signature with different thresholds each see their own event: a rule never fires again on the event
// made for a higher threshold in the same window.
func TestLogThresholdEachThresholdItsOwnEvent(t *testing.T) {
	e, l := logEnv(t)
	msg := []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "{{trigger.count}}"}}}
	e.rule("Ten", "log_threshold", msg, logRule(10))
	e.rule("Twenty", "log_threshold", msg, logRule(20))
	l.counts["ls-fw|"+failedLogon] = 12
	e.must(e.svc.PollLogs(e.ctx()))
	_, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	l.counts["ls-fw|"+failedLogon] = 25
	e.clock.Advance(time.Minute)
	e.must(e.svc.PollLogs(e.ctx()))
	_, err = e.svc.Evaluate(e.ctx())
	e.must(err)
	if got := len(e.actions()); got != 2 {
		t.Fatalf("%d requests, want one per rule", got)
	}
}

// The logs module off (or not wired): no event and no error; the evaluate job goes on.
func TestLogThresholdLogsOff(t *testing.T) {
	e, l := logEnv(t)
	e.rule("Failed logons", "log_threshold", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "x"}}}, logRule(1))
	l.counts["ls-fw|"+failedLogon] = 5
	l.off = true
	e.must(e.svc.PollLogs(e.ctx()))
	l.off, l.broken = false, true
	e.must(e.svc.PollLogs(e.ctx())) // a failure is logged, not returned: the evaluate job goes on
	if n := e.count(`SELECT COUNT(*) FROM resp_events`); n != 0 {
		t.Fatalf("%d events while logs is off or failing", n)
	}
	l.broken = false
	e.clock.Advance(time.Minute)
	e.must(e.svc.PollLogs(e.ctx()))
	if n := e.count(`SELECT COUNT(*) FROM resp_events`); n != 1 {
		t.Fatalf("%d events once logs answers again, want 1", n)
	}
	e2 := newEnv(t)
	e2.must(e2.svc.PollLogs(e2.ctx()))
}

// A log_threshold rule names exactly one signature, counted in 5 to 1440 minutes; a signature is pasted from the digest as it is
// (=, <ip>), and nothing else of a condition value is widened.
func TestLogThresholdRuleChecks(t *testing.T) {
	e, _ := logEnv(t)
	msg := []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "x"}}}
	add := func(conds ...response.Condition) error {
		_, err := e.svc.AddRule(e.ctx(), admin, response.RuleInput{Name: "Log rule", Enabled: true, Trigger: "log_threshold", Match: "all", Conditions: conds, Actions: msg, MaxPerHour: 5})
		return err
	}
	n, w, short := 10, 5, 4
	sig := func(v string, win *int) response.Condition {
		return response.Condition{Field: "signature", Op: "count_window", Value: v, N: &n, WindowMin: win}
	}
	if err := add(sig("logid=0100032002 action=login", &w)); err != nil {
		t.Errorf("a FortiGate signature: %v", err)
	}
	if err := add(sig("Failed password for <name> from <ip> port <n> ssh2", &w)); err != nil {
		t.Errorf("a mined signature: %v", err)
	}
	wantCode(t, add(), 400, "invalid")
	wantCode(t, add(sig(failedLogon, &short)), 400, "invalid")
	wantCode(t, add(sig(failedLogon, &w), sig("4720: A user account was created", &w)), 400, "invalid")
	wantCode(t, add(sig("a\nb", &w)), 400, "invalid")
	r, err := e.svc.AddRule(e.ctx(), admin, response.RuleInput{Name: "Trimmed", Enabled: true, Trigger: "log_threshold", Match: "all", Actions: msg, MaxPerHour: 5,
		Conditions: []response.Condition{sig(" "+failedLogon+"  ", &w)}})
	if err != nil || r.Conditions[0].Value != failedLogon {
		t.Errorf("a pasted signature is not trimmed: %+v %v", r.Conditions, err)
	}
	_, err = e.svc.AddRule(e.ctx(), admin, response.RuleInput{Name: "Any", Enabled: true, Trigger: "log_threshold", Match: "any", Actions: msg, MaxPerHour: 5,
		Conditions: []response.Condition{sig(failedLogon, &w), {Field: "count", Op: "gte", Value: "1"}}})
	wantCode(t, err, 400, "invalid") // "any" would match the events made for other rules' signatures
	_, err = e.svc.AddRule(e.ctx(), admin, response.RuleInput{Name: "Sig text", Enabled: true, Trigger: "log_threshold", Match: "all", MaxPerHour: 5,
		Actions: []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "{{trigger.signature}}"}}}, Conditions: []response.Condition{sig(failedLogon, &w)}})
	wantCode(t, err, 400, "invalid") // device text is compared, never sent
	// other triggers keep the narrow value set
	_, err = e.svc.AddRule(e.ctx(), admin, response.RuleInput{Name: "Other", Enabled: true, Trigger: "honeypot", Match: "all", Actions: msg, MaxPerHour: 5,
		Conditions: []response.Condition{{Field: "decoy", Op: "eq", Value: "a=b"}}})
	wantCode(t, err, 400, "invalid")
}

// #348, D-288: every address that alone sent N lines of the signature in the window is an event of its own with source_ip, so
// a ban rule bans each attacker (fail2ban maxretry, Wazuh same_srcip); an address under N is never banned for the others' lines.
// One burst of one address is one event; a second address reaching N in the same burst is a new event.
func TestLogThresholdBansEachAddressThatReachedTheThreshold(t *testing.T) {
	e, l := logEnv(t)
	e.rule("Ban", "log_threshold", []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.source_ip}}"}, TTLMin: intp(60)}}, logRule(10))
	key := "ls-fw|" + failedLogon
	l.counts[key] = 40
	l.addrs[key] = []response.LogAddress{addr("203.0.113.9", 14), addr("::ffff:198.51.100.7", 11), addr("192.0.2.5", 9), addr("192.0.2.6", 6)}
	e.must(e.svc.PollLogs(e.ctx()))
	if got := e.logEvents(); !slices.Equal(got, []string{"198.51.100.7", "203.0.113.9"}) {
		t.Fatalf("events for %q, want the two addresses over 10 (IPv4-mapped as IPv4) and no source-only event", got)
	}
	if len(l.asked) != 1 || l.asked[0] != 50 {
		t.Fatalf("TopAddresses asked for %v, want 50 once", l.asked)
	}
	_, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	var clis []string
	for _, a := range e.actions() {
		clis = append(clis, a.Items[0].Change.CLI)
	}
	slices.Sort(clis)
	if !slices.Equal(clis, []string{"blocklist add 198.51.100.7", "blocklist add 203.0.113.9"}) {
		t.Fatalf("requests %q", clis)
	}
	// the same burst: no second event for the two; the third address now over 10 is its own event
	l.addrs[key][2].Count = 10
	e.clock.Advance(time.Minute)
	e.must(e.svc.PollLogs(e.ctx()))
	if got := e.logEvents(); !slices.Equal(got, []string{"192.0.2.5", "198.51.100.7", "203.0.113.9"}) {
		t.Fatalf("events %q after a third address reached 10", got)
	}
	// once the burst left the counted window (5 + 5 minutes), the same addresses are new events
	e.clock.Advance(10 * time.Minute)
	e.must(e.svc.PollLogs(e.ctx()))
	if got := e.logEvents(); len(got) != 6 {
		t.Fatalf("events %q after the window, want 6", got)
	}
}

// The addresses could not be read (a failure, not "none"): the count still makes its source-only event, said once as a warning.
// An address with a zone, or not valid, is never an event.
func TestLogThresholdAddressesUnreadable(t *testing.T) {
	e, l := logEnv(t)
	e.rule("Alert", "log_threshold", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "{{trigger.count}} on {{trigger.source_device}} from {{trigger.source_ip}}"}}}, logRule(10))
	key := "ls-fw|" + failedLogon
	l.counts[key] = 12
	l.addrs[key] = []response.LogAddress{{Addr: netip.MustParseAddr("fe80::1%eth0"), Count: 12}, {Count: 12}}
	e.must(e.svc.PollLogs(e.ctx()))
	if got := e.logEvents(); !slices.Equal(got, []string{""}) {
		t.Fatalf("events %q, want one source-only event (a zoned or invalid address is never one)", got)
	}
	e2, l2 := logEnv(t)
	e2.rule("Alert", "log_threshold", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "x"}}}, logRule(10))
	l2.counts[key] = 12
	l2.addrs[key] = []response.LogAddress{addr("203.0.113.9", 12)}
	l2.topBroken = true
	e2.must(e2.svc.PollLogs(e2.ctx()))
	if got := e2.logEvents(); !slices.Equal(got, []string{""}) {
		t.Fatalf("events %q with the addresses unreadable, want one source-only event", got)
	}
}

// The Logs module turned off between the count and the addresses: no event at all, not a source-only one (SYS-5).
func TestLogThresholdLogsOffBeforeTheAddresses(t *testing.T) {
	e, l := logEnv(t)
	e.rule("Alert", "log_threshold", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "x"}}}, logRule(10))
	l.counts["ls-fw|"+failedLogon] = 12
	l.topOff = true
	e.must(e.svc.PollLogs(e.ctx()))
	if got := e.logEvents(); len(got) != 0 {
		t.Fatalf("events %q while the Logs module is off", got)
	}
}
