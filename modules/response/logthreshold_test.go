package response_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/response"
)

// fakeLogs is the logs module's read port: declared sources and a count per (source, signature).
type fakeLogs struct {
	mu      sync.Mutex
	sources []response.LogSource
	counts  map[string]int // source id + "|" + signature
	off     bool
	broken  bool
	windows []time.Duration
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
	l := &fakeLogs{sources: []response.LogSource{{ID: "ls-fw", Name: "FortiGate"}, {ID: "ls-dc", Name: "DC01"}}, counts: map[string]int{}}
	return newEnv(t, func(c *response.Config) { c.LogCounts = l }), l
}

// #332, D-287: a log_threshold rule fires when a declared log source reached N lines of the signature in W minutes, once per
// window; the event names the log source, not an address, so an action that needs {{trigger.source_ip}} is not available.
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
		refused = refused || l.Kind == "refused" && strings.Contains(l.Detail, "Not available: this event has no value for {{trigger.source_ip}}")
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
