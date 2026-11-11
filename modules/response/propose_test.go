package response_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/response"
)

// WP-13b slice 13b-10 (D-97, INV-15, INV-16, FORBID-5): AI proposals through the Go port as the service identity ai:response.

// evFake stands in for the logs and core/conn lookups. Ids it does not know are not found.
type evFake struct {
	mu  sync.Mutex
	ioc map[string]response.EvidenceRef
	cfg map[string]response.EvidenceRef
	err error
}

func (f *evFake) ports() response.EvidencePorts {
	return response.EvidencePorts{
		IocHit: func(_ context.Context, id string) (response.EvidenceRef, bool, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			r, ok := f.ioc[id]
			return r, ok, f.err
		},
		ConfigRead: func(_ context.Context, id string) (response.EvidenceRef, bool, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			r, ok := f.cfg[id]
			return r, ok, f.err
		},
	}
}

const (
	hostIP = "198.51.100.7"
	policy = "12" // the target of the high-risk action: a firewall policy number
)

// propEnv is an environment with execution on, findings on a device at hostIP, known-bad connections and reads of the AI, all behind the
// fake ports.
func propEnv(t *testing.T, withPorts bool) (*env, *fakeTwoStep, *evFake) {
	t.Helper()
	ev := &evFake{
		ioc: map[string]response.EvidenceRef{
			"ioc-host":   {Summary: "PC-HR-01 connected to a listed address", Relates: []string{hostIP}},
			"ioc-else":   {Summary: "Something about another address", Relates: []string{"203.0.113.9"}},
			"ioc-vlan30": {Summary: "A listed address seen on VLAN 30", Relates: []string{"30"}},
			"ioc-mac":    {Summary: "A listed address seen from one MAC", Relates: []string{"AA-BB-CC-DD-EE-01"}},
		},
		// reads the AI made: two through the firewall connection of the action, one through another connection
		cfg: map[string]response.EvidenceRef{
			"read-1":     {Summary: "Read the policy list of Office firewall", Connection: "cn-fw"},
			"read-2":     {Summary: "Read policy 12 of Office firewall", Connection: "cn-fw"},
			"read-other": {Summary: "Read the rules of another firewall", Connection: "cn-other"},
		},
	}
	f := &fakeTwoStep{off: map[string]bool{}}
	e := newEnv(t, func(c *response.Config) {
		c.TwoStep = f
		if withPorts {
			c.Evidence = ev.ports()
		}
	})
	e.dir.devices["a1"] = response.DeviceInfo{ID: "a1", Name: "PC-HR-01", IP: hostIP, Approved: true}
	e.dir.findings["f1"] = response.FindingInfo{ID: "f1", AssetID: "a1", CVE: "CVE-2024-0001", Severity: "high", Status: "confirmed"}
	e.dir.findings["f2"] = response.FindingInfo{ID: "f2", AssetID: "a1", CVE: "CVE-2024-0002", Severity: "high", Status: "confirmed"}
	e.turnOn()
	return e, f, ev
}

func lowBody() response.ProposeBody {
	return response.ProposeBody{Trigger: "finding", ActionID: "blocklist_add", Params: map[string]string{"ip": hostIP}, Confidence: 0.85,
		Evidence: []response.ProposedEvidence{{Kind: "finding", ID: "f1"}}, Why: "The device runs a service with an exploited vulnerability."}
}

// highBody is the body of the high-risk action on the firewall: a finding (it proves the trigger and names the device for the never-touch
// check) and two reads the AI made through the connection of the action, which are about every target of that action.
func highBody() response.ProposeBody {
	return response.ProposeBody{Trigger: "finding", ActionID: "fgt_policy_disable", Params: map[string]string{"id": policy}, Confidence: 0.95,
		Evidence: []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "config_read", ID: "read-1"}, {Kind: "config_read", ID: "read-2"}}, Why: "A firewall policy lets the exploited service out."}
}

// allowHigh binds the high-risk action to the firewall and lets the AI propose it.
func (e *env) allowHigh() {
	e.t.Helper()
	e.firewall("fgt_policy_disable")
	on := true
	_, err := e.svc.ChangeAction(e.ctx(), admin, "fgt_policy_disable", response.CatalogUpdate{AIMayPropose: &on})
	e.must(err)
	e.exec.present = `"status":"disable"`
}

func (e *env) propose(b response.ProposeBody) (response.ProposeResult, error) {
	e.t.Helper()
	return e.svc.Propose(e.ctx(), b)
}

func (e *env) mustPropose(b response.ProposeBody) response.ProposeResult {
	e.t.Helper()
	r, err := e.propose(b)
	e.must(err)
	return r
}

func (e *env) notes() int { return e.count(`SELECT COUNT(*) FROM resp_ai_notes`) }

// newest is the newest line of resp_log of the kind: who wrote it and what it says.
func (e *env) newest(kind string) (actor, detail string) {
	e.t.Helper()
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT actor, detail FROM resp_log WHERE kind = ? ORDER BY seq DESC LIMIT 1`, kind).Scan(&actor, &detail); err != nil {
		e.t.Fatalf("no %s line: %v", kind, err)
	}
	return actor, detail
}

// full is the stored request a proposal made (the port itself answers a narrow view).
func (e *env) full(id string) response.ActionRequest {
	e.t.Helper()
	for _, a := range e.actions() {
		if a.ID == id {
			return a
		}
	}
	e.t.Fatalf("no request %s", id)
	return response.ActionRequest{}
}

// ---- INV-15: the gates, in order ----

// inv15Gate is one row of the INV-15 table. arm puts the box and the body in the state that makes this gate refuse; the test of row i arms
// rows i..last at once, so gate i must refuse first while every later gate would have refused too; row i-1, armed the same way, proves the
// earlier gate beats this one. Arms that build the world (a request made by a rule) run first, then the arms that change
// settings or the body, latest gate first so that an earlier gate's change wins where two change the same thing. No row replaces the
// evidence list: each evidence row breaks it in exactly one way.
type inv15Gate struct {
	name   string
	world  bool // the arm builds the world (a request made by a rule) and runs before the arms that change settings or the body
	arm    func(e *env, b *response.ProposeBody)
	status int
	code   string
	msg    string                     // part of the refusal text, for the gates that share a code
	outcom string                     // set for the gates that answer a note instead of a refusal
	after  func(t *testing.T, e *env) // what else must be true after this gate answered
}

func (e *env) setting(path string, val any) {
	e.t.Helper()
	raw, err := json.Marshal(val)
	e.must(err)
	e.exec1(`UPDATE resp_settings SET value = json_set(value, ?, json(?))`, path, string(raw))
}

// priorRequest makes a pending request for the high-risk action on policy 12 from a rule, and returns it.
func (e *env) priorRequest(event string) response.ActionRequest {
	e.t.Helper()
	if len(mustRules(e)) == 0 {
		e.rule("Cut the policy", "honeypot", []response.RuleAction{{ActionID: "fgt_policy_disable", Params: map[string]string{"id": policy}, TTLMin: intp(1440)}}, nil)
	}
	seen := map[string]bool{}
	for _, a := range e.actions() {
		seen[a.ID] = true
	}
	sum := e.fire(e.trap(event, "192.168.10.157"))
	for _, a := range e.actions() {
		if !seen[a.ID] {
			return a
		}
	}
	_, d := e.newest("refused")
	e.t.Fatalf("the rule made no request: %+v (%s)", sum, d)
	return response.ActionRequest{}
}

func inv15Gates() []inv15Gate {
	return []inv15Gate{
		{name: "maintenance", status: 409, code: "maintenance", arm: func(e *env, _ *response.ProposeBody) {
			now := e.clock.Now()
			e.setting("$.maintenance", []response.Window{{ID: "w1", Name: "Night", Start: store.FormatTS(now.Add(-time.Hour)), End: store.FormatTS(now.Add(time.Hour))}})
		}},
		{name: "circuit breaker", status: 409, code: "circuit_open", arm: func(e *env, _ *response.ProposeBody) {
			e.setting("$.breaker_tripped_at", store.FormatTS(e.clock.Now()))
		}},
		{name: "AI paused", status: 409, code: "ai_paused", arm: func(e *env, _ *response.ProposeBody) {
			e.setting("$.ai.paused_at", store.FormatTS(e.clock.Now()))
			e.setting("$.ai.paused_reason", "3 of the last 5 AI requests were rejected")
		}},
		{name: "trigger the admin did not allow", status: 403, code: "trigger_not_allowed", msg: "has not allowed", arm: func(_ *env, b *response.ProposeBody) { b.Trigger = "unknown_device" }},
		{name: "trigger no evidence can prove", status: 403, code: "trigger_not_allowed", msg: "no kind of evidence", arm: func(e *env, b *response.ProposeBody) {
			e.setting("$.ai.triggers", []string{"finding", "honeypot"})
			b.Trigger = "honeypot"
		}},
		{name: "action not for the AI", status: 403, code: "action_not_ai_allowed", arm: func(e *env, _ *response.ProposeBody) {
			e.exec1(`UPDATE resp_catalog SET ai_may_propose = 0 WHERE id = 'fgt_policy_disable'`)
		}},
		{name: "plan", status: 409, code: "invalid_target", arm: func(_ *env, b *response.ProposeBody) { b.Params = map[string]string{"id": "not a number"} }},
		{name: "evidence missing", status: 400, code: "evidence_missing", arm: func(_ *env, b *response.ProposeBody) { b.Evidence = nil }},
		{name: "evidence invalid", status: 422, code: "evidence_invalid", arm: func(_ *env, b *response.ProposeBody) {
			b.Evidence = append(slices.Clone(b.Evidence), response.ProposedEvidence{Kind: "config_read", ID: "read-made-up"})
		}},
		{name: "evidence mismatch", status: 422, code: "evidence_mismatch", msg: "about the target", arm: func(_ *env, b *response.ProposeBody) {
			b.Evidence = slices.Clone(b.Evidence)
			for i := range b.Evidence { // the reads went through another connection: about nothing this action touches
				if b.Evidence[i].Kind == "config_read" {
					b.Evidence[i].ID = "read-other"
				}
			}
		}},
		{name: "low confidence", outcom: "suggestion", arm: func(_ *env, b *response.ProposeBody) { b.Confidence = 0.5 }},
		{name: "already open", world: true, status: 409, code: "already_open", arm: func(e *env, _ *response.ProposeBody) { e.priorRequest("h-open") }},
		{name: "rejected within 7 days", world: true, status: 409, code: "repeat_blocked", arm: func(e *env, _ *response.ProposeBody) {
			a := e.priorRequest("h-rej")
			e.asAI(a.ID, `{"confidence":0.95,"evidence":[{"kind":"finding","id":"f1","summary":"s"},{"kind":"config_read","id":"read-1","summary":"s"},{"kind":"config_read","id":"read-2","summary":"s"}],"why":"test","second_check":null,"in_app_only":true}`)
			e.reject(a, "Not now", "none")
		}},
		{name: "budget", outcom: "digest", arm: func(e *env, _ *response.ProposeBody) {
			e.setting("$.ai.budget_hour", 1)
			e.exec1(`INSERT INTO resp_actions (id, source, proposal_id, asset_name, title, risk, status, requested_at, expires_at, requires_approvals, items)
				VALUES ('act-usage', 'ai', 'ai:usage', 'X', 'Earlier AI request', 'low', 'expired', ?, ?, 1, '[]')`, store.FormatTS(e.clock.Now().Add(-time.Minute)), store.FormatTS(e.clock.Now().Add(time.Hour)))
		}},
		{name: "second check", status: 422, code: "second_check_failed", arm: func(_ *env, b *response.ProposeBody) { b.Confidence = 0.89 }},
		{name: "global breaker trips", status: 409, code: "circuit_open", arm: func(e *env, _ *response.ProposeBody) { e.setting("$.breaker_max_per_hour", 0) },
			after: func(t *testing.T, e *env) {
				if e.settings().BreakerTrippedAt == nil || !e.logHas("breaker", "Circuit breaker tripped") {
					t.Error("the trip was not committed: the breaker is still closed or has no log line")
				}
			}},
		{name: "request", outcom: "request", arm: func(*env, *response.ProposeBody) {}},
	}
}

func TestContract_INV15_GatesRunInOrder(t *testing.T) {
	t.Parallel()
	all := inv15Gates()
	for i, g := range all {
		t.Run(fmt.Sprintf("%02d %s", i+1, g.name), func(t *testing.T) {
			e, _, _ := propEnv(t, true)
			e.allowHigh()
			b := highBody()
			for _, world := range []bool{true, false} {
				for j := len(all) - 1; j >= i; j-- { // the later gates are armed too: this one must still be the one that answers
					if all[j].world == world {
						all[j].arm(e, &b)
					}
				}
			}
			requests, notes, logs := e.requests(), e.notes(), e.count(`SELECT COUNT(*) FROM resp_log`)
			res, err := e.propose(b)
			switch {
			case g.code != "":
				wantCode(t, err, g.status, g.code)
				if g.msg != "" && !contains(err.Error(), g.msg) {
					t.Fatalf("the refusal says %q, want it to say %q", err, g.msg)
				}
				if e.requests() != requests || e.notes() != notes {
					t.Fatalf("a refusal created something: requests %d -> %d, notes %d -> %d", requests, e.requests(), notes, e.notes())
				}
				if actor, detail := e.newest("refused"); actor != "ai:response" || !contains(detail, g.code) {
					t.Fatalf("the newest refused line is %q by %q, want %s by ai:response", detail, actor, g.code)
				}
			default:
				e.must(err)
				if res.Outcome != g.outcom {
					t.Fatalf("outcome %q, want %q (%s)", res.Outcome, g.outcom, res.Note)
				}
				if g.outcom == "request" {
					if e.requests() != requests+1 || res.Request == nil {
						t.Fatalf("no request was created: %+v", res)
					}
					if actor, detail := e.newest("proposal"); actor != "ai:response" || !contains(detail, "read-1") {
						t.Fatalf("the newest proposal line is %q by %q", detail, actor)
					}
				} else {
					if e.requests() != requests || e.notes() != notes+1 || res.Request != nil {
						t.Fatalf("a %s note must be one note and no request (requests %d -> %d, notes %d -> %d)", g.outcom, requests, e.requests(), notes, e.notes())
					}
					if actor, _ := e.newest("ai_note"); actor != "ai:response" {
						t.Fatalf("the newest ai_note line is by %q", actor)
					}
				}
			}
			if g.after != nil {
				g.after(t, e)
			}
			if e.count(`SELECT COUNT(*) FROM resp_log`) <= logs {
				t.Fatal("nothing was logged")
			}
			if e.exec.count() != 0 {
				t.Fatal("a proposal reached a device")
			}
		})
	}
}

func TestPropose_UnknownActionBeatsTheMaintenanceWindow(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	inv15Gates()[0].arm(e, nil)
	b := lowBody()
	b.ActionID = "no_such_action"
	_, err := e.propose(b)
	wantCode(t, err, 400, "invalid")
	_, err = e.propose(lowBody())
	wantCode(t, err, 409, "maintenance")
}

// ---- notes ----

func TestPropose_NotesAreCappedAtFifty(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	for i := range 55 {
		b := lowBody()
		b.Confidence = 0.5
		b.Why = fmt.Sprintf("note %d", i)
		if r := e.mustPropose(b); r.Outcome != "suggestion" || r.Request != nil {
			t.Fatalf("outcome %+v", r)
		}
		e.clock.Advance(time.Second)
	}
	if e.notes() != 50 || e.requests() != 0 {
		t.Fatalf("%d notes, %d requests", e.notes(), e.requests())
	}
	st, err := e.svc.AIState(e.ctx())
	e.must(err)
	if len(st.Notes) != 50 || st.Notes[0].Why != "note 54" || st.Notes[49].Why != "note 5" || st.Notes[0].Kind != "suggestion" || len(st.Notes[0].Evidence) != 1 {
		t.Fatalf("state: %d notes, first %+v, last %+v", len(st.Notes), st.Notes[0], st.Notes[len(st.Notes)-1])
	}
	m, err := e.svc.Metrics(e.ctx())
	e.must(err)
	if m.Suggestions != 50 || m.Digested != 0 {
		t.Fatalf("metrics: %+v", m)
	}
}

func TestPropose_SuggestionAndDigestAreNotesWithNoRequest(t *testing.T) {
	t.Parallel()
	e, _, ev := propEnv(t, true)
	low := lowBody()
	low.Confidence = 0.79
	if r := e.mustPropose(low); r.Outcome != "suggestion" || r.Request != nil || !contains(r.Note, "suggestion note") {
		t.Fatalf("%+v", r)
	}
	e.saveSettings(func(in *response.SettingsInput) { in.AI.BudgetHour = 1 })
	e.mustPropose(lowBody())
	e.clock.Advance(time.Second)
	ev.add("ioc-8", "198.51.100.8")
	over := lowBody()
	over.Params = map[string]string{"ip": "198.51.100.8"}
	over.Trigger, over.Evidence = "ioc_connection", []response.ProposedEvidence{{Kind: "ioc_hit", ID: "ioc-8"}}
	if r := e.mustPropose(over); r.Outcome != "digest" || r.Request != nil {
		t.Fatalf("%+v", r)
	}
	if e.requests() != 1 || e.notes() != 2 {
		t.Fatalf("%d requests, %d notes", e.requests(), e.notes())
	}
	m, err := e.svc.Metrics(e.ctx())
	e.must(err)
	if m.Suggestions != 1 || m.Digested != 1 {
		t.Fatalf("metrics: %+v", m)
	}
}

func (f *evFake) add(id string, relates ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ioc[id] = response.EvidenceRef{Summary: "Listed address " + id, Relates: relates}
}

// ---- evidence ----

// iocBody is the low-risk body when a known-bad connection is the evidence: the trigger it proves is ioc_connection.
func iocBody(id string) response.ProposeBody {
	b := lowBody()
	b.Trigger = "ioc_connection"
	b.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: id}}
	return b
}

func TestPropose_EvidenceIsLookedUpNeverTrusted(t *testing.T) {
	t.Parallel()
	t.Run("a nil port refuses", func(t *testing.T) {
		e, _, _ := propEnv(t, false)
		_, err := e.propose(iocBody("ioc-host"))
		wantCode(t, err, 422, "evidence_invalid")
		e.allowHigh()
		b := highBody()
		_, err = e.propose(b)
		wantCode(t, err, 422, "evidence_invalid") // the reads of the AI cannot be looked up: nothing proves them
		if e.requests() != 0 {
			t.Fatal("created")
		}
	})
	t.Run("no directory means no finding", func(t *testing.T) {
		e := newEnv(t, func(c *response.Config) { c.Directory = nil })
		_, err := e.propose(lowBody())
		wantCode(t, err, 422, "evidence_invalid")
	})
	t.Run("a wrong id refuses", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		for _, ev := range []response.ProposedEvidence{{Kind: "finding", ID: "f-nope"}, {Kind: "ioc_hit", ID: "ioc-nope"}, {Kind: "config_read", ID: "read-nope"}} {
			b := lowBody()
			b.Evidence = []response.ProposedEvidence{ev}
			_, err := e.propose(b)
			wantCode(t, err, 422, "evidence_invalid")
		}
	})
	t.Run("one made-up item among real ones refuses", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		b := lowBody()
		b.Evidence = append(b.Evidence, response.ProposedEvidence{Kind: "ioc_hit", ID: "ioc-nope"})
		_, err := e.propose(b)
		wantCode(t, err, 422, "evidence_invalid")
	})
	t.Run("closed, false-positive and resolved findings are not evidence", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		for _, st := range []string{"false_positive", "patched", "mitigated", "not_relevant", "resolved", ""} {
			e.dir.findings["f1"] = response.FindingInfo{ID: "f1", AssetID: "a1", CVE: "CVE-2024-0001", Severity: "high", Status: st}
			_, err := e.propose(lowBody())
			wantCode(t, err, 422, "evidence_invalid")
		}
		e.dir.findings["f1"] = response.FindingInfo{ID: "f1", AssetID: "a1", CVE: "CVE-2024-0001", Severity: "high", Status: "suspected"}
		e.mustPropose(lowBody())
	})
	t.Run("evidence about something else refuses", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		_, err := e.propose(iocBody("ioc-else"))
		wantCode(t, err, 422, "evidence_mismatch")
	})
	t.Run("a known-bad connection about the target is evidence", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		if r := e.mustPropose(iocBody("ioc-host")); r.Outcome != "request" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("a finding on the target device is about the target", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		r := e.mustPropose(lowBody())
		a := e.full(r.Request.ID)
		if len(a.AI.Evidence) != 1 || !contains(a.AI.Evidence[0].Summary, "CVE-2024-0001") || a.FindingID == nil || *a.FindingID != "f1" || a.CVE == nil || *a.CVE != "CVE-2024-0001" {
			t.Fatalf("%+v", a)
		}
		if a.AssetID == nil || *a.AssetID != "a1" || a.AssetName != "PC-HR-01" {
			t.Fatalf("the device whose address is the target is shown: %+v %q", a.AssetID, a.AssetName)
		}
	})
	t.Run("the device shown is the one whose address is the target, not the first finding's", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		e.dir.devices["a2"] = response.DeviceInfo{ID: "a2", Name: "NAS", IP: "198.51.100.9", Approved: true}
		e.dir.findings["f3"] = response.FindingInfo{ID: "f3", AssetID: "a2", CVE: "CVE-2024-0003", Severity: "high", Status: "confirmed"}
		b := lowBody()
		b.Params = map[string]string{"ip": "198.51.100.9"}
		b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "finding", ID: "f3"}}
		a := e.full(e.mustPropose(b).Request.ID)
		if a.AssetID == nil || *a.AssetID != "a2" || a.AssetName != "NAS" {
			t.Fatalf("asset %v %q", a.AssetID, a.AssetName)
		}
	})
	t.Run("a host name that looks like an address never matches an address", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		e.dir.devices["a1"] = response.DeviceInfo{ID: "a1", Name: "198.51.100.8", IP: hostIP, Approved: true} // a DHCP host name
		b := lowBody()
		b.Params = map[string]string{"ip": "198.51.100.8"}
		_, err := e.propose(b)
		wantCode(t, err, 422, "evidence_mismatch")
	})
	t.Run("addresses compare in their canonical spelling", func(t *testing.T) {
		e, _, ev := propEnv(t, true)
		ev.add("ioc-v6", "2001:DB8::0:1")
		b := iocBody("ioc-v6")
		b.Params = map[string]string{"ip": "2001:db8::1"}
		if r := e.mustPropose(b); r.Outcome != "request" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("what a port says is cleaned before it is stored", func(t *testing.T) {
		e, _, ev := propEnv(t, true)
		ev.ioc["ioc-dirty"] = response.EvidenceRef{Summary: "bad\u202e\r\n\x00connection\u200b to\u3164 x", Relates: []string{hostIP}}
		r := e.mustPropose(iocBody("ioc-dirty"))
		if got := e.full(r.Request.ID).AI.Evidence[0].Summary; got != "bad connection to x" {
			t.Fatalf("summary %q", got)
		}
	})
	t.Run("a lookup that returns another canonical id is kept under that id", func(t *testing.T) {
		e, _, ev := propEnv(t, true)
		ev.ioc["alias"] = response.EvidenceRef{ID: "ioc-host", Summary: "same hit", Relates: []string{hostIP}}
		b := iocBody("ioc-host")
		b.Evidence = append(b.Evidence, response.ProposedEvidence{Kind: "ioc_hit", ID: "alias"})
		if got := e.full(e.mustPropose(b).Request.ID).AI.Evidence; len(got) != 1 || got[0].ID != "ioc-host" {
			t.Fatalf("one object under two ids counts once: %+v", got)
		}
	})
}

// A read of the AI relates to a device action through that same connection and to nothing else (D-119).
func TestPropose_ConfigReadsAreEvidenceOnlyOfTheirOwnConnection(t *testing.T) {
	t.Parallel()
	t.Run("two reads through the connection of the action pass the second check", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		e.allowHigh()
		r := e.mustPropose(highBody())
		if r.Outcome != "request" || r.Request.Risk != response.RiskHigh {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("a read through another connection says nothing about the action", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		e.allowHigh()
		b := highBody()
		b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "config_read", ID: "read-other"}}
		_, err := e.propose(b)
		wantCode(t, err, 422, "evidence_mismatch")
	})
	t.Run("a box action can never be justified by reads", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		b := lowBody()
		b.Params = map[string]string{"ip": "198.51.100.8"} // the finding is about another address
		b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "config_read", ID: "read-1"}, {Kind: "config_read", ID: "read-2"}}
		_, err := e.propose(b)
		wantCode(t, err, 422, "evidence_mismatch")
	})
	t.Run("reads alone never prove a trigger", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		b := lowBody()
		b.Evidence = []response.ProposedEvidence{{Kind: "config_read", ID: "read-1"}, {Kind: "config_read", ID: "read-2"}}
		_, err := e.propose(b)
		wantCode(t, err, 422, "evidence_mismatch")
		if !contains(err.Error(), "proves the trigger") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a read without a connection relates to nothing", func(t *testing.T) {
		e, _, ev := propEnv(t, true)
		e.allowHigh()
		ev.cfg["read-bare"] = response.EvidenceRef{Summary: "a read"}
		b := highBody()
		b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "config_read", ID: "read-bare"}}
		_, err := e.propose(b)
		wantCode(t, err, 422, "evidence_mismatch")
	})
}

// A finding gives the trigger and the device; the trigger has to be proven by a kind of evidence that can prove it (D-119).
func TestPropose_TriggerMustBeProvenByEvidence(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	b := iocBody("ioc-host")
	b.Trigger = "finding" // a finding trigger with only a known-bad connection
	_, err := e.propose(b)
	wantCode(t, err, 422, "evidence_mismatch")
	b = lowBody()
	b.Trigger = "ioc_connection" // an ioc trigger with only a finding
	_, err = e.propose(b)
	wantCode(t, err, 422, "evidence_mismatch")
	b.Evidence = append(b.Evidence, response.ProposedEvidence{Kind: "ioc_hit", ID: "ioc-host"})
	if r := e.mustPropose(b); r.Outcome != "request" {
		t.Fatalf("%+v", r)
	}
}

// The trigger catalog says which kinds prove which trigger. Triggers with no kind cannot be used by the AI at all.
func TestPropose_TriggerEvidenceMap(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	tl, err := e.svc.Triggers(e.ctx())
	e.must(err)
	want := map[string]bool{"finding": true, "ioc_connection": true}
	for _, tr := range tl {
		if want[tr.ID] {
			continue
		}
		e.saveSettings(func(in *response.SettingsInput) { in.AI.Triggers = []string{tr.ID} })
		b := lowBody()
		b.Trigger = tr.ID
		_, err := e.propose(b)
		wantCode(t, err, 403, "trigger_not_allowed")
		if !contains(err.Error(), "no kind of evidence") {
			t.Errorf("%s: %v", tr.ID, err)
		}
	}
}

func TestPropose_OnlyRelatedEvidenceCounts(t *testing.T) {
	t.Parallel()
	t.Run("repeat: related plus unrelated evidence is not new evidence", func(t *testing.T) {
		e, _, ev := propEnv(t, true)
		r := e.mustPropose(lowBody())
		e.clock.Advance(time.Minute)
		e.reject(e.full(r.Request.ID), "Our scanner", "none")
		e.clock.Advance(time.Minute)
		b := lowBody()
		b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "ioc_hit", ID: "ioc-else"}} // ioc-else is new but about another address
		_, err := e.propose(b)
		wantCode(t, err, 409, "repeat_blocked")
		ev.add("ioc-new", hostIP) // new and about the target
		b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "ioc_hit", ID: "ioc-new"}}
		if r := e.mustPropose(b); r.Outcome != "request" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("high risk: one related plus one unrelated is not two", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		e.allowHigh()
		b := highBody()
		b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "config_read", ID: "read-1"}, {Kind: "config_read", ID: "read-other"}}
		_, err := e.propose(b)
		wantCode(t, err, 422, "second_check_failed")
		if !contains(err.Error(), "about the target (got 1)") {
			t.Fatalf("%v", err)
		}
	})
}

func TestPropose_AFailingLookupAnswersAtTheEvidenceGateAndIsLogged(t *testing.T) {
	t.Parallel()
	e, _, ev := propEnv(t, true)
	ev.err = fmt.Errorf("logs are down")
	// an earlier gate still answers first
	inv15Gates()[0].arm(e, nil)
	_, err := e.propose(iocBody("ioc-host"))
	wantCode(t, err, 409, "maintenance")
	e.setting("$.maintenance", []response.Window{})
	_, err = e.propose(iocBody("ioc-host"))
	wantCode(t, err, 503, "evidence_unavailable")
	if actor, detail := e.newest("refused"); actor != "ai:response" || !contains(detail, "evidence_unavailable") {
		t.Fatalf("not logged: %q by %q", detail, actor)
	}
	if e.requests() != 0 || e.notes() != 0 {
		t.Fatal("created")
	}
	ev.err = nil
	e.mustPropose(iocBody("ioc-host"))
}

func TestPropose_TheSameEvidenceTwiceCountsOnce(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	e.allowHigh()
	b := highBody()
	b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "config_read", ID: "read-1"}, {Kind: "config_read", ID: "read-1"}}
	_, err := e.propose(b)
	wantCode(t, err, 422, "second_check_failed")
}

// ---- never-touch needs a subject ----

// deviceAction adds a custom action on the firewall connection that names one value of a device part, and lets the AI propose it.
func (e *env) deviceAction(param string) string {
	e.t.Helper()
	e.firewall("fgt_policy_disable")
	a, err := e.svc.AddAction(e.ctx(), admin, response.CatalogInput{Name: "Quarantine " + param, ConnectionID: "cn-fw", Risk: response.RiskLow, Enabled: true, AIMayPropose: true,
		Run:      response.Tpl{Method: "POST", Path: "/q/{" + param + "}", Body: `{"q":"on"}`},
		Rollback: response.Tpl{Method: "DELETE", Path: "/q/{" + param + "}"}})
	e.must(err)
	return a.ID
}

func TestPropose_PortMACAndVLANActionsNeedTheSubjectAndRespectNeverTouch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ param, value, hit string }{{"mac", "aa:bb:cc:dd:ee:01", "ioc-mac"}, {"vlan", "30", "ioc-vlan30"}} {
		t.Run(tc.param, func(t *testing.T) {
			e, _, _ := propEnv(t, true)
			id := e.deviceAction(tc.param)
			body := response.ProposeBody{Trigger: "ioc_connection", ActionID: id, Params: map[string]string{tc.param: tc.value}, Confidence: 0.9, Why: "A listed address came from here.",
				Evidence: []response.ProposedEvidence{{Kind: "ioc_hit", ID: tc.hit}}}
			// no finding, no subject: the never-touch list cannot be checked
			_, err := e.propose(body)
			wantCode(t, err, 409, "never_touch")
			// with a finding on an ordinary device it is allowed
			ok := body
			ok.Evidence = append(slices.Clone(body.Evidence), response.ProposedEvidence{Kind: "finding", ID: "f1"})
			// ... but not when any cited finding is about a protected device (every one is checked, not the first)
			e.dir.devices["gw"] = response.DeviceInfo{ID: "gw", Name: "gateway", IP: "198.51.100.1", Kind: "router"}
			e.dir.findings["f-gw"] = response.FindingInfo{ID: "f-gw", AssetID: "gw", CVE: "CVE-2024-0009", Severity: "high", Status: "confirmed"}
			bad := body
			bad.Evidence = append(slices.Clone(ok.Evidence), response.ProposedEvidence{Kind: "finding", ID: "f-gw"})
			_, err = e.propose(bad)
			wantCode(t, err, 409, "never_touch")
			bad.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: tc.hit}, {Kind: "finding", ID: "f-gw"}, {Kind: "finding", ID: "f1"}}
			_, err = e.propose(bad)
			wantCode(t, err, 409, "never_touch")
			if e.requests() != 0 {
				t.Fatal("created")
			}
			if r := e.mustPropose(ok); r.Outcome != "request" {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestPropose_NeverTouchRefusalDoesNotEchoBidi(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	e.dir.devices["gw"] = response.DeviceInfo{ID: "gw", Name: "gate\u202eway\u200b", IP: hostIP, Kind: "router"}
	_, err := e.propose(lowBody())
	wantCode(t, err, 409, "never_touch")
	_, detail := e.newest("refused")
	for _, s := range []string{err.Error(), detail} {
		if strings.ContainsAny(s, "\u202e\u200b") || !contains(s, "gateway") {
			t.Fatalf("hidden characters or the name is gone: %q", s)
		}
	}
}

// ---- the body at the boundary ----

func TestPropose_BodyIsValidatedAtTheBoundary(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	long := func(n int) string { return strings.Repeat("a", n) }
	cases := map[string]func(b *response.ProposeBody){
		"NaN confidence":        func(b *response.ProposeBody) { b.Confidence = math.NaN() },
		"infinite confidence":   func(b *response.ProposeBody) { b.Confidence = math.Inf(1) },
		"confidence above 1":    func(b *response.ProposeBody) { b.Confidence = 1.01 },
		"negative confidence":   func(b *response.ProposeBody) { b.Confidence = -0.1 },
		"empty why":             func(b *response.ProposeBody) { b.Why = "" },
		"why of only invisible": func(b *response.ProposeBody) { b.Why = "\u200b\u202e \n" },
		"why over 400":          func(b *response.ProposeBody) { b.Why = long(401) },
		"11 pieces of evidence": func(b *response.ProposeBody) {
			b.Evidence = slices.Repeat([]response.ProposedEvidence{{Kind: "finding", ID: "f1"}}, 11)
		},
		"param over 200":  func(b *response.ProposeBody) { b.Params = map[string]string{"ip": long(201)} },
		"param name":      func(b *response.ProposeBody) { b.Params = map[string]string{"ip; rm": hostIP} },
		"too many params": func(b *response.ProposeBody) { b.Params = manyParams(21) },
		"evidence id over 120": func(b *response.ProposeBody) {
			b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: long(121)}}
		},
		"empty evidence id":      func(b *response.ProposeBody) { b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: ""}} },
		"evidence kind":          func(b *response.ProposeBody) { b.Evidence = []response.ProposedEvidence{{Kind: "command", ID: "f1"}} },
		"control in evidence id": func(b *response.ProposeBody) { b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1\n"}} },
		"empty action":           func(b *response.ProposeBody) { b.ActionID = "" },
		"action with a slash":    func(b *response.ProposeBody) { b.ActionID = "../x" },
		"trigger":                func(b *response.ProposeBody) { b.Trigger = "Finding; drop" },
		"unknown action":         func(b *response.ProposeBody) { b.ActionID = "no_such_action" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			b := lowBody()
			mut(&b)
			before := e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused'`)
			_, err := e.propose(b)
			wantCode(t, err, 400, "invalid")
			if e.requests() != 0 || e.notes() != 0 || e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused'`) != before+1 {
				t.Fatal("a refused body was not logged exactly once, or created something")
			}
		})
	}
	// why with control and bidi characters is kept, cleaned
	b := lowBody()
	b.Why = "line one\r\n\x00line\u202e two\u200b"
	r := e.mustPropose(b)
	if a := e.full(r.Request.ID); a.AI.Why != "line one line two" || *a.TriggerSummary != "line one line two" {
		t.Fatalf("why %q", a.AI.Why)
	}
}

func manyParams(n int) map[string]string {
	m := map[string]string{}
	for i := range n {
		m[strings.Repeat("a", i+1)] = "x"
	}
	return m
}

// The body has no field that could hold a command, a path, a template, a header or a summary of the evidence (INV-14, FORBID-5).
func TestProposeBodyHasNoCommandField(t *testing.T) {
	t.Parallel()
	names := func(v any) []string {
		var out []string
		rt := reflect.TypeOf(v)
		for i := range rt.NumField() {
			out = append(out, rt.Field(i).Name+":"+rt.Field(i).Type.String())
		}
		return out
	}
	if got, want := names(response.ProposeBody{}), []string{"Trigger:string", "ActionID:string", "Params:map[string]string", "Confidence:float64", "Evidence:[]response.ProposedEvidence", "Why:string"}; !slices.Equal(got, want) {
		t.Fatalf("ProposeBody fields changed: %v. A new field needs a decision (D-97, INV-15) and a review of what it can carry into a command", got)
	}
	if got, want := names(response.ProposedEvidence{}), []string{"Kind:string", "ID:string"}; !slices.Equal(got, want) {
		t.Fatalf("ProposedEvidence fields changed: %v", got)
	}
	raw, err := json.Marshal(highBody())
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(raw, &keys)
	for k := range keys {
		if !slices.Contains([]string{"trigger", "action_id", "params", "confidence", "evidence", "why"}, k) {
			t.Errorf("wire key %q", k)
		}
	}
}

// ---- repeat ----

func TestPropose_RepeatRule(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) (*env, *evFake) {
		e, _, ev := propEnv(t, true)
		r := e.mustPropose(lowBody())
		e.clock.Advance(time.Minute)
		e.reject(e.full(r.Request.ID), "Our scanner", "none")
		e.clock.Advance(time.Minute)
		return e, ev
	}
	t.Run("blocked within 7 days without new evidence", func(t *testing.T) {
		e, _ := setup(t)
		_, err := e.propose(lowBody())
		wantCode(t, err, 409, "repeat_blocked")
		e.clock.Advance(6 * 24 * time.Hour)
		_, err = e.propose(lowBody())
		wantCode(t, err, 409, "repeat_blocked")
	})
	t.Run("allowed with new evidence", func(t *testing.T) {
		e, _ := setup(t)
		b := lowBody()
		b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "finding", ID: "f2"}}
		if r := e.mustPropose(b); r.Outcome != "request" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("allowed after 7 days", func(t *testing.T) {
		e, _ := setup(t)
		e.clock.Advance(7*24*time.Hour + time.Minute)
		if r := e.mustPropose(lowBody()); r.Outcome != "request" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("another target is not blocked", func(t *testing.T) {
		e, ev := setup(t)
		b := lowBody()
		b.Params = map[string]string{"ip": "198.51.100.8"}
		ev.add("ioc-8", "198.51.100.8")
		b.Trigger, b.Evidence = "ioc_connection", []response.ProposedEvidence{{Kind: "ioc_hit", ID: "ioc-8"}}
		if r := e.mustPropose(b); r.Outcome != "request" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("a rule's rejected request does not block the AI", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		e.rule("Block", "ioc_connection", blockAction(60), nil)
		e.fire(e.iocEvent("ev1", hostIP))
		e.reject(e.only(), "No", "none")
		if r := e.mustPropose(lowBody()); r.Outcome != "request" {
			t.Fatalf("%+v", r)
		}
	})
}

// ---- budget ----

func TestPropose_BudgetDefaultsAreTwoAnHourAndFiveADay(t *testing.T) {
	t.Parallel()
	e, _, ev := propEnv(t, true)
	if st := e.settings(); st.AI.BudgetHour != 2 || st.AI.BudgetDay != 5 {
		t.Fatalf("defaults: %+v", st.AI)
	}
	at := func(i int) response.ProposeBody {
		ev.add(fmt.Sprintf("ioc-b%d", i), fmt.Sprintf("198.51.100.%d", 20+i))
		b := lowBody()
		b.Params = map[string]string{"ip": fmt.Sprintf("198.51.100.%d", 20+i)}
		b.Trigger, b.Evidence = "ioc_connection", []response.ProposedEvidence{{Kind: "ioc_hit", ID: fmt.Sprintf("ioc-b%d", i)}}
		return b
	}
	steps := []struct {
		after time.Duration
		want  string
	}{
		{0, "request"}, {0, "request"}, {0, "digest"}, // two in the hour, the third is over the hour
		{61 * time.Minute, "request"}, {0, "request"}, {0, "digest"}, // the hour is free again; the day is at 4
		{61 * time.Minute, "request"}, {0, "digest"}, // the fifth of the day, then the sixth is over the day (the hour holds only one)
	}
	for i, st := range steps {
		e.clock.Advance(st.after)
		if r := e.mustPropose(at(i)); r.Outcome != st.want {
			t.Fatalf("proposal %d: %s, want %s", i, r.Outcome, st.want)
		}
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_actions WHERE source = 'ai'`); n != 5 || e.notes() != 3 {
		t.Fatalf("%d AI requests, %d notes, want 5 and 3", n, e.notes())
	}
	e.clock.Advance(24 * time.Hour)
	if r := e.mustPropose(at(7)); r.Outcome != "request" {
		t.Fatalf("a day later: %s", r.Outcome)
	}
}

// ---- high risk ----

func TestPropose_HighRiskSecondCheck(t *testing.T) {
	t.Parallel()
	e, f, _ := propEnv(t, true)
	e.allowHigh()
	one := highBody()
	one.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "config_read", ID: "read-1"}} // the finding is about the device, not about the policy
	_, err := e.propose(one)
	wantCode(t, err, 422, "second_check_failed")
	low := highBody()
	low.Confidence = 0.89
	_, err = e.propose(low)
	wantCode(t, err, 422, "second_check_failed")
	if e.requests() != 0 {
		t.Fatal("a failed second check created a request")
	}
	ok := highBody()
	ok.Confidence = 0.9
	r := e.mustPropose(ok)
	if r.Outcome != "request" || r.Request == nil || r.Request.Risk != response.RiskHigh || r.Request.RequiresApprovals != 2 {
		t.Fatalf("%+v", r)
	}
	a := e.full(r.Request.ID).AI
	if !a.InAppOnly || !r.Request.InAppOnly || a.SecondCheck == nil || !a.SecondCheck.OK || a.Confidence != 0.9 || len(a.Evidence) != 3 || !contains(r.Note, "two different people") {
		t.Fatalf("ai: %+v", a)
	}
	// one approval of the 13b-9 path is not enough: two people, each with their own code
	f.give(oper.ID, purposeOf(r.Request.ID), "111111")
	first, err := e.svc.Approve(e.ctx(), oper, r.Request.ID, nil, "111111")
	e.must(err)
	if first.Status != response.StatusPending || len(first.Approvals) != 1 || e.exec.count() != 0 {
		t.Fatalf("one approval was enough: %+v", first)
	}
	f.give(oper.ID, purposeOf(r.Request.ID), "222222")
	_, err = e.svc.Approve(e.ctx(), oper, r.Request.ID, nil, "222222")
	wantCode(t, err, 409, "same_approver")
	f.give(oper2.ID, purposeOf(r.Request.ID), "333333")
	done, err := e.svc.Approve(e.ctx(), oper2, r.Request.ID, nil, "333333")
	e.must(err)
	if len(done.Approvals) != 2 || done.Approvals[0].UserID == done.Approvals[1].UserID || done.Status == response.StatusPending {
		t.Fatalf("two people did not approve it: %+v", done)
	}
}

func TestPropose_LowRiskRequestIsNotInAppOnly(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	r := e.mustPropose(lowBody())
	a := e.full(r.Request.ID)
	if r.Request.Risk != response.RiskLow || r.Request.InAppOnly || a.AI.InAppOnly || a.AI.SecondCheck != nil || r.Request.RequiresApprovals != 1 || a.Items[0].TTLMin == nil || *a.Items[0].TTLMin != 1440 {
		t.Fatalf("%+v %+v", r.Request, a.AI)
	}
}

// ---- concurrency ----

func TestPropose_ConcurrentProposalsForOneTargetCreateOneRequest(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	const n = 8
	var wg sync.WaitGroup
	res := make([]response.ProposeResult, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res[i], errs[i] = e.svc.Propose(e.ctx(), lowBody())
		}()
	}
	close(start)
	wg.Wait()
	made := 0
	for i := range n {
		switch {
		case errs[i] == nil && res[i].Outcome == "request":
			made++
		case errs[i] != nil:
			wantCode(t, errs[i], 409, "already_open")
		default:
			t.Fatalf("proposal %d: %+v", i, res[i])
		}
	}
	if made != 1 || e.requests() != 1 {
		t.Fatalf("%d proposals made a request, %d requests exist", made, e.requests())
	}
}

func TestPropose_ConcurrentProposalsStayInsideTheBudget(t *testing.T) {
	t.Parallel()
	e, _, ev := propEnv(t, true)
	const n = 6
	for i := range n {
		ev.add(fmt.Sprintf("ioc-c%d", i), fmt.Sprintf("198.51.100.%d", 40+i))
	}
	var wg sync.WaitGroup
	res := make([]response.ProposeResult, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := lowBody()
			b.Params = map[string]string{"ip": fmt.Sprintf("198.51.100.%d", 40+i)}
			b.Trigger, b.Evidence = "ioc_connection", []response.ProposedEvidence{{Kind: "ioc_hit", ID: fmt.Sprintf("ioc-c%d", i)}}
			res[i], errs[i] = e.svc.Propose(e.ctx(), b)
		}()
	}
	wg.Wait()
	made, digested := 0, 0
	for i := range n {
		e.must(errs[i])
		switch res[i].Outcome {
		case "request":
			made++
		case "digest":
			digested++
		}
	}
	if made != 2 || digested != n-2 || e.requests() != 2 {
		t.Fatalf("%d requests, %d digests, %d stored: the hourly budget of 2 was passed", made, digested, e.requests())
	}
}

// ---- identity ----

func TestPropose_ActorIsAIResponseAndNothingIsPreApproved(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	r := e.mustPropose(lowBody())
	got := e.only()
	if got.ID != r.Request.ID || got.Source != "ai" || got.PreApproved || got.Status != response.StatusPending || len(got.Approvals) != 0 || got.AI == nil || !strings.HasPrefix(got.ProposalID, "ai:") || got.RuleID != nil {
		t.Fatalf("request: %+v", got)
	}
	for _, kind := range []string{"proposal", "request"} {
		if e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = ? AND actor = 'ai:response'`, kind) != 1 {
			t.Errorf("no %s line by ai:response", kind)
		}
	}
	for _, action := range []string{"response.proposal", "response.request"} {
		if e.count(`SELECT COUNT(*) FROM core_audit WHERE action = ? AND user = 'ai:response'`, action) != 1 {
			t.Errorf("no %s audit line by ai:response", action)
		}
	}
	if !e.logHas("proposal", "finding f1") {
		t.Error("the proposal line does not name the evidence")
	}
	if e.seen.count(response.EventRequestCreated) != 1 {
		t.Errorf("%d request-created events: notify hears of a proposal like a rule's request", e.seen.count(response.EventRequestCreated))
	}
	if e.exec.count() != 0 {
		t.Error("a proposal reached a device")
	}
	if v := e.verifyLog(); !v {
		t.Error("the log chain is broken")
	}
}

func (e *env) verifyLog() bool {
	e.t.Helper()
	r, err := e.svc.VerifyLog(e.ctx())
	e.must(err)
	return r.OK
}

func TestPropose_NeverTouchStillHolds(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	e.dir.devices["gw"] = response.DeviceInfo{ID: "gw", Name: "gateway", IP: hostIP, Kind: "router"}
	_, err := e.propose(lowBody())
	wantCode(t, err, 409, "never_touch")
	if e.requests() != 0 {
		t.Fatal("created")
	}
}

func TestPropose_PausedAIAnswersTheMockText(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	g := inv15Gates()[2]
	g.arm(e, nil)
	_, err := e.propose(lowBody())
	wantCode(t, err, 409, "ai_paused")
	if !contains(err.Error(), "3 of the last 5") {
		t.Fatalf("%v", err)
	}
}

// ---- AIActions ----

func TestAIActions_OnlyEnabledActionsTheAIMayPropose_NoTemplateText(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	e.allowHigh()
	l, err := e.svc.AIActions(e.ctx())
	e.must(err)
	var ids []string
	for _, a := range l {
		ids = append(ids, a.ID)
	}
	cat, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	var want []string
	for _, c := range cat.Items {
		if c.Enabled && c.AIMayPropose {
			want = append(want, c.ID)
		}
	}
	if !slices.Equal(ids, want) || !slices.Contains(ids, "blocklist_add") || !slices.Contains(ids, "fgt_policy_disable") {
		t.Fatalf("listed %v, enabled and AI-allowed %v", ids, want)
	}
	off := false
	_, err = e.svc.ChangeAction(e.ctx(), admin, "blocklist_add", response.CatalogUpdate{AIMayPropose: &off})
	e.must(err)
	_, err = e.svc.ChangeAction(e.ctx(), admin, "fgt_policy_disable", response.CatalogUpdate{Enabled: &off})
	e.must(err)
	l, err = e.svc.AIActions(e.ctx())
	e.must(err)
	for _, a := range l {
		if a.ID == "blocklist_add" || a.ID == "fgt_policy_disable" {
			t.Fatalf("%s is listed but is not enabled for the AI", a.ID)
		}
	}
	on := true
	_, err = e.svc.ChangeAction(e.ctx(), admin, "blocklist_add", response.CatalogUpdate{AIMayPropose: &on})
	e.must(err)
	l, err = e.svc.AIActions(e.ctx())
	e.must(err)
	i := slices.IndexFunc(l, func(a response.AIAction) bool { return a.ID == "blocklist_add" })
	if i < 0 || l[i].Risk != response.RiskLow || !l[i].Reversible || len(l[i].Params) != 1 || l[i].Params[0].Name != "ip" || l[i].Params[0].Type != "ip" || l[i].Params[0].Label == "" {
		t.Fatalf("blocklist_add: %+v", l)
	}
	raw, err := json.Marshal(l)
	e.must(err)
	var rows []map[string]any
	e.must(json.Unmarshal(raw, &rows))
	for _, row := range rows {
		for k := range row {
			if !slices.Contains([]string{"id", "name", "description", "risk", "reversible", "available", "params"}, k) {
				t.Errorf("AIAction exposes %q", k)
			}
		}
	}
	// no template text of the catalog reaches the list
	full, err := e.svc.Catalog(e.ctx(), true)
	e.must(err)
	for _, c := range full.Items {
		for _, text := range []string{c.Run.CLI, c.Run.Path, c.Run.Body, c.Rollback.CLI, c.Rollback.Path, c.Precheck.CLI} {
			if len(text) > 8 && strings.Contains(string(raw), text) {
				t.Errorf("template text of %s is in the list: %q", c.ID, text)
			}
		}
	}
	// a typed parameter carries its pattern or range
	if i := slices.IndexFunc(l, func(a response.AIAction) bool { return a.ID == "fgt_policy_disable" }); i >= 0 {
		if p := l[i].Params[0]; p.Type != "id" || p.Min != 1 || p.Max != 2147483647 {
			t.Errorf("an id has the range 1..2147483647: %+v", p)
		}
	}
	have := map[string]response.AIParam{}
	for _, a := range l {
		for _, p := range a.Params {
			have[p.Type] = p
		}
	}
	if p, ok := have["interface"]; ok && p.Pattern == "" {
		t.Errorf("interface has no pattern: %+v", p)
	}
}

func TestAIActions_UnavailableIsSaid(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	on := true
	_, err := e.svc.ChangeAction(e.ctx(), admin, "fgt_policy_disable", response.CatalogUpdate{Enabled: &on, AIMayPropose: &on})
	e.must(err)
	l, err := e.svc.AIActions(e.ctx())
	e.must(err)
	for _, a := range l {
		switch a.ID {
		case "fgt_policy_disable":
			if a.Available {
				t.Error("a device action with no connection is available")
			}
		case "blocklist_add":
			if !a.Available {
				t.Error("blocklist_add is not available")
			}
		}
	}
	_, err = e.propose(highBody())
	wantCode(t, err, 409, "tool_unavailable")
}

// ---- what the AI gets back ----

func TestPropose_ResultIsANarrowView(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	r := e.mustPropose(lowBody())
	raw, err := json.Marshal(r)
	e.must(err)
	var top map[string]json.RawMessage
	e.must(json.Unmarshal(raw, &top))
	if len(top) != 3 || top["outcome"] == nil || top["note"] == nil || top["request"] == nil {
		t.Fatalf("result keys: %s", raw)
	}
	var req map[string]any
	e.must(json.Unmarshal(top["request"], &req))
	keys := make([]string, 0, len(req))
	for k := range req {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if want := []string{"expires_at", "id", "in_app_only", "requires_approvals", "risk", "status", "title"}; !slices.Equal(keys, want) {
		t.Fatalf("request keys %v, want %v", keys, want)
	}
	// nothing of the rendered change can leave the port: not in the JSON, not in the Go type
	for _, bad := range []string{"blocklist add", "198.51.100.7\"", "cli", "rest", "url", "headers", "body", "change", "items"} {
		if strings.Contains(string(top["request"]), `"`+bad+`"`) || (bad == "blocklist add" && strings.Contains(string(top["request"]), bad)) {
			t.Errorf("the result carries %q: %s", bad, top["request"])
		}
	}
	rt := reflect.TypeOf(response.ProposedRequest{})
	for i := range rt.NumField() {
		switch rt.Field(i).Type.String() {
		case "string", "int", "bool", "response.Status", "response.Risk":
		default:
			t.Errorf("ProposedRequest.%s is a %s", rt.Field(i).Name, rt.Field(i).Type)
		}
	}
	if r.Request.Status != response.StatusPending || r.Request.RequiresApprovals != 1 || r.Request.ExpiresAt == "" || r.Request.Title != "Add 198.51.100.7 to the block list" || r.Request.ID == "" {
		t.Fatalf("%+v", r.Request)
	}
	n := lowBody()
	n.Confidence = 0.5
	n.Params = map[string]string{"ip": hostIP}
	if r := e.mustPropose(n); r.Request != nil || r.Outcome != "suggestion" {
		t.Fatalf("%+v", r)
	}
}

// ---- the module switch ----

func TestPropose_ModuleOffRefusesAndWritesNothing(t *testing.T) {
	t.Parallel()
	g := &gate{on: true}
	e := newEnv(t, func(c *response.Config) { c.Modules = g })
	e.dir.devices["a1"] = response.DeviceInfo{ID: "a1", Name: "PC-HR-01", IP: hostIP, Approved: true}
	e.dir.findings["f1"] = response.FindingInfo{ID: "f1", AssetID: "a1", CVE: "CVE-2024-0001", Severity: "high", Status: "confirmed"}
	e.turnOn()
	if l, err := e.svc.AIActions(e.ctx()); err != nil || len(l) == 0 {
		t.Fatalf("module on: %v %v", err, l)
	}
	g.on = false
	logs, audits, events := e.count(`SELECT COUNT(*) FROM resp_log`), e.count(`SELECT COUNT(*) FROM core_audit`), e.seen.count(response.EventRequestCreated)
	_, err := e.propose(lowBody())
	wantCode(t, err, 404, "not_found")
	if e.requests() != 0 || e.notes() != 0 || e.count(`SELECT COUNT(*) FROM resp_log`) != logs || e.count(`SELECT COUNT(*) FROM core_audit`) != audits || e.seen.count(response.EventRequestCreated) != events {
		t.Fatal("a proposal with the module off wrote or published something")
	}
	l, err := e.svc.AIActions(e.ctx())
	if err != nil || l == nil || len(l) != 0 {
		t.Fatalf("AIActions with the module off: %v %v", l, err)
	}
	g.on = true
	e.mustPropose(lowBody())
}

// ---- the lock ----

// A subscriber of the request-created event calls back into the service (it takes the service lock). The events go out with the lock
// released, so this must finish.
func TestPropose_EventsGoOutWithTheLockReleased(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	e.bus.Subscribe(response.EventRequestCreated, func(ctx context.Context, _ events.Event) error {
		_, err := e.svc.ResumeAI(ctx, admin) // takes the service lock
		return err
	})
	done := make(chan error, 1)
	go func() { _, err := e.propose(lowBody()); done <- err }()
	select {
	case err := <-done:
		e.must(err)
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: Propose published its events while holding the service lock")
	}
}

// ---- rate limits ----

func TestPropose_SixtyCallsAnHour(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	bad := lowBody()
	bad.Why = "" // the cheapest call there is: refused at the boundary, but counted
	for range 60 {
		_, err := e.propose(bad)
		wantCode(t, err, 400, "invalid")
	}
	_, err := e.propose(lowBody())
	wantCode(t, err, 429, "rate_limited")
	if ae, _ := apierrAs(err); ae.Extra["retry_after"] == nil || ae.Extra["retry_after"].(int) < 1 || ae.Extra["retry_after"].(int) > 3600 {
		t.Fatalf("Retry-After: %v", ae.Extra)
	}
	for range 5 { // refused again within the minute: one log line in all
		_, err = e.propose(lowBody())
		wantCode(t, err, 429, "rate_limited")
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'rate_limited%'`); n != 1 {
		t.Fatalf("%d rate_limited lines, want 1 per minute", n)
	}
	if e.requests() != 0 {
		t.Fatal("created")
	}
	e.clock.Advance(61 * time.Second)
	_, err = e.propose(lowBody())
	wantCode(t, err, 429, "rate_limited")
	if n := e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND detail LIKE 'rate_limited%'`); n != 2 || !e.logHas("refused", "6 refused since the last line") {
		t.Fatalf("%d lines; the second must carry the count of the first minute", n)
	}
	e.clock.Advance(time.Hour)
	if r := e.mustPropose(lowBody()); r.Outcome != "request" {
		t.Fatalf("an hour later: %+v", r)
	}
}

func TestPropose_NotesOfEachKindHaveTheirOwnCapOfFifty(t *testing.T) {
	t.Parallel()
	e, _, ev := propEnv(t, true)
	e.saveSettings(func(in *response.SettingsInput) { in.AI.BudgetHour = 1 })
	e.mustPropose(lowBody()) // the one request of the hour
	for i := range 3 {
		ev.add(fmt.Sprintf("ioc-d%d", i), fmt.Sprintf("198.51.100.%d", 60+i))
		b := iocBody(fmt.Sprintf("ioc-d%d", i))
		b.Params = map[string]string{"ip": fmt.Sprintf("198.51.100.%d", 60+i)}
		if r := e.mustPropose(b); r.Outcome != "digest" {
			t.Fatalf("%+v", r)
		}
		e.clock.Advance(time.Second)
	}
	for i := range 54 { // 1 + 3 + 54 = 58 calls
		b := lowBody()
		b.Confidence = 0.5
		b.Why = fmt.Sprintf("note %d", i)
		e.mustPropose(b)
		e.clock.Advance(time.Second)
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_ai_notes WHERE kind = 'suggestion'`); n != 50 {
		t.Fatalf("%d suggestions", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_ai_notes WHERE kind = 'digest'`); n != 3 {
		t.Fatalf("%d digests: a flood of suggestions pushed them out", n)
	}
	st, err := e.svc.AIState(e.ctx())
	e.must(err)
	if len(st.Notes) != 53 {
		t.Fatalf("the state shows %d notes", len(st.Notes))
	}
}

// ---- cancellations ----

// A cancellation (the emergency stop, an action edited) is status rejected too, but it is no verdict of a person: it does not block a
// repeat for 7 days and does not count for the quality breaker.
func TestPropose_ACancellationIsNotARejection(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	r := e.mustPropose(lowBody())
	before, err := e.svc.AIState(e.ctx())
	e.must(err)
	n, err := e.svc.EmergencyStop(e.ctx(), oper)
	e.must(err)
	if n != 1 || e.full(r.Request.ID).Status != response.StatusRejected {
		t.Fatalf("cancelled %d: %+v", n, e.full(r.Request.ID))
	}
	_, err = e.svc.ResetBreaker(e.ctx(), admin)
	e.must(err)
	e.turnOn()
	e.clock.Advance(time.Minute)
	st, err := e.svc.AIState(e.ctx())
	e.must(err)
	if st.Quality.Decided != before.Quality.Decided || st.Quality.Rejected != before.Quality.Rejected {
		t.Fatalf("a cancellation counts for the quality breaker: %+v", st.Quality)
	}
	r2 := e.mustPropose(lowBody())
	if r2.Outcome != "request" {
		t.Fatalf("a cancellation blocked the repeat: %+v", r2)
	}
	// a rejection by a person still does both
	e.reject(e.full(r2.Request.ID), "no", "none")
	st, err = e.svc.AIState(e.ctx())
	e.must(err)
	if st.Quality.Rejected != before.Quality.Rejected+1 {
		t.Fatalf("a rejection by a person is not counted: %+v", st.Quality)
	}
	_, err = e.propose(lowBody())
	wantCode(t, err, 409, "repeat_blocked")
}

func TestPropose_AnActionEditCancelsWithoutCountingAsARejection(t *testing.T) {
	t.Parallel()
	e, _, _ := propEnv(t, true)
	e.allowHigh()
	e.mustPropose(highBody())
	e.clock.Advance(time.Minute)
	off := false
	_, err := e.svc.ChangeAction(e.ctx(), admin, "fgt_policy_disable", response.CatalogUpdate{Enabled: &off})
	e.must(err)
	on := true
	_, err = e.svc.ChangeAction(e.ctx(), admin, "fgt_policy_disable", response.CatalogUpdate{Enabled: &on})
	e.must(err)
	st, err := e.svc.AIState(e.ctx())
	e.must(err)
	if st.Quality.Rejected != 0 || st.Quality.Decided != 0 {
		t.Fatalf("%+v", st.Quality)
	}
}

// ---- RequestProposal is a person's action ----

func TestRequestProposal_LogsThePersonNotTheAI(t *testing.T) {
	t.Parallel()
	e := planEnv(t)
	on := true
	_, err := e.svc.ChangeAction(e.ctx(), admin, "fgt_ban_ip", response.CatalogUpdate{AIMayPropose: &on})
	e.must(err)
	e.plan("plan-1", `{"id":"pr-1","action_id":"fgt_ban_ip","params":{"ip":"192.168.10.21"},"ttl_min":1440,"asset_id":"a-nas","asset_name":"NAS"}`)
	a, err := e.svc.RequestProposal(e.ctx(), oper, "pr-1")
	e.must(err)
	if actor, _ := e.newest("request"); actor != "it@acme.example (app)" {
		t.Fatalf("the request line is by %q", actor)
	}
	if e.count(`SELECT COUNT(*) FROM resp_log WHERE actor = 'ai:response'`) != 0 || e.count(`SELECT COUNT(*) FROM core_audit WHERE user = 'ai:response' AND target = ?`, a.ID) != 0 {
		t.Fatal("a person's request was logged as the AI's")
	}
}

func apierrAs(err error) (*apierr.Error, bool) { return apierr.As(err) }
