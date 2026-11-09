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

// propEnv is an environment with execution on, a finding on a device at hostIP, a known-bad connection about hostIP and about policy 12
// and a connection read, all behind the fake ports.
func propEnv(t *testing.T, withPorts bool) (*env, *fakeTwoStep, *evFake) {
	t.Helper()
	ev := &evFake{
		ioc: map[string]response.EvidenceRef{
			"ioc-1":    {Summary: "Known-bad connection to the firewall policy", Relates: []string{policy}},
			"ioc-host": {Summary: "PC-HR-01 connected to a listed address", Relates: []string{hostIP}},
			"ioc-else": {Summary: "Something about another address", Relates: []string{"203.0.113.9"}},
		},
		cfg: map[string]response.EvidenceRef{"cn-fw/fetch_url": {Summary: "Read fetch_url on Office firewall"}},
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

// highBody is the body of the high-risk action: two pieces of evidence, one of them about policy 12.
func highBody() response.ProposeBody {
	return response.ProposeBody{Trigger: "finding", ActionID: "fgt_policy_disable", Params: map[string]string{"id": policy}, Confidence: 0.95,
		Evidence: []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "ioc_hit", ID: "ioc-1"}}, Why: "A firewall policy lets the exploited service out."}
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

// ---- INV-15: the gates, in order ----

// gate is one row of the INV-15 table. arm puts the box and the body in the state that makes this gate refuse; the test of row i arms
// rows i..last at once (latest first, so an earlier gate's change wins where two change the same thing), which proves that gate i
// refuses first while every later gate would have refused too. Row i-1, armed the same way, proves the earlier gate beats this one.
type inv15Gate struct {
	name   string
	arm    func(e *env, b *response.ProposeBody)
	status int
	code   string
	outcom string // set for the two gates that answer a note instead of a refusal
}

func (e *env) setting(path string, val any) {
	e.t.Helper()
	raw, err := json.Marshal(val)
	e.must(err)
	e.exec1(`UPDATE resp_settings SET value = json_set(value, ?, json(?))`, path, string(raw))
}

// priorRule makes a pending request for the high-risk action on policy 12, from a rule, and returns it.
func (e *env) priorRequest(event string) response.ActionRequest {
	e.t.Helper()
	if len(mustRules(e)) == 0 {
		e.rule("Cut the policy", "honeypot", []response.RuleAction{{ActionID: "fgt_policy_disable", Params: map[string]string{"id": policy}, TTLMin: intp(1440)}}, nil)
	}
	seen := map[string]bool{}
	for _, a := range e.actions() {
		seen[a.ID] = true
	}
	e.fire(e.trap(event, "192.168.10.157"))
	for _, a := range e.actions() {
		if !seen[a.ID] {
			return a
		}
	}
	e.t.Fatal("the rule made no request")
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
		{name: "trigger", status: 403, code: "trigger_not_allowed", arm: func(_ *env, b *response.ProposeBody) { b.Trigger = "honeypot" }},
		{name: "action not for the AI", status: 403, code: "action_not_ai_allowed", arm: func(e *env, _ *response.ProposeBody) {
			e.exec1(`UPDATE resp_catalog SET ai_may_propose = 0 WHERE id = 'fgt_policy_disable'`)
		}},
		{name: "plan", status: 409, code: "invalid_target", arm: func(_ *env, b *response.ProposeBody) { b.Params = map[string]string{"id": "not a number"} }},
		{name: "evidence missing", status: 400, code: "evidence_missing", arm: func(_ *env, b *response.ProposeBody) { b.Evidence = nil }},
		{name: "evidence invalid", status: 422, code: "evidence_invalid", arm: func(_ *env, b *response.ProposeBody) {
			b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "ioc_hit", ID: "ioc-made-up"}}
		}},
		{name: "evidence mismatch", status: 422, code: "evidence_mismatch", arm: func(_ *env, b *response.ProposeBody) {
			b.Evidence = []response.ProposedEvidence{{Kind: "finding", ID: "f1"}, {Kind: "ioc_hit", ID: "ioc-else"}}
		}},
		{name: "low confidence", outcom: "suggestion", arm: func(_ *env, b *response.ProposeBody) { b.Confidence = 0.5 }},
		{name: "already open", status: 409, code: "already_open", arm: func(e *env, _ *response.ProposeBody) { e.priorRequest("h-open") }},
		{name: "rejected within 7 days", status: 409, code: "repeat_blocked", arm: func(e *env, _ *response.ProposeBody) {
			a := e.priorRequest("h-rej")
			e.asAI(a.ID, `{"confidence":0.95,"evidence":[{"kind":"finding","id":"f1","summary":"s"},{"kind":"ioc_hit","id":"ioc-1","summary":"s"}],"why":"test","second_check":null,"in_app_only":true}`)
			e.reject(a, "Not now", "none")
		}},
		{name: "budget", outcom: "digest", arm: func(e *env, _ *response.ProposeBody) {
			e.setting("$.ai.budget_hour", 1)
			e.exec1(`INSERT INTO resp_actions (id, source, proposal_id, asset_name, title, risk, status, requested_at, expires_at, requires_approvals, items)
				VALUES ('act-usage', 'ai', 'ai:usage', 'X', 'Earlier AI request', 'low', 'expired', ?, ?, 1, '[]')`, store.FormatTS(e.clock.Now().Add(-time.Minute)), store.FormatTS(e.clock.Now().Add(time.Hour)))
		}},
		{name: "second check", status: 422, code: "second_check_failed", arm: func(_ *env, b *response.ProposeBody) {
			b.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: "ioc-1"}}
		}},
		{name: "request", outcom: "request", arm: func(*env, *response.ProposeBody) {}},
	}
}

func TestContract_INV15_GatesRunInOrder(t *testing.T) {
	all := inv15Gates()
	for i, g := range all {
		t.Run(fmt.Sprintf("%02d %s", i+1, g.name), func(t *testing.T) {
			e, _, _ := propEnv(t, true)
			e.allowHigh()
			b := highBody()
			for j := len(all) - 1; j >= i; j-- { // the later gates are armed too: this one must still be the one that answers
				all[j].arm(e, &b)
			}
			requests, notes, logs := e.requests(), e.notes(), e.count(`SELECT COUNT(*) FROM resp_log`)
			res, err := e.propose(b)
			switch {
			case g.code != "":
				wantCode(t, err, g.status, g.code)
				if e.requests() != requests || e.notes() != notes {
					t.Fatalf("a refusal created something: requests %d -> %d, notes %d -> %d", requests, e.requests(), notes, e.notes())
				}
				if !e.logHas("refused", g.code) || e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'refused' AND actor = 'ai:response'`) == 0 {
					t.Fatal("the refusal is not in resp_log under ai:response")
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
				} else if e.requests() != requests || e.notes() != notes+1 || res.Request != nil || e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'ai_note' AND actor = 'ai:response'`) != 1 {
					t.Fatalf("a %s note must be one note, one log line and no request (requests %d -> %d, notes %d -> %d)", g.outcom, requests, e.requests(), notes, e.notes())
				}
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

// ---- notes ----

func TestPropose_NotesAreCappedAtFifty(t *testing.T) {
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
	over.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: "ioc-8"}}
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

func TestPropose_EvidenceIsLookedUpNeverTrusted(t *testing.T) {
	t.Run("a nil port refuses", func(t *testing.T) {
		e, _, _ := propEnv(t, false)
		b := lowBody()
		b.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: "ioc-host"}}
		_, err := e.propose(b)
		wantCode(t, err, 422, "evidence_invalid")
		b.Evidence = []response.ProposedEvidence{{Kind: "config_read", ID: "cn-fw/fetch_url"}}
		_, err = e.propose(b)
		wantCode(t, err, 422, "evidence_invalid")
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
		for _, ev := range []response.ProposedEvidence{{Kind: "finding", ID: "f-nope"}, {Kind: "ioc_hit", ID: "ioc-nope"}, {Kind: "config_read", ID: "cn-fw/nothing"}} {
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
	t.Run("evidence about something else refuses", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		b := lowBody()
		b.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: "ioc-else"}}
		_, err := e.propose(b)
		wantCode(t, err, 422, "evidence_mismatch")
	})
	t.Run("a finding on the target device is about the target", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		r := e.mustPropose(lowBody())
		if r.Request == nil || len(r.Request.AI.Evidence) != 1 || !contains(r.Request.AI.Evidence[0].Summary, "CVE-2024-0001") || r.Request.FindingID == nil || *r.Request.FindingID != "f1" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("a set of connection reads alone is accepted", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		b := lowBody()
		b.Evidence = []response.ProposedEvidence{{Kind: "config_read", ID: "cn-fw/fetch_url"}}
		r := e.mustPropose(b)
		if r.Outcome != "request" || r.Request.AI.Evidence[0].Kind != "config_read" {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("a connection read next to other evidence does not stand in for it", func(t *testing.T) {
		e, _, _ := propEnv(t, true)
		b := lowBody()
		b.Evidence = []response.ProposedEvidence{{Kind: "config_read", ID: "cn-fw/fetch_url"}, {Kind: "ioc_hit", ID: "ioc-else"}}
		_, err := e.propose(b)
		wantCode(t, err, 422, "evidence_mismatch")
	})
	t.Run("a port that fails creates nothing", func(t *testing.T) {
		e, _, ev := propEnv(t, true)
		ev.err = fmt.Errorf("logs are down")
		b := lowBody()
		b.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: "ioc-host"}}
		if _, err := e.propose(b); err == nil || e.requests() != 0 {
			t.Fatalf("err %v, %d requests", err, e.requests())
		}
	})
	t.Run("what a port says is cleaned before it is stored", func(t *testing.T) {
		e, _, ev := propEnv(t, true)
		ev.ioc["ioc-dirty"] = response.EvidenceRef{Summary: "bad\u202e\r\n\x00connection\u200b to\u3164 x", Relates: []string{hostIP}}
		b := lowBody()
		b.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: "ioc-dirty"}}
		r := e.mustPropose(b)
		if got := r.Request.AI.Evidence[0].Summary; got != "bad connection to x" {
			t.Fatalf("summary %q", got)
		}
	})
}

func TestPropose_TheSameEvidenceTwiceCountsOnce(t *testing.T) {
	e, _, _ := propEnv(t, true)
	e.allowHigh()
	b := highBody()
	b.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: "ioc-1"}, {Kind: "ioc_hit", ID: "ioc-1"}}
	_, err := e.propose(b)
	wantCode(t, err, 422, "second_check_failed")
}

// ---- the body at the boundary ----

func TestPropose_BodyIsValidatedAtTheBoundary(t *testing.T) {
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
	if r.Request.AI.Why != "line one line two" || *r.Request.TriggerSummary != "line one line two" {
		t.Fatalf("why %q", r.Request.AI.Why)
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
	setup := func(t *testing.T) (*env, *evFake) {
		e, _, ev := propEnv(t, true)
		r := e.mustPropose(lowBody())
		e.clock.Advance(time.Minute)
		e.reject(*r.Request, "Our scanner", "none")
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
		b.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: "ioc-8"}}
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
	e, _, ev := propEnv(t, true)
	if st := e.settings(); st.AI.BudgetHour != 2 || st.AI.BudgetDay != 5 {
		t.Fatalf("defaults: %+v", st.AI)
	}
	at := func(i int) response.ProposeBody {
		ev.add(fmt.Sprintf("ioc-b%d", i), fmt.Sprintf("198.51.100.%d", 20+i))
		b := lowBody()
		b.Params = map[string]string{"ip": fmt.Sprintf("198.51.100.%d", 20+i)}
		b.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: fmt.Sprintf("ioc-b%d", i)}}
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
	e, f, _ := propEnv(t, true)
	e.allowHigh()
	one := highBody()
	one.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: "ioc-1"}}
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
	a := r.Request.AI
	if !a.InAppOnly || a.SecondCheck == nil || !a.SecondCheck.OK || a.Confidence != 0.9 || len(a.Evidence) != 2 || !contains(r.Note, "two different people") {
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
	e, _, _ := propEnv(t, true)
	r := e.mustPropose(lowBody())
	if r.Request.Risk != response.RiskLow || r.Request.AI.InAppOnly || r.Request.AI.SecondCheck != nil || r.Request.RequiresApprovals != 1 || r.Request.Items[0].TTLMin == nil || *r.Request.Items[0].TTLMin != 1440 {
		t.Fatalf("%+v %+v", r.Request, r.Request.AI)
	}
}

// ---- concurrency ----

func TestPropose_ConcurrentProposalsForOneTargetCreateOneRequest(t *testing.T) {
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
			b.Evidence = []response.ProposedEvidence{{Kind: "ioc_hit", ID: fmt.Sprintf("ioc-c%d", i)}}
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
	e, _, _ := propEnv(t, true)
	e.dir.devices["gw"] = response.DeviceInfo{ID: "gw", Name: "gateway", IP: hostIP, Kind: "router"}
	_, err := e.propose(lowBody())
	wantCode(t, err, 409, "never_touch")
	if e.requests() != 0 {
		t.Fatal("created")
	}
}

func TestPropose_PausedAIAnswersTheMockText(t *testing.T) {
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
