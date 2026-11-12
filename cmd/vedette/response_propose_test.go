package main

import (
	"testing"
	"time"

	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/response"
)

// WP-13b slice 13b-10 (D-97, D-119) in the real wiring: the AI proposal goes through the Go port, never through HTTP, and evidence the
// binary cannot look up yet fails closed.

func TestWiringProposeThroughTheGoPort(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	for _, m := range []string{"notify", "inventory", "response"} {
		s.setModule(m, true)
	}
	ctx := t.Context()
	c := s.connCreate(connInput("Office firewall", "tok-0123456789-abcdef"))
	svc := s.d.Response
	body := response.ProposeBody{Trigger: "ioc_connection", ActionID: "blocklist_add", Params: map[string]string{"ip": "198.51.100.7"}, Confidence: 0.9,
		Evidence: []response.ProposedEvidence{{Kind: "ioc_hit", ID: "det-1"}}, Why: "A listed address."}
	// A known-bad connection or a read the box has no record of is no evidence (both lookups are wired, #365 and #376): a read tool that merely exists proves nothing.
	_, err := svc.Propose(ctx, body)
	apiErr(t, err, 422, "evidence_invalid")
	body.Evidence = []response.ProposedEvidence{{Kind: "config_read", ID: c.ID + "/fetch_url"}}
	_, err = svc.Propose(ctx, body)
	apiErr(t, err, 422, "evidence_invalid")
	// A finding the box does not hold is no evidence either.
	body.Trigger, body.Evidence = "finding", []response.ProposedEvidence{{Kind: "finding", ID: "f-nope"}}
	_, err = svc.Propose(ctx, body)
	apiErr(t, err, 422, "evidence_invalid")
	if n := s.count(`SELECT count(*) FROM resp_actions`) + s.count(`SELECT count(*) FROM resp_ai_notes`); n != 0 {
		t.Fatalf("%d rows were created from evidence that does not exist", n)
	}
	if n := s.count(`SELECT count(*) FROM resp_log WHERE kind = 'refused' AND actor = 'ai:response'`); n != 3 {
		t.Errorf("%d refusals by ai:response", n)
	}
	acts, err := svc.AIActions(ctx)
	if err != nil || len(acts) == 0 {
		t.Fatalf("AIActions: %v %v", err, acts)
	}
	// With the module off the port refuses and lists nothing.
	s.setModule("response", false)
	if _, err := svc.Propose(ctx, body); err == nil {
		t.Error("Propose with the module off")
	}
	if l, err := svc.AIActions(ctx); err != nil || len(l) != 0 {
		t.Errorf("AIActions with the module off: %v %v", l, err)
	}
	s.setModule("response", true)
	// The same thing over HTTP does not exist (FORBID-5).
	for _, role := range []string{"operator", "admin"} {
		code, v := s.do("POST", "/response/ai/proposals", role, `{"trigger":"finding","action_id":"blocklist_add","params":{"ip":"198.51.100.8"},"confidence":0.9,"evidence":[],"why":"x"}`)
		if code != 404 || at(v, "error", "code") != "not_found" {
			t.Errorf("POST /response/ai/proposals as %s: %d %v", role, code, v)
		}
	}
}

// ai 7 (D-311): config_read evidence is a read the ai module recorded, at most 24 hours old, looked up through the real wiring. A
// read it found does not prove the ioc_connection trigger, so the answer moves from evidence_invalid to evidence_mismatch; an old
// row, an unknown id and the ai module off are evidence_invalid.
func TestWiringConfigReadIsTheAIRecordOfAReadThroughTheConnection(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	for _, m := range []string{"notify", "inventory", "response", "ai"} {
		s.setModule(m, true)
	}
	ctx := t.Context()
	now := time.Now().UTC()
	s.exec(`INSERT INTO ai_read (id, ts, connection_id, connection_name, tool, job) VALUES ('rd-fresh', ?, 'cn-fw', 'Office firewall', 'show_addr', 'ask-my-data'), ('rd-old', ?, 'cn-fw', 'Office firewall', 'show_addr', 'ask-my-data')`,
		ai.FormatTS(now.Add(-time.Hour)), ai.FormatTS(now.Add(-25*time.Hour)))
	body := response.ProposeBody{Trigger: "ioc_connection", ActionID: "blocklist_add", Params: map[string]string{"ip": "198.51.100.7"}, Confidence: 0.9,
		Evidence: []response.ProposedEvidence{{Kind: "config_read", ID: "rd-fresh"}}, Why: "A read of the firewall."}
	_, err := s.d.Response.Propose(ctx, body)
	apiErr(t, err, 422, "evidence_mismatch")
	for _, id := range []string{"rd-old", "rd-nope"} {
		body.Evidence = []response.ProposedEvidence{{Kind: "config_read", ID: id}}
		_, err = s.d.Response.Propose(ctx, body)
		apiErr(t, err, 422, "evidence_invalid")
	}
	s.setModule("ai", false)
	body.Evidence = []response.ProposedEvidence{{Kind: "config_read", ID: "rd-fresh"}}
	_, err = s.d.Response.Propose(ctx, body)
	apiErr(t, err, 422, "evidence_invalid")
	ref, ok, err := aiConfigRead(s.d.AI)(ctx, "rd-fresh")
	if ok || err != nil || ref.Connection != "" || ref.Summary != "" {
		t.Fatalf("lookup with the ai module off: %+v %v %v", ref, ok, err)
	}
	s.setModule("ai", true)
	ref, ok, err = aiConfigRead(s.d.AI)(ctx, "rd-fresh")
	if !ok || err != nil || ref.Connection != "cn-fw" || ref.ID != "rd-fresh" || len(ref.Relates) != 0 || ref.Summary == "" {
		t.Fatalf("lookup: %+v %v %v", ref, ok, err)
	}
}
