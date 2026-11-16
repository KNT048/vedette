package ai_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/modules/ai"
)

// M2-2 (walk n74): "Ask my AI" for a Juniper finding gave prose and steps but no config, and a paragraph stopped at 500 characters
// in the middle of a sentence ("No confirmed recommendation exists yet, and a"). The mitigation-config brief now asks for config blocks
// (one line per string) and keeps every text whole up to a sentence end.
func TestBriefConfig_M2_2_ConfigBlocksAndNoMidSentenceCut(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	long := strings.Repeat("Restricting J-Web can stop browser management of the switch. ", 40) // about 2,400 characters
	answer, _ := json.Marshal(map[string]any{
		"paragraphs": []string{"Junos OS 15.1R7.9 is inside the affected range (before 20.4).", long},
		"steps":      []string{"Back up the configuration.", "Apply the blocks below.", "Check that J-Web no longer answers."},
		"configs": []map[string]any{
			{"title": "Juniper EX4200-48T (Junos OS)", "lines": []string{"delete system services web-management", "commit\n"}, "side_effect": "J-Web stops working.", "based_on": "the vendor advisory"},
			{"title": "FortiGate", "lines": []string{"config firewall policy", "    edit 0\n        set srcintf \"lan\"", "    next", "end"}, "side_effect": "Blocks HTTP to the switch.", "based_on": "general hardening"},
			{"title": "Too long", "lines": []string{strings.Repeat("x", 500)}, "side_effect": "", "based_on": ""},
			{"title": "Empty", "lines": []string{"  ", ""}, "side_effect": "", "based_on": ""},
		},
	})
	a.fake.setAnswer(string(answer))
	out, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobMitigationConfig, Actor: "it@acme.example", Target: "CVE-2023-36845", Question: "Write the config."})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Paragraphs) != 2 || !strings.HasSuffix(out.Paragraphs[1], "switch.") || len([]rune(out.Paragraphs[1])) > 1500 {
		t.Fatalf("paragraph 2 = %q: cut mid-sentence or over the limit", out.Paragraphs[1])
	}
	if !out.Shortened {
		t.Fatal("a cut paragraph and a left-out config block must set Shortened")
	}
	if len(out.Configs) != 2 { // the over-long block is left out whole, the empty one is no block
		t.Fatalf("configs = %+v", out.Configs)
	}
	if c := out.Configs[0]; c.Code != "delete system services web-management\ncommit" || c.SideEffect != "J-Web stops working." || c.BasedOn != "the vendor advisory" {
		t.Fatalf("junos block = %+v", c)
	}
	if c := out.Configs[1].Code; c != "config firewall policy\n    edit 0\n        set srcintf \"lan\"\n    next\nend" {
		t.Fatalf("fortigate block lost its lines or indentation: %q", c)
	}
	req := a.fake.reqs[len(a.fake.reqs)-1]
	if !strings.Contains(string(req.Schema.JSON), `"configs"`) || req.MaxTokens < 8000 || !strings.Contains(req.System, "firewall") {
		t.Fatalf("the config job did not ask for config blocks: max %d, schema %s", req.MaxTokens, req.Schema.JSON)
	}

	// an answer without a single config line is not what the job asked for
	a.fake.setAnswer(`{"paragraphs":["Restrict J-Web."],"steps":["Do it."],"configs":[]}`)
	_, err = a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobMitigationConfig, Actor: "it@acme.example", Question: "Write the config."})
	var ae *apierr.Error
	if !asAPI(err, &ae) || ae.Code != "ai_bad_format" {
		t.Fatalf("no config = %v", err)
	}

	// a short answer is kept as it is and is not marked shortened; explain-finding has no config blocks
	a.fake.setAnswer(`{"paragraphs":["The device runs the product."],"steps":["Update it."]}`)
	out, err = a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobExplainFinding, Actor: "it@acme.example", Question: "Explain."})
	if err != nil || out.Shortened || len(out.Configs) != 0 || out.Paragraphs[0] != "The device runs the product." {
		t.Fatalf("explain = %+v, %v", out, err)
	}
}
