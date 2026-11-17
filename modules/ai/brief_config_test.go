package ai_test

import (
	"encoding/json"
	"net/netip"
	"slices"
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
		"paragraphs":       []string{"Junos OS 15.1R7.9 is inside the affected range (before 20.4).", long},
		"steps":            []string{"Back up the configuration.", "Apply the blocks below.", "Check that J-Web no longer answers."},
		"no_config_reason": "",
		"configs": []map[string]any{
			{"title": "Juniper EX4200-48T (Junos OS)", "lines": []string{"delete system services web-management", "commit"}, "side_effect": "J-Web stops working.", "based_on": "the vendor advisory"},
			{"title": "FortiGate", "lines": []string{"config firewall policy", "    edit 0", "        set dstaddr \"192.168.18.47/32\"", "        set srcaddr \"192.168.18.0/24\"", "    next", "end"}, "side_effect": "Blocks HTTP to the switch.", "based_on": "general practice, no source in the data names it"},
			// r1 M2: two commands in one string would become one command once a mask rewrites the answer: the block is left out
			{"title": "Two in one", "lines": []string{"config firewall policy\nend"}, "side_effect": "", "based_on": ""},
			// r2: an address the box does not know is kept and named for checking, never a reason to leave the block out; a netmask and a
			// wildcard are not addresses
			{"title": "Elsewhere", "lines": []string{"set address 203.0.113.9", "set subnet 192.168.18.47 255.255.255.255", "access-list 101 deny tcp any 192.168.18.0 0.0.0.255 eq 443"}, "side_effect": "", "based_on": ""},
			// r2 M4: invisible characters go, so the line shown is the line pasted
			{"title": "nftables", "lines": []string{"nft add rule inet filter forward ip daddr 192.168.18.47 tcp dport 443\u2028 drop\u200b\u202e"}, "side_effect": "Drops HTTPS.", "based_on": "general practice, no source in the data names it"},
			{"title": "Too long", "lines": []string{strings.Repeat("x", 500)}, "side_effect": "", "based_on": ""},
			{"title": "Empty", "lines": []string{"  ", ""}, "side_effect": "", "based_on": ""},
		},
	})
	a.fake.setAnswer(string(answer))
	trusted := []netip.Addr{netip.MustParseAddr("192.168.18.47")}
	out, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobMitigationConfig, Actor: "it@acme.example", Target: "CVE-2023-36845", Question: "Write the config.", Trusted: trusted})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Paragraphs) != 2 || !strings.HasSuffix(out.Paragraphs[1], "switch.") || len([]rune(out.Paragraphs[1])) > 1500 {
		t.Fatalf("paragraph 2 = %q: cut mid-sentence or over the limit", out.Paragraphs[1])
	}
	if !out.Shortened {
		t.Fatal("a cut paragraph and a left-out config block must set Shortened")
	}
	if len(out.Configs) != 4 { // the over-long and two-in-one blocks are left out whole, the empty one is no block
		t.Fatalf("configs = %+v", out.Configs)
	}
	if c := out.Configs[0]; c.Code != "delete system services web-management\ncommit" || c.SideEffect != "J-Web stops working." || c.BasedOn != "the vendor advisory" {
		t.Fatalf("junos block = %+v", c)
	}
	if c := out.Configs[1].Code; c != "config firewall policy\n    edit 0\n        set dstaddr \"192.168.18.47/32\"\n        set srcaddr \"192.168.18.0/24\"\n    next\nend" {
		t.Fatalf("fortigate block lost its lines or indentation: %q", c)
	}
	if c := out.Configs[1]; len(c.Check) != 0 {
		t.Fatalf("a /32 of the device and its /24 are not to check: %v", c.Check)
	}
	if c := out.Configs[2]; c.Title != "Elsewhere" || !slices.Equal(c.Check, []string{"203.0.113.9"}) {
		t.Fatalf("elsewhere block = %+v", c)
	}
	if c := out.Configs[3]; c.Code != "nft add rule inet filter forward ip daddr 192.168.18.47 tcp dport 443 drop" {
		t.Fatalf("invisible characters kept: %q", c.Code)
	}
	req := a.fake.reqs[len(a.fake.reqs)-1]
	if !strings.Contains(string(req.Schema.JSON), `"configs"`) || req.MaxTokens < 8000 || !strings.Contains(req.System, "firewall") {
		t.Fatalf("the config job did not ask for config blocks: max %d, schema %s", req.MaxTokens, req.Schema.JSON)
	}

	// r1 H1: an honest answer with no config and the reason is kept (a local flaw has no firewall rule)
	a.fake.setAnswer(`{"paragraphs":["A local flaw."],"steps":["Install the update."],"configs":[],"no_config_reason":"The attack is local (AV:L): no firewall rule helps."}`)
	out, err = a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobMitigationConfig, Actor: "it@acme.example", Question: "Write the config."})
	if err != nil || len(out.Configs) != 0 || out.NoConfigReason != "The attack is local (AV:L): no firewall rule helps." || out.Shortened {
		t.Fatalf("honest no-config answer = %+v, %v", out, err)
	}
	// r2 M1: checked as kept: an answer whose only block is left out (two commands in one line) and that gives no reason is a format error
	a.fake.setAnswer(`{"paragraphs":["Restrict J-Web."],"steps":["Do it."],"configs":[{"title":"x","lines":["a\nb"],"side_effect":"","based_on":""}],"no_config_reason":""}`)
	if _, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobMitigationConfig, Actor: "it@acme.example", Question: "Write the config."}); err == nil {
		t.Fatal("an answer with nothing kept and no reason was accepted")
	}
	// an answer without a single config line and without a reason is not what the job asked for
	a.fake.setAnswer(`{"paragraphs":["Restrict J-Web."],"steps":["Do it."],"configs":[],"no_config_reason":" "}`)
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
