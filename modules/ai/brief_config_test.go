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

// answersJSON is an answer of the brief with the four answers, in a shuffled order, and the other fields of the job after them.
func answersJSON(rest string) string {
	if rest != "" {
		rest = "," + rest
	}
	return `{"answers":[{"key":"urgency","text":"Exploited in the wild.","refs":[]},{"key":"affected","text":"Yes: the device runs the product.","refs":[]},` +
		`{"key":"fix","text":"Update to 21.2R3-S7.","refs":[]},{"key":"workaround","text":"No workaround is published: install the fix.","refs":[]}]` + rest + `}`
}

// Regression: "Ask my AI" for a Juniper finding gave prose and steps but no config, and a paragraph stopped at 500 characters
// in the middle of a sentence ("No confirmed recommendation exists yet, and a"). The mitigation-config brief now asks for config blocks
// (one line per string) and keeps every text whole up to a sentence end.
func TestBriefConfig_M2_2_ConfigBlocksAndNoMidSentenceCut(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	long := strings.Repeat("Restricting J-Web can stop browser management of the switch. ", 40) // about 2,400 characters
	answer, _ := json.Marshal(map[string]any{
		"answers": []map[string]any{
			{"key": "affected", "text": "Junos OS 15.1R7.9 is inside the affected range (before 20.4).", "refs": []int{1, 2, 9}},
			{"key": "fix", "text": long, "refs": []int{}},
			{"key": "workaround", "text": "No workaround is published: install the fix.", "refs": []int{}},
			{"key": "urgency", "text": "Exploited in the wild.", "refs": []int{2, 2}},
		},
		"steps":            []string{"Back up the configuration.", "Apply the blocks below.", "Check that J-Web no longer answers."},
		"no_config_reason": "",
		"configs": []map[string]any{
			{"title": "Juniper EX4200-48T (Junos OS)", "lines": []string{"delete system services web-management", "commit"}, "side_effect": "J-Web stops working.", "based_on": "the vendor advisory"},
			{"title": "FortiGate", "lines": []string{"config firewall policy", "    edit 0", "        set dstaddr \"192.168.142.47/32\"", "        set srcaddr \"192.168.142.0/24\"", "    next", "end"}, "side_effect": "Blocks HTTP to the switch.", "based_on": "general practice, no source in the data names it"},
			// r1 M2: two commands in one string would become one command once a mask rewrites the answer: the block is left out
			{"title": "Two in one", "lines": []string{"config firewall policy\nend"}, "side_effect": "", "based_on": ""},
			// r2: an address the box does not know is kept and named for checking, never a reason to leave the block out; a netmask and a
			// wildcard are not addresses
			{"title": "Elsewhere", "lines": []string{"set address 203.0.113.9", "set subnet 192.168.142.47 255.255.255.255", "access-list 101 deny tcp any 192.168.142.0 0.0.0.255 eq 443"}, "side_effect": "", "based_on": ""},
			// r2 M4: invisible characters go, so the line shown is the line pasted
			{"title": "nftables", "lines": []string{"nft add rule inet filter forward ip daddr 192.168.142.47 tcp dport 443\u2028 drop\u200b\u202e"}, "side_effect": "Drops HTTPS.", "based_on": "general practice, no source in the data names it"},
			{"title": "Too long", "lines": []string{strings.Repeat("x", 500)}, "side_effect": "", "based_on": ""},
			{"title": "Empty", "lines": []string{"  ", ""}, "side_effect": "", "based_on": ""},
		},
	})
	a.fake.setAnswer(string(answer))
	trusted := []netip.Addr{netip.MustParseAddr("192.168.142.47")}
	refs := []ai.BriefRef{{Title: "Vendor advisory", URL: "https://supportportal.juniper.net/JSA72300"}, {Title: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-36845"}}
	out, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobMitigationConfig, Actor: "it@acme.example", Target: "CVE-2023-36845", Question: "Write the config.", Refs: refs, Trusted: trusted})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Answers) != 4 || !strings.HasSuffix(out.Answers[1].Text, "switch.") || len([]rune(out.Answers[1].Text)) > 1200 {
		t.Fatalf("answer 2 = %+v: cut mid-sentence or over the limit", out.Answers)
	}
	// the links of an answer are the references the box offered, by the numbers the model named; a number it was not offered (9) and a
	// repeated one are dropped
	if got := out.Answers[0].Links; len(got) != 2 || got[0] != refs[0] || got[1] != refs[1] {
		t.Fatalf("links of the first answer = %+v", got)
	}
	if got := out.Answers[3].Links; len(got) != 1 || got[0] != refs[1] {
		t.Fatalf("links of the last answer = %+v", got)
	}
	if len(out.Paragraphs) != 0 {
		t.Fatalf("paragraphs = %v: the answers replace them", out.Paragraphs)
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
	if c := out.Configs[1].Code; c != "config firewall policy\n    edit 0\n        set dstaddr \"192.168.142.47/32\"\n        set srcaddr \"192.168.142.0/24\"\n    next\nend" {
		t.Fatalf("fortigate block lost its lines or indentation: %q", c)
	}
	if c := out.Configs[1]; len(c.Check) != 0 {
		t.Fatalf("a /32 of the device and its /24 are not to check: %v", c.Check)
	}
	if c := out.Configs[2]; c.Title != "Elsewhere" || !slices.Equal(c.Check, []string{"203.0.113.9"}) {
		t.Fatalf("elsewhere block = %+v", c)
	}
	if c := out.Configs[3]; c.Code != "nft add rule inet filter forward ip daddr 192.168.142.47 tcp dport 443 drop" {
		t.Fatalf("invisible characters kept: %q", c.Code)
	}
	req := a.fake.reqs[len(a.fake.reqs)-1]
	if !strings.Contains(string(req.Schema.JSON), `"configs"`) || req.MaxTokens < 8000 || !strings.Contains(req.System, "firewall") {
		t.Fatalf("the config job did not ask for config blocks: max %d, schema %s", req.MaxTokens, req.Schema.JSON)
	}

	// r1 H1: an honest answer with no config and the reason is kept (a local flaw has no firewall rule)
	a.fake.setAnswer(answersJSON(`"steps":["Install the update."],"configs":[],"no_config_reason":"The attack is local (AV:L): no firewall rule helps."`))
	out, err = a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobMitigationConfig, Actor: "it@acme.example", Question: "Write the config."})
	if err != nil || len(out.Configs) != 0 || out.NoConfigReason != "The attack is local (AV:L): no firewall rule helps." || out.Shortened {
		t.Fatalf("honest no-config answer = %+v, %v", out, err)
	}
	// r2 M1: checked as kept: an answer whose only block is left out (two commands in one line) and that gives no reason is a format error
	a.fake.setAnswer(answersJSON(`"steps":["Do it."],"configs":[{"title":"x","lines":["a\nb"],"side_effect":"","based_on":""}],"no_config_reason":""`))
	if _, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobMitigationConfig, Actor: "it@acme.example", Question: "Write the config."}); err == nil {
		t.Fatal("an answer with nothing kept and no reason was accepted")
	}
	// an answer without a single config line and without a reason is not what the job asked for
	a.fake.setAnswer(answersJSON(`"steps":["Do it."],"configs":[],"no_config_reason":" "`))
	_, err = a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobMitigationConfig, Actor: "it@acme.example", Question: "Write the config."})
	var ae *apierr.Error
	if !asAPI(err, &ae) || ae.Code != "ai_bad_format" {
		t.Fatalf("no config = %v", err)
	}

	// a short answer is kept as it is and is not marked shortened; explain-finding has no config blocks
	a.fake.setAnswer(answersJSON(""))
	out, err = a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobExplainFinding, Actor: "it@acme.example", Question: "Explain."})
	if err != nil || out.Shortened || len(out.Configs) != 0 || len(out.Steps) != 0 || out.Answers[0].Text != "Yes: the device runs the product." {
		t.Fatalf("explain = %+v, %v", out, err)
	}
}

// An answer said "the fixed release is 20.4 or later" from the Evidence's "before 20.4" while the finding page said 20.4 is not the
// fix, and wrote a rule for a firewall that traffic to the device never crosses. Both finding jobs tell the model that the "Fixed
// version" line is the fix and that a range end is not one; the config job writes rules only for the firewalls the network block
// offers and names the firewall it assumed when the box does not know the path.
func TestBrief_FixFollowsThePageAndRulesFollowThePath(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	fix := []string{`The "Fix for this device" line is the fix`, "never name a release of another release train",
		`never call the "before" end of an affected range a fix`, "never work out a fixed release from an affected version"}
	path := []string{"never for one it says is not on the path to this device", `put "(assumed)" in the block's "title"`,
		`in "no_config_reason" name each firewall you assumed is in front of the device`, "write no firewall block and no Linux gateway example"}
	for _, c := range []struct {
		job    ai.Job
		answer string
		want   []string
	}{
		{ai.JobExplainFinding, answersJSON(""), fix},
		{ai.JobMitigationConfig, answersJSON(`"steps":["Patch."],"configs":[],"no_config_reason":"No open port serves the vulnerable part."`), append(slices.Clone(fix), path...)},
	} {
		a.fake.setAnswer(c.answer)
		if _, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: c.job, Actor: "it@acme.example", Target: "CVE-2023-0001", Question: "Explain this finding."}); err != nil {
			t.Fatalf("%s: %v", c.job.Name(), err)
		}
		req := a.fake.lastRequest(t)
		all := req.System + req.Messages[0].Text
		for _, w := range c.want {
			if !strings.Contains(all, w) {
				t.Errorf("%s: the instructions lack %q", c.job.Name(), w)
			}
		}
		if strings.Contains(all, "which release fixes it (say so from the data") {
			t.Errorf("%s: the instructions still ask the model to name a fix whatever the data says", c.job.Name())
		}
	}
}

// An answer blocked only port 80 of a switch whose web interface also served 443 ("ssl/https"), and applied its change with a plain
// commit on a platform with an automatic rollback. The config job covers the ports of the vulnerable product, plain and TLS, never a
// port of another product, and applies the change the safe way the data names for the target, never inventing one.
func TestBriefConfig_EveryPortOfTheServiceAndSafeApply(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.setAnswer(answersJSON(`"steps":["Patch."],"configs":[],"no_config_reason":"No open port serves the vulnerable part."`))
	if _, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobMitigationConfig, Actor: "it@acme.example", Target: "CVE-2023-0001", Question: "Write the config."}); err != nil {
		t.Fatal(err)
	}
	req := a.fake.lastRequest(t)
	all := req.System + req.Messages[0].Text
	for _, w := range []string{
		`as the "Ports of the vulnerable product" line gives them`, "plain and TLS alike", "never only one of them",
		"never a port it calls another product", "may be a reverse proxy in front of the vulnerable product",
		"Of the ports it calls not known which product, cover the ones of the same service as a port that runs it",
		`say in "no_config_reason" which of them you covered and why`, "never every web port of the device",
		"When it says the vulnerability is in the device's own platform, choose the interface the vulnerability names",
		"that target's change is applied that way", `a command it calls a separate step goes in "steps", never in "lines"`,
		"never end such a block with a plain commit alone",
		"For a remote change to a network device or firewall the data gives no safe apply, never name an automatic rollback",
	} {
		if !strings.Contains(all, w) {
			t.Errorf("the instructions lack %q", w)
		}
	}
}

// An answer put a drop rule for a switch's web ports on its gateway and said to verify "from a host outside the admin network that the
// ports are refused": hosts on the switch's own subnet reach it directly, not through the gateway, so they still connect, and a drop
// times out rather than being refused. The config job says which traffic a firewall rule stops and that only the change on the device
// protects it from its own network, refuses where the product can, and makes every verify step name where to test from and the result
// that matches the rule's action.
func TestBriefConfig_VerifyMatchesTheRuleActionAndWhereTrafficPasses(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.setAnswer(answersJSON(`"steps":["Patch."],"configs":[],"no_config_reason":"No open port serves the vulnerable part."`))
	if _, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobMitigationConfig, Actor: "it@acme.example", Target: "CVE-2023-0001", Question: "Write the config."}); err != nil {
		t.Fatal(err)
	}
	req := a.fake.lastRequest(t)
	all := req.System + req.Messages[0].Text
	for _, w := range []string{
		// what a gateway rule protects from
		`A firewall or router rule's "side_effect" also says which traffic it stops, as the network block gives it`,
		"it protects the device only from other networks, hosts on the device's own network still reach the device directly",
		"only the change on the device itself protects it from them",
		// the rule's action, per protocol and per source: a TCP reset only on TCP ports, internal traffic refused, Internet traffic dropped
		"Choose such a rule's action by where the blocked traffic comes from and by each port's protocol",
		`TCP ports with a TCP reset (nftables "reject with tcp reset"`, `a Junos firewall filter term "then reject tcp-reset"`,
		`a FortiGate deny policy with "set send-deny-packet enable"`,
		`UDP ports with an ICMP reject (nftables plain "reject", iptables "-p udp -j REJECT") in a rule of their own, never a TCP reset, and never TCP and UDP ports in one match with a TCP reset`,
		"Traffic that arrives from the Internet (the device is reachable through a port forward or a public address) is dropped silently in a rule of its own placed before the reject",
		"a FortiGate deny policy drops unless send-deny-packet is enabled; a pfSense Block rule drops",
		// the verify step: the observable result matches the action, and where to test from
		"Every verify step says where to test from and the result the person sees, matching the action of the rule it checks and the network tested from",
		`a silent drop or deny (nftables "drop", a FortiGate deny without send-deny-packet, a pfSense Block, a Junos "discard") makes the connection time out with no answer`,
		"a TCP reset makes a TCP connection refused at once", `a UDP port is never "refused"`,
		"Never call a timeout refused, or a refusal a timeout.",
		"Test a firewall or router rule from a host whose traffic crosses that firewall, as its line in the network block says, never from the device's own network",
		"pick the test host by its route to the device (a traceroute or tracert lists the firewall as a hop), not by an address range",
		"never tell the person to check that rule with a scan from Vedette",
		// the device's own change: where to test depends on the change
		"Test the device's own change from a host it is meant to block",
		"a service turned off answers no host, so it is refused from any host, the device's own network included",
		"an access restriction on the device (an allowed admin network, trusted hosts, a local-in policy, a host firewall rule) is tested from a host outside the allowed sources, with the result its action gives",
		"from an allowed host the port still answers, as expected",
	} {
		if !strings.Contains(all, w) {
			t.Errorf("the instructions lack %q", w)
		}
	}
	// explain-finding writes no rule and gets none of this
	a.fake.setAnswer(answersJSON(""))
	if _, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobExplainFinding, Actor: "it@acme.example", Target: "CVE-2023-0001", Question: "Explain."}); err != nil {
		t.Fatal(err)
	}
	if req := a.fake.lastRequest(t); strings.Contains(req.System+req.Messages[0].Text, "Every verify step") {
		t.Error("explain-finding carries the config job's verify rule")
	}
}

// The four answers are the whole of the explanation: the answer of an older shape (paragraphs and steps), a missing, repeated or unknown
// answer and an empty one are format errors the box asks again about, never a page with an empty section.
func TestBrief_TheFourAnswersAreRequired(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	one := func(key string) string { return `{"key":"` + key + `","text":"Text.","refs":[]}` }
	for name, answer := range map[string]string{
		"the older shape":    `{"paragraphs":["The device runs the product."],"steps":["Update it."]}`,
		"three answers":      `{"answers":[` + one("affected") + `,` + one("fix") + `,` + one("urgency") + `]}`,
		"a repeated answer":  `{"answers":[` + one("affected") + `,` + one("affected") + `,` + one("fix") + `,` + one("urgency") + `]}`,
		"an unknown answer":  `{"answers":[` + one("affected") + `,` + one("fix") + `,` + one("urgency") + `,` + one("why_not") + `]}`,
		"an empty answer":    `{"answers":[` + one("affected") + `,` + one("fix") + `,` + one("urgency") + `,{"key":"workaround","text":"  ","refs":[]}]}`,
		"answers not a list": `{"answers":"yes"}`,
	} {
		a.fake.setAnswer(answer)
		_, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobExplainFinding, Actor: "it@acme.example", Target: "CVE-2023-0001", Question: "Explain."})
		var ae *apierr.Error
		if !asAPI(err, &ae) || ae.Code != "ai_bad_format" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The instructions of both finding jobs ask for the four questions, in order, and never for a paragraph about what is absent.
func TestBrief_InstructionsAskTheFourQuestionsAndNoWhyThereIsNo(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	for _, c := range []struct {
		job    ai.Job
		answer string
	}{{ai.JobExplainFinding, answersJSON("")}, {ai.JobMitigationConfig, answersJSON(`"steps":["Patch."],"configs":[],"no_config_reason":"The attack is local."`)}} {
		a.fake.setAnswer(c.answer)
		if _, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: c.job, Actor: "it@acme.example", Target: "CVE-2023-0001", Question: "Explain."}); err != nil {
			t.Fatal(err)
		}
		req := a.fake.lastRequest(t)
		all := req.System + req.Messages[0].Text
		for _, w := range []string{`"affected" (Am I affected?`, `"fix" (How do I fix it?`, `"workaround" (What if I cannot patch yet?`, `"urgency" (How urgent?`,
			"never write a paragraph that explains why something is absent", "every claim a reference supports carries its number",
			"Give firewall or gateway rules, and back-up and roll-back steps, only when the attack is over the network"} {
			if !strings.Contains(all, w) {
				t.Errorf("%s: the instructions lack %q", c.job.Name(), w)
			}
		}
		for _, bad := range []string{"why there is no", "Why there is no", "explains why no", `"paragraphs"`} {
			if strings.Contains(all, bad) {
				t.Errorf("%s: the instructions contain %q", c.job.Name(), bad)
			}
		}
	}
}

// A web address the model writes in an answer is removed: the links of an answer are the references the box offered, written by the box.
func TestBrief_AddressesInAnswerTextAreRemoved(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.setAnswer(`{"answers":[{"key":"affected","text":"Yes, see https://evil.example/patch now or www.evil.example for details.","refs":[]},` +
		`{"key":"fix","text":"Update.","refs":[]},{"key":"workaround","text":"None.","refs":[]},{"key":"urgency","text":"High.","refs":[]}]}`)
	out, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobExplainFinding, Actor: "it@acme.example", Question: "Explain."})
	if err != nil || strings.Contains(out.Answers[0].Text, "evil") || out.Answers[0].Text != "Yes, see now or for details." {
		t.Fatalf("answer = %q, %v", out.Answers[0].Text, err)
	}
}

// An answer that is only a web address is empty once the address is removed: a format error, not an empty section.
func TestBrief_AnAnswerThatIsOnlyAnAddressIsEmpty(t *testing.T) {
	a := newAPI(t)
	a.withProfile()
	a.fake.setAnswer(`{"answers":[{"key":"affected","text":"https://evil.example/x","refs":[]},{"key":"fix","text":"Update.","refs":[]},{"key":"workaround","text":"None.","refs":[]},{"key":"urgency","text":"High.","refs":[]}]}`)
	_, err := a.svc.Brief(a.ctx(), ai.BriefRequest{Job: ai.JobExplainFinding, Actor: "it@acme.example", Question: "Explain."})
	var ae *apierr.Error
	if !asAPI(err, &ae) || ae.Code != "ai_bad_format" {
		t.Fatalf("err = %v", err)
	}
}
