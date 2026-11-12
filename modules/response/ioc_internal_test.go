package response

import "testing"

// Review of #376 (D-336): what decides is the rule's templates as well as the values: the device's address inside free text (a custom
// low-risk {text} action calling a NAC) names the device too.
func TestHeldForAutoReadsTheRuleTemplates(t *testing.T) {
	ev := Det{Trigger: "ioc_connection", Fields: map[string]string{"src_ip": "192.168.10.105", "device": "PC-SALES-02", "dest_kind": "ip", "dest_ip": "185.220.101.47", "switch_port": ""}}
	dest := []RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}}}
	if why := heldForAuto(ev, dest, []itemRec{{Values: map[ParamType]string{PIP: "185.220.101.47"}}}); why != "" {
		t.Fatalf("blocking the listed address is held: %s", why)
	}
	for name, c := range map[string]struct {
		specs []RuleAction
		vals  map[ParamType]string
	}{
		"address in text":      {[]RuleAction{{Params: map[string]string{"text": "isolate {{trigger.src_ip}} now"}}}, map[ParamType]string{PText: "isolate 192.168.10.105 now"}},
		"device name in text":  {[]RuleAction{{Params: map[string]string{"text": "{{trigger.device}} quarantine"}}}, map[ParamType]string{PText: "PC-SALES-02 quarantine"}},
		"switch port template": {[]RuleAction{{Params: map[string]string{"interface": "{{trigger.switch_port}}"}}}, map[ParamType]string{PInterface: ""}},
		"fixed source address": {[]RuleAction{{Params: map[string]string{"ip": "192.168.10.105"}}}, map[ParamType]string{PIP: "192.168.10.105"}},
		"fixed device name":    {[]RuleAction{{Params: map[string]string{"name": "pc-sales-02"}}}, map[ParamType]string{PName: "pc-sales-02"}},
	} {
		if heldForAuto(ev, c.specs, []itemRec{{Values: c.vals}}) == "" {
			t.Errorf("%s: not held", name)
		}
	}
	ev.Fields["dest_kind"] = "domain"
	if heldForAuto(ev, dest, nil) == "" {
		t.Error("a domain-only hit is not held")
	}
}
