package ai_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
)

// The response planner (cmd/vedette/ai_plan.go) sends the device as "Device: <name> (<ip>), kind <kind>". With the personal-data hook
// on, the model must still get the address, or no plan can propose an action about the device (D-205).
func TestResponsePlanPromptKeepsTheDeviceIP(t *testing.T) {
	for _, d := range [][3]string{{"NAS-01", "192.168.1.20", "nas"}, {"Camera-0042", "192.168.100.42", "camera"}, {"fw-edge-2", "fe80::1", "firewall"}} {
		a := newAPI(t)
		id := a.withProfile()
		a.want("PUT", "/ai/assignments", "admin", assignBody(false, map[string][2]string{"response-plan": {id, ""}}), 200, "")
		a.want("PUT", "/ai/hooks/builtin/block-pii", "admin", `{"enabled":true}`, 200, "")
		dev := fmt.Sprintf("Device: %s (%s), kind %s\nFinding: %s\n", d[0], d[1], d[2], "CVE-2024-3400")
		_, err := a.newService().RunJob(a.ctx(), ai.JobSpec{Job: ai.JobResponsePlan, Actor: "system", Task: "Write a plan.", Question: "Write the response plan.",
			Data: []ai.DataBlock{{Kind: "inventory", Source: "the device of the finding", Text: dev}}, Schema: &provider.Schema{Name: "response_plan", JSON: []byte(`{"type":"object"}`)}, MaxTokens: 100})
		if err != nil {
			t.Fatal(err)
		}
		if got := a.fake.lastRequest(t).Messages[0].Text; !strings.Contains(got, dev) {
			t.Errorf("the provider got %q, want the line %q", got, dev)
		}
	}
}
