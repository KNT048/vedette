package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/ai/provider"
)

// INV-14 at the door of the loop: whatever sits in the toolbox, a tool that is not a read tool of the job is neither offered nor run,
// and a write tool cannot be reached by a read tool of the same name in another case.
func TestContract_INV14_AskLoopOffersAndRunsReadToolsOnly(t *testing.T) {
	t.Parallel()
	ran := map[string]int{}
	mk := func(name string, access Access, enabled bool, jobs ...Job) toolImpl {
		return toolImpl{
			Tool: Tool{Name: name, Access: access, Enabled: enabled, Jobs: jobs, Schema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)},
			run: func(context.Context, map[string]any) (toolOut, error) {
				ran[name]++
				return toolOut{Text: "ok", Summary: "ok"}, nil
			},
		}
	}
	all := []toolImpl{
		mk("get_status", AccessRead, true, JobAskMyData),
		mk("push_config", AccessWrite, true, JobAskMyData),
		mk("PUSH_CONFIG", AccessRead, true, JobAskMyData), // a read tool that borrows the name of a write tool
		mk("switched_off", AccessRead, false, JobAskMyData),
		mk("other_job", AccessRead, true, JobWeeklyReport),
		mk("odd", Access("admin"), true, JobAskMyData),
		mk("bad name!", AccessRead, true, JobAskMyData),
	}
	ts := &toolSession{svc: &Service{}, job: JobAskMyData, impl: map[string]toolImpl{}}
	for _, ti := range all {
		ts.impl[ti.Name] = ti
		ts.tools = append(ts.tools, ti.Tool)
	}
	h, err := newHarness(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ts.defs(); len(got) != 1 || got[0].Name != "get_status" {
		t.Fatalf("offered = %v", got)
	}
	for _, n := range []string{"push_config", "PUSH_CONFIG", "Push_Config", "switched_off", "other_job", "odd", "bad name!", "never_heard_of"} {
		res := ts.runCall(t.Context(), h.runner, Prompt{Fence: "f"}, provider.ToolCall{ID: "c", Name: n, Arguments: json.RawMessage(`{}`)}, 0, 0)
		if !res.IsError || !strings.Contains(res.Content, "not available") {
			t.Errorf("%s: %+v", n, res)
		}
	}
	if res := ts.runCall(t.Context(), h.runner, Prompt{Fence: "f"}, provider.ToolCall{ID: "c", Name: "get_status", Arguments: json.RawMessage(`{}`)}, 0, 0); res.IsError {
		t.Fatalf("the read tool: %+v", res)
	}
	if len(ran) != 1 || ran["get_status"] != 1 {
		t.Fatalf("tools that ran = %v", ran)
	}
}
