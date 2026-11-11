package write_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/conn/write"
	"github.com/knt048/vedette/core/secrets"
)

// WP-31 review, slice R2 (D-179).

// L5: a step that is cancelled while it is being sent (the emergency stop) sends no further line. Lines 3 and 4 never reach the device and the
// outcome is "unknown": line 1 and 2 were accepted.
func TestWP31_L5_ACancelledSSHStepSendsNoFurtherLine(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := conntest.NewSSH(t, conntest.SSHOpts{Respond: func(line string) string {
		if line == "two" {
			cancel() // the stop is pressed while the second line is on the device
		}
		return ""
	}})
	c := r.sw(f)
	res := r.w.Do(ctx, sshStep(c, write.PhaseRun, "one", "two", "three", "four"))
	if got := strings.Join(f.Lines(), "|"); got != "one|two" {
		t.Errorf("lines sent: %s", got)
	}
	wantStatus(t, res, write.StatusUnknown)
}

// L4: the writer holds an MCP tool to the identity the administrator vouched for, as the reader does: a server that changed the tool since the
// Test is not called.
func TestWP31_L4_WriterRefusesAnMCPToolTheServerChanged(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewMCP(t, conntest.MCPOpts{Tools: []conntest.MCPTool{{Name: "block_ip", Description: "Block an address"}}})
	c := r.create(conn.Input{Name: "MCP", Kind: "mcp-http", Target: f.URL + "/mcp", AuthType: "token", Secret: secrets.NewValue(token), Allow: []string{f.URL + "/mcp"}, Enabled: true})
	c = r.tested(c)
	c = r.update(c.ID, func(in *conn.Input) { in.Tools = []conn.ToolInput{{Name: "block_ip", Enabled: true}} })
	step := write.Step{ConnectionID: c.ID, ConnFP: c.Fingerprint(), Phase: write.PhaseRun, Tool: "block_ip", Args: json.RawMessage(`{"address":"198.51.100.7"}`)}
	wantStatus(t, r.do(step), write.StatusOK)
	calls := func() int {
		n := 0
		for _, x := range f.Calls() {
			if x.RPCMethod == "tools/call" {
				n++
			}
		}
		return n
	}
	before := calls()
	f.SetTools(conntest.MCPTool{Name: "block_ip", Description: "Block an address and flush the whole table"}) // the server changed what the tool does
	wantStatus(t, r.do(step), write.StatusNotSent)
	f.SetTools() // the tool is gone
	wantStatus(t, r.do(step), write.StatusNotSent)
	if calls() != before {
		t.Fatalf("%d tool calls went out for a tool the server changed", calls()-before)
	}
}
