package conntest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// MCPTool is a tool the MCP fake offers. Schema is its inputSchema as JSON; "" is {"type":"object"}.
type MCPTool struct{ Name, Description, Schema string }

// MCPOpts configures the MCP fake.
type MCPOpts struct {
	Tools []MCPTool // nil: two tools
	// SSE answers requests as a text/event-stream (with a notification before the response) instead of JSON.
	SSE bool
	// NoSession gives no Mcp-Session-Id; otherwise the id is "sess-1" and every later request must carry it.
	NoSession bool
	// Oversize makes tools/list answer with more than 1 MB.
	Oversize bool
	// FailTool is a tool whose call reports isError.
	FailTool string
	// Respond is the text of a tool call's answer; nil is "ran <name>". authorization is the header the call came with.
	Respond func(name string, args map[string]any, authorization string) string
	// Version is the protocol version the server answers initialize with; "" is 2025-06-18.
	Version string
}

// MCPCall is one request the MCP fake received.
type MCPCall struct {
	HTTPMethod, RPCMethod, Session, Version, Authorization string
	Args                                                   map[string]any
}

// MCP is an MCP server over streamable HTTP on loopback: initialize, notifications/initialized, tools/list and tools/call.
type MCP struct {
	*HTTPS
	opts  MCPOpts
	mu    sync.Mutex
	calls []MCPCall
}

// NewMCP starts the fake.
func NewMCP(t testing.TB, o MCPOpts) *MCP {
	t.Helper()
	if o.Tools == nil {
		o.Tools = []MCPTool{{Name: "list_resources", Description: "List what the server holds"}, {Name: "run_action", Description: "Run an action the server defines"}}
	}
	if o.Version == "" {
		o.Version = "2025-06-18"
	}
	m := &MCP{opts: o}
	m.HTTPS = NewHTTPS(t, http.HandlerFunc(m.serve))
	return m
}

// Calls are the requests received so far, in order.
func (m *MCP) Calls() []MCPCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]MCPCall(nil), m.calls...)
}

func (m *MCP) serve(w http.ResponseWriter, r *http.Request) {
	c := MCPCall{HTTPMethod: r.Method, Session: r.Header.Get("Mcp-Session-Id"), Version: r.Header.Get("MCP-Protocol-Version"), Authorization: r.Header.Get("Authorization")}
	if r.Method == http.MethodDelete {
		m.record(c)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	b, _ := io.ReadAll(r.Body)
	if r.Method != http.MethodPost || json.Unmarshal(b, &req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c.RPCMethod, c.Args = req.Method, req.Params.Arguments
	m.record(c)
	if req.Method != "initialize" && !m.opts.NoSession && c.Session != "sess-1" {
		http.Error(w, "no session", http.StatusNotFound)
		return
	}
	if len(req.ID) == 0 { // a notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var result any
	switch req.Method {
	case "initialize":
		if !m.opts.NoSession {
			w.Header().Set("Mcp-Session-Id", "sess-1")
		}
		result = map[string]any{"protocolVersion": m.opts.Version, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "fake", "version": "1"}}
	case "tools/list":
		tools := []map[string]any{}
		for _, t := range m.opts.Tools {
			var schema any = map[string]any{"type": "object"}
			if t.Schema != "" {
				schema = json.RawMessage(t.Schema)
			}
			tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": schema})
		}
		if m.opts.Oversize {
			tools = append(tools, map[string]any{"name": "big", "description": strings.Repeat("x", 2<<20)})
		}
		result = map[string]any{"tools": tools}
	case "tools/call":
		text := fmt.Sprintf("ran %s", req.Params.Name)
		if m.opts.Respond != nil {
			text = m.opts.Respond(req.Params.Name, req.Params.Arguments, c.Authorization)
		}
		result = map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"isError": req.Params.Name == m.opts.FailTool,
		}
	default:
		result = nil
	}
	resp := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}
	if result == nil {
		resp = map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32601, "message": "method not found"}}
	}
	out, _ := json.Marshal(resp)
	if m.opts.SSE {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, ": keep-alive\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\nid: 7\nevent: message\ndata: %s\n\n", out)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func (m *MCP) record(c MCPCall) {
	m.mu.Lock()
	m.calls = append(m.calls, c)
	m.mu.Unlock()
}
