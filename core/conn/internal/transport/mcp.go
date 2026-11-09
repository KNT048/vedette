package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The MCP protocol versions this client speaks, newest first (modelcontextprotocol.io, Transports: Streamable HTTP).
var mcpVersions = []string{"2025-06-18", "2025-03-26"}

const (
	maxMCPTools = 100
	maxMCPPages = 10
	maxMCPText  = 64 << 10
)

// MCPTool is a tool an MCP server offers, as the server described it: untrusted text.
type MCPTool struct {
	Name        string
	Description string
}

// MCPResult is the answer of a tool call. Text is the text parts of the result, capped; it is device output and stays in memory.
type MCPResult struct {
	IsError bool
	Text    string
}

// MCP is a session with an MCP server over streamable HTTP and JSON-RPC (D-94 (3)): initialize, notifications/initialized,
// tools/list and tools/call, one POST each, with the Mcp-Session-Id the server gave. A reply as JSON or as an event stream is
// understood. Nothing else of the protocol is implemented: a request from the server (sampling, roots) is ignored.
type MCP struct {
	c       *Client
	url     string
	auth    Auth
	session string
	version string
	next    int64
}

// NewMCP returns a client for the server at url (the address of its endpoint).
func NewMCP(c *Client, url string, a Auth) *MCP { return &MCP{c: c, url: url, auth: a} }

// Session is the session id the server gave, "" if it gave none.
func (m *MCP) Session() string { return m.session }

// Initialize opens the session.
func (m *MCP) Initialize(ctx context.Context) error {
	res, hdr, err := m.call(ctx, "initialize", map[string]any{
		"protocolVersion": mcpVersions[0], "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "vedette", "version": "1"},
	})
	if err != nil {
		return err
	}
	var r struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(res, &r) != nil {
		return deviceErr("the server's answer to initialize is not valid")
	}
	ok := false
	for _, v := range mcpVersions {
		ok = ok || v == r.ProtocolVersion
	}
	if !ok {
		return deviceErr("the server speaks MCP version %s, which Vedette does not", r.ProtocolVersion)
	}
	m.version = r.ProtocolVersion
	if sid := hdr.Get("Mcp-Session-Id"); sid != "" {
		if len(sid) > 256 || strings.ContainsFunc(sid, func(c rune) bool { return c < 0x21 || c > 0x7e }) {
			return deviceErr("the server gave a session id that is not valid")
		}
		m.session = sid
	}
	return m.notify(ctx, "notifications/initialized")
}

// ListTools returns the tools the server offers, up to 100.
func (m *MCP) ListTools(ctx context.Context) ([]MCPTool, error) {
	var out []MCPTool
	cursor := ""
	for range maxMCPPages {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		res, _, err := m.call(ctx, "tools/list", params)
		if err != nil {
			return nil, err
		}
		var r struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if json.Unmarshal(res, &r) != nil {
			return nil, deviceErr("the server's list of tools is not valid")
		}
		for _, t := range r.Tools {
			if len(out) >= maxMCPTools {
				return out, nil
			}
			out = append(out, MCPTool{Name: t.Name, Description: t.Description})
		}
		if r.NextCursor == "" {
			return out, nil
		}
		cursor = r.NextCursor
	}
	return out, nil
}

// CallTool runs one tool. args are typed JSON values, never a command line. A tool that reports an error (isError) is an
// MCPResult with IsError set, not a Go error: the call itself worked.
func (m *MCP) CallTool(ctx context.Context, name string, args map[string]any) (MCPResult, error) {
	if args == nil {
		args = map[string]any{}
	}
	res, _, err := m.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return MCPResult{}, err
	}
	var r struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(res, &r) != nil {
		return MCPResult{}, deviceErr("the server's answer to the call is not valid")
	}
	var b strings.Builder
	for _, c := range r.Content {
		if c.Type == "text" && b.Len() < maxMCPText {
			b.WriteString(c.Text)
			b.WriteByte('\n')
		}
	}
	text := b.String()
	if len(text) > maxMCPText {
		text = text[:maxMCPText]
	}
	return MCPResult{IsError: r.IsError, Text: text}, nil
}

// Close ends the session on the server, as far as it lets us; the answer does not matter.
func (m *MCP) Close(ctx context.Context) {
	if m.session == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, _ = m.c.Do(ctx, m.auth, Request{Method: http.MethodDelete, URL: m.url, Header: m.headers()})
}

func (m *MCP) headers() http.Header {
	h := http.Header{}
	h.Set("Accept", "application/json, text/event-stream")
	h.Set("Content-Type", "application/json")
	if m.version != "" {
		h.Set("MCP-Protocol-Version", m.version)
	}
	if m.session != "" {
		h.Set("Mcp-Session-Id", m.session)
	}
	return h
}

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  any             `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (m *MCP) notify(ctx context.Context, method string) error {
	body, _ := json.Marshal(rpcMsg{JSONRPC: "2.0", Method: method})
	s, err := m.c.Open(ctx, m.auth, Request{Method: http.MethodPost, URL: m.url, Header: m.headers(), Body: body})
	if err != nil {
		return err
	}
	defer s.Close()
	_, _ = io.Copy(io.Discard, s.Body)
	return statusError(s.Status, 200, 202, 204)
}

func statusError(got int, ok ...int) error {
	for _, o := range ok {
		if got == o {
			return nil
		}
	}
	switch got {
	case http.StatusUnauthorized, http.StatusForbidden:
		return deviceErr("the server refused the sign-in (HTTP %d)", got)
	case http.StatusNotFound:
		return deviceErr("the server answered HTTP 404: check the address, or the session ended")
	}
	return deviceErr("the server answered HTTP %d", got)
}

// call sends one request and returns its result and the headers of the answer.
func (m *MCP) call(ctx context.Context, method string, params any) (json.RawMessage, http.Header, error) {
	m.next++
	id := strconv.FormatInt(m.next, 10)
	body, err := json.Marshal(rpcMsg{JSONRPC: "2.0", ID: json.RawMessage(id), Method: method, Params: params})
	if err != nil {
		return nil, nil, errors.New("the request could not be built")
	}
	s, err := m.c.Open(ctx, m.auth, Request{Method: http.MethodPost, URL: m.url, Header: m.headers(), Body: body})
	if err != nil {
		return nil, nil, err
	}
	defer s.Close()
	if err := statusError(s.Status, 200); err != nil {
		return nil, nil, err
	}
	media, _, _ := mime.ParseMediaType(s.Header.Get("Content-Type"))
	var reply *rpcMsg
	switch media {
	case "application/json":
		b, err := io.ReadAll(s.Body)
		if err != nil {
			return nil, nil, cleanTransportError(err, m.auth)
		}
		if len(b) > MaxResponse {
			return nil, nil, deviceErr("the answer is larger than %d MB", MaxResponse>>20)
		}
		reply = pick(b, id)
	case "text/event-stream":
		err := ReadEvents(s.Body, func(ev Event) bool {
			if ev.Type != "message" {
				return false
			}
			reply = pick([]byte(ev.Data), id)
			return reply != nil
		})
		if reply == nil && err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, nil, errors.New("timed out")
			}
			return nil, nil, deviceErr("the event stream of the server is not valid or too large")
		}
	default:
		return nil, nil, deviceErr("the server answered with %q, not JSON", media)
	}
	if reply == nil {
		return nil, nil, deviceErr("the server did not answer the request")
	}
	if reply.Error != nil {
		return nil, nil, deviceErrAuth(m.auth, "the server reported an error (%d): %s", reply.Error.Code, reply.Error.Message)
	}
	return reply.Result, s.Header, nil
}

// pick finds the JSON-RPC response with the id among what the server sent (one object or a batch); anything else the server
// said, notifications and its own requests included, is dropped.
func pick(b []byte, id string) *rpcMsg {
	var msgs []rpcMsg
	if strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
		if json.Unmarshal(b, &msgs) != nil {
			return nil
		}
	} else {
		var one rpcMsg
		if json.Unmarshal(b, &one) != nil {
			return nil
		}
		msgs = []rpcMsg{one}
	}
	for i := range msgs {
		if msgs[i].Method == "" && string(msgs[i].ID) == id {
			return &msgs[i]
		}
	}
	return nil
}
