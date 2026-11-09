package transport_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/conn/internal/transport"
	"github.com/knt048/vedette/core/secrets"
)

func mcpFor(t *testing.T, o conntest.MCPOpts) (*conntest.MCP, *transport.MCP) {
	t.Helper()
	f := conntest.NewMCP(t, o)
	c := transport.NewHTTPS(transport.HTTPSConfig{Dialer: dialer(), TOFU: true})
	return f, transport.NewMCP(c, f.URL+"/mcp", transport.Auth{Type: "token", Secret: secrets.NewValue("tok-0123456789")})
}

// D-94 (3): initialize, notifications/initialized, then tools/list with the session id; JSON and event-stream answers alike.
func TestMCPSessionAndDiscovery(t *testing.T) {
	t.Parallel()
	for name, sse := range map[string]bool{"json": false, "sse": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f, m := mcpFor(t, conntest.MCPOpts{SSE: sse})
			ctx := context.Background()
			if err := m.Initialize(ctx); err != nil {
				t.Fatal(err)
			}
			if m.Session() != "sess-1" {
				t.Fatalf("session = %q", m.Session())
			}
			tools, err := m.ListTools(ctx)
			if err != nil || len(tools) != 2 || tools[0].Name != "list_resources" {
				t.Fatalf("tools %+v, err %v", tools, err)
			}
			m.Close(ctx)
			var seq []string
			for _, c := range f.Calls() {
				seq = append(seq, c.HTTPMethod+" "+c.RPCMethod)
				if c.Authorization != "Bearer tok-0123456789" {
					t.Errorf("%s sent %q", c.RPCMethod, c.Authorization)
				}
				if c.RPCMethod == "tools/list" && (c.Session != "sess-1" || c.Version != "2025-06-18") {
					t.Errorf("tools/list sent session %q version %q", c.Session, c.Version)
				}
			}
			if got := strings.Join(seq, ", "); got != "POST initialize, POST notifications/initialized, POST tools/list, DELETE " {
				t.Fatalf("requests: %s", got)
			}
		})
	}
}

func TestMCPCallToolTypedArgumentsAndIsError(t *testing.T) {
	t.Parallel()
	f, m := mcpFor(t, conntest.MCPOpts{FailTool: "broken"})
	ctx := context.Background()
	if err := m.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := m.CallTool(ctx, "run_action", map[string]any{"vlan": 30, "enabled": true, "name": "x; rm -rf /"})
	if err != nil || r.IsError || !strings.Contains(r.Text, "ran run_action") {
		t.Fatalf("result %+v, err %v", r, err)
	}
	calls := f.Calls()
	args := calls[len(calls)-1].Args
	if args["vlan"] != float64(30) || args["enabled"] != true || args["name"] != "x; rm -rf /" {
		t.Fatalf("the server received %#v: arguments are typed JSON values", args)
	}
	r, err = m.CallTool(ctx, "broken", nil)
	if err != nil || !r.IsError {
		t.Fatalf("isError: result %+v, err %v: a tool error is a result, not a transport error", r, err)
	}
}

func TestMCPRefusesWhatItCannotTrust(t *testing.T) {
	t.Parallel()
	t.Run("oversized answer", func(t *testing.T) {
		t.Parallel()
		var de *transport.DeviceError
		_, m := mcpFor(t, conntest.MCPOpts{Oversize: true})
		if err := m.Initialize(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := m.ListTools(context.Background()); !errors.As(err, &de) {
			t.Fatalf("err = %v, want a DeviceError", err)
		}
	})
	t.Run("unknown protocol version", func(t *testing.T) {
		t.Parallel()
		var de *transport.DeviceError
		_, m := mcpFor(t, conntest.MCPOpts{Version: "1999-01-01"})
		if err := m.Initialize(context.Background()); !errors.As(err, &de) {
			t.Fatalf("err = %v, want a DeviceError", err)
		}
	})
	t.Run("a server with no session id", func(t *testing.T) {
		t.Parallel()
		_, m := mcpFor(t, conntest.MCPOpts{NoSession: true})
		if err := m.Initialize(context.Background()); err != nil || m.Session() != "" {
			t.Fatalf("err %v, session %q", err, m.Session())
		}
		if tools, err := m.ListTools(context.Background()); err != nil || len(tools) != 2 {
			t.Fatalf("tools %v, err %v", tools, err)
		}
	})
	t.Run("a call before initialize has no session", func(t *testing.T) {
		t.Parallel()
		var de *transport.DeviceError
		_, m := mcpFor(t, conntest.MCPOpts{})
		if _, err := m.ListTools(context.Background()); !errors.As(err, &de) {
			t.Fatalf("err = %v, want the server's refusal as a DeviceError", err)
		}
	})
}

func TestReadEvents(t *testing.T) {
	t.Parallel()
	in := ": comment\r\n\r\nid: 1\r\nevent: message\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\nretry: 5\r\n\r\ndata: second\n\ndata: cut off"
	var got []transport.Event
	if err := transport.ReadEvents(strings.NewReader(in), func(e transport.Event) bool { got = append(got, e); return false }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Data != "{\"a\":\n1}" || got[0].ID != "1" || got[0].Type != "message" || got[1].Data != "second" {
		t.Fatalf("events %+v", got)
	}
	n := 0
	_ = transport.ReadEvents(strings.NewReader("data: 1\n\ndata: 2\n\n"), func(transport.Event) bool { n++; return true })
	if n != 1 {
		t.Fatalf("fn was called %d times after it asked to stop", n)
	}
}
