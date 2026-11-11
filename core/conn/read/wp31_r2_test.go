package read_test

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/conn/read"
	"github.com/knt048/vedette/core/secrets"
)

// WP-31 review, slice R2, L4 (D-179 (5)): the server's annotations can only take trust away. A tool that says destructiveHint, or readOnlyHint false,
// can never be marked read; one that starts to say so after it was marked read is not called.
func TestWP31_L4_ADestructiveMCPToolCanNeverBeMarkedRead(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewMCP(t, conntest.MCPOpts{Tools: []conntest.MCPTool{
		{Name: "list_things", Description: "List", Annotations: `{"readOnlyHint":true}`},
		{Name: "drop_things", Description: "Drop", Annotations: `{"destructiveHint":true}`},
		{Name: "touch_things", Description: "Touch", Annotations: `{"readOnlyHint":false}`},
	}})
	c := r.create(conn.Input{Name: "MCP", Kind: "mcp-http", Target: f.URL, AuthType: "token", Secret: secrets.NewValue(token), Allow: []string{f.URL}, Enabled: true})
	c = r.tested(c)
	for _, name := range []string{"drop_things", "touch_things"} {
		err := r.tryUpdate(c.ID, func(in *conn.Input) { in.Tools = []conn.ToolInput{{Name: name, Enabled: true, Access: str("read")}} })
		if e, ok := apierr.As(err); !ok || e.Code != "invalid_tool_access" {
			t.Errorf("%s marked read: %v", name, err)
		}
	}
	if err := r.tryUpdate(c.ID, func(in *conn.Input) {
		in.Tools = []conn.ToolInput{{Name: "list_things", Enabled: true, Access: str("read")}}
	}); err != nil {
		t.Fatalf("a read-only tool: %v", err)
	}
	c = r.get(c.ID)
	if _, err := r.call(c, "list_things", nil); err != nil {
		t.Fatalf("the read tool: %v", err)
	}
	// The server now says the tool may change something: it is a different tool, and the reader does not call it.
	f.SetTools(conntest.MCPTool{Name: "list_things", Description: "List", Annotations: `{"destructiveHint":true}`})
	if _, err := r.call(c, "list_things", nil); !errors.Is(err, read.ErrUnavailable) {
		t.Fatalf("a tool that turned destructive was called: %v", err)
	}
}

func (r *rig) tryUpdate(id string, f func(*conn.Input)) error {
	r.t.Helper()
	cur := r.get(id)
	in := conn.Input{Name: cur.Name, Kind: cur.Kind, Target: cur.Target, AuthType: cur.Auth.Type, Username: cur.Username, Allow: cur.Allow, Enabled: cur.Enabled}
	f(&in)
	return r.env.DB.Write(r.t.Context(), func(tx *sql.Tx) error { _, err := r.svc.Update(r.t.Context(), tx, admin, id, in); return err })
}
