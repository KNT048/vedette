package conn

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/knt048/vedette/core/store/coredb"
)

// The pin is stored as one text (DATA_MODEL core_connection.pin) and shown as {kind, value, first_seen}.
const (
	pinTLSPrefix   = "tls-sha256:"
	pinRootsPrefix = "tls-roots:"
	pinSSHPrefix   = "ssh:"
)

func decodePin(pin, seen *string) *Pin {
	if pin == nil {
		return nil
	}
	p := &Pin{FirstSeen: deref(seen)}
	switch {
	case strings.HasPrefix(*pin, pinRootsPrefix):
		p.Kind, p.Value = "tls_roots", strings.TrimPrefix(*pin, pinRootsPrefix)
	case strings.HasPrefix(*pin, pinTLSPrefix):
		p.Kind, p.Value = "tls_sha256", strings.TrimPrefix(*pin, pinTLSPrefix)
	case strings.HasPrefix(*pin, pinSSHPrefix):
		p.Kind, p.Value = "ssh_hostkey", strings.TrimPrefix(*pin, pinSSHPrefix)
	default:
		return nil // a value this version did not write: show no pin rather than a made-up one
	}
	return p
}

func encodePin(p *Pin) (pin, seen *string) {
	if p == nil {
		return nil, nil
	}
	prefix := pinTLSPrefix
	switch p.Kind {
	case "ssh_hostkey":
		prefix = pinSSHPrefix
	case "tls_roots":
		prefix = pinRootsPrefix
	}
	v, s := prefix+p.Value, p.FirstSeen
	return &v, &s
}

func encodeAllow(allow []string) string {
	b, _ := json.Marshal(allow) // a string slice always encodes
	return string(b)
}

func decodeAllow(s string) ([]string, error) {
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

func fromRow(r coredb.GetConnectionRow, tools []Tool) (Connection, error) {
	allow, err := decodeAllow(r.Allow)
	if err != nil {
		return Connection{}, fmt.Errorf("conn: allow-list of %s is not valid: %w", r.ID, err)
	}
	if tools == nil {
		tools = []Tool{}
	}
	return Connection{
		ID: r.ID, Name: r.Name, Kind: r.Kind, Target: r.Target, AssetID: r.AssetID,
		Auth:     Auth{Type: r.AuthType, Last4: r.Last4, KeyFingerprint: r.KeyFp},
		Username: r.Username, Pin: decodePin(r.Pin, r.PinSeen), Allow: allow, Tools: tools,
		Enabled: r.Enabled, Status: r.Status, LastTest: r.LastTest, UpdatedAt: r.UpdatedAt, secretID: r.SecretID,
	}, nil
}

func get(ctx context.Context, q *coredb.Queries, id string) (Connection, error) {
	r, err := q.GetConnection(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Connection{}, notFound()
	}
	if err != nil {
		return Connection{}, fmt.Errorf("conn: read: %w", err)
	}
	rows, err := q.ListToolsOfConnection(ctx, id)
	if err != nil {
		return Connection{}, fmt.Errorf("conn: read tools: %w", err)
	}
	tools := make([]Tool, len(rows))
	for i, t := range rows {
		tools[i] = Tool{Name: t.Name, Access: t.Access, Description: t.Description, Enabled: t.Enabled}
	}
	return fromRow(r, tools)
}

func list(ctx context.Context, q *coredb.Queries) ([]Connection, error) {
	rows, err := q.ListConnections(ctx)
	if err != nil {
		return nil, fmt.Errorf("conn: list: %w", err)
	}
	trs, err := q.ListConnectionTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("conn: list tools: %w", err)
	}
	byConn := map[string][]Tool{}
	for _, t := range trs {
		byConn[t.ConnectionID] = append(byConn[t.ConnectionID], Tool{Name: t.Name, Access: t.Access, Description: t.Description, Enabled: t.Enabled})
	}
	out := make([]Connection, 0, len(rows))
	for _, r := range rows {
		c, err := fromRow(coredb.GetConnectionRow(r), byConn[r.ID])
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func updateParams(c Connection) coredb.UpdateConnectionParams {
	pin, seen := encodePin(c.Pin)
	return coredb.UpdateConnectionParams{
		ID: c.ID, Name: c.Name, NameKey: nameKey(c.Name), Kind: c.Kind, Target: c.Target, AssetID: c.AssetID, AuthType: c.Auth.Type, Username: c.Username,
		SecretID: c.secretID, KeyFp: c.Auth.KeyFingerprint, Pin: pin, PinSeen: seen, Allow: encodeAllow(c.Allow), Enabled: c.Enabled,
		Status: c.Status, LastTest: c.LastTest, UpdatedAt: c.UpdatedAt,
	}
}

func writeTools(ctx context.Context, q *coredb.Queries, id string, tools []Tool) error {
	for i, t := range tools {
		err := q.InsertConnectionTool(ctx, coredb.InsertConnectionToolParams{
			ConnectionID: id, Name: t.Name, Pos: int64(i), Access: t.Access, Description: t.Description, Enabled: t.Enabled,
		})
		if err != nil {
			return fmt.Errorf("conn: insert tool: %w", err)
		}
	}
	return nil
}

// builtinTools is what a new connection offers by kind. Generic only (D-58): what a particular device can do is described
// by the action templates. A write tool starts OFF (D-41, D-51): an administrator turns it on, and it then runs only through
// a response action that people approve. The tools of an MCP server are found by the first Test (slice 13b-5), as write tools
// that start off (D-94 (3)); until then there are none.
func builtinTools(kind string) []Tool {
	r := func(name, desc string) Tool {
		return Tool{Name: name, Access: "read", Description: desc, Enabled: true}
	}
	w := func(name, desc string) Tool { return Tool{Name: name, Access: "write", Description: desc} }
	switch kind {
	case KindSSH:
		return []Tool{r("run_allowed_command", "Run one command from the allow list and return its output"), w("run_approved_command", "Run one command that an approved action defines")}
	case KindHTTP:
		return []Tool{r("fetch_url", "Fetch a page from an allowed address and return its text"), w("send_request", "Send one API request that an approved action defines")}
	case KindRESTCONF:
		return []Tool{r("get_config", "Read configuration or status data"), w("apply_config", "Apply one configuration change that an approved action defines")}
	case KindAutomation:
		return []Tool{r("list_jobs", "List the jobs or workflows the platform offers"), w("launch_job", "Start one job or workflow that an approved action defines")}
	}
	return []Tool{}
}

// applyTools returns base with the switches of the input applied; a tool the input does not name keeps its state, and a name
// that is not a tool of the connection is ignored. Only an MCP server may change a tool's access.
func applyTools(base []Tool, in []ToolInput, mcp bool) []Tool {
	out := make([]Tool, len(base))
	for i, t := range base {
		for _, x := range in {
			if x.Name != t.Name {
				continue
			}
			t.Enabled = x.Enabled
			if mcp && x.Access != nil {
				t.Access = *x.Access
			}
			break
		}
		out[i] = t
	}
	return out
}
