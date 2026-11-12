package mcpserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	mcpserver "github.com/knt048/vedette/modules/mcp-server"
)

var all = []string{"assets", "findings", "feeds"}

func TestContract_MigrationsUsePrefix(t *testing.T) {
	t.Parallel()
	storetest.AssertMigrationsUsePrefix(t, mcpserver.ModuleID, mcpserver.Migrations, "mcp_", storetest.Migration{Module: "core", FS: core.Migrations})
}

// INV-3, POST-2, INV-8: the token is vmcp_ + 32 hex, shown once; the database keeps its SHA-256 and the last 4 only; the
// audit row names it by its last 4.
func TestContract_INV3_TokenShownOnceAndStoredHashed(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	secret, tok, err := w.svc.Create(t.Context(), "admin@example.com", "  Nam's Claude  ", []string{"feeds", "assets", "feeds"})
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^vmcp_[0-9a-f]{32}$`).MatchString(secret) {
		t.Fatalf("token %q", secret)
	}
	if tok.Name != "Nam's Claude" || !slices.Equal(tok.Scopes, []string{"assets", "feeds"}) || tok.Last4 != secret[len(secret)-4:] || tok.LastUsed != nil {
		t.Fatalf("item = %+v", tok)
	}
	dump := w.scalar(`SELECT id || name || scopes || token_hash || last4 || created_at FROM mcp_tokens`)
	if strings.Contains(dump, secret) || strings.Contains(dump, secret[5:]) {
		t.Fatal("the token is stored readable")
	}
	if h := w.scalar(`SELECT token_hash FROM mcp_tokens`); len(h) != 64 {
		t.Fatalf("token_hash = %q", h)
	}
	audits := w.auditRows("mcp.token_create")
	if len(audits) != 1 || audits[0] != "admin@example.com|Nam's Claude|scopes assets,feeds, last 4 "+secret[len(secret)-4:] {
		t.Fatalf("audit = %q", audits[0])
	}
	list, err := w.svc.Tokens(t.Context())
	if err != nil || len(list) != 1 || list[0].ID != tok.ID {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if b, _ := json.Marshal(list); strings.Contains(string(b), secret[5:]) {
		t.Fatal("the list carries the token")
	}
}

// INV-2: a token needs at least one known scope; a bad name or scope list is refused and saves nothing, no audit row.
func TestContract_INV2_CreateRefusals(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	cases := []struct {
		name   string
		scopes []string
		code   string
	}{
		{"ok", nil, "invalid_scopes"},
		{"ok", []string{}, "invalid_scopes"},
		{"ok", []string{"assets", "secrets"}, "invalid_scopes"},
		{"ok", []string{"Assets"}, "invalid_scopes"},
		{"", all, "invalid_name"},
		{"   ", all, "invalid_name"},
		{strings.Repeat("a", 65), all, "invalid_name"},
		{"a<script>", all, "invalid_name"},
		{"line\nbreak", all, "invalid_name"},
	}
	for _, c := range cases {
		_, _, err := w.svc.Create(t.Context(), "admin@example.com", c.name, c.scopes)
		e, ok := apierr.As(err)
		if !ok || e.Status != http.StatusBadRequest || e.Code != c.code {
			t.Errorf("Create(%q, %v) = %v, want 400 %s", c.name, c.scopes, err, c.code)
		}
	}
	if n := w.scalar(`SELECT count(*) FROM mcp_tokens`); n != "0" {
		t.Fatalf("%s tokens saved", n)
	}
	if a := w.auditRows("mcp.token_create"); len(a) != 0 {
		t.Fatalf("audit = %v", a)
	}
}

// D-231: at most MaxTokens tokens; the next one is 400 too_many and nothing is saved.
func TestContract_TokenCap(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	for i := range mcpserver.MaxTokens {
		w.token(fmt.Sprintf("t%d", i), "feeds")
	}
	_, _, err := w.svc.Create(t.Context(), "admin@example.com", "one more", all)
	if e, ok := apierr.As(err); !ok || e.Code != "too_many" || e.Status != 400 {
		t.Fatalf("err = %v", err)
	}
	if n := w.scalar(`SELECT count(*) FROM mcp_tokens`); n != fmt.Sprint(mcpserver.MaxTokens) {
		t.Fatalf("%s tokens", n)
	}
}

// INV-4: a revoked token is refused at once with 401; a wrong or malformed one too; the revoke is audited; 404 for an unknown id.
func TestContract_INV4_RevokeIsImmediate(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	secret := w.token("ci", all...)
	c := w.modern(secret)
	if r := c.request("tools/list", nil); r.status != 200 {
		t.Fatalf("before revoke: %d %s", r.status, r.raw)
	}
	list, _ := w.svc.Tokens(t.Context())
	if err := w.svc.Revoke(t.Context(), "admin@example.com", list[0].ID); err != nil {
		t.Fatal(err)
	}
	r := c.request("tools/list", nil)
	if r.status != http.StatusUnauthorized || !strings.Contains(r.header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("after revoke: %d %v %s", r.status, r.header, r.raw)
	}
	if a := w.auditRows("mcp.token_revoke"); len(a) != 1 || a[0] != "admin@example.com|ci|last 4 "+secret[len(secret)-4:] {
		t.Fatalf("audit = %v", a)
	}
	if err := w.svc.Revoke(t.Context(), "admin@example.com", list[0].ID); !isNotFound(err) {
		t.Fatalf("second revoke = %v", err)
	}
	for _, bad := range []string{"", "vmcp_" + strings.Repeat("0", 32), secret + "x", strings.ToUpper(secret), "Basic " + secret} {
		r := w.modern(bad).request("tools/list", nil)
		if r.status != http.StatusUnauthorized || r.header.Get("WWW-Authenticate") == "" {
			t.Errorf("token %q: %d", bad, r.status)
		}
	}
	// no bearer at all: the challenge has no error attribute
	r = (&client{w: w, modern: true}).request("tools/list", nil)
	if r.status != 401 || r.header.Get("WWW-Authenticate") != `Bearer realm="vedette-mcp"` {
		t.Fatalf("no token: %d %q", r.status, r.header.Get("WWW-Authenticate"))
	}
}

func isNotFound(err error) bool {
	e, ok := apierr.As(err)
	return ok && e.Status == 404
}

// INV-4: last_used is written by use: a tool call always, other requests at most once a minute.
func TestContract_INV4_LastUsed(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c := w.modern(w.token("ci", all...))
	if got := w.scalar(`SELECT last_used FROM mcp_tokens`); got != "" {
		t.Fatalf("last_used before use = %q", got)
	}
	c.request("tools/list", nil)
	if got := w.scalar(`SELECT last_used FROM mcp_tokens`); got != "2026-11-11T09:00:00.000Z" {
		t.Fatalf("last_used = %q", got)
	}
	w.clock.Advance(10 * time.Second)
	c.request("tools/list", nil)
	if got := w.scalar(`SELECT last_used FROM mcp_tokens`); got != "2026-11-11T09:00:00.000Z" {
		t.Fatalf("a list 10 s later wrote last_used = %q", got)
	}
	structured(t, c.call("hot_vulnerabilities", nil))
	if got := w.scalar(`SELECT last_used FROM mcp_tokens`); got != "2026-11-11T09:00:10.000Z" {
		t.Fatalf("a call did not write last_used: %q", got)
	}
}

// INV-1: exactly the seven read tools, all read-only, each with an input and an output schema; none can write.
func TestContract_INV1_SevenReadOnlyTools(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	for _, c := range []*client{w.modern(w.token("m", all...)), w.legacy(w.token("l", all...))} {
		tools, _ := c.request("tools/list", nil).result(t)["tools"].([]any)
		var names []string
		for _, x := range tools {
			m := x.(map[string]any)
			names = append(names, m["name"].(string))
			ann := m["annotations"].(map[string]any)
			if ann["readOnlyHint"] != true || ann["destructiveHint"] != false || ann["openWorldHint"] != false {
				t.Errorf("%s annotations = %v", m["name"], ann)
			}
			for _, k := range []string{"inputSchema", "outputSchema"} {
				if s, ok := m[k].(map[string]any); !ok || s["type"] != "object" {
					t.Errorf("%s %s = %v", m["name"], k, m[k])
				}
			}
			if in := m["inputSchema"].(map[string]any); in["additionalProperties"] != false {
				t.Errorf("%s accepts unknown arguments", m["name"])
			}
		}
		want := []string{"list_assets", "get_asset", "list_findings", "get_finding", "lookup_cve", "lookup_ioc", "hot_vulnerabilities"}
		if !slices.Equal(names, want) {
			t.Fatalf("tools = %v", names)
		}
	}
	if len(mcpserver.Tools) != 7 {
		t.Fatalf("%d tools", len(mcpserver.Tools))
	}
	for _, tl := range mcpserver.Tools {
		if regexp.MustCompile(`(?i)^(set|update|delete|create|add|remove|run|exec|scan|patch|write|apply)`).MatchString(tl.Name) {
			t.Errorf("tool %s sounds like a write", tl.Name)
		}
	}
}

// INV-2: a token sees only the tools of its scopes, and calling another tool is refused (no partial answer) and audited.
func TestContract_INV2_ScopeIsEnforced(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c := w.modern(w.token("feeds only", "feeds"))
	tools, _ := c.request("tools/list", nil).result(t)["tools"].([]any)
	var names []string
	for _, x := range tools {
		names = append(names, x.(map[string]any)["name"].(string))
	}
	if !slices.Equal(names, []string{"lookup_cve", "lookup_ioc", "hot_vulnerabilities"}) {
		t.Fatalf("tools = %v", names)
	}
	before := w.src.calls.Load()
	for _, name := range []string{"list_assets", "get_asset", "list_findings", "get_finding"} {
		r := c.call(name, map[string]any{"id": "as-fw"})
		if r.code() != -32602 || !strings.Contains(r.msg.Error.Message, "scope") || len(r.msg.Result) != 0 {
			t.Errorf("%s: %d %s", name, r.status, r.raw)
		}
	}
	if w.src.calls.Load() != before {
		t.Fatal("a refused call read the source")
	}
	audits := w.auditRows("mcp.call")
	if len(audits) != 4 || audits[0] != "mcp:feeds only|feeds only|tool list_assets, refused, scope assets missing, token …"+last4(w) {
		t.Fatalf("audit = %v", audits)
	}
}

// INV-6, INV-8: arguments are checked at the edge (a bad one is a tool error the agent can fix) and never written to the audit
// log: one row per call names the token, the tool and the outcome.
func TestContract_INV6_INV8_ArgumentsCheckedAndNotAudited(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c := w.modern(w.token("soc", all...))
	bad := []struct {
		tool string
		args map[string]any
	}{
		{"lookup_cve", map[string]any{"cve": "CVE-24-1 OR 1=1 marker-x1"}},
		{"lookup_cve", map[string]any{}},
		{"lookup_cve", map[string]any{"cve": 2024}},
		{"lookup_ioc", map[string]any{"value": "http://bad.example/x marker-x1"}},
		{"lookup_ioc", map[string]any{"value": strings.Repeat("a", 254)}},
		{"lookup_ioc", map[string]any{"value": "bad.example1"}},
		{"lookup_ioc", map[string]any{"value": "bad.xn--q9jyb4c-"}},
		{"lookup_ioc", map[string]any{"value": "-bad.example"}},
		{"lookup_ioc", map[string]any{"value": "bad.example."}},
		{"get_asset", map[string]any{"id": "../../etc/passwd"}},
		{"get_asset", map[string]any{"id": "as-fw", "extra": "marker-x1"}},
		{"get_finding", map[string]any{}},
		{"list_assets", map[string]any{"limit": 0}},
		{"list_assets", map[string]any{"limit": 101}},
		{"list_assets", map[string]any{"limit": 2.5}},
		{"list_assets", map[string]any{"offset": -1}},
		{"list_assets", map[string]any{"query": "a\u0000b"}},
		{"list_findings", map[string]any{"status": "open; DROP"}},
		{"list_findings", map[string]any{"cve": "nope"}},
		{"hot_vulnerabilities", map[string]any{"window": "30d"}},
	}
	for _, b := range bad {
		if msg := toolError(t, c.call(b.tool, b.args)); !strings.HasPrefix(msg, "Invalid arguments: ") || strings.Contains(msg, "marker-x1") && !strings.Contains(msg, "extra") {
			t.Errorf("%s %v: %q", b.tool, b.args, msg)
		}
	}
	// arguments that are not an object
	r := c.post([]byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"lookup_cve","arguments":[1],"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`),
		map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "lookup_cve"})
	if !strings.Contains(toolError(t, r), "JSON object") {
		t.Fatalf("array arguments: %s", r.raw)
	}
	structured(t, c.call("lookup_cve", map[string]any{"cve": "cve-2024-21762"}))
	audits := w.auditRows("mcp.call")
	if len(audits) != len(bad)+2 {
		t.Fatalf("%d audit rows for %d calls", len(audits), len(bad)+2)
	}
	for _, a := range audits {
		if strings.Contains(a, "marker-x1") || strings.Contains(a, "21762") || strings.Contains(a, "passwd") {
			t.Errorf("an argument reached the audit log: %q", a)
		}
	}
	if audits[len(audits)-1] != "mcp:soc|soc|tool lookup_cve, ok, 1 results, token …"+last4(w) || audits[0] != "mcp:soc|soc|tool lookup_cve, bad arguments, token …"+last4(w) {
		t.Fatalf("audit = %v", audits)
	}
}

// INV-7: what each tool answers fits its output schema exactly: no field outside the schema, every required one present.
func TestContract_INV7_AnswersFitTheirOutputSchema(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c := w.modern(w.token("soc", all...))
	calls := []struct {
		tool string
		args map[string]any
	}{
		{"list_assets", nil},
		{"list_assets", map[string]any{"query": "FORTI", "limit": 1}},
		{"get_asset", map[string]any{"id": "as-fw"}},
		{"get_asset", map[string]any{"id": "as-nas"}},
		{"list_findings", map[string]any{"status": "all"}},
		{"get_finding", map[string]any{"id": "fn-1"}},
		{"get_finding", map[string]any{"id": "fn-2"}},
		{"lookup_cve", map[string]any{"cve": "CVE-2024-21762"}},
		{"lookup_cve", map[string]any{"cve": "CVE-2020-0001"}},
		{"lookup_ioc", map[string]any{"value": "bad.example"}},
		{"lookup_ioc", map[string]any{"value": "good.example"}},
		{"lookup_ioc", map[string]any{"value": "discord.xn--q9jyb4c"}}, // an IDN top-level domain, as feeds lists it
		{"hot_vulnerabilities", map[string]any{"window": "24h", "limit": 1}},
	}
	for _, x := range calls {
		tl, _ := mcpserver.ToolByName(x.tool)
		var schema map[string]any
		if err := json.Unmarshal(tl.Output, &schema); err != nil {
			t.Fatalf("%s output schema: %v", x.tool, err)
		}
		got := structured(t, c.call(x.tool, x.args))
		if err := fits(schema, got, x.tool); err != nil {
			t.Errorf("%s %v: %v", x.tool, x.args, err)
		}
	}
}

// fits is a small JSON Schema check for the keywords the tool schemas use: type (with null), properties, required,
// additionalProperties false, items, enum, oneOf, maxItems.
func fits(s map[string]any, v any, path string) error {
	if alts, ok := s["oneOf"].([]any); ok {
		n := 0
		for _, a := range alts {
			if fits(a.(map[string]any), v, path) == nil {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("%s: matches %d of oneOf", path, n)
		}
		return nil
	}
	types := []string{}
	switch t := s["type"].(type) {
	case string:
		types = append(types, t)
	case []any:
		for _, x := range t {
			types = append(types, x.(string))
		}
	}
	kind := "null"
	switch x := v.(type) {
	case map[string]any:
		kind = "object"
	case []any:
		kind = "array"
	case string:
		kind = "string"
	case bool:
		kind = "boolean"
	case float64:
		kind = "number"
		if x == float64(int64(x)) && !slices.Contains(types, "number") {
			kind = "integer"
		}
	}
	if len(types) > 0 && !slices.Contains(types, kind) {
		return fmt.Errorf("%s: %s, want %v", path, kind, types)
	}
	if f, ok := s["format"].(string); ok && kind == "string" {
		re := map[string]*regexp.Regexp{"date-time": regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$`), "date": regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)}[f]
		if re == nil || !re.MatchString(v.(string)) {
			return fmt.Errorf("%s: %q is not a %s", path, v, f)
		}
	}
	if e, ok := s["enum"].([]any); ok && !slices.Contains(e, v) {
		return fmt.Errorf("%s: %v not in %v", path, v, e)
	}
	switch x := v.(type) {
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		for _, r := range s["required"].([]any) {
			if _, ok := x[r.(string)]; !ok {
				return fmt.Errorf("%s: missing %s", path, r)
			}
		}
		for k, val := range x {
			ps, ok := props[k].(map[string]any)
			if !ok {
				return fmt.Errorf("%s: field %s is not in the schema", path, k)
			}
			if err := fits(ps, val, path+"."+k); err != nil {
				return err
			}
		}
	case []any:
		if m, ok := s["maxItems"].(float64); ok && float64(len(x)) > m {
			return fmt.Errorf("%s: %d items", path, len(x))
		}
		for i, it := range x {
			if err := fits(s["items"].(map[string]any), it, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// The tools answer what the source holds: filters, paging and the "not listed" answers.
func TestContract_ToolAnswers(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c := w.modern(w.token("soc", all...))
	p := structured(t, c.call("list_assets", map[string]any{"limit": 1})).(map[string]any)
	if p["total"] != 2.0 || p["next_offset"] != 1.0 || p["items"].([]any)[0].(map[string]any)["id"] != "as-fw" {
		t.Fatalf("page 1 = %v", p)
	}
	p = structured(t, c.call("list_assets", map[string]any{"limit": 1, "offset": 1})).(map[string]any)
	if p["next_offset"] != nil || p["items"].([]any)[0].(map[string]any)["id"] != "as-nas" {
		t.Fatalf("page 2 = %v", p)
	}
	if p = structured(t, c.call("list_assets", map[string]any{"kind": "NAS"})).(map[string]any); p["total"] != 1.0 {
		t.Fatalf("kind filter = %v", p)
	}
	if p = structured(t, c.call("list_findings", nil)).(map[string]any); p["total"] != 1.0 {
		t.Fatalf("open findings = %v", p)
	}
	if p = structured(t, c.call("list_findings", map[string]any{"status": "patched", "asset_id": "as-nas"})).(map[string]any); p["total"] != 1.0 {
		t.Fatalf("patched = %v", p)
	}
	if p = structured(t, c.call("list_findings", map[string]any{"status": "all", "cve": "cve-2024-21762"})).(map[string]any); p["total"] != 1.0 {
		t.Fatalf("by cve = %v", p)
	}
	if m := structured(t, c.call("lookup_cve", map[string]any{"cve": "CVE-2020-0001"})).(map[string]any); m["listed"] != false || m["entry"] != nil {
		t.Fatalf("unlisted cve = %v", m)
	}
	if m := structured(t, c.call("lookup_ioc", map[string]any{"value": "bad.example"})).(map[string]any); m["verdict"] != "block" {
		t.Fatalf("ioc = %v", m)
	}
	if !strings.Contains(toolError(t, c.call("get_asset", map[string]any{"id": "as-nope"})), "no device") {
		t.Fatal("unknown device")
	}
	h := structured(t, c.call("hot_vulnerabilities", nil)).(map[string]any)["items"].([]any)
	if h[0].(map[string]any)["cve"] != "CVE-2026-1001" {
		t.Fatalf("hot not newest first: %v", h)
	}
}

// soft dependencies: a scope whose module is off answers a tool error that says so, not an empty list.
func TestContract_SourceModuleOff(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.src.off["inventory"] = true
	c := w.modern(w.token("soc", all...))
	if msg := toolError(t, c.call("list_assets", nil)); !strings.Contains(msg, "inventory module is off") {
		t.Fatalf("msg = %q", msg)
	}
	if a := w.auditRows("mcp.call"); len(a) != 1 || !strings.HasSuffix(a[0], "module inventory off, token …"+last4(w)) {
		t.Fatalf("audit = %v", a)
	}
}

// INV-5, FORBID-4: the server listens on loopback only; any other address is refused when the service is built.
func TestContract_INV5_LoopbackOnly(t *testing.T) {
	t.Parallel()
	db := storetest.New(t)
	for _, addr := range []string{"0.0.0.0:8765", "192.168.1.5:8765", "[::]:8765", "10.0.0.1:1"} {
		_, err := mcpserver.New(mcpserver.Config{DB: db, Audit: audit.New(nil), Log: slog.New(slog.DiscardHandler), Source: sampleSource(), Modules: &switches{},
			Listen: netip.MustParseAddrPort(addr)})
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Errorf("%s: %v", addr, err)
		}
	}
	// D-395: in a container the unspecified address of its own namespace is allowed (the unit publishes the port on the host's
	// 127.0.0.1 only), and the endpoint shown is the host's side of that publish; a named address off loopback stays refused.
	for _, addr := range []string{"192.168.1.5:8765", "10.0.0.1:1", "172.30.0.2:8765"} {
		_, err := mcpserver.New(mcpserver.Config{DB: db, Audit: audit.New(nil), Log: slog.New(slog.DiscardHandler), Source: sampleSource(), Modules: &switches{},
			Listen: netip.MustParseAddrPort(addr), InContainer: true})
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Errorf("in a container, %s: %v", addr, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:8765", "[::]:8765"} {
		s, err := mcpserver.New(mcpserver.Config{DB: db, Audit: audit.New(nil), Log: slog.New(slog.DiscardHandler), Source: sampleSource(), Modules: &switches{},
			Listen: netip.MustParseAddrPort(addr), InContainer: true})
		if err != nil {
			t.Fatalf("in a container, %s: %v", addr, err)
		}
		if bind, url := s.Endpoint(); bind.String() != "127.0.0.1:8765" || url != "http://127.0.0.1:8765/mcp" {
			t.Errorf("in a container, %s: endpoint %s %s", addr, bind, url)
		}
	}
}

// POST-1, SYS-5: the port is open while the module is on and closed when it goes off; tokens are kept. Off, a request that
// still reaches the handler gets 404, not 401.
func TestContract_POST1_PortFollowsTheSwitch(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	secret := w.token("ci", all...)
	svc, err := mcpserver.New(mcpserver.Config{DB: w.db, Audit: audit.New(nil), Log: slog.New(slog.DiscardHandler), Source: w.src, Modules: w.sw,
		Listen: netip.MustParseAddrPort("127.0.0.1:0")})
	if err != nil {
		t.Fatal(err)
	}
	var subs []func(string, bool)
	w.sw.on.Store(false)
	svc.Follow(t.Context(), func(f func(string, bool)) { subs = append(subs, f) })
	if bind, _ := svc.Endpoint(); bind.Port() != 0 {
		t.Fatalf("listening while off: %s", bind)
	}
	w.sw.on.Store(true)
	subs[0](mcpserver.ModuleID, true)
	var bind netip.AddrPort
	waitFor(t, func() bool { bind, _ = svc.Endpoint(); return bind.Port() != 0 })
	_, endpoint := svc.Endpoint()
	if endpoint != "http://"+bind.String()+"/mcp" || !bind.Addr().IsLoopback() {
		t.Fatalf("endpoint %s", endpoint)
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Mcp-Session-Id") != "" {
		t.Fatalf("over the socket: %d, session %q", resp.StatusCode, resp.Header.Get("Mcp-Session-Id"))
	}
	w.sw.on.Store(false)
	if r := w.modern(secret).request("tools/list", nil); r.status != 404 {
		t.Fatalf("off, the handler answered %d", r.status)
	}
	subs[0](mcpserver.ModuleID, false)
	waitFor(t, func() bool {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", bind.String())
		if err == nil {
			_ = conn.Close()
		}
		return err != nil
	})
	if n := w.scalar(`SELECT count(*) FROM mcp_tokens`); n != "1" {
		t.Fatalf("tokens after off = %s", n)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		<-time.After(10 * time.Millisecond)
	}
}

// Streamable HTTP rules (D-230): POST only, no browser origin, JSON only, one message per request, notifications 202.
func TestContract_Transport(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	secret := w.token("ci", all...)
	c := w.modern(secret)
	list := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`)
	mh := map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"}
	with := func(extra map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range mh {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	cases := []struct {
		name   string
		body   []byte
		hdr    map[string]string
		status int
		code   int
	}{
		{"browser origin", list, with(map[string]string{"Origin": "http://127.0.0.1:8765"}), 403, -32600},
		{"rebinding origin", list, with(map[string]string{"Origin": "https://evil.example"}), 403, -32600},
		{"form post", list, with(map[string]string{"Content-Type": "text/plain"}), 415, -32600},
		{"batch", []byte(`[` + string(list) + `]`), mh, 400, -32600},
		{"not json", []byte(`{"jsonrpc":`), mh, 400, -32700},
		{"jsonrpc 1", []byte(`{"jsonrpc":"1.0","id":1,"method":"tools/list"}`), mh, 400, -32700},
		{"null id", []byte(`{"jsonrpc":"2.0","id":null,"method":"tools/list"}`), mh, 400, -32600},
		{"object id", []byte(`{"jsonrpc":"2.0","id":{},"method":"tools/list"}`), mh, 400, -32600},
		{"too large", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("x", 70<<10) + `"}}`), mh, 413, -32600},
		{"version header mismatch", list, with(map[string]string{"MCP-Protocol-Version": "2025-06-18"}), 400, -32020},
		{"method header mismatch", list, with(map[string]string{"Mcp-Method": "tools/call"}), 400, -32020},
		{"no method header", list, with(map[string]string{"Mcp-Method": ""}), 400, -32020},
		{"modern header, no meta", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`), mh, 400, -32602},
		{"unknown legacy version", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`), map[string]string{"MCP-Protocol-Version": "2024-01-01"}, 400, -32022},
		{"missing capabilities", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`), mh, 400, -32602},
		{"future version", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`),
			with(map[string]string{"MCP-Protocol-Version": "2099-01-01"}), 400, -32022},
		{"unknown method modern", []byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`),
			with(map[string]string{"Mcp-Method": "resources/list"}), 404, -32601},
		{"unknown method legacy", []byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`), map[string]string{"MCP-Protocol-Version": "2025-06-18"}, 200, -32601},
		{"discover is modern only", []byte(`{"jsonrpc":"2.0","id":1,"method":"server/discover"}`), map[string]string{"MCP-Protocol-Version": "2025-11-25"}, 200, -32601},
	}
	for _, x := range cases {
		w.clock.Advance(2 * time.Second) // every request takes from the bucket, refused or not
		r := c.post(x.body, x.hdr)
		if r.status != x.status || r.code() != x.code {
			t.Errorf("%s: %d %d, want %d %d: %s", x.name, r.status, r.code(), x.status, x.code, r.raw)
		}
	}
	if r := c.post([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), nil); r.status != 202 || len(r.raw) != 0 {
		t.Fatalf("notification: %d %s", r.status, r.raw)
	}
	for _, m := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		req, _ := http.NewRequestWithContext(t.Context(), m, "http://127.0.0.1:8765/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		rec := httptest.NewRecorder()
		w.h.ServeHTTP(rec, req)
		if rec.Code != 405 || rec.Header().Get("Allow") != "POST" {
			t.Errorf("%s: %d", m, rec.Code)
		}
	}
	// a header that names the tool in base64 is decoded before it is compared
	r := c.post([]byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hot_vulnerabilities","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`),
		map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "=?base64?aG90X3Z1bG5lcmFiaWxpdGllcw==?="})
	structured(t, r)
	r = c.post([]byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hot_vulnerabilities","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`),
		map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "list_assets"})
	if r.status != 400 || r.code() != -32020 {
		t.Fatalf("Mcp-Name mismatch: %d %s", r.status, r.raw)
	}
	if a := w.auditRows("mcp.call"); len(a) != 1 {
		t.Fatalf("a refused request was audited as a call: %v", a)
	}
}

// Both eras work end to end: the legacy handshake (no session), and the stateless 2026-07-28 revision with server/discover.
func TestContract_BothEras(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	secret := w.token("ci", all...)
	lg := w.legacy(secret)
	init := lg.request("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "x", "version": "1"}})
	m := init.result(t)
	if m["protocolVersion"] != "2025-06-18" || init.header.Get("Mcp-Session-Id") != "" || m["serverInfo"].(map[string]any)["version"] != "1.2.3" {
		t.Fatalf("initialize: %s %v", init.raw, init.header)
	}
	if _, has := m["resultType"]; has {
		t.Fatal("a legacy result carries resultType")
	}
	if m := lg.request("initialize", map[string]any{"protocolVersion": "2030-01-01"}).result(t); m["protocolVersion"] != "2025-11-25" {
		t.Fatalf("unknown version answered %v", m["protocolVersion"])
	}
	if r := lg.post([]byte(`{"jsonrpc":"2.0","id":5,"method":"tools/list"}`), map[string]string{"MCP-Protocol-Version": ""}); r.status != 200 {
		t.Fatalf("2025-03-26 client without the header: %d %s", r.status, r.raw)
	}
	structured(t, lg.call("lookup_cve", map[string]any{"cve": "CVE-2024-21762"}))
	md := w.modern(secret)
	d := md.request("server/discover", nil).result(t)
	if d["resultType"] != "complete" || !slices.Equal(toStrings(d["supportedVersions"]), []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"}) {
		t.Fatalf("discover = %v", d)
	}
	if d["_meta"].(map[string]any)["io.modelcontextprotocol/serverInfo"].(map[string]any)["name"] != "vedette" {
		t.Fatalf("discover meta = %v", d["_meta"])
	}
	if r := md.request("ping", nil).result(t); r["resultType"] != "complete" {
		t.Fatalf("ping = %v", r)
	}
	if r := md.request("tools/list", map[string]any{"cursor": "x"}); r.code() != -32602 {
		t.Fatalf("cursor: %s", r.raw)
	}
	r := md.call("get_asset", map[string]any{"id": "as-fw"})
	if res := r.result(t); res["resultType"] != "complete" {
		t.Fatalf("call result = %v", res)
	}
	if r := md.call("no_such_tool", nil); r.code() != -32602 || !strings.Contains(r.msg.Error.Message, "Unknown tool") {
		t.Fatalf("unknown tool: %s", r.raw)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// D-232: a token gets a burst of 30 requests, then 429 with Retry-After until its bucket refills; tool calls are also capped per day.
func TestContract_RateLimits(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c := w.modern(w.token("loop", all...))
	other := w.modern(w.token("other", all...))
	for i := range 30 {
		if r := c.request("ping", nil); r.status != 200 {
			t.Fatalf("request %d: %d", i, r.status)
		}
	}
	r := c.request("ping", nil)
	if r.status != 429 || r.header.Get("Retry-After") != "2" || r.code() != -31429 {
		t.Fatalf("31st: %d %q %s", r.status, r.header.Get("Retry-After"), r.raw)
	}
	if r := other.request("ping", nil); r.status != 200 {
		t.Fatalf("another token was limited: %d", r.status)
	}
	w.clock.Advance(2 * time.Second)
	if r := c.request("ping", nil); r.status != 200 {
		t.Fatalf("after refill: %d", r.status)
	}
	// the daily cap: 2000 calls, spread so the minute bucket never runs dry
	for i := range 2000 {
		w.clock.Advance(2 * time.Second)
		if r := other.call("hot_vulnerabilities", nil); r.status != 200 {
			t.Fatalf("call %d: %d %s", i, r.status, r.raw)
		}
	}
	w.clock.Advance(2 * time.Second)
	if r := other.call("hot_vulnerabilities", nil); r.status != 429 {
		t.Fatalf("call 2001: %d", r.status)
	}
	if r := other.request("tools/list", nil); r.status != 200 {
		t.Fatalf("the daily cap stopped a list: %d", r.status)
	}
	if n := len(w.auditRows("mcp.call")); n != 2000 {
		t.Fatalf("%d audit rows: a limited call must not write one", n)
	}
}

// The source failing is an error result with no detail of the failure; the audit row says error.
func TestContract_SourceErrorIsNotLeaked(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c := w.modern(w.token("soc", all...))
	w.svc = nil
	failing := &failingSource{fakeSource: sampleSource()}
	svc, err := mcpserver.New(mcpserver.Config{DB: w.db, Audit: audit.New(nil), Log: slog.New(slog.DiscardHandler), Source: failing, Modules: w.sw})
	if err != nil {
		t.Fatal(err)
	}
	w.h = svc.Handler()
	msg := toolError(t, c.call("list_assets", nil))
	if strings.Contains(msg, "sqlite") || !strings.Contains(msg, "could not answer") {
		t.Fatalf("msg = %q", msg)
	}
	if a := w.auditRows("mcp.call"); len(a) != 1 || !strings.Contains(a[0], "list_assets, error, token …") {
		t.Fatalf("audit = %v", a)
	}
}

type failingSource struct{ *fakeSource }

func (failingSource) Assets(context.Context) ([]mcpserver.Asset, error) {
	return nil, errors.New("sqlite: database disk image is malformed at /var/lib/vedette/vedette.db")
}

// last4 is the last 4 characters of the only token of w, as the audit rows name it.
func last4(w *world) string {
	return w.scalar(`SELECT last4 FROM mcp_tokens ORDER BY created_at, id LIMIT 1`)
}

// Review M4: a request the server refuses still takes from the token's bucket, so mismatched headers cannot be sent without limit.
func TestContract_RefusedRequestsCountTowardTheLimit(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c := w.modern(w.token("noisy", all...))
	bad := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`)
	for range 30 {
		if r := c.post(bad, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call"}); r.status != 400 {
			t.Fatalf("mismatch: %d", r.status)
		}
	}
	if r := c.request("tools/list", nil); r.status != 429 || r.header.Get("Retry-After") == "" || string(r.msg.ID) != "null" {
		t.Fatalf("after 30 refused requests: %d %s", r.status, r.raw)
	}
}

// Review M6: a legacy request that sends the mirrored headers must match them too (a proxy may route on them).
func TestContract_LegacyMirrorsMustMatch(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c := w.legacy(w.token("ci", all...))
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_asset","arguments":{"id":"as-fw"}}}`)
	for _, h := range []map[string]string{
		{"MCP-Protocol-Version": "2025-06-18", "Mcp-Name": "lookup_cve"},
		{"MCP-Protocol-Version": "2025-06-18", "Mcp-Method": "tools/list"},
		{"MCP-Protocol-Version": "2025-06-18", "Mcp-Method": "tools/call", "Mcp-Name": "=?base64?not base64?="},
	} {
		if r := c.post(body, h); r.status != 400 || r.code() != -32020 {
			t.Errorf("%v: %d %s", h, r.status, r.raw)
		}
	}
	if r := c.post(body, map[string]string{"MCP-Protocol-Version": "2025-06-18", "Mcp-Method": "tools/call", "Mcp-Name": "get_asset"}); r.status != 200 {
		t.Fatalf("matching legacy mirrors: %d %s", r.status, r.raw)
	}
	init := []byte(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if r := c.post(init, map[string]string{"Mcp-Method": "tools/call"}); r.status != 400 || r.code() != -32020 {
		t.Fatalf("initialize with a wrong Mcp-Method: %d %s", r.status, r.raw)
	}
	if a := w.auditRows("mcp.call"); len(a) != 1 {
		t.Fatalf("audit = %v", a)
	}
}

// Review M3: a port another process holds is reported (listening false, the reason) instead of an address that would hand
// the token to that process; and a start after shutdown opens nothing (review L8).
func TestContract_PortHeldElsewhereIsReported(t *testing.T) {
	t.Parallel()
	squatter, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = squatter.Close() }()
	w := newWorld(t)
	sw := &switches{}
	sw.on.Store(true)
	svc, err := mcpserver.New(mcpserver.Config{DB: w.db, Audit: audit.New(nil), Log: slog.New(slog.DiscardHandler), Source: w.src, Modules: sw,
		Listen: netip.MustParseAddrPort(squatter.Addr().String())})
	if err != nil {
		t.Fatal(err)
	}
	svc.Follow(t.Context(), func(func(string, bool)) {})
	if on, why := svc.Listening(); on || why == nil || !strings.Contains(why.Error(), "listen") {
		t.Fatalf("listening = %v, %v", on, why)
	}
	got, err := mcpserver.NewMcpHandlers(svc).CoreGetCoreMcp(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(squatter.Addr().(*net.TCPAddr).Port)
	if got.Listening || got.ListenError.Null || got.ListenError.Value != "The port "+port+" could not be opened: another program may hold it. Vedette tries again every 15 seconds." {
		t.Fatalf("GET /core/mcp = listening %v, %+v", got.Listening, got.ListenError)
	}
	done, cancel := context.WithCancel(t.Context())
	cancel()
	fresh, _ := mcpserver.New(mcpserver.Config{DB: w.db, Audit: audit.New(nil), Log: slog.New(slog.DiscardHandler), Source: w.src, Modules: sw,
		Listen: netip.MustParseAddrPort("127.0.0.1:0")})
	if err := fresh.Start(done); err == nil {
		t.Fatal("a start after shutdown opened the port")
	}
	if on, _ := fresh.Listening(); on {
		t.Fatal("listening after a cancelled start")
	}
}
