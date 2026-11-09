package server_test

import (
	"context"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/server"
)

type secStub struct{}

func (secStub) HandleSession(ctx context.Context, _ oas.OperationName, _ oas.Session) (context.Context, error) {
	return ctx, nil
}

// The route table (roles, tags) and the generated router agree: every operation of the table is found
// by method and path, with the same operation id. A mismatch would give some route no role check.
func TestRouteTableMatchesRouter(t *testing.T) {
	t.Parallel()
	srv, err := oas.NewServer(composite{Fallback: server.Fallback{Log: slog.New(slog.DiscardHandler)}}, secStub{}, oas.WithPathPrefix(server.Prefix))
	if err != nil {
		t.Fatal(err)
	}
	param := regexp.MustCompile(`\{[^}]+\}`)
	if len(routes.Operations) < 200 {
		t.Fatalf("route table has %d operations; the generator output looks wrong", len(routes.Operations))
	}
	for id, op := range routes.Operations {
		path := server.Prefix + param.ReplaceAllString(op.Path, "x1")
		route, ok := srv.FindPath(op.Method, &url.URL{Path: path})
		if !ok {
			t.Errorf("%s: router does not know %s %s", id, op.Method, op.Path)
			continue
		}
		if route.OperationID() != id || route.PathPattern() != op.Path {
			t.Errorf("%s: router says %s %s", id, route.OperationID(), route.PathPattern())
		}
	}
}

// INV-5: every operation has a valid role.
func TestEveryOperationHasAValidRole(t *testing.T) {
	t.Parallel()
	valid := []routes.Role{routes.Public, routes.Viewer, routes.Operator, routes.Admin}
	for id, op := range routes.Operations {
		if !slices.Contains(valid, op.MinRole) {
			t.Errorf("%s has role %q", id, op.MinRole)
		}
	}
}

// Every operation maps to a module that has a MANIFEST.yaml, except findings, whose folder arrives
// with WP-21 (D-57 (6)); it is allowed explicitly so a typo in the mapping cannot hide behind it.
func TestEveryOperationMapsToAModuleWithAManifest(t *testing.T) {
	t.Parallel()
	ms, err := modreg.Load(os.DirFS("../../modules"))
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{"findings": true}
	for _, m := range ms {
		known[m.ID] = true
	}
	used := map[string]int{}
	for id, op := range routes.Operations {
		m := server.ModuleOf(op)
		used[m]++
		if !known[m] {
			t.Errorf("%s (%s %s) maps to module %q, which has no manifest", id, op.Method, op.Path, m)
		}
	}
	var names []string
	for m := range used {
		names = append(names, m)
	}
	sort.Strings(names)
	t.Logf("operations per module: %v", used)
	for _, m := range []string{"findings", "scan", "agent-intake", "sensor-passive", "host", "mcp-server", "auth-oidc", "core"} {
		if used[m] == 0 {
			t.Errorf("no operation maps to %q: an override is dead or the contract changed", m)
		}
	}
}

func TestModuleOfOverrides(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path, tag, want string
	}{
		{"/findings", "findings", "findings"},
		{"/findings/{id}/status", "findings", "findings"},
		{"/scans/runs", "scan", "scan"},
		{"/scans", "scan", "scan"},
		{"/core/oidc", "core", "auth-oidc"},
		{"/core/sso/login", "core", "auth-oidc"},
		{"/core/mcp/tokens", "core", "mcp-server"},
		{"/core/network", "core", "host"},
		{"/core/network/span", "core", "host"},
		{"/core/networks", "core", "core"}, // a prefix must end on a segment boundary
		{"/core/general", "core", "core"},
		{"/install/osquery", "inventory", "agent-intake"},
		{"/intake/osquery/enroll", "inventory", "agent-intake"},
		{"/inventory/agents", "inventory", "agent-intake"},
		{"/inventory/agents/tokens", "inventory", "agent-intake"},
		{"/inventory/agentsmith", "inventory", "inventory"},
		{"/inventory/sensors", "inventory", "sensor-passive"},
		{"/inventory/devices", "inventory", "inventory"},
		{"/auth/login", "core", "core"},
		{"/me", "core", "core"},
		{"/modules/{id}", "core", "core"},
		{"/setup", "core", "core"},
		{"/feeds/hot", "feeds", "feeds"},
		{"/response/approve/{token}", "response", "response"},
	}
	for _, tt := range tests {
		if got := server.ModuleOf(routes.Operation{Path: tt.path, Tag: tt.tag}); got != tt.want {
			t.Errorf("ModuleOf(%s, tag %s) = %q, want %q", tt.path, tt.tag, got, tt.want)
		}
	}
}
