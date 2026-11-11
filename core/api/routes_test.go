package api_test

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
)

type specOp struct {
	ID       string   `json:"operationId"`
	MinRole  string   `json:"x-min-role"`
	Tags     []string `json:"tags"`
	Security *[]any   `json:"security"`
}

// loadSpec returns method+" "+path -> operation for every operation of api/openapi.json.
func loadSpec(t *testing.T) map[string]specOp {
	t.Helper()
	raw, err := os.ReadFile("../../api/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]specOp{}
	for p, item := range doc.Paths {
		for m, rawOp := range item {
			var op specOp
			if err := json.Unmarshal(rawOp, &op); err != nil || op.ID == "" {
				t.Fatalf("%s %s: not an operation: %v", m, p, err)
			}
			out[strings.ToUpper(m)+" "+p] = op
		}
	}
	return out
}

func TestRoutesCoverContract(t *testing.T) {
	t.Parallel()
	spec := loadSpec(t)
	if len(routes.Operations) != len(spec) {
		t.Fatalf("routes has %d operations, contract has %d (run make generate-api)", len(routes.Operations), len(spec))
	}
	for key, op := range spec {
		got, ok := routes.Operations[op.ID]
		if !ok {
			t.Errorf("%s: operationId %q missing from routes", key, op.ID)
			continue
		}
		if got.Method+" "+got.Path != key {
			t.Errorf("%s: routes says %s %s", key, got.Method, got.Path)
		}
		if string(got.MinRole) != op.MinRole {
			t.Errorf("%s: role %q, contract %q", key, got.MinRole, op.MinRole)
		}
		if len(op.Tags) == 0 || got.Tag != op.Tags[0] {
			t.Errorf("%s: tag %q, contract %v", key, got.Tag, op.Tags)
		}
	}
}

func TestEveryOperationHasRole(t *testing.T) {
	t.Parallel()
	valid := []routes.Role{routes.Public, routes.Viewer, routes.Operator, routes.Admin}
	for id, op := range routes.Operations {
		if !slices.Contains(valid, op.MinRole) {
			t.Errorf("%s: role %q is not viewer/operator/admin/public", id, op.MinRole)
		}
	}
}

// INV-5 (modules/core/CONTRACT.md) allows these public paths.
func inv5Public(p string) bool {
	switch {
	case p == "/setup", p == "/core/auth-options":
		return true
	case strings.HasPrefix(p, "/core/setup"), strings.HasPrefix(p, "/auth/"),
		strings.HasPrefix(p, "/install/"), strings.HasPrefix(p, "/intake/"):
		return true
	}
	return false
}

// publicExceptions are public in the contract but not listed in INV-5's text. The CONTRACT text is
// incomplete: they have no session by design (one-time email links, firewall list fetch); the SSO round trip is under /auth/ (D-194).
// Fix INV-5 in a contract PR; until then this list is the explicit, reviewed set.
var publicExceptions = []string{
	"GET /response/approve/{token}",
	"POST /response/approve/{token}",
	"GET /response/blocklist/{token}.txt",
}

func TestPublicOperationsAreExactlyINV5(t *testing.T) {
	t.Parallel()
	var got, want []string
	for _, op := range routes.Operations {
		if op.MinRole == routes.Public {
			got = append(got, op.Method+" "+op.Path)
		}
	}
	for _, op := range routes.Operations {
		if inv5Public(op.Path) && op.MinRole != routes.Public {
			t.Errorf("%s %s matches INV-5 public paths but has role %q", op.Method, op.Path, op.MinRole)
		}
	}
	for _, op := range routes.Operations {
		key := op.Method + " " + op.Path
		if op.MinRole == routes.Public && (inv5Public(op.Path) || slices.Contains(publicExceptions, key)) {
			want = append(want, key)
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("public operations not allowed by INV-5 or the exception list:\n got  %v\n want %v", got, want)
	}
	for _, e := range publicExceptions {
		if !slices.Contains(got, e) {
			t.Errorf("stale exception %q: not public in the contract any more", e)
		}
	}
}

// Public operations declare security: [] in the contract and nothing else does (API_CONVENTIONS 7.4).
func TestPublicMatchesEmptySecurity(t *testing.T) {
	t.Parallel()
	for key, op := range loadSpec(t) {
		empty := op.Security != nil && len(*op.Security) == 0
		if empty != (op.MinRole == "public") {
			t.Errorf("%s: x-min-role %q but security empty=%v", key, op.MinRole, empty)
		}
	}
}

type noSecurity struct{}

func (noSecurity) HandleSession(ctx context.Context, _ oas.OperationName, _ oas.Session) (context.Context, error) {
	return ctx, nil
}

// The generated router and the role table agree on operation ids, method and path.
func TestRouterMatchesRoutes(t *testing.T) {
	t.Parallel()
	srv, err := oas.NewServer(oas.UnimplementedHandler{}, noSecurity{})
	if err != nil {
		t.Fatal(err)
	}
	for id, op := range routes.Operations {
		// Fill every {param} with a plain segment; the router matches by template.
		p := op.Path
		for strings.Contains(p, "{") {
			i, j := strings.Index(p, "{"), strings.Index(p, "}")
			p = p[:i] + "x" + p[j+1:]
		}
		route, ok := srv.FindPath(op.Method, &url.URL{Path: path.Clean(p)})
		if !ok {
			t.Errorf("%s: router has no route for %s %s", id, op.Method, p)
			continue
		}
		if route.OperationID() != id {
			t.Errorf("%s %s: router operation %q, table %q", op.Method, op.Path, route.OperationID(), id)
		}
	}
}
