package server_test

import (
	"encoding/json"
	"flag"
	"os"
	"sort"
	"testing"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/server"
)

var updateRouteModules = flag.Bool("update-route-modules", false, "rewrite api/route-modules.json")

// api/route-modules.json lists "METHOD /path/{id}" -> module for every operation. The SPA test
// web/src/lib/apiModules.test.ts checks its own moduleOf against the same file, so the frontend (which
// modules go to the real backend in `make dev-api`) cannot drift from ModuleOf. Regenerate with
// go test ./core/server -run RouteModules -update-route-modules.
func TestRouteModulesFixture(t *testing.T) {
	got := map[string]string{}
	for _, op := range routes.Operations {
		got[op.Method+" "+op.Path] = server.ModuleOf(op)
	}
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	const file = "../../api/route-modules.json"
	if *updateRouteModules {
		out := []byte("{\n")
		for i, k := range keys {
			kb, _ := json.Marshal(k)
			vb, _ := json.Marshal(got[k])
			out = append(out, "  "...)
			out = append(out, kb...)
			out = append(out, ": "...)
			out = append(out, vb...)
			if i < len(keys)-1 {
				out = append(out, ',')
			}
			out = append(out, '\n')
		}
		out = append(out, "}\n"...)
		if err := os.WriteFile(file, out, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for k, m := range got {
		if want[k] != m {
			t.Errorf("%s: ModuleOf = %q, api/route-modules.json has %q (run with -update-route-modules)", k, m, want[k])
		}
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("api/route-modules.json lists %s, the route table has no such operation", k)
		}
	}
}
