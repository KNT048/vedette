// Package main is the CI helper (D-140): `ci changes` decides which of the go and web jobs a pull request needs,
// `ci shard I N` prints the I-th of N stable, disjoint, complete package shards for `go test`.
// Classification is fail-safe: a path no rule names runs everything.
package main

import "strings"

// Result says which suites a set of changed paths can affect.
type Result struct{ Go, Web bool }

type rule struct {
	prefix string // path prefix (ends in "/") or exact path
	r      Result
}

// rules are checked in order; the first match wins. Every "none" entry is a path that no test, embed or build
// step reads: guard_test.go fails when Go or web code starts reading one (D-140).
var rules = []rule{
	// Read by a test, so they come before the broad "none" prefixes below.
	{"docs/API_CONVENTIONS.md", Result{Go: true}},                     // core/apierr, modules/core codes and connections tests
	{"docs/specs/host-api.md", Result{Go: true}},                      // modules/host contract tests
	{"docs/DEPLOYMENT.md", Result{Go: true}},                          // deploy/systemd/unit_test.go compares section 6.1 with the unit file (D-150)
	{"docs/INSTALL-CONTAINER.md", Result{Go: true}},                   // deploy/compose/compose_test.go keeps its backup image equal to pins.env (D-168)
	{"modules/core/testdata/", Result{true, true}},                    // chain_vectors.json is a vector for Go and web
	{"web/src/features/response/templates/", Result{true, true}},      // Go reads the *.sample.json files
	{"web/src/features/core/testdata/", Result{true, true}},           // Go reads connections_matrix.json and keys/
	{"web/src/features/core/bundles.ts", Result{true, true}},          // modules/core/handlers_setup_test.go
	{"web/src/features/inventory/agentConfig.ts", Result{true, true}}, // modules/agent-intake/schedule_test.go: the Go schedule equals the GUI list
	{"web/src/locales/en/core.json", Result{true, true}},              // modules/core/auditlabels_test.go: every audit action has a label
	{"THIRD_PARTY_NOTICES.md", Result{Go: true}},                      // make notices-check (verify-go-static) holds it to go list and web/package.json (D-159)
	{"web/package.json", Result{true, true}},                          // the same check reads the web production dependencies

	// No test reads these.
	{".ai/", Result{}},
	{".claude/", Result{}},
	{"docs/", Result{}},
	{"skills/", Result{}},
	{".github/ISSUE_TEMPLATE/", Result{}},
	{".github/CODEOWNERS", Result{}},
	{".github/pull_request_template.md", Result{}},
	{"README.md", Result{}},
	{"CHANGELOG.md", Result{}},
	{"CLAUDE.md", Result{}},
	{"CONTRIBUTING.md", Result{}},
	{"SECURITY.md", Result{}},
	{"PRIVACY.md", Result{}},
	{"NOTICE", Result{}},
	{"LICENSE", Result{}},
	{".mcp.json.example", Result{}},

	// Both sides read these (openapi drift, shared data, the CI definition itself).
	{"api/", Result{true, true}},
	{"content/", Result{true, true}},
	{"scripts/", Result{true, true}},
	{"Makefile", Result{true, true}},
	{".github/workflows/", Result{true, true}},

	// One side only.
	{"web/", Result{Web: true}},
	{"modules/", Result{Go: true}},
	{"core/", Result{Go: true}},
	{"host/", Result{Go: true}},
	{"cmd/", Result{Go: true}},
	{"internal/", Result{Go: true}},
	{"tools/", Result{Go: true}},
	{"go.mod", Result{Go: true}},
	{"go.sum", Result{Go: true}},
	{"sqlc.yaml", Result{Go: true}},
	{".golangci.yml", Result{Go: true}},
}

// Classify says what one repo-relative path (slash separated) affects. A path no rule names affects both.
func Classify(p string) Result {
	p = strings.TrimPrefix(p, "./")
	for _, r := range rules {
		if p == r.prefix || (strings.HasSuffix(r.prefix, "/") && strings.HasPrefix(p, r.prefix)) {
			return r.r
		}
	}
	return Result{true, true}
}

// ClassifyAll is the union over paths. No path at all runs everything (nothing to reason about).
func ClassifyAll(paths []string) Result {
	if len(paths) == 0 {
		return Result{true, true}
	}
	var out Result
	for _, p := range paths {
		c := Classify(p)
		out.Go = out.Go || c.Go
		out.Web = out.Web || c.Web
	}
	return out
}

// Outputs are the job switches CI reads: Go is go-static and go-release, Tests is go-test.
type Outputs struct{ Go, Tests, Web, Vuln, Audit bool }

// Decide maps the event and the changed paths to job switches. diffOK is false when the diff could not be
// computed; then everything runs. A pull request is narrowed by its paths. A push to main runs only go-test (D-365):
// the merge queue already ran every job on that exact tree, and the push run is what saves main's Go test cache, the
// only cache pull requests and the queue can restore. The daily schedule runs everything, uncached (ci.yml passes
// -count=1), plus both vulnerability scans. workflow_dispatch, merge_group and any unknown event run everything.
func Decide(event string, changed []string, diffOK bool) Outputs {
	switch {
	case event == "schedule":
		return Outputs{Go: true, Tests: true, Web: true, Vuln: true, Audit: true}
	case event == "push":
		return Outputs{Tests: true}
	case event == "pull_request" && diffOK:
		c := ClassifyAll(changed)
		return Outputs{Go: c.Go, Tests: c.Go, Web: c.Web, Vuln: c.Go}
	default:
		return Outputs{Go: true, Tests: true, Web: true, Vuln: true}
	}
}
