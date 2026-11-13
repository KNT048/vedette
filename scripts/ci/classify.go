// Package main is the CI helper (D-140): `ci changes` decides which of the go and web jobs a pull request needs,
// `ci shard I N` prints the I-th of N stable, disjoint, complete package shards for `go test` (on a pull request only the
// shard's packages the change reaches, D-413).
// Classification is fail-safe: a path no rule names runs everything.
package main

import (
	"maps"
	"path"
	"slices"
	"strings"
)

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
	{"docs/API_CONVENTIONS.md", Result{Go: true}},                          // core/apierr, modules/core codes and connections tests
	{"docs/specs/host-api.md", Result{Go: true}},                           // modules/host contract tests
	{"docs/DEPLOYMENT.md", Result{Go: true}},                               // deploy/systemd/unit_test.go compares section 6.1 with the unit file (D-150)
	{"docs/RUNBOOK.md", Result{Go: true}},                                  // deploy/deb/apparmor_test.go keeps the AppArmor repair command equal to the postinst one (D-412)
	{"docs/INSTALL-CONTAINER.md", Result{Go: true}},                        // deploy/compose/compose_test.go keeps its backup image equal to pins.env (D-168)
	{"modules/response/data/triggers.json", Result{true, true}},            // web/src/features/response/triggers.test.ts holds data.ts to it (D-390)
	{"modules/core/testdata/", Result{true, true}},                         // chain_vectors.json is a vector for Go and web
	{"web/src/features/response/templates/", Result{true, true}},           // Go reads the *.sample.json files
	{"web/src/features/core/testdata/", Result{true, true}},                // Go reads connections_matrix.json and keys/
	{"web/src/features/exposure/contract.ts", Result{true, true}},          // modules/exposure/notice_test.go: the mock's commitment sentence equals the box's (D-473)
	{"web/src/features/logs/snippets.ts", Result{true, true}},              // modules/logs/siem_test.go: the SIEM samples equal what the formatters write
	{"web/src/features/core/bundles.ts", Result{true, true}},               // modules/core/handlers_setup_test.go
	{"web/src/features/core/ContainerOnly.tsx", Result{true, true}},        // deploy/compose/compose_test.go: its backup image equals pins.env (D-381)
	{"web/src/features/inventory/agentConfig.ts", Result{true, true}},      // modules/agent-intake/schedule_test.go: the Go schedule equals the GUI list
	{"web/src/features/inventory/installScripts.ts", Result{true, true}},   // modules/agent-intake/install_test.go: the served scripts and OSQUERY_VERSION equal the GUI's
	{"web/src/features/inventory/scripts/osquery.sh", Result{true, true}},  // the same test renders the GUI template
	{"web/src/features/inventory/scripts/osquery.ps1", Result{true, true}}, // the same
	{"web/src/locales/en/core.json", Result{true, true}},                   // modules/core/auditlabels_test.go: every audit action has a label
	{"web/src/locales/en/common.json", Result{true, true}},                 // modules/manifests_test.go: every module has a display name (W1-25)
	{"THIRD_PARTY_NOTICES.md", Result{Go: true}},                           // make notices-check (verify-go-static) holds it to go list and web/package.json (D-159)
	{"web/package.json", Result{true, true}},                               // the same check reads the web production dependencies

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
	{"PRIVACY.md", Result{Web: true}}, // web/src/features/core/privacyFlows.test.ts holds the Privacy page to its flow table (#472)
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

// Outputs are the job switches CI reads: Go is go-static, go-lint and go-release, Tests is go-test. WebAll is false only
// for a pull request whose web-side paths all lie under web/: then web-verify runs only the tests vitest --changed reaches.
type Outputs struct{ Go, Tests, Web, WebAll, Vuln, Audit bool }

// Decide maps the event and the changed paths to job switches. diffOK is false when the diff could not be
// computed; then everything runs. A pull request is narrowed by its paths, and go-test and web-verify run only the packages
// and tests the change reaches (D-413; Affected, WebAll). A push to main runs the full suite, Go and web (D-413: there is
// no merge queue, so the push run is the first full run of the merged tree), without the vulnerability scans the pull
// request ran; it also saves main's Go caches (go-test's, go-static's, golangci-lint's), the only caches pull requests can
// restore (D-365, D-372). The daily schedule runs everything, uncached and shuffled (ci.yml passes -count=2 -shuffle=on and
// -race), plus both vulnerability scans. workflow_dispatch and any unknown event run everything.
func Decide(event string, changed []string, diffOK bool) Outputs {
	switch {
	case event == "schedule":
		return Outputs{Go: true, Tests: true, Web: true, WebAll: true, Vuln: true, Audit: true}
	case event == "push":
		return Outputs{Go: true, Tests: true, Web: true, WebAll: true}
	case event == "pull_request" && diffOK:
		c := ClassifyAll(changed)
		webAll := len(changed) == 0
		for _, p := range changed {
			webAll = webAll || (Classify(p).Web && !strings.HasPrefix(strings.TrimPrefix(p, "./"), "web/"))
		}
		return Outputs{Go: c.Go, Tests: c.Go, Web: c.Web, WebAll: c.Web && webAll, Vuln: c.Go}
	default:
		return Outputs{Go: true, Tests: true, Web: true, WebAll: true, Vuln: true}
	}
}

// Affected says which Go packages a pull request's go-test runs (D-413): every package holding a changed file the Go side
// reads, and every package that imports one of those directly (tests included). dirs maps a package directory (repo
// relative, slash separated) to its import path; imports maps an import path to what it and its tests import. A non-Go file
// belongs to the nearest package directory above it (testdata, migrations, embedded files). all is true when a changed path
// the Go side reads lies in no package directory (go.mod, the Makefile, scripts, docs or web files a test reads, a deleted
// or new package): then every package runs. ponytail: a test that reads another package's files runs on main's full push
// run after the merge, not on the pull request; upgrade path: feed guard_test.go's goReads into this function.
func Affected(changed []string, dirs map[string]string, imports map[string][]string) (pkgs map[string]bool, all bool) {
	changedPkgs := map[string]bool{}
	for _, p := range changed {
		p = strings.TrimPrefix(p, "./")
		if !Classify(p).Go {
			continue
		}
		ip, found := "", false
		for d := path.Dir(p); d != "." && d != "/" && !found; d = path.Dir(d) {
			ip, found = dirs[d]
			if strings.HasSuffix(p, ".go") {
				break // a .go file belongs to its own directory only
			}
		}
		if !found {
			return nil, true
		}
		changedPkgs[ip] = true
	}
	pkgs = maps.Clone(changedPkgs)
	for ip, imps := range imports {
		if slices.ContainsFunc(imps, func(imp string) bool { return changedPkgs[imp] }) {
			pkgs[ip] = true
		}
	}
	return pkgs, false
}
