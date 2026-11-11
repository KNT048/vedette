package core_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every audit action the backend writes has a label in Settings -> Audit log, and every kind of action (the part before the
// first dot) has a filter label (D-180: the rows showed the raw code `user.password_reset`). The actions are read from the Go
// source; the labels from web/src/locales/en/core.json. It is a Go test so a pull request that only changes Go still runs it
// (scripts/ci/classify.go runs both jobs for a change to core.json).
//
// An action is a literal `area.name` on a line that gives it to the audit log: `Action: "..."`, a variable named action, or a
// call of step, refuse, audit, auditTx or record. Event names and secret purposes share the shape and are skipped.
// ponytail: literal scan; an action built at run time from a variable it cannot see is not covered. Upgrade path: one exported
// list of actions in Go that both the writers and this test read.
var (
	auditCall    = regexp.MustCompile(`\b(Action|action|auditAction)\b|\.(step|refuse|audit|auditTx|record)\(`)
	auditLiteral = regexp.MustCompile(`"([a-z][a-z0-9-]*(?:\.[a-z0-9_]+)+)"`)
	auditNoise   = regexp.MustCompile(`Event|[pP]urpose`)
	auditFile    = regexp.MustCompile(`\.(json|csv)$`) // a file name on the same line, not an action
)

func auditActionsInSource(t *testing.T) map[string]string {
	t.Helper()
	root := "../.."
	skip := map[string]bool{"node_modules": true, ".git": true, "web": true, "oas": true, "coredb": true, "routes": true, "testdata": true, "docs": true}
	found := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p) //nolint:gosec // source files of this repository
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(src), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "//") || !auditCall.MatchString(code) || auditNoise.MatchString(code) {
				continue
			}
			for _, m := range auditLiteral.FindAllStringSubmatch(code, -1) {
				if auditFile.MatchString(m[1]) {
					continue
				}
				found[m[1]] = strings.TrimPrefix(p, root+"/")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// hasLabel resolves key in a JSON object the way i18next does for these keys: a flat key "a.b" or nested objects, mixed.
func hasLabel(obj map[string]any, key string) bool {
	if s, ok := obj[key].(string); ok && s != "" {
		return true
	}
	for i, c := range key {
		if c != '.' {
			continue
		}
		if sub, ok := obj[key[:i]].(map[string]any); ok && hasLabel(sub, key[i+1:]) {
			return true
		}
	}
	return false
}

func TestEveryAuditActionHasALabel(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../web/src/locales/en/core.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	audit, _ := doc["audit"].(map[string]any)
	actions, _ := audit["action"].(map[string]any)
	groups, _ := audit["group"].(map[string]any)
	found := auditActionsInSource(t)
	for _, a := range []string{"auth.login", "user.password_reset", "user.disable", "account.password", "sensor-ca.create"} {
		if _, ok := found[a]; !ok {
			t.Errorf("the scan did not find %s: it is broken", a)
		}
	}
	if len(found) < 100 {
		t.Fatalf("only %d actions found: the scan is broken", len(found))
	}
	var missing []string
	kinds := map[string]string{}
	for a, f := range found {
		if !hasLabel(actions, a) {
			missing = append(missing, a+" ("+f+")")
		}
		kinds[strings.SplitN(a, ".", 2)[0]] = a
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("audit actions without a label in web/src/locales/en/core.json audit.action:\n%s", strings.Join(missing, "\n"))
	}
	for k, a := range kinds {
		if s, _ := groups[k].(string); s == "" {
			t.Errorf("kind %q (of %s) has no label in audit.group", k, a)
		}
	}
	if got, _ := actions["auth"].(map[string]any)["login_failed"].(string); got != "Failed sign-in" {
		t.Errorf("auth.login_failed is labelled %q: it is written for every failed sign-in, not only a wrong two-step code", got)
	}
}
