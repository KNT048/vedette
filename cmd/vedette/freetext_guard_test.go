package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// freeTextRead is code that decides something from free text a person or the code wrote for people: a note, an evidence sentence,
// an event's detail. In Go, a string test (HasPrefix, HasSuffix, Contains, EqualFold, Index) on a .Note, .Evidence or .Detail field,
// or a comparison of one with a literal; in SQL, a LIKE, GLOB or equality on a note, evidence or detail column.
var freeTextRead = regexp.MustCompile(`(?:HasPrefix|HasSuffix|Contains|EqualFold|Index)\(\s*(?:strings\.ToLower\()?[\w.]*\.(?:Note|Evidence|Detail)\b|` +
	`\.(?:Note|Evidence|Detail)\s*(?:==|!=)\s*"[^"]|` +
	`\b(?:note|evidence|detail)\s+(?:NOT\s+)?(?:LIKE|GLOB)\s|\b(?:note|evidence|detail)\s*(?:=|<>|!=)\s*'[^']`)

// Guard: no code decides from the text of a note, an evidence sentence or an event's detail. What a decision needs is a column or a
// field of its own (a state, a resolution, a via, a software line), so a reworded sentence never changes what the box does. The uses
// named here are the ones left, each with its reason; any other fails, and an allowance whose use is gone fails too.
func TestGuard_NoDecisionReadsFreeText(t *testing.T) {
	t.Parallel()
	allowed := map[string]string{
		// The response module (not shown in this release) tells a person's rejection from a cancellation by the note the server writes
		// ("Rejected by <name>"); it moves to a column of its own with the module.
		"modules/response/ai.go": "byPersonSQL",
	}
	root := filepath.Join("..", "..")
	used := map[string]bool{}
	for _, dir := range []string{"cmd", "core", "modules", "host", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, err := os.ReadFile(p) //nolint:gosec // a source file of this repository found by the walk
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			for i, l := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(strings.TrimSpace(l), "//") || !freeTextRead.MatchString(l) {
					continue
				}
				if name, ok := allowed[rel]; ok && strings.Contains(l, name) {
					used[rel] = true
					continue
				}
				t.Errorf("%s:%d decides from free text: %s", rel, i+1, strings.TrimSpace(l))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for rel := range allowed {
		if !used[rel] {
			t.Errorf("%s no longer reads free text: remove it from the allow-list", rel)
		}
	}
}
