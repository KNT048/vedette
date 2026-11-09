package core_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every error code the auth library and the core handlers can send is in API_CONVENTIONS 3.3 (3.2 rule 4:
// a new code goes into the table in the commit that adds it).
func TestEveryErrorCodeOfCoreIsCatalogued(t *testing.T) {
	t.Parallel()
	doc, err := os.ReadFile("../../docs/API_CONVENTIONS.md")
	if err != nil {
		t.Fatal(err)
	}
	constRE := regexp.MustCompile(`\bCode\w*\s*=\s*"([a-z][a-z0-9_]*)"`)
	newRE := regexp.MustCompile(`apierr\.New\(\s*(?:\d{3}|http\.\w+),\s*"([a-z][a-z0-9_]*)"`)
	found := map[string]string{}
	for _, dir := range []string{"../../core/auth", ".", "../../core/server", "../../core/apierr"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f) //nolint:gosec // source files of this repository
			if err != nil {
				t.Fatal(err)
			}
			for _, re := range []*regexp.Regexp{constRE, newRE} {
				for _, m := range re.FindAllStringSubmatch(string(src), -1) {
					found[m[1]] = f
				}
			}
		}
	}
	if len(found) < 40 {
		t.Fatalf("only %d codes found: the scan is broken", len(found))
	}
	for code, file := range found {
		if !regexp.MustCompile("(?m)^\\| `" + regexp.QuoteMeta(code) + "` \\|").Match(doc) {
			t.Errorf("code %q (%s) is not in API_CONVENTIONS 3.3", code, file)
		}
	}
	for _, code := range []string{"invalid_setup_code", "sample_unavailable", "invalid_from", "invalid_to", "misdirected_request", "current_session", "invalid_timezone"} {
		if _, ok := found[code]; !ok {
			t.Errorf("the scan did not find %q: it looks for Code constants and apierr.New calls", code)
		}
	}
}
