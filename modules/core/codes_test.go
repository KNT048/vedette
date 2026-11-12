package core_test

import (
	"bytes"
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
	for _, dir := range []string{"../../core/auth", ".", "../../core/server", "../../core/apierr", "../../core/conn"} {
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
		// A line that starts with "| `code` |" (what the multi-line regexp ^\| `code` \| matched, without a scan of the whole
		// document by a regexp for each code: seconds under -race).
		if row := []byte("| `" + code + "` |"); !bytes.HasPrefix(doc, row) && !bytes.Contains(doc, append([]byte("\n"), row...)) {
			t.Errorf("code %q (%s) is not in API_CONVENTIONS 3.3", code, file)
		}
	}
	for _, code := range []string{"address_refused", "device_error", "connection_changed", "pin_mismatch", "unreachable"} {
		if f, ok := found[code]; !ok || !strings.Contains(f, "core/conn") {
			t.Errorf("the scan did not find %q in core/conn: it must read that package too", code)
		}
	}
	// The codes of Test are answered by POST /core/connections/{id}/test: every row names it (a row that names only the response
	// endpoints for connection_changed hides that a Test returns it).
	for _, code := range []string{"address_refused", "device_error", "connection_changed", "pin_mismatch", "unreachable", "connection_off"} {
		row := regexp.MustCompile("(?m)^\\| `" + code + "` \\|.*$").FindString(string(doc))
		if !strings.Contains(row, "POST /core/connections/{id}/test") {
			t.Errorf("the row of %s does not name POST /core/connections/{id}/test, which returns it: %q", code, row)
		}
	}
	for _, code := range []string{"invalid_setup_code", "sample_unavailable", "invalid_from", "invalid_to", "misdirected_request", "current_session", "invalid_timezone"} {
		if _, ok := found[code]; !ok {
			t.Errorf("the scan did not find %q: it looks for Code constants and apierr.New calls", code)
		}
	}
}
