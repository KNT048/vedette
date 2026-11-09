package core_test

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// API_CONVENTIONS rule 3.2.4: a new error code goes into the §3.3 catalogue in the same commit. The connection
// endpoints (D-93, D-94) return codes of their own, and the shared rows must name the endpoints that return them.
func TestConnections_ErrorCodesAreCatalogued(t *testing.T) {
	raw, err := os.ReadFile("../../docs/API_CONVENTIONS.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, code := range []string{"kind_unsupported", "pin_mismatch", "username_required", "connection_off", "invalid_tool_access"} {
		if !strings.Contains(doc, "| `"+code+"` |") {
			t.Errorf("%s is returned by /core/connections (web/src/features/core/connectionsMock.ts) but is not in API_CONVENTIONS §3.3", code)
		}
	}
	if strings.Contains(doc, "| `invalid_username` |") {
		t.Error("invalid_username was replaced by invalid on the field username (D-73); it must not be catalogued")
	}
	want := map[string]string{
		"in_use":              "DELETE /core/connections/{id}",
		"unreachable":         "POST /core/connections/{id}/test",
		"invalid_target":      "POST /core/connections",
		"invalid_allow":       "POST /core/connections",
		"secret_required":     "POST /core/connections",
		"connection_off":      "POST /core/connections/{id}/test",
		"kind_unsupported":    "POST /core/connections",
		"invalid_tool_access": "PUT /core/connections/{id}",
	}
	for _, line := range strings.Split(doc, "\n") {
		for code, ep := range want {
			if strings.HasPrefix(line, "| `"+code+"` |") && !strings.Contains(line, ep) {
				t.Errorf("the %s row does not name %s: %s", code, ep, line)
			}
		}
	}
	// The per-status headers count their rows (a recount is part of adding a code).
	counts := map[string]int{}
	header := ""
	for _, line := range strings.Split(doc, "\n") {
		switch {
		case strings.HasPrefix(line, "#### HTTP "):
			header = strings.Fields(line)[2]
			if !strings.Contains(line, "(") {
				t.Fatalf("header without a count: %s", line)
			}
		case strings.HasPrefix(line, "#"):
			header = ""
		case header != "" && strings.HasPrefix(line, "| `"):
			counts[header]++
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "#### HTTP ") {
			f := strings.Fields(line)
			n := strings.Trim(f[3], "(")
			if n != strconv.Itoa(counts[f[2]]) {
				t.Errorf("%s says %s codes, the table has %d", line, n, counts[f[2]])
			}
		}
	}
}
