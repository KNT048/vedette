package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Guard: the readers that talk about a finding (the assistant, the MCP tools, the response triggers, the mitigation module) read the view
// of the finding (findings.View) and the brief of its CVE (feeds.Brief), never the older read model or the older fix readers. This lists,
// per file, the older names that may still appear, and why; any other use fails. A name leaves the list when its file moves to the view.
func TestGuard_FindingReadersReadTheViewNotTheOlderModel(t *testing.T) {
	t.Parallel()
	older := []string{"findings.Row", "findings.Record", "findings.FixedIn", "findings.KevInfo", "FixedInFor", "RowFixes", "LegacyStatus", "ShownConfidence",
		"findings.UpdateAction", ".ToFix(", "findings.RowFix", "findings.Guide",
		// the older one-finding and list reads of the service
		"fnd.Get(", "fnd.List(", "finding.Get(", "finding.List(", "findings.Get(", "findings.List(", "Findings.Get(", "Findings.List("}
	// the allowed uses: Provider.Guidance is called by the finding page's older read (GET /findings/{id}) with the older row, and the
	// action handlers read the record that read hands them; both move with the finding page.
	allowed := map[string][]string{
		"modules/mitigation/guidance.go":  {"findings.Row", "findings.Guide"},
		"modules/mitigation/hardening.go": {"findings.Row"},
		"modules/mitigation/handlers.go":  {"findings.Record", "finding.Get("},
	}
	root := filepath.Join("..", "..")
	checked := []string{"cmd/vedette/ai.go", "cmd/vedette/ai_plan.go", "cmd/vedette/mcpserver.go", "cmd/vedette/response.go", "cmd/vedette/findingcase.go"}
	for _, dir := range []string{"modules/ai", "modules/mitigation", "modules/mcp-server"} {
		m, _ := filepath.Glob(filepath.Join(root, dir, "*.go"))
		for _, f := range m {
			if !strings.HasSuffix(f, "_test.go") {
				rel, _ := filepath.Rel(root, f)
				checked = append(checked, rel)
			}
		}
	}
	for _, rel := range checked {
		b, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // paths listed in this test
		if err != nil {
			t.Fatal(err)
		}
		var code []string
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "//") {
				code = append(code, l)
			}
		}
		text := strings.Join(code, "\n")
		for _, name := range older {
			if strings.Contains(text, name) && !slices.Contains(allowed[rel], name) {
				t.Errorf("%s reads %s: read findings.View and feeds.Brief (findingCase), or name the use in this guard with its reason", rel, name)
			}
		}
	}
	for rel, names := range allowed { // an allowance nobody uses any more is removed
		b, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // paths listed in this test
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			if !strings.Contains(string(b), n) {
				t.Errorf("%s no longer uses %s: remove it from the allow-list", rel, n)
			}
		}
	}
}
