package main

import (
	"strings"
	"testing"
)

// The daily run's failed jobs' logs become one line per package with its failed tests; a timeout names the running test, a build
// failure names the package alone, and a run with nothing failed prints nothing (D-365).
func TestFailuresListsEachFailedTestByPackage(t *testing.T) {
	t.Parallel()
	log := strings.Join([]string{
		"2026-11-11T22:27:35.3195630Z --- FAIL: TestWazuh_ALongPassGoesOnAtTheNextTick (1.61s)",
		"2026-11-11T22:27:35.3276231Z     wazuh_test.go:675: after a pass cut by the budget",
		"2026-11-11T22:27:35.3294998Z FAIL",
		"2026-11-11T22:27:35.3375300Z FAIL\tgithub.com/knt048/vedette/modules/agent-intake\t59.572s",
		"2026-11-11T22:29:10.0935204Z ok  \tgithub.com/knt048/vedette/modules/core\t143.831s",
		"--- FAIL: TestA (0.1s)",
		"    --- FAIL: TestA/sub (0.0s)",
		"--- FAIL: TestA (0.1s)",
		"FAIL\tgithub.com/knt048/vedette/core/jobs\t2.0s",
		"panic: test timed out after 10m0s",
		"\trunning tests:",
		"\t\tTestContract_INV17_BlocklistEntryLimit (1s)",
		"",
		"goroutine 192052 [running]:",
		"FAIL\tgithub.com/knt048/vedette/modules/response\t600.136s",
		"FAIL\tgithub.com/knt048/vedette/cmd/vedette [build failed]",
	}, "\n") + "\n"
	var out strings.Builder
	if err := printFailures(strings.NewReader(log), &out, "https://github.com/KNT048/vedette/actions/runs/1"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"- `cmd/vedette`: (no test named",
		"- `core/jobs`: `TestA`\n",
		"- `modules/agent-intake`: `TestWazuh_ALongPassGoesOnAtTheNextTick`\n",
		"- `modules/response`: `TestContract_INV17_BlocklistEntryLimit (timed out)`\n",
		"actions/runs/1",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "modules/core`") {
		t.Errorf("a passing package is listed:\n%s", out.String())
	}
	out.Reset()
	if err := printFailures(strings.NewReader("ok  \tgithub.com/knt048/vedette/core/jobs\t2.0s\n"), &out, "u"); err != nil || out.Len() != 0 {
		t.Fatalf("nothing failed but printed %q (%v)", out.String(), err)
	}
}
