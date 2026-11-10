package scan

import (
	"slices"
	"testing"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

// D-133 (5), SP-3b: nuclei may write JSONL only for matches, so an empty output or a not-matched line means "no match
// reported", never "not vulnerable". It never resolves, downgrades or marks a finding, and an empty output is not
// "unresponsive".
func TestContract_INV8_NoMatchNeverTouchesTheFinding(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.reply = func(j nucleiargv.Job) (Output, error) {
		if j.Targets[0].Host == "192.168.10.12" {
			return Output{}, nil // WEB01: nothing printed at all
		}
		return lines()(j) // NAS: a not-matched line for its template
	}
	v := r.start("a-web01", "a-nas02")
	r.wait()
	got := r.run(v.ID)
	if got.Status != "done" || got.Done != 2 {
		t.Fatalf("an empty output stopped the run: %+v", got)
	}
	for _, id := range []string{"a-web01", "a-nas02"} {
		row := slices.IndexFunc(got.Results, func(x RunRow) bool { return x.TargetID == id && x.Template != nil })
		if row < 0 || got.Results[row].Result != "not_matched" || got.Results[row].Note[len(got.Results[row].Note)-len("no match reported by the scan template."):] != "no match reported by the scan template." {
			t.Fatalf("%s: %+v", id, got.Results)
		}
	}
	if len(r.findings.confirms) != 0 { // and the Findings port has no other call: nothing else can touch a finding
		t.Fatalf("a no-match touched findings: %v", r.findings.confirms)
	}
	if n := r.count(`SELECT count(*) FROM scan_probe WHERE result = 'not_matched'`); n != 2 {
		t.Fatalf("probe rows as not matched: %d", n)
	}
}
