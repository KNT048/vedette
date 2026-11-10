package sensoractive

import (
	"slices"
	"strconv"
	"testing"
	"unicode"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/scan/nucleiout"
)

// FuzzNucleiResultPath feeds arbitrary worker output through everything core does with a nuclei result: the result's own checks
// and the fail-closed parser. The property: no panic, and whatever comes out names only templates and targets the job asked
// for, with evidence that is plain text.
func FuzzNucleiResultPath(f *testing.F) {
	f.Add([]byte(`{"template-id":"CVE-2024-1","host":"192.168.10.20:8080","matcher-status":true,"request":"GET /","response":"ok"}` + "\n"))
	f.Add([]byte(`{"template-id":"CVE-2024-2","host":"http://192.168.10.20:8080","matcher-status":false,"error":"timeout"}` + "\n" + "garbage\n"))
	f.Add([]byte(`{"template-id":"CVE-2024-1","host":"192.168.10.20","port":"8080","matcher-status":true}`))
	f.Add([]byte("{\"template-id\":\"CVE-2024-1\",\"host\":\"10.0.0.7:22\",\"matcher-status\":true,\"response\":\"\\u202e\\u0000\"}\n"))
	templates := []string{"CVE-2024-1", "CVE-2024-2"}
	targets := []string{"192.168.10.20:8080", "10.0.0.7:22"}
	d := NewDispatcher(DispatcherOptions{})
	f.Fuzz(func(t *testing.T, out []byte) {
		res := &sensorlink.JobResult{Status: "done"}
		res.SetJSONL(out)
		j := &djob{spec: sensorlink.Job{ID: "x"}, res: res}
		b, err := d.nucleiOutcome(j)
		if err != nil {
			t.Fatalf("a done result with exit 0 failed: %v", err)
		}
		results, err := nucleiout.Parse(b, templates, targets)
		if err != nil {
			return
		}
		for _, r := range results {
			if !slices.Contains(templates, r.Template) || !slices.Contains(targets, r.Target) {
				t.Fatalf("a result outside the job: %+v", r)
			}
			for _, s := range []string{r.Request, r.Response, r.Error} {
				for _, c := range s {
					if c != '\n' && c != '\t' && (unicode.IsControl(c) || unicode.Is(unicode.Cf, c)) {
						t.Fatalf("evidence holds a control or format character %s", strconv.QuoteRune(c))
					}
				}
			}
		}
	})
}
