package worker_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// FULL-4 (D-527): a nuclei job of depth full (testing terms accepted) runs behind the same own-IP fence as own_ip, with templates
// of the sets its depth allows in the image's own index, and says so in the heartbeat. Nothing reaches a network.

func (r *nrig) fullJob(disruptive bool) sensorlink.Job {
	j := r.ownIPJob(id1)
	j.Nuclei.Rate, j.Nuclei.Depth, j.Nuclei.Disruptive = nucleiargv.FullRate, nucleiargv.DepthFull, disruptive
	return j
}

func TestFullNucleiRunsTheDeepSetBehindTheFence(t *testing.T) {
	t.Parallel()
	eg := &fakeEgress{answers: []string{"8.8.8.8"}}
	r := startNuclei(t, printJSONL, func(c *worker.Config) { c.Egress = eg })
	editIndex(t, r.pack.Index, "CVE-2024-2", func(m map[string]any) { m["sets"] = []string{"deep"}; delete(m, "own_ip"); delete(m, "cve") })
	r.core.push(r.fullJob(false))
	if got := r.core.next(t); got.res.Status != "done" || eg.count() != 1 {
		t.Fatalf("result = %+v after %d rounds", got.res, eg.count())
	}
	args := strings.Split(strings.TrimSpace(r.nu.Argv()), "\n")
	if err := nucleiargv.Validate(args); err != nil || !slices.Contains(args, strings.Join(nucleiargv.FullForbiddenTags(false), ",")) || !slices.Contains(args, "-or") {
		t.Fatalf("argv %q: %v", args, err)
	}
}

// A disruptive template in a job without the tick, a KEV-only template (a write method the full rule left out) in a full job, a
// deep template in an own_ip job of D-520, a write in the file of a full job, and a full job outside own_ip are invalid_job;
// nuclei never starts and the fence is never asked.
func TestFullNucleiRefusesWhatItsDepthDoesNotAllow(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		mut func(*testing.T, *nrig)
		job func(*nrig) sensorlink.Job
	}{
		"a disruptive template without the tick": {
			func(t *testing.T, r *nrig) {
				editIndex(t, r.pack.Index, "CVE-2024-2", func(m map[string]any) { m["sets"] = []string{"kev", "disruptive"} })
			},
			func(r *nrig) sensorlink.Job { return r.fullJob(false) },
		},
		"a KEV-only template at full depth": {
			func(t *testing.T, r *nrig) {
				editIndex(t, r.pack.Index, "CVE-2024-2", func(m map[string]any) { m["sets"] = []string{"kev"} })
			},
			func(r *nrig) sensorlink.Job { return r.fullJob(true) },
		},
		"a deep-only template in an own_ip job": {
			func(t *testing.T, r *nrig) {
				editIndex(t, r.pack.Index, "CVE-2024-2", func(m map[string]any) { m["sets"] = []string{"deep"}; delete(m, "own_ip") })
			},
			func(r *nrig) sensorlink.Job { return r.ownIPJob(id1) },
		},
		"a PUT in the file": {
			func(t *testing.T, r *nrig) {
				rewrite(t, r.pack.Index, r.pack.File("CVE-2024-2"), "CVE-2024-2", "id: CVE-2024-2\nhttp:\n  - raw:\n      - |\n        PUT /x HTTP/1.1\n        Host: {{Hostname}}\n")
			},
			func(r *nrig) sensorlink.Job { return r.fullJob(true) },
		},
		"a full job on the LAN": {
			func(*testing.T, *nrig) {},
			func(r *nrig) sensorlink.Job {
				j := r.job(id1)
				j.Nuclei.Rate, j.Nuclei.Depth = nucleiargv.FullRate, nucleiargv.DepthFull
				return j
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			eg := &fakeEgress{answers: []string{"8.8.8.8"}}
			r := startNuclei(t, printJSONL, func(c *worker.Config) { c.Egress = eg })
			c.mut(t, r)
			r.core.push(c.job(r))
			if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "invalid_job" || r.nu.Argv() != "" || eg.count() != 0 {
				t.Fatalf("result = %+v, rounds %d, argv %q", got.res, eg.count(), r.nu.Argv())
			}
		})
	}
}
