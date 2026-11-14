package worker_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// D-520: a nuclei job of scope own_ip (exposure's safe checks on the box's own public IP, D-561) runs only after the worker saw by
// itself that the box leaves the Internet through the address (the own-IP fence of the external nmap shape, D-514). Nothing reaches
// a network: the nuclei is a shell script and the public-IP services are a fake.

func (r *nrig) ownIPJob(id string) sensorlink.Job {
	j := r.job(id)
	j.Nuclei.Targets = []sensorlink.NucleiTarget{{Host: "8.8.8.8", Port: 18443, Scheme: "http"}}
	j.Nuclei.Rate, j.Nuclei.Scope = nucleiargv.OwnIPRate, nucleiargv.ScopeOwnIP
	return j
}

func TestOwnIPNucleiRunsOnlyOnTheBoxsOwnIP(t *testing.T) {
	t.Parallel()
	eg := &fakeEgress{answers: []string{"8.8.8.8"}}
	r := startNuclei(t, printJSONL, func(c *worker.Config) { c.Egress = eg })
	r.core.push(r.ownIPJob(id1))
	if got := r.core.next(t); got.res.Status != "done" || eg.count() != 1 {
		t.Fatalf("result = %+v after %d rounds", got.res, eg.count())
	}
	args := strings.Split(strings.TrimSpace(r.nu.Argv()), "\n")
	if err := nucleiargv.Validate(args); err != nil || args[len(args)-1] != "http://8.8.8.8:18443" || !slices.Contains(args, strings.Join(nucleiargv.OwnIPForbiddenTags(), ",")) {
		t.Fatalf("argv %q: %v", args, err)
	}
}

// Not the box's own address, or no way to tell: refused with the reason, and nuclei never starts.
func TestOwnIPNucleiRefusedWhenTheEgressIsNotOwn(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		eg   *fakeEgress
		want string
	}{
		"another address": {&fakeEgress{answers: []string{"1.1.1.1"}}, "not_own_ip"},
		"no answer":       {&fakeEgress{answers: []string{""}}, "egress_unverified"},
		"no fence":        {nil, "egress_unverified"},
	} {
		eg := c.eg
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := startNuclei(t, printJSONL, func(c *worker.Config) {
				if eg != nil {
					c.Egress = eg
				}
			})
			r.core.push(r.ownIPJob(id1))
			if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != c.want || got.res.ExitCode != -1 {
				t.Fatalf("result = %+v", got.res)
			}
			if r.nu.Argv() != "" {
				t.Fatalf("nuclei ran: %s", r.nu.Argv())
			}
		})
	}
}

// The grammar of the scope, checked again in the worker before the fence is asked: a private target, two targets, another rate, an
// unknown scope, a public target without the scope, a template the image's index does not mark own_ip, and a template file that
// fails the worker's own text check (a POST, a credential) are invalid_job (D-520).
func TestOwnIPNucleiGrammar(t *testing.T) {
	t.Parallel()
	for name, mut := range map[string]func(*testing.T, *nrig, *sensorlink.NucleiJob){
		"private target": func(_ *testing.T, _ *nrig, n *sensorlink.NucleiJob) { n.Targets[0].Host = "192.168.10.20" },
		"two targets": func(_ *testing.T, _ *nrig, n *sensorlink.NucleiJob) {
			n.Targets = append(n.Targets, sensorlink.NucleiTarget{Host: "8.8.8.8", Port: 80})
		},
		"rate 20":       func(_ *testing.T, _ *nrig, n *sensorlink.NucleiJob) { n.Rate = 20 },
		"unknown scope": func(_ *testing.T, _ *nrig, n *sensorlink.NucleiJob) { n.Scope = "internet" },
		"public in lan": func(_ *testing.T, _ *nrig, n *sensorlink.NucleiJob) { n.Scope = "" },
		"not own_ip in the index": func(t *testing.T, r *nrig, _ *sensorlink.NucleiJob) {
			editIndex(t, r.pack.Index, "CVE-2024-2", func(m map[string]any) { delete(m, "own_ip") })
		},
		"a POST in the file": func(t *testing.T, r *nrig, _ *sensorlink.NucleiJob) {
			rewrite(t, r.pack.Index, r.pack.File("CVE-2024-2"), "CVE-2024-2", "id: CVE-2024-2\nhttp:\n  - raw:\n      - |\n        POST /x HTTP/1.1\n        Host: {{Hostname}}\n")
		},
		"a credential in the file": func(t *testing.T, r *nrig, _ *sensorlink.NucleiJob) {
			rewrite(t, r.pack.Index, r.pack.File("CVE-2024-2"), "CVE-2024-2", "id: CVE-2024-2\nhttp:\n  - path:\n      - \"{{BaseURL}}/login?user=admin&password=admin\"\n")
		},
		"not in the index": func(_ *testing.T, _ *nrig, n *sensorlink.NucleiJob) { n.Templates = []string{"CVE-2099-1"} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			eg := &fakeEgress{answers: []string{"8.8.8.8"}}
			r := startNuclei(t, printJSONL, func(c *worker.Config) { c.Egress = eg })
			j := r.ownIPJob(id1)
			mut(t, r, j.Nuclei)
			r.core.push(j)
			if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "invalid_job" || r.nu.Argv() != "" || eg.count() != 0 {
				t.Fatalf("result = %+v, rounds %d, argv %q", got.res, eg.count(), r.nu.Argv())
			}
		})
	}
}

// rewrite replaces the file of template id with body and its hash in the index, so only the own_ip text check can refuse it.
func rewrite(t *testing.T, index, file, id, body string) {
	t.Helper()
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	editIndex(t, index, id, func(m map[string]any) { m["sha256"] = hex.EncodeToString(sum[:]) })
}

// editIndex changes the entry of template id in the index file.
func editIndex(t *testing.T, index, id string, edit func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(index) //nolint:gosec // a test's temp file
	if err != nil {
		t.Fatal(err)
	}
	var ix map[string]any
	if err := json.Unmarshal(raw, &ix); err != nil {
		t.Fatal(err)
	}
	for _, x := range ix["templates"].([]any) {
		if m := x.(map[string]any); m["id"] == id {
			edit(m)
		}
	}
	if raw, err = json.Marshal(ix); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
