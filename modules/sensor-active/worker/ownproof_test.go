package worker_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/egressip"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// The ownership proof of the box's own public IP: core proves an address the box's own from one sighting of it as the box's egress,
// for 90 days from the latest sighting, also while the box goes out through another line (two Internet lines behind a router that
// balances them). A job for such an address carries the time of that sighting (proven_at); the worker accepts it when it holds
// (egressip.ProofHolds) and asks no public-IP service. Without a proof that holds, its own sighting decides, as before.

// testNow is the worker's clock in every rig (start): proofs are dated from it.
var testNow = time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)

func provenAt(d time.Duration) *time.Time {
	at := testNow.Add(-d)
	return &at
}

// The box goes out through 1.1.1.1 in every round; 8.8.8.8 was seen as its egress 30 days ago (its other line). The External
// shape, both full shapes and an own_ip nuclei job run on it, and no public-IP service is asked.
func TestAProvenIPRunsWhileTheBoxGoesOutThroughAnotherLine(t *testing.T) {
	t.Parallel()
	for _, kind := range []nmapargv.Kind{nmapargv.External, nmapargv.ExternalFull, nmapargv.ExternalDisruptive} {
		t.Run(kind.Name(), func(t *testing.T) {
			t.Parallel()
			nm := writeNmapVersion(t, nmapargv.ReviewedNmapVersion, printXML)
			eg := &fakeEgress{answers: []string{"1.1.1.1"}}
			r := start(t, nm, func(c *worker.Config) { c.Egress = eg })
			j := sensorlink.Job{ID: id1, Kind: sensorlink.KindNmap, Shape: kind.Name(), Rate: nmapargv.ExternalRateOf(kind), Targets: []string{"8.8.8.8"},
				TimeoutS: 60, ProvenAt: provenAt(30 * 24 * time.Hour)}
			if kind == nmapargv.ExternalDisruptive { // the deep scan's last step: the open ports of its full run
				j.Ports = []int{22, 443}
			}
			r.core.push(j)
			if got := r.core.next(t); got.res.Status != "done" || got.res.XMLB64 == "" || eg.count() != 0 {
				t.Fatalf("result = %+v after %d rounds", got.res, eg.count())
			}
			if !strings.HasSuffix(strings.TrimSpace(nm.argvLog()), "8.8.8.8") {
				t.Fatalf("argv: %s", nm.argvLog())
			}
		})
	}
	t.Run("nuclei own_ip", func(t *testing.T) {
		t.Parallel()
		eg := &fakeEgress{answers: []string{"1.1.1.1"}}
		r := startNuclei(t, printJSONL, func(c *worker.Config) { c.Egress = eg })
		j := r.ownIPJob()
		j.Nuclei.ProvenAt = provenAt(30 * 24 * time.Hour)
		r.core.push(j)
		if got := r.core.next(t); got.res.Status != "done" || eg.count() != 0 {
			t.Fatalf("result = %+v after %d rounds", got.res, eg.count())
		}
		if r.nu.Argv() == "" {
			t.Fatal("nuclei did not run")
		}
	})
}

// A proof that does not hold is no proof: older than 90 days, or dated after the worker's clock by more than the slack. The
// worker's own sighting then decides as for a job without one, so another address is refused not_own_ip after every round
// and no services at all egress_unverified: the reason codes are those of a job without a proof.
func TestAProofThatDoesNotHoldIsRefusedLikeNoProof(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		at      *time.Time
		answers []string
		want    string
	}{
		"older than 90 days":      {provenAt(egressip.ProofValid + time.Second), []string{"1.1.1.1"}, "not_own_ip"},
		"in the future":           {provenAt(-time.Hour), []string{"1.1.1.1"}, "not_own_ip"},
		"no proof":                {nil, []string{"1.1.1.1"}, "not_own_ip"},
		"expired, no service":     {provenAt(100 * 24 * time.Hour), []string{""}, "egress_unverified"},
		"expired, seen again now": {provenAt(100 * 24 * time.Hour), []string{"8.8.8.8"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			nm := writeNmap(t, printXML)
			eg := &fakeEgress{answers: c.answers}
			r := start(t, nm, func(cfg *worker.Config) { cfg.Egress = eg })
			j := externalJob(id1, "8.8.8.8")
			j.ProvenAt = c.at
			r.core.push(j)
			got := r.core.next(t)
			if c.want == "" {
				if got.res.Status != "done" || eg.count() != 1 {
					t.Fatalf("result = %+v after %d rounds", got.res, eg.count())
				}
				return
			}
			if got.res.Status != "refused" || got.res.Reason != c.want || eg.count() != worker.EgressRounds || nm.argvLog() != "" {
				t.Fatalf("result = %+v after %d rounds, argv %q", got.res, eg.count(), nm.argvLog())
			}
		})
	}
	t.Run("nuclei own_ip older than 90 days", func(t *testing.T) {
		t.Parallel()
		eg := &fakeEgress{answers: []string{"1.1.1.1"}}
		r := startNuclei(t, printJSONL, func(c *worker.Config) { c.Egress = eg })
		j := r.ownIPJob()
		j.Nuclei.ProvenAt = provenAt(91 * 24 * time.Hour)
		r.core.push(j)
		if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "not_own_ip" || r.nu.Argv() != "" {
			t.Fatalf("result = %+v, argv %q", got.res, r.nu.Argv())
		}
	})
}

// A proof changes nothing else of the grammar: a shared (CGNAT) address, a private one or two targets are invalid_job before
// anything is asked, and a proof on a job that is not of the box's own IP (a LAN shape, a domain_ip job, a LAN nuclei job) makes
// the job invalid too.
func TestAProofDoesNotWidenTheGrammar(t *testing.T) {
	t.Parallel()
	at := provenAt(24 * time.Hour)
	withProof := func(j sensorlink.Job) sensorlink.Job { j.ProvenAt = at; return j }
	for name, j := range map[string]sensorlink.Job{
		"cgnat target":     withProof(externalJob(id1, "100.64.0.1")),
		"private target":   withProof(externalJob(id1, "192.168.10.20")),
		"two targets":      withProof(sensorlink.Job{ID: id1, Shape: "external", Rate: nmapargv.ExternalRate, Targets: []string{"8.8.8.8", "1.1.1.1"}, TimeoutS: 60}),
		"a LAN shape":      withProof(sensorlink.Job{ID: id1, Shape: "normal", Rate: 100, Targets: []string{"192.168.10.20"}, TimeoutS: 60}),
		"a domain_ip job":  withProof(domainNmapJob(nmapargv.ExternalFull, fenceKey)),
		"documentation IP": withProof(externalJob(id1, "203.0.113.5")),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			nm := writeNmapVersion(t, nmapargv.ReviewedNmapVersion, printXML)
			eg := &fakeEgress{answers: []string{"8.8.8.8"}}
			r := start(t, nm, func(c *worker.Config) { c.Egress = eg }, withFence(t, newZone())) // a domain_ip job would pass its fence
			r.core.push(j)
			if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "invalid_job" || nm.argvLog() != "" || eg.count() != 0 {
				t.Fatalf("result = %+v, rounds %d, argv %q", got.res, eg.count(), nm.argvLog())
			}
		})
	}
	t.Run("a LAN nuclei job", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, printJSONL)
		j := r.job(id1)
		j.Nuclei.ProvenAt = at
		r.core.push(j)
		if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "invalid_job" || r.nu.Argv() != "" {
			t.Fatalf("result = %+v", got.res)
		}
	})
	t.Run("a cgnat own_ip nuclei job", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, printJSONL, func(c *worker.Config) { c.Egress = &fakeEgress{answers: []string{"100.64.0.1"}} })
		j := r.ownIPJob()
		j.Nuclei.Targets[0].Host, j.Nuclei.ProvenAt = "100.64.0.1", at
		r.core.push(j)
		if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "invalid_job" || r.nu.Argv() != "" {
			t.Fatalf("result = %+v", got.res)
		}
	})
}

// The re-check of a running full job keeps to the proof: while it holds, a tick that would see the other line does not stop nmap;
// once the proof runs out during the run, the next tick asks the services and stops the job (not_own_ip) when they name another
// address. The proof is one second from running out at the start, so the clock moves less than the worker's lease.
func TestAFullJobOnAProvenIPKeepsRunningWhileTheProofHolds(t *testing.T) {
	t.Parallel()
	waitGo := `while [ ! -f "$DIR/go" ]; do sleep 0.02; done
` + printXML
	nm := writeNmapVersion(t, nmapargv.ReviewedNmapVersion, waitGo)
	eg := &fakeEgress{answers: []string{"1.1.1.1"}}
	ticks := make(chan time.Time)
	r := start(t, nm, func(cfg *worker.Config) { cfg.Egress, cfg.EgressTicks = eg, ticks })
	r.core.push(sensorlink.Job{ID: id1, Kind: sensorlink.KindNmap, Shape: "external_full", Rate: nmapargv.FullRate, Targets: []string{"8.8.8.8"}, TimeoutS: 60,
		ProvenAt: provenAt(egressip.ProofValid - time.Second)})
	waitFor(t, "nmap to start", func() bool { return nm.argvLog() != "" })
	ticks <- time.Time{}
	ticks <- time.Time{} // the second send returns once the watcher has finished the first re-check
	if eg.count() != 0 {
		t.Fatalf("%d rounds while the proof holds", eg.count())
	}
	r.clock.Advance(2 * time.Second) // the proof runs out during the run (well inside the lease)
	ticks <- time.Time{}
	got := r.core.next(t)
	if got.res.Status != "stopped" || got.res.Reason != "not_own_ip" || got.res.XMLB64 != "" || eg.count() != worker.EgressRounds {
		t.Fatalf("result = %+v after %d rounds", got.res, eg.count())
	}
	if err := os.WriteFile(filepath.Join(nm.dir, "go"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The heartbeat says own_proof, so core sends the proof to this worker.
func TestHeartbeatSaysOwnProof(t *testing.T) {
	t.Parallel()
	r := start(t, writeNmap(t, printXML), func(c *worker.Config) { c.Egress = &fakeEgress{answers: []string{"8.8.8.8"}} })
	select {
	case hb := <-r.core.beats:
		if !hb.OwnProof {
			t.Fatalf("heartbeat = %+v", hb)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no heartbeat")
	}
}
