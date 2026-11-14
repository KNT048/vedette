package worker_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// fakeEgress answers the rounds of the own-IP fence from a list (the last answer repeats); no test asks a real service.
type fakeEgress struct {
	mu      sync.Mutex
	answers []string // an address, or "" for a round without agreement
	rounds  int
}

func (f *fakeEgress) Round(context.Context) (netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.answers[min(f.rounds, len(f.answers)-1)]
	f.rounds++
	if a == "" {
		return netip.Addr{}, errors.New("no agreement")
	}
	return netip.MustParseAddr(a), nil
}

func (f *fakeEgress) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rounds
}

func externalJob(id, target string) sensorlink.Job {
	return sensorlink.Job{ID: id, Kind: sensorlink.KindNmap, Shape: "external", Rate: nmapargv.ExternalRate, Targets: []string{target}, TimeoutS: 60}
}

// D-514: the worker runs the external shape only after it saw by itself that the box leaves the Internet through the address. A
// load-balanced uplink may show another address first: the fence asks again, up to EgressRounds rounds, and stops at the first yes;
// a yes stands for EgressFresh, so the next job of the same address asks nobody.
func TestExternalJobRunsOnlyOnTheBoxsOwnIP(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, printXML)
	eg := &fakeEgress{answers: []string{"", "1.1.1.1", "8.8.8.8"}}
	r := start(t, nm, func(c *worker.Config) { c.Egress = eg })
	r.core.push(externalJob(id1, "8.8.8.8"))
	if got := r.core.next(t); got.res.Status != "done" {
		t.Fatalf("result = %+v", got.res)
	}
	if n := eg.count(); n != 3 {
		t.Fatalf("%d rounds, want 3 (stop at the first that names the address)", n)
	}
	want := strings.Join(append([]string{"--privileged", "-sS", "-sV", "-Pn", "-n", "--max-rate", "100", "--max-retries", "2", "--host-timeout", "3m", "-p", nmapargv.ExternalPorts, "-oX", "-", "8.8.8.8"}, ""), "\n")
	if nm.argvLog() != want {
		t.Fatalf("argv:\n%s\nwant:\n%s", nm.argvLog(), want)
	}
	waitFor(t, "running to clear", func() bool { return r.core.runningNow() == "" })
	r.core.push(externalJob(id2, "8.8.8.8"))
	if got := r.core.next(t); got.res.Status != "done" || eg.count() != 3 {
		t.Fatalf("second job: %+v after %d rounds", got.res, eg.count())
	}
	waitFor(t, "running to clear", func() bool { return r.core.runningNow() == "" })
	r.clock.Advance(worker.EgressFresh) // the yes is stale: the next job asks again (the last answer, 8.8.8.8, repeats)
	r.core.push(externalJob("00000000000000000000000000000003", "8.8.8.8"))
	if got := r.core.next(t); got.res.Status != "done" || eg.count() != 4 {
		t.Fatalf("third job: %+v after %d rounds", got.res, eg.count())
	}
}

// Not the box's own address in any of the rounds: refused not_own_ip. No round answered at all (services unreachable, TLS, no
// agreement) or no fence configured: refused egress_unverified (#723 review M1). Either way nmap never starts.
func TestExternalJobRefusedWhenTheAddressIsNotTheBoxs(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		eg   *fakeEgress
		want string
	}{
		"another address":             {&fakeEgress{answers: []string{"1.1.1.1"}}, "not_own_ip"},
		"no answer, then another one": {&fakeEgress{answers: []string{"", "1.1.1.1", ""}}, "not_own_ip"},
		"no answer":                   {&fakeEgress{answers: []string{""}}, "egress_unverified"},
		"no fence":                    {nil, "egress_unverified"},
	} {
		eg := c.eg
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			nm := writeNmap(t, printXML)
			r := start(t, nm, func(c *worker.Config) {
				if eg != nil {
					c.Egress = eg
				}
			})
			r.core.push(externalJob(id1, "8.8.8.8"))
			got := r.core.next(t)
			if got.res.Status != "refused" || got.res.Reason != c.want || got.res.ExitCode != -1 {
				t.Fatalf("result = %+v", got.res)
			}
			if nm.argvLog() != "" {
				t.Fatalf("nmap ran: %s", nm.argvLog())
			}
			if eg != nil && eg.count() != worker.EgressRounds {
				t.Fatalf("%d rounds, want %d", eg.count(), worker.EgressRounds)
			}
		})
	}
}

// D-526: the two full shapes run behind the same own-IP fence as the external one, with the argv nmapargv builds; another address
// is refused before nmap, and a full job at another rate or on a LAN address is invalid_job before the fence is asked.
func TestFullJobsRunOnlyOnTheBoxsOwnIP(t *testing.T) {
	t.Parallel()
	for _, kind := range []nmapargv.Kind{nmapargv.ExternalFull, nmapargv.ExternalDisruptive} {
		job := func(target string, rate int) sensorlink.Job {
			return sensorlink.Job{ID: id1, Kind: sensorlink.KindNmap, Shape: kind.Name(), Rate: rate, Targets: []string{target}, TimeoutS: 60}
		}
		want, err := nmapargv.Build(kind, nmapargv.FullRate, []netip.Addr{netip.MustParseAddr("8.8.8.8")})
		if err != nil {
			t.Fatal(err)
		}
		for name, c := range map[string]struct {
			job    sensorlink.Job
			answer string
			status string
			reason string
			rounds int
		}{
			"the box's own IP":    {job("8.8.8.8", nmapargv.FullRate), "8.8.8.8", "done", "", 1},
			"another address":     {job("8.8.8.8", nmapargv.FullRate), "1.1.1.1", "refused", "not_own_ip", worker.EgressRounds},
			"another rate":        {job("8.8.8.8", nmapargv.ExternalRate), "8.8.8.8", "refused", "invalid_job", 0},
			"a LAN address":       {job("192.168.10.20", nmapargv.FullRate), "192.168.10.20", "refused", "invalid_job", 0},
			"two public adresses": {sensorlink.Job{ID: id1, Shape: kind.Name(), Rate: nmapargv.FullRate, Targets: []string{"8.8.8.8", "1.1.1.1"}, TimeoutS: 60}, "8.8.8.8", "refused", "invalid_job", 0},
		} {
			t.Run(kind.Name()+"/"+name, func(t *testing.T) {
				t.Parallel()
				nm := writeNmap(t, printXML)
				eg := &fakeEgress{answers: []string{c.answer}}
				r := start(t, nm, func(cfg *worker.Config) { cfg.Egress = eg })
				r.core.push(c.job)
				got := r.core.next(t)
				if got.res.Status != c.status || got.res.Reason != c.reason || eg.count() != c.rounds {
					t.Fatalf("result = %+v after %d rounds", got.res, eg.count())
				}
				ran := strings.Join(append(slices.Clone(want), ""), "\n")
				if c.status != "done" {
					ran = ""
				}
				if nm.argvLog() != ran {
					t.Fatalf("argv:\n%s\nwant:\n%s", nm.argvLog(), ran)
				}
			})
		}
	}
}

// The grammar of the external shape, checked again in the worker: one public address at the fixed rate; a private address, two
// addresses or another rate are invalid_job before the fence is even asked.
func TestExternalJobGrammar(t *testing.T) {
	t.Parallel()
	for name, j := range map[string]sensorlink.Job{
		"private target":    externalJob(id1, "192.168.10.20"),
		"cgnat target":      externalJob(id1, "100.64.0.1"),
		"two targets":       {ID: id1, Shape: "external", Rate: nmapargv.ExternalRate, Targets: []string{"8.8.8.8", "1.1.1.1"}, TimeoutS: 60},
		"another rate":      {ID: id1, Shape: "external", Rate: 1000, Targets: []string{"8.8.8.8"}, TimeoutS: 60},
		"public in normal":  {ID: id1, Shape: "normal", Rate: 100, Targets: []string{"8.8.8.8"}, TimeoutS: 60},
		"documentation net": externalJob(id1, "203.0.113.5"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			nm := writeNmap(t, printXML)
			eg := &fakeEgress{answers: []string{"8.8.8.8"}}
			r := start(t, nm, func(c *worker.Config) { c.Egress = eg })
			r.core.push(j)
			got := r.core.next(t)
			if got.res.Status != "refused" || got.res.Reason != "invalid_job" || nm.argvLog() != "" || eg.count() != 0 {
				t.Fatalf("result = %+v, rounds %d, argv %q", got.res, eg.count(), nm.argvLog())
			}
		})
	}
}
