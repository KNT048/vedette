package worker_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// A typed public IP job runs only after the worker's own fence found the IP's proof now; the worker takes no word of core's for it.

type proofFiles struct {
	mu sync.Mutex
	m  map[string]string
}

func (f *proofFiles) Fetch(_ context.Context, rawURL string, _ netip.Addr) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.m[rawURL]; ok {
		return []byte(v), nil
	}
	return nil, errors.New("answered 404")
}

func withTypedFence(t *testing.T, files *proofFiles) func(*worker.Config) {
	t.Helper()
	f, err := domainfence.New(fenceKey, newZone(), func(d string) bool { return d == domainAddr }, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.SetFetcher(files)
	return func(c *worker.Config) { c.Fence = f }
}

func typedNmapJob(key []byte) sensorlink.Job {
	tok := domainfence.Token(key, domainAddr)
	return sensorlink.Job{ID: id1, Kind: sensorlink.KindNmap, Shape: nmapargv.ExternalFull.Name(), Rate: nmapargv.FullRate, Targets: []string{domainAddr}, TimeoutS: 60,
		Scope: sensorlink.ScopeDomainIP, Domain: &sensorlink.DomainScope{Domain: domainAddr, Name: domainAddr, Token: tok, Typed: &sensorlink.TypedScope{Method: domainfence.MethodFile}}}
}

func TestTypedIPNmapJobRunsOnlyWithItsProof(t *testing.T) {
	t.Parallel()
	good := domainfence.Token(fenceKey, domainAddr)
	forged := domainfence.Token(otherKey, domainAddr)
	url := "http://" + domainAddr + domainfence.ProofPath
	for name, c := range map[string]struct {
		files map[string]string
		job   sensorlink.Job
		want  string // "" = the job runs
	}{
		"a proved IP":               {map[string]string{url: good}, typedNmapJob(fenceKey), ""},
		"a forged proof in the job": {map[string]string{url: forged}, typedNmapJob(otherKey), domainfence.TokenForeign},
		"the file is gone":          {map[string]string{}, typedNmapJob(fenceKey), domainfence.NotOwned},
		"a proof for another IP":    {map[string]string{"http://8.8.8.8" + domainfence.ProofPath: good}, typedNmapJob(fenceKey), domainfence.NotOwned},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			nm := writeNmapVersion(t, nmapargv.ReviewedNmapVersion, printXML)
			r := start(t, nm, withTypedFence(t, &proofFiles{m: c.files}))
			r.core.push(c.job)
			got := r.core.next(t)
			if c.want == "" {
				if got.res.Status != "done" {
					t.Fatalf("result = %+v", got.res)
				}
				return
			}
			if got.res.Status != "refused" || got.res.Reason != c.want || nm.argvLog() != "" {
				t.Fatalf("result = %+v, argv %q", got.res, nm.argvLog())
			}
		})
	}
}

func TestAWorkerWithAFenceSaysItChecksTypedIPs(t *testing.T) {
	t.Parallel()
	nm := writeNmapVersion(t, nmapargv.ReviewedNmapVersion, printXML)
	r := start(t, nm, withTypedFence(t, &proofFiles{m: map[string]string{}}))
	select {
	case hb := <-r.core.beats:
		if !hb.DomainIP || !hb.TypedIP {
			t.Fatalf("heartbeat %+v", hb)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no heartbeat")
	}
}
