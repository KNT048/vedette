package exposure

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"sync"
	"testing"
)

// treeFixture is testdata/tree_targets.json: the domain targets of one installation in the order they were added, and the names each
// of their scans found, in the order the scans ran.
type treeFixture struct {
	Targets []struct {
		Value string `json:"value"`
	} `json:"targets"`
	Scans []struct {
		Target string    `json:"target"`
		Hosts  []HostRow `json:"hosts"`
	} `json:"scans"`
}

// listRunner answers a domain scan with the names of hosts, as the surface scanner does: a name the scan's plan leaves to another
// target (or out of its scope) is listed without being probed, every other one comes with its addresses.
type listRunner struct {
	mu    sync.Mutex
	hosts map[string][]HostRow // by target value
	asked map[string][]string  // the names each scan probed, by target value
}

func (r *listRunner) Scan(_ context.Context, st ScanTarget) (Content, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := Content{Hosts: []HostRow{}, Ports: []PortRow{}}
	for _, h := range r.hosts[st.Value] {
		if !runnerScans(st, h.Name) {
			listName(&c, h)
			continue
		}
		r.asked[st.Value] = append(r.asked[st.Value], h.Name)
		c.Hosts = append(c.Hosts, h)
	}
	return c, nil
}

// The count over the domain targets of one installation, replayed in the order they were added and scanned: the pairs of a subdomain
// target and its parent target stored as unrelated targets, and the names scanned by two targets. The subdomain was added first and its
// parent a day later; the parent's scan found the subdomain among its names. Both counts are 0: the parent takes the subdomain under it
// when it is added, and its scan lists the subdomain without probing it.
func TestCount_SubdomainTargetsUnrelatedToTheirParentAndNamesScannedTwice(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("testdata/tree_targets.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx treeFixture
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	run := &listRunner{hosts: map[string][]HostRow{}, asked: map[string][]string{}}
	for _, s := range fx.Scans {
		run.hosts[s.Target] = s.Hosts
	}
	e.svc.SetRunner(run)
	ids := map[string]string{}
	var records []string
	for _, tg := range fx.Targets {
		v, err := e.svc.AddDomain(e.ctx(), "admin@example.com", tg.Value)
		if err != nil {
			t.Fatal(err)
		}
		ids[tg.Value] = v.ID
		records = append(records, txtRecord(v.Token))
		e.dns.put("example.com", records...) // each target's own record on the zone apex, as on the installation
		e.advance(DomainCheckEvery)
		if r, err := e.svc.Verify(e.ctx(), "operator@example.com", v.ID); err != nil || !r.Verified {
			t.Fatalf("verify %s: %+v %v", tg.Value, r, err)
		}
		if _, err := e.commit(v.ID); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range fx.Scans {
		e.advance(ScanEvery)
		if _, err := e.svc.Scan(e.ctx(), "admin@example.com", ids[s.Target]); err != nil {
			t.Fatalf("scan %s: %v", s.Target, err)
		}
	}
	pairs, err := unplacedPairs(e.ctx(), e.db.Reader())
	if err != nil {
		t.Fatal(err)
	}
	twice := 0 // the names the runner probed for two targets
	for _, n := range run.asked[fx.Targets[0].Value] {
		if slices.Contains(run.asked[fx.Targets[1].Value], n) {
			twice++
		}
	}
	t.Logf("subdomain targets unrelated to their parent: %d; names scanned by two targets: %d", pairs, twice)
	if pairs != 0 || twice != 0 {
		t.Errorf("unrelated parent and child pairs = %d, names scanned twice = %d; want 0 and 0", pairs, twice)
	}
	if n, err := doubleScanned(e.ctx(), e.db.Reader()); err != nil || n != int64(twice) { // the selfcheck reads what the scans recorded
		t.Errorf("the selfcheck counts %d names scanned twice (%v), the runner was asked %d", n, err, twice)
	}
}
