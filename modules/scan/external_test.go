package scan

import (
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// INV-12 (D-229): the external-surface scan logs its probes in the probe log before they go out and completes them after; the
// rows read like any other probe (GET /scans/probes, the CSV, the 90-day retention).
func TestExternalProbesAreInTheProbeLog(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := ExternalProbe{ID: "xp-1", IP: "203.0.113.7", Label: "203.0.113.7", Template: "exposure: tcp", Request: "TCP connect to 98 ports"}
	if err := e.svc.RecordExternalProbes(e.ctx(), []ExternalProbe{p}); err != nil {
		t.Fatal(err)
	}
	l, err := e.svc.Probes(e.ctx())
	if err != nil || len(l) != 1 || l[0].Result != "no_response" || l[0].RunID != nil || l[0].IP != "203.0.113.7" {
		t.Fatalf("before: %+v %v", l, err)
	}
	e.clock.mu.Lock()
	e.clock.now = e.clock.now.Add(time.Minute)
	e.clock.mu.Unlock()
	p.Answered, p.Request = true, "TCP connect to 98 ports; open: 22, 443"
	if err := e.svc.RecordExternalProbes(e.ctx(), []ExternalProbe{p}); err != nil {
		t.Fatal(err)
	}
	l, err = e.svc.Probes(e.ctx())
	if err != nil || len(l) != 1 || l[0].Result != "banner" || l[0].Request != p.Request || l[0].TS != store.FormatTS(t0) { // the time of the first write
		t.Fatalf("after: %+v %v", l, err)
	}
}
