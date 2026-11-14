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

// D-520: a template probe of exposure's safe checks is completed with its outcome (matched, not_matched); any other result is not
// written (the row keeps the meaning of Answered).
func TestExternalTemplateProbeResult(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ps := []ExternalProbe{
		{ID: "tp-1", IP: "203.0.114.7", Label: "203.0.114.7:18443", Template: "CVE-2021-41773", Request: "GET /icons/.%2e/ (nuclei)", Result: "matched"},
		{ID: "tp-2", IP: "203.0.114.7", Label: "203.0.114.7:18443", Template: "CVE-2021-42013", Request: "GET /icons/ (nuclei)", Result: "not_matched"},
		{ID: "tp-3", IP: "203.0.114.7", Label: "203.0.114.7:18443", Template: "CVE-2024-1", Request: "GET / (nuclei)", Result: "stopped"},
	}
	if err := e.svc.RecordExternalProbes(e.ctx(), ps); err != nil {
		t.Fatal(err)
	}
	l, err := e.svc.Probes(e.ctx())
	got := map[string]string{}
	for _, r := range l {
		got[r.Template] = r.Result
	}
	if err != nil || got["CVE-2021-41773"] != "matched" || got["CVE-2021-42013"] != "not_matched" || got["CVE-2024-1"] != "no_response" {
		t.Fatalf("%v %v", got, err)
	}
}
