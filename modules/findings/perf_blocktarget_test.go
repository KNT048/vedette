//go:build perf

package findings

import (
	"fmt"
	"testing"
	"time"
)

// TestPerfBlockTarget times the lists' block combination (ListedFixes: By device, By fix, Home and the report read it) on a synthetic
// network of 20 devices, each running one nginx line, with 300 CVEs of six ranges each whose fixes differ, so every line combines many
// groups into one block; one CVE in ten has a later train with no fix, so the block also splits. Measurement only:
// go test -tags perf ./modules/findings/ -run TestPerfBlockTarget -v
func TestPerfBlockTarget(t *testing.T) {
	e := newEnv(t)
	e.feeds.vulns = nil
	for i := range 300 {
		var ranges []string
		for train := 26; train <= 31; train++ {
			ranges = append(ranges, fmt.Sprintf("1.%d.0-1.%d.%d", train, train, 6+(i*7+train)%40))
		}
		if i%10 == 0 {
			ranges[len(ranges)-1] = "1.31.0-=1.31.60"
		}
		e.feeds.vulns = append(e.feeds.vulns, rangedCVE(fmt.Sprintf("CVE-2026-8%04d", i), "f5", "nginx", ranges...))
	}
	e.inv.assets, e.inv.match = map[string]AssetView{}, map[string]Asset{}
	for i := range 20 {
		id := fmt.Sprintf("web-%02d", i)
		e.inv.assets[id] = AssetView{ID: id, Hostname: ptr(id), IP: fmt.Sprintf("192.0.2.%d", 10+i), Kind: "server", Approved: true}
		e.inv.match[id] = Asset{ID: id, Name: id, Software: []Software{blockLine("s-"+id, "f5", "nginx", "1.30.5")}}
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	var best time.Duration
	var n int
	for range 3 {
		start := time.Now()
		listed, err := e.svc.ListedFixes(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); best == 0 || d < best {
			best = d
		}
		n = len(listed)
	}
	t.Logf("ListedFixes: %d open findings, best of 3: %v", n, best.Round(time.Millisecond))
}
