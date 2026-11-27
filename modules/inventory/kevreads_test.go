package inventory_test

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// countingKEV is fakeKEV that counts how many times the exploited list is read.
type countingKEV struct {
	fakeKEV
	reads *atomic.Int64
}

func (c countingKEV) CVEIndex(ctx context.Context) (inventory.KEVIndex, error) {
	c.reads.Add(1)
	return c.fakeKEV.CVEIndex(ctx)
}

// A device with hundreds of packages reads the exploited list once for its page and once for each agent report that changes its
// software, not once per software line: the page of a server with 900 packages took tens of seconds when every line read the
// whole list.
func TestKEVReads_DetailAndAgentReportReadTheListOnce(t *testing.T) {
	t.Parallel()
	const n = 600
	reads := &atomic.Int64{}
	kev := countingKEV{fakeKEV: fakeKEV{cves: map[string][]string{
		"vendor0007|tool0007": {"CVE-2026-0007"},
		"vendor0599|tool0599": {"CVE-2026-0599"},
		"vendor0600|tool0600": {"CVE-2026-0600"},
	}}, reads: reads}
	e := newEnv(t, withKEV(kev))
	ctx := e.ctx()
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.80")}
	pkg := func(i int, version string) observe.Software {
		return observe.Software{Display: fmt.Sprintf("tool%04d", i), Vendor: fmt.Sprintf("vendor%04d", i), Product: fmt.Sprintf("tool%04d", i),
			Version: version, Confidence: 1, Packaged: true}
	}
	list := make([]observe.Software, 0, n+1)
	for i := range n {
		list = append(list, pkg(i, "1.0"))
	}
	report := func(items []observe.Software) int64 {
		t.Helper()
		e.tick(time.Minute)
		reads.Store(0)
		sightedBy(ctx, t, e.svc, hint, observe.Osquery)
		if err := e.svc.ReplaceSoftware(ctx, hint, observe.Osquery, nil, items); err != nil {
			t.Fatal(err)
		}
		return reads.Load()
	}
	first := report(list)
	id := deviceAt(t, e, hint.IP)

	reads.Store(0)
	d := e.detail(id)
	detailReads := reads.Load()
	if len(d.Asset.Software) != n {
		t.Fatalf("%d software lines, want %d", len(d.Asset.Software), n)
	}
	for _, l := range d.Asset.Software {
		want := []string{}
		switch l.Display {
		case "tool0007":
			want = []string{"CVE-2026-0007"}
		case "tool0599":
			want = []string{"CVE-2026-0599"}
		}
		if !slices.Equal(l.KevCVEs, want) {
			t.Fatalf("%s: kev_cves %v, want %v", l.Display, l.KevCVEs, want)
		}
	}

	e.ev.reset()
	list = append(list, pkg(n, "1.0")) // a new package with an exploited CVE
	added := report(list)
	if got := matchedCVEs(e); !slices.Equal(got, []string{"CVE-2026-0600"}) {
		t.Fatalf("match events after a new package: %v", got)
	}

	e.ev.reset()
	list[n-1] = pkg(n-1, "1.1") // a version update only: the keys stay, the device is matched again
	updated := report(list)
	if got := matchedCVEs(e); len(got) != 1 {
		t.Fatalf("match events after a version update: %v", got)
	}

	t.Logf("exploited-list reads with %d lines: first report %d, device page %d, report with a new package %d, version update %d",
		n, first, detailReads, added, updated)
	if detailReads > 1 || first > 1 || added > 1 || updated > 1 {
		t.Errorf("the exploited list was read per line or per key set: first report %d, device page %d, new package %d, version update %d (want at most 1 each)",
			first, detailReads, added, updated)
	}
}

// matchedCVEs lists the CVEs of the match events published since the last reset.
func matchedCVEs(e *env) []string {
	var out []string
	for _, ev := range e.ev.named(inventory.EventMatchChanged) {
		out = append(out, ev.Data.(inventory.MatchEvent).CVE)
	}
	slices.Sort(out)
	return out
}
