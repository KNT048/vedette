package sensoractive

import (
	"context"
	"testing"

	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// policyOnly is an Inventory that answers only ScanPolicy.
type policyOnly struct {
	Inventory
	dec Decision
}

func (p policyOnly) ScanPolicy(context.Context, string) (Decision, error) { return p.dec, nil }

// D-511 (#714 round 2, M2, FORBID-6): a gentle scan with titles stops when the device is made fragile while it runs; the plain gentle
// scan of the same device goes on, and so does a titles scan whose device stays unknown and not fragile.
func TestTitlesScanStopsWhenTheDeviceTurnsFragile(t *testing.T) {
	t.Parallel()
	first := Decision{Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Unclassified: true}
	fragile := first
	fragile.Fragile = true
	for _, c := range []struct {
		name string
		kind nmapargv.Kind
		dec  Decision
		stop bool
	}{
		{"titles, made fragile", nmapargv.GentleTitles, fragile, true},
		{"titles, still unknown and not fragile", nmapargv.GentleTitles, first, false},
		{"plain gentle, made fragile", nmapargv.Gentle, fragile, false},
	} {
		stopped := false
		s := &Service{inv: policyOnly{dec: c.dec}}
		s.cur = &running{cancel: func() { stopped = true }, asset: "a-1", rate: 1}
		s.setKind(c.kind)
		if err := s.AssetChanged(t.Context(), "a-1"); err != nil {
			t.Fatal(err)
		}
		if stopped != c.stop {
			t.Errorf("%s: stopped = %v, want %v", c.name, stopped, c.stop)
		}
	}
}
