package inventory

import (
	"slices"
	"testing"
)

// A write that announces a device's match and its software change makes findings match the device once: the software change of a
// device with a match event is left out, every other event stays in its order.
func TestOneMatchPerDevice(t *testing.T) {
	t.Parallel()
	in := []Event{
		{Name: EventAssetUpdated, Data: AssetEvent{AssetID: "a"}},
		{Name: EventSoftwareChanged, Data: AssetEvent{AssetID: "a"}},
		{Name: EventSoftwareChanged, Data: AssetEvent{AssetID: "b"}},
		{Name: EventMatchChanged, Data: MatchEvent{AssetID: "a", CVE: "CVE-2024-3400", Basis: "product"}},
		{Name: EventMatchChanged, Data: MatchEvent{AssetID: "a", CVE: "CVE-2024-3401", Basis: "product"}},
	}
	var got []string
	for _, e := range oneMatchPerDevice(slices.Clone(in)) {
		switch d := e.Data.(type) {
		case AssetEvent:
			got = append(got, e.Name+" "+d.AssetID)
		case MatchEvent:
			got = append(got, e.Name+" "+d.AssetID+" "+d.CVE)
		}
	}
	want := []string{EventAssetUpdated + " a", EventSoftwareChanged + " b", EventMatchChanged + " a CVE-2024-3400", EventMatchChanged + " a CVE-2024-3401"}
	if !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	if out := oneMatchPerDevice(in[:3]); len(out) != 3 {
		t.Fatalf("no match event: %d events kept, want 3", len(out))
	}
}
