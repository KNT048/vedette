package feeds

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/oas"
)

// A signal with no detail answers "detail": null (the schema's "no facts"), not an empty object; a signal with facts keeps them.
func TestBriefSignalWithoutDetailAnswersNull(t *testing.T) {
	t.Parallel()
	at := time.Date(2025, 3, 4, 0, 0, 0, 0, time.UTC)
	b := Brief{CVE: "CVE-2025-22225", Signals: []BriefSignal{
		{Signal: Signal{Kind: "exploited", Source: "cisa-kev", FirstSeen: at, LastSeen: at, Qualifies: true}, SourceName: "CISA KEV"},
		{Signal: Signal{Kind: "public_exploit", Source: "nuclei-templates", FirstSeen: at, LastSeen: at, Qualifies: true,
			Detail: json.RawMessage(`{"stars": 244}`)}, SourceName: "nuclei-templates"},
	}}
	got, err := convert[oas.FeedsGetFeedsCveIDOK](toBriefDTO(b))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(got.Signals) != 2 {
		t.Fatalf("signals = %d, want 2", len(got.Signals))
	}
	if d := got.Signals[0].Detail; !d.Null {
		t.Errorf("signal without detail: detail = %v, want null", d.Value)
	}
	if d := got.Signals[1].Detail; d.Null || len(d.Value) != 1 {
		t.Errorf("signal with detail: detail = %+v, want {stars: 244}", d)
	}
}
