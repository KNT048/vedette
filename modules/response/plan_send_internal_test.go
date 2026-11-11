package response

import (
	"context"
	"testing"
)

// D-313 after review: a read the AI cites is sent only for an action on a device through that read's connection, and never for a
// high-risk action, where it would make the second check out of one finding and a read that is not about the target.
func TestCitedReadsOnlyForTheActionsConnectionAndNeverHighRisk(t *testing.T) {
	reads := map[string]EvidenceRef{"rd-fw": {Connection: "cn-fw"}, "rd-other": {Connection: "cn-other"}}
	s := &Service{cfg: Config{Evidence: EvidencePorts{ConfigRead: func(_ context.Context, id string) (EvidenceRef, bool, error) {
		r, ok := reads[id]
		return r, ok, nil
	}}}}
	offered := []AIAction{{ID: "fw_medium", Risk: RiskMedium, ConnectionID: "cn-fw"}, {ID: "fw_high", Risk: RiskHigh, ConnectionID: "cn-fw"}, {ID: "box", Risk: RiskLow}}
	ids := []string{"rd-fw", "rd-other", "rd-nope"}
	if got := s.citedReads(t.Context(), ids, offered, "fw_medium"); len(got) != 1 || got[0] != (ProposedEvidence{Kind: EvConfigRead, ID: "rd-fw"}) {
		t.Fatalf("medium: %+v", got)
	}
	for _, a := range []string{"fw_high", "box", "not_offered"} {
		if got := s.citedReads(t.Context(), ids, offered, a); len(got) != 0 {
			t.Errorf("%s: reads kept %+v", a, got)
		}
	}
	s.cfg.Evidence.ConfigRead = nil
	if got := s.citedReads(t.Context(), ids, offered, "fw_medium"); len(got) != 0 {
		t.Errorf("no lookup: reads kept %+v", got)
	}
}
