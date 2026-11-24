package findings

import (
	"regexp"
	"testing"
)

// storedWord is a vocabulary code as it is stored (detected_again, version_moved, no_range_data) or a stored field set beside its
// value ("via person", "basis statement"): never what an audit line says.
var storedWord = regexp.MustCompile(`\b[a-z]+_[a-z_]+\b|\bvia [a-z]+|\bbasis [a-z]+`)

// Every audit line the findings module writes says each stored code in words: the audit page shows the detail as written, so a
// code in it is a raw key on the screen and in the CSV export. This walks every resolution, way, reason to reopen, detection basis
// and question kind.
func TestAuditDetailsSayEveryCodeInWords(t *testing.T) {
	f := Finding{ID: "f-1", CVE: "CVE-2026-0001"}
	var raw []string
	check := func(what, detail string) {
		if m := storedWord.FindString(detail); m != "" {
			raw = append(raw, what+": "+detail)
		}
	}
	for _, b := range DetectionBases {
		f.Basis = b
		_, d := auditAction(f, Event{Kind: EvCreated})
		check("created "+string(b), d)
	}
	for _, r := range Resolutions {
		for _, v := range Vias {
			e := Event{Kind: EvHandled, Detail: EventDetail{Resolution: r, Via: v}}
			if v == ViaVersionMoved {
				e.Detail.FromVersion, e.Detail.ToVersion = "1.30.5", "1.30.6"
			}
			if r == ResolutionAccepted {
				e.Detail.AcceptedUntil = "2026-12-24"
			}
			_, d := auditAction(f, e)
			check("handled "+string(r)+" "+string(v), d)
		}
	}
	for _, why := range []string{WhyStillDetected, WhyDetectedAgain, WhyAcceptanceExpired, WhyPerson} {
		_, d := auditAction(f, Event{Kind: EvReopened, Detail: EventDetail{Why: why}})
		check("reopened "+why, d)
	}
	for _, k := range QuestionKinds {
		check("question "+string(k), questionAuditDetail(Question{Kind: k, CVE: "CVE-2026-0001", AssetID: "a-1"}, "answered not affected"))
	}
	t.Logf("%d audit details hold a stored code", len(raw))
	for _, r := range raw {
		t.Errorf("a stored code in an audit detail: %s", r)
	}
}
