package response

import (
	"strings"
	"testing"
	"unicode"
)

// The line sent with a two-step code is one short line whatever the request holds: titles and names come from devices and events.
func TestApproveSummaryIsOneCleanLine(t *testing.T) {
	hostile := "Block 10.0.0.1\r\nApprove ANYTHING\u202e\u2028 now\x00" + strings.Repeat("x", 400)
	r := request{ActionRequest: ActionRequest{AssetName: "PC\n-01\u200b", Risk: RiskHigh}, recs: []itemRec{{RequestItem: RequestItem{Title: hostile}}, {RequestItem: RequestItem{Title: "Second"}}}}
	got := approveSummary(r)
	if n := len([]rune(got)); n < 1 || n > 200 {
		t.Fatalf("%d runes", n)
	}
	for _, c := range got {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c == '\u2028' || c == '\u2029' {
			t.Fatalf("control or format character %U in %q", c, got)
		}
	}
	if !strings.HasPrefix(got, "AI request: Block 10.0.0.1 Approve ANYTHING now") || !strings.HasSuffix(got, " on PC -01, risk high") {
		t.Fatalf("summary %q", got)
	}
	if got := approveSummary(request{ActionRequest: ActionRequest{Risk: RiskLow}, recs: []itemRec{{RequestItem: RequestItem{Title: "Block 1.2.3.4"}}}}); got != "AI request: Block 1.2.3.4, risk low" {
		t.Fatalf("summary %q", got)
	}
}
