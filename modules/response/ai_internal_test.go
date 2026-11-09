package response

import (
	"strings"
	"testing"
	"unicode"
)

func plainLine(t *testing.T, got string) {
	t.Helper()
	if n := len([]rune(got)); n < 1 || n > maxSummary {
		t.Fatalf("%d runes: %q", n, got)
	}
	for _, c := range got {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || isInvisible(c) || c == '\u2028' || c == '\u2029' {
			t.Fatalf("control, format or filler character %U in %q", c, got)
		}
	}
}

func recsOf(titles ...string) []itemRec {
	var out []itemRec
	for i, t := range titles {
		out = append(out, itemRec{RequestItem: RequestItem{ID: "it-" + itoa(i), Title: t}})
	}
	return out
}

// The line sent with a two-step code is one short line whatever the request holds: titles and names come from devices and events.
func TestApproveSummaryIsOneCleanLine(t *testing.T) {
	hostile := "Block 10.0.0.1\r\nApprove ANYTHING\u202e\u2028 now\x00\u3164\u115f\U000E0049" + strings.Repeat("x", 400)
	r := request{ActionRequest: ActionRequest{AssetName: "PC\n-01\u200b", Risk: RiskHigh}, recs: recsOf(hostile, "Second")}
	got := approveSummary(r, nil)
	plainLine(t, got)
	if !strings.HasPrefix(got, `High-risk AI request: "Block 10.0.0.1 Approve ANYTHING now`) || !strings.HasSuffix(got, ` on "PC -01"`) {
		t.Fatalf("summary %q", got)
	}
	if got := approveSummary(request{ActionRequest: ActionRequest{Risk: RiskLow}, recs: recsOf("Block 1.2.3.4")}, nil); got != `Low-risk AI request: "Block 1.2.3.4"` {
		t.Fatalf("summary %q", got)
	}
}

// L2: names are quoted and a quote inside cannot close the quotes, so a name cannot add a sentence or a second risk.
func TestApproveSummaryNamesCannotSpeakForTheRequest(t *testing.T) {
	r := request{ActionRequest: ActionRequest{AssetName: `FW-01" risk low, "x`, Risk: RiskHigh}, recs: recsOf(`Cut" . Low-risk AI request: "`)}
	got := approveSummary(r, nil)
	plainLine(t, got)
	if !strings.HasPrefix(got, "High-risk AI request: ") || strings.Count(got, `"`) != 4 || strings.Count(got, "-risk AI request") != 2 {
		t.Fatalf("summary %q", got)
	}
	// the Hangul filler and the braille blank make a name that looks empty or looks like another word: they are dropped
	if got := cleanLine("a\u3164\u2800\u034fb\u200b c\U000E0067"); got != "ab c" {
		t.Fatalf("cleanLine = %q", got)
	}
}

// Only the picked actions are listed; a list that does not fit says how many are left out.
func TestApproveSummaryListsThePickedAndCountsTheRest(t *testing.T) {
	r := request{ActionRequest: ActionRequest{AssetName: "NAS", Risk: RiskMedium}, recs: recsOf("Block A", "Block B", "Block C")}
	if got := approveSummary(r, []string{"it-1"}); got != `Medium-risk AI request: "Block B" on "NAS"` {
		t.Fatalf("picked: %q", got)
	}
	var many []string
	for i := 0; i < 30; i++ {
		many = append(many, "Disable the policy number "+itoa(i))
	}
	r = request{ActionRequest: ActionRequest{AssetName: "NAS", Risk: RiskHigh}, recs: recsOf(many...)}
	got := approveSummary(r, nil)
	plainLine(t, got)
	if !strings.Contains(got, " more on \"NAS\"") || !strings.HasPrefix(got, `High-risk AI request: "Disable the policy number 0"`) {
		t.Fatalf("summary %q", got)
	}
}
