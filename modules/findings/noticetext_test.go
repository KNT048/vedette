package findings

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// The status words people read in an alert are the ones the finding page shows: the page's locale file is the reference.
func TestStatusTextMatchesTheWeb(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../web/src/locales/en/common.json")
	if err != nil {
		t.Fatal(err)
	}
	var loc struct {
		FindingStatus struct {
			Meaning map[string]string `json:"meaning"`
		} `json:"findingStatus"`
	}
	if err := json.Unmarshal(raw, &loc); err != nil {
		t.Fatal(err)
	}
	var names map[string]json.RawMessage
	var top map[string]json.RawMessage
	_ = json.Unmarshal(raw, &top)
	_ = json.Unmarshal(top["findingStatus"], &names)
	for layer := UrgencyUnderAttack; layer <= UrgencyUpdate; layer++ {
		code := LayerCode(layer)
		var name string
		if err := json.Unmarshal(names[code], &name); err != nil || name != StatusName(layer) {
			t.Errorf("layer %d: name %q, the page says %q", layer, StatusName(layer), name)
		}
		if m := loc.FindingStatus.Meaning[code]; m != StatusMeaning(layer) {
			t.Errorf("layer %d: meaning %q, the page says %q", layer, StatusMeaning(layer), m)
		}
	}
}

func TestReasonsLine(t *testing.T) {
	t.Parallel()
	day := func(d int) time.Time { return time.Date(2026, 11, d, 8, 0, 0, 0, time.UTC) }
	v := View{Reasons: []ViewReason{
		{Reason: Reason{Layer: UrgencyExploited, Source: "rapid7-blog", Since: day(20)}, Name: "Rapid7"},
		{Reason: Reason{Layer: UrgencyPublicExploit, Source: "metasploit", Since: day(18)}, Name: "Metasploit"},
	}}
	want := "Exploited in the wild: Rapid7 (20 Nov 2026), not yet on CISA's list · Public exploit available: Metasploit (18 Nov 2026)"
	if got := v.ReasonsLine(time.UTC); got != want {
		t.Errorf("reasons line = %q, want %q", got, want)
	}
	v.Reasons = []ViewReason{{Reason: Reason{Layer: UrgencyExploited, Source: "cisa-kev", Since: day(19)}, Name: "CISA KEV", Due: "2026-12-03"}}
	if got := v.ReasonsLine(time.UTC); got != "Exploited in the wild: CISA KEV (19 Nov 2026, fix due 3 Dec 2026)" {
		t.Errorf("listed: %q", got)
	}
	if got := (View{}).ReasonsLine(time.UTC); got != "" {
		t.Errorf("no reasons: %q", got)
	}
	if !strings.Contains(StatusName(0), "Update") {
		t.Error("an unknown layer reads as update recommended")
	}
}
