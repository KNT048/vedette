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
		{Reason: Reason{Layer: UrgencyExploited, Source: "mandiant", Since: day(19)}, Name: "Mandiant"},
		{Reason: Reason{Layer: UrgencyPublicExploit, Source: "github-poc", Since: day(18)}, Name: "GitHub", Detail: "244 stars"},
	}}
	want := "Exploited in the wild: Rapid7, Mandiant (19 Nov 2026); not yet in CISA KEV · Public exploit available: GitHub, 244 stars (18 Nov 2026)"
	if got := v.ReasonsLine(); got != want {
		t.Errorf("reasons line = %q, want %q", got, want)
	}
	v.Reasons = []ViewReason{{Reason: Reason{Layer: UrgencyExploited, Source: "cisa-kev", Since: day(19)}, Name: "CISA KEV", Due: "2026-12-03"}}
	if got := v.ReasonsLine(); got != "Exploited in the wild: CISA KEV (19 Nov 2026); fix by 3 Dec 2026" {
		t.Errorf("listed: %q", got)
	}
	if got := (View{}).ReasonsLine(); got != "" {
		t.Errorf("no reasons: %q", got)
	}
	if !strings.Contains(StatusName(0), "Update") {
		t.Error("an unknown layer reads as update recommended")
	}
}

// The words of the reasons line are the page's: its locale keys are the reference.
func TestReasonsWordsMatchTheWeb(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../web/src/locales/en/common.json")
	if err != nil {
		t.Fatal(err)
	}
	var loc struct {
		Reasons map[string]string `json:"reasons"`
	}
	if err := json.Unmarshal(raw, &loc); err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	got := View{Reasons: []ViewReason{{Reason: Reason{Layer: UrgencyExploited, Source: "rapid7-blog", Since: day}, Name: "Rapid7", Due: "2026-12-03"}}}.ReasonsLine()
	want := "Exploited in the wild: Rapid7 (19 Nov 2026); " + loc.Reasons["notInKev"] + "; " + strings.Replace(loc.Reasons["due"], "{{date}}", "3 Dec 2026", 1)
	if got != want {
		t.Errorf("reasons line = %q, the page's words give %q", got, want)
	}
}

// The confirmation line an alert or a report says is the one under the status on every screen: the page's locale is the reference.
func TestVerificationLineMatchesTheWeb(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../web/src/locales/en/common.json")
	if err != nil {
		t.Fatal(err)
	}
	var loc struct {
		Verification struct {
			Scan          string            `json:"scan"`
			Device        string            `json:"device"`
			Person        string            `json:"person"`
			PersonUnnamed string            `json:"personUnnamed"`
			NotYetBasis   string            `json:"notYetBasis"`
			Basis         map[string]string `json:"basis"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(raw, &loc); err != nil {
		t.Fatal(err)
	}
	w := loc.Verification
	day := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	created := []Event{{Kind: EvCreated, TS: day, Actor: "system"}}
	cases := []struct {
		f    Finding
		evs  []Event
		want string
	}{
		{Finding{Verified: VerifiedScan, Basis: DetectScan, FirstSeen: day}, created, w.Scan},
		{Finding{Verified: VerifiedDevice, Basis: DetectDeviceVersion, FirstSeen: day}, created, w.Device},
		{Finding{Verified: VerifiedPerson, Basis: DetectPerson, FirstSeen: day}, []Event{{Kind: EvConfirmed, TS: day, Actor: "it@acme.example"}},
			strings.Replace(w.Person, "{{by}}", "it@acme.example", 1)},
		{Finding{Verified: VerifiedPerson, Basis: DetectPerson, FirstSeen: day}, nil, w.PersonUnnamed},
	}
	for _, b := range DetectionBases {
		cases = append(cases, struct {
			f    Finding
			evs  []Event
			want string
		}{Finding{Verified: VerifiedNo, Basis: b, FirstSeen: day}, nil, strings.Replace(w.NotYetBasis, "{{basis}}", w.Basis[string(b)], 1)})
	}
	for _, c := range cases {
		if got := (View{Finding: c.f, Events: c.evs}).VerificationLine(); got != c.want {
			t.Errorf("%s/%s: line = %q, the page says %q", c.f.Verified, c.f.Basis, got, c.want)
		}
	}
}
