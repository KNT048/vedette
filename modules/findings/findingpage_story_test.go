package findings

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The finding page says one thing about how sure Vedette is: the evidence sentence the matcher stored ("…; no scan has confirmed it
// yet, so this is only suspected.") keeps its last clause only while the finding is suspected. Once a person confirmed it, the page's
// headline says "confirmed" and the evidence no longer says "only suspected" next to it.
func TestFindingPage_EvidenceFollowsTheStatus(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.feeds.vulns = []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})}
	id := e.seed()
	summary := func() string {
		t.Helper()
		_, b := e.call("GET", "/findings/"+id, "viewer", "")
		ev, _ := b["evidence"].(map[string]any)
		s, _ := ev["summary"].(string)
		return s
	}
	if s := summary(); !strings.HasSuffix(s, suspectedClause) {
		t.Fatalf("suspected: summary %q, want the stored sentence with its clause", s)
	}
	if code, b := e.call("POST", "/findings/"+id+"/verify", "admin", `{"note":"logged in, it runs 6.1.1"}`); code != 200 {
		t.Fatalf("verify: %d %v", code, b)
	}
	s := summary()
	if strings.Contains(s, "only suspected") || !strings.HasSuffix(s, "(before 6.1.2).") {
		t.Fatalf("confirmed: summary %q, want the facts without \"only suspected\"", s)
	}
	if r, _ := e.svc.Get(t.Context(), id); !strings.HasSuffix(r.Evidence.Summary, suspectedClause) {
		t.Fatalf("the stored sentence changed: %q", r.Evidence.Summary)
	}
}

// A finding on no exploited list (update recommended) still names the software line it is on and the version the box has: the page
// and the "What to do" guidance read the finding's stored line, so neither falls back to "the software".
func TestFindingPage_FindingOnNoListKeepsItsSoftware(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.feeds.vulns = []Vuln{qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}})}
	a := nas("6.1.1")
	a.Software[0].Source = "manual"
	e.inv.match["a-1"] = a
	id := e.seed()
	delete(e.feeds.kev, "CVE-2022-27593") // the CVE leaves the exploited list: the finding stays, as an update recommended
	_, b := e.call("GET", "/findings/"+id, "viewer", "")
	if b["kev"] != nil {
		t.Fatalf("kev = %v", b["kev"])
	}
	kv, _ := b["known_version"].(map[string]any)
	if kv["software"] != "Photo Station" || kv["version"] != "6.1.1" {
		t.Fatalf("known_version = %v, want the stored line's software and version", b["known_version"])
	}
}

// The class "a history row the page cannot name": every kind of finding event becomes an action of the page's history, and every
// action has a label in the page's words (web/src/locales/en/findings.json "history"). Before, urgency_changed and fix_changed
// reached the page as raw codes. A note says what the change was.
func TestFindingPage_EveryHistoryActionHasALabel(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../web/src/locales/en/findings.json")
	if err != nil {
		t.Fatal(err)
	}
	var loc struct {
		History map[string]any `json:"history"`
	}
	if err := json.Unmarshal(b, &loc); err != nil {
		t.Fatal(err)
	}
	details := []EventDetail{{}, {Resolution: ResolutionPatched, Via: ViaPerson}, {Resolution: ResolutionMitigated, Via: ViaPerson},
		{Resolution: ResolutionAccepted, Via: ViaPerson, AcceptedUntil: "2026-12-31"}, {Resolution: ResolutionNotRelevant, Via: ViaDataCorrected},
		{Resolution: ResolutionFalsePositive, Via: ViaPerson}, {Why: WhyDetectedAgain}, {Why: WhyStillDetected}, {Why: WhyPerson},
		{Layer: UrgencyExploited}, {From: "qnap|photo station|update|6.1.2", To: "qnap|photo station|none_yet|"}}
	unlabelled := map[string]bool{}
	for _, k := range EventKinds {
		for _, d := range details {
			if k == EvHandled && d.Resolution == "" {
				continue // a handling always has a resolution
			}
			h := historyEntry(Event{Kind: k, Actor: SystemUser, Detail: d})
			if _, ok := loc.History[h.Action]; !ok {
				unlabelled[h.Action] = true
			}
		}
	}
	t.Logf("history actions without a label: %d %v", len(unlabelled), unlabelled)
	if len(unlabelled) != 0 {
		t.Errorf("%d history actions have no label in findings.json history: %v", len(unlabelled), unlabelled)
	}
	if h := historyEntry(Event{Kind: EvUrgencyChanged, Detail: EventDetail{Layer: UrgencyExploited}}); h.Note != "Now: Exploited in the wild." {
		t.Errorf("urgency note = %q", h.Note)
	}
	for to, want := range map[string]string{
		"qnap|photo station|update|6.1.2":      "Now: update to 6.1.2 or later.",
		"qnap|photo station|none_yet|":         "Now: no fix from the vendor yet.",
		"qnap|photo station|unknown|":          "Now: Vedette's data names no fixed release.",
		"ubuntu|openssl|distro_update|3.0.13-0": "Now: install the distribution's package 3.0.13-0 or later.",
	} {
		if h := historyEntry(Event{Kind: EvFixChanged, Detail: EventDetail{To: to}}); h.Note != want {
			t.Errorf("fix note for %q = %q, want %q", to, h.Note, want)
		}
	}
}
