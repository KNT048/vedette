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
		"qnap|photo station|update|6.1.2":       "Now: update to 6.1.2 or later.",
		"qnap|photo station|none_yet|":          "Now: no fix from the vendor yet.",
		"qnap|photo station|unknown|":           "Now: Vedette's data names no fixed release.",
		"ubuntu|openssl|distro_update|3.0.13-0": "Now: install the distribution's package 3.0.13-0 or later.",
	} {
		if h := historyEntry(Event{Kind: EvFixChanged, Detail: EventDetail{To: to}}); h.Note != want {
			t.Errorf("fix note for %q = %q, want %q", to, h.Note, want)
		}
	}
}

// Every fix kind a fix_changed event can move to has its own words in the history note: a kind that falls through to the generic
// "update to … or later" tells a person to install something that is not the fix (a restart into a kernel that is already installed).
func TestFindingPage_EveryFixKindHasItsOwnHistoryNote(t *testing.T) {
	t.Parallel()
	generic := fixChangeNote("p|" + string(FixUpdate) + "|7.0.0-44.44")
	for _, k := range knownFixKinds {
		if k == FixUpdate {
			continue
		}
		if got := fixChangeNote("ubuntu|linux kernel|" + string(k) + "|7.0.0-44.44"); got == generic || got == "" {
			t.Errorf("fix kind %q: history note %q is the generic update sentence", k, got)
		}
	}
	if got, want := fixChangeNote("ubuntu|linux kernel|restart|7.0.0-44.44"), "Now: restart the device to run the installed 7.0.0-44.44."; got != want {
		t.Errorf("restart note = %q, want %q", got, want)
	}
}

// A fix key of a fix only a subscription carries ends in its channel ("…|distro_update|<release>|ubuntu_pro"). The history note still
// reads the kind and the release, and says the subscription, never "update to ubuntu_pro or later".
func TestFindingPage_HistoryNoteOfAChannelFix(t *testing.T) {
	t.Parallel()
	for key, want := range map[string]string{
		FixKey("ubuntu|python3-pip", Fix{Kind: FixDistroUpdate, Version: "25.1.1+dfsg-1ubuntu2+esm3", Channel: ChannelUbuntuPro}): "Now: install the distribution's package 25.1.1+dfsg-1ubuntu2+esm3 or later (only Ubuntu Pro has it).",
		FixKey("microsoft|windows 10", Fix{Kind: FixOSUpdate, Version: "19045.6456", Channel: ChannelESU}):                        "Now: install the operating system update to build 19045.6456 or later (only with Extended Security Updates).",
		FixKey("ubuntu|python3-pip", Fix{Kind: FixDistroUpdate, Version: "25.1.1+dfsg-1ubuntu2.1"}):                               "Now: install the distribution's package 25.1.1+dfsg-1ubuntu2.1 or later.",
	} {
		if got := fixChangeNote(key); got != want {
			t.Errorf("fixChangeNote(%q) = %q, want %q", key, got, want)
		}
	}
}
