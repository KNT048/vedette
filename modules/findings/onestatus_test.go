package findings

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/oas"
)

// withExploitedSignal wires the urgency inputs so CVE-2026-1001 (nas01's layer-2 finding) is exploited in the wild on CISA's list, as
// the urgency pass rated it, with the day the list asks for the fix.
func withExploitedSignal(e *httpEnv) {
	e.svc.cfg.Urgency = UrgencySources{
		Facts: func(_ context.Context, cves []string) (map[string]CVEFacts, error) {
			out := map[string]CVEFacts{}
			for _, c := range cves {
				if c == "CVE-2026-1001" {
					out[c] = CVEFacts{Signals: []Signal{{Kind: SignalExploited, Source: "cisa-kev", FirstSeen: t0.Add(-72 * time.Hour), Qualifies: true,
						URL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}}}
				}
			}
			return out, nil
		},
		Names: func(context.Context) (map[string]string, error) {
			return map[string]string{"cisa-kev": "CISA KEV"}, nil
		},
	}
	due := "2026-12-03"
	e.feeds.kev = map[string]KevInfo{"CVE-2026-1001": {DueDate: &due}}
}

// rowJSON is the CVE row of id inside a By device answer, as raw JSON fields.
func rowJSON(t *testing.T, e *httpEnv, device, id string) map[string]json.RawMessage {
	t.Helper()
	code, b := e.raw("GET", "/findings/devices?device="+device, "viewer", "")
	if code != 200 {
		t.Fatalf("by device: %d %s", code, b)
	}
	var cards struct {
		Items []struct {
			Blocks []struct {
				Findings []map[string]json.RawMessage `json:"findings"`
			} `json:"blocks"`
		} `json:"items"`
	}
	if err := json.Unmarshal(b, &cards); err != nil {
		t.Fatal(err)
	}
	for _, c := range cards.Items {
		for _, bl := range c.Blocks {
			for _, r := range bl.Findings {
				var rid string
				_ = json.Unmarshal(r["id"], &rid)
				if rid == id {
					return r
				}
			}
		}
	}
	t.Fatalf("no row %s on %s", id, device)
	return nil
}

// A CVE row of By device (also the device's Findings tab and Home's Fix first, which read the same blocks) carries the status lines of
// its finding's own page: the same urgency reasons and the same confirmation, field for field.
func TestModelAPI_ARowSaysWhatItsFindingPageSays(t *testing.T) {
	e := modelEnv(t)
	withExploitedSignal(e)
	for _, c := range []struct{ device, id string }{{"a-nas", "f-n1"}, {"a-nas", "f-n2"}, {"a-new", "f-p1"}} {
		row := rowJSON(t, e, c.device, c.id)
		code, b := e.raw("GET", "/findings/"+c.id+"/view", "viewer", "")
		if code != 200 {
			t.Fatalf("view %s: %d %s", c.id, code, b)
		}
		var view map[string]json.RawMessage
		if err := json.Unmarshal(b, &view); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"urgency", "verification"} {
			var got, want any
			_ = json.Unmarshal(row[k], &got)
			_ = json.Unmarshal(view[k], &want)
			if got == nil || !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s: row %s, its page %s", c.id, k, row[k], view[k])
			}
		}
	}
	// the reasons line itself is there: CISA KEV with its date and the fix-by day, and the device's own confirmation
	var u struct {
		Reasons []struct {
			Name, Date string
			Due        *string
		} `json:"reasons"`
	}
	row := rowJSON(t, e, "a-nas", "f-n1")
	_ = json.Unmarshal(row["urgency"], &u)
	if len(u.Reasons) != 1 || u.Reasons[0].Name != "CISA KEV" || u.Reasons[0].Due == nil || *u.Reasons[0].Due != "2026-12-03" {
		t.Errorf("f-n1 reasons %s", row["urgency"])
	}
	var v struct{ Verified, Basis string }
	_ = json.Unmarshal(row["verification"], &v)
	if v.Verified != "device" {
		t.Errorf("f-n1 verification %s", row["verification"])
	}
	conform[oas.FindingsGetFindingsDevicesOK](t, e, "GET", "/findings/devices", "viewer", "")
	conform[oas.FindingsGetFindingsOverviewOK](t, e, "GET", "/findings/overview", "viewer", "")
}

// A person's confirmation reads the same on the row as on the page: who confirmed it and when.
func TestModelAPI_ARowNamesWhoConfirmedIt(t *testing.T) {
	e := modelEnv(t)
	if code, b := e.raw("POST", "/findings/f-p1/verify", "admin", `{"note":"logged in, the affected build runs"}`); code != 200 {
		t.Fatalf("verify: %d %s", code, b)
	}
	row := rowJSON(t, e, "a-new", "f-p1")
	var v struct {
		Verified string
		By, At   *string
	}
	_ = json.Unmarshal(row["verification"], &v)
	if v.Verified != "person" || v.By == nil || *v.By == "" || v.At == nil {
		t.Errorf("row verification %s, want the person and the time", row["verification"])
	}
}

// A block with no release to install ("No fix known yet", "No fix data") links the vendor's advisory the exploited list names for its
// cause, never CISA's or NVD's page; a block with a release keeps no link it does not have.
func TestModelAPI_ANoFixBlockLinksTheAdvisory(t *testing.T) {
	e := modelEnv(t)
	e.feeds.kev = map[string]KevInfo{
		"CVE-2026-3001": {Links: []string{"https://www.cisa.gov/news-events/alerts/x", "https://nvd.nist.gov/vuln/detail/CVE-2026-3001", "https://openprinting.github.io/advisory-3001"}},
		"CVE-2026-1001": {Links: []string{"https://www.openssh.com/security.html"}},
	}
	cards := conform[oas.FindingsGetFindingsDevicesOK](t, e, "GET", "/findings/devices?device=a-new", "viewer", "")
	b := cards.Items[0].Blocks[0]
	if u, ok := b.Fix.URL.Get(); !ok || u.String() != "https://openprinting.github.io/advisory-3001" {
		t.Errorf("no-fix block url %v, want the vendor's advisory", b.Fix.URL)
	}
	nas := conform[oas.FindingsGetFindingsDevicesOK](t, e, "GET", "/findings/devices?device=a-nas", "viewer", "")
	if u, ok := nas.Items[0].Blocks[0].Fix.URL.Get(); ok {
		t.Errorf("an update block got a link %v", u)
	}
	fixes := conform[oas.FindingsGetFindingsFixesOK](t, e, "GET", "/findings/fixes?q=cups", "viewer", "")
	if u, ok := fixes.Items[0].Fix.URL.Get(); !ok || u.String() != "https://openprinting.github.io/advisory-3001" {
		t.Errorf("By fix no-fix card url %v", fixes.Items[0].Fix.URL)
	}
}

// Home counts the devices that have open findings, the Vedette box like any device, by the badge each carries (one rule everywhere). The trend starts on the day this box began keeping findings, not 30 days before a fresh install.
func TestModelAPI_HomeCountsTheBoxAndStartsTheTrendAtInstall(t *testing.T) {
	e := modelEnv(t)
	e.inv.mu.Lock()
	a := e.inv.assets["a-nas"]
	a.Box = true
	e.inv.assets["a-nas"] = a
	e.inv.mu.Unlock()
	o := conform[oas.FindingsGetFindingsOverviewOK](t, e, "GET", "/findings/overview", "viewer", "")
	badges := o.Devices.ByStatus
	if n := badges.UnderAttack + badges.Exploited + badges.PublicExploit + badges.CriticalEdge + badges.UpdateRecommended; n != 3 {
		t.Errorf("devices by badge %d, want 3 (fw01, printer-07 and nas01, the box)", n)
	}
	af := o.Devices.Affected
	if af.Exploited != 2 || af.PublicExploit != 1 || af.UnderAttack+af.CriticalEdge+af.UpdateRecommended != 0 {
		t.Errorf("devices with findings %+v, want nas01 (the box) and printer-07 exploited, fw01 public exploit", af)
	}
	// the findings tables were made just now (the test's migration): the trend starts today, not 29 days ago
	today := e.svc.now().UTC().Format(time.DateOnly)
	if got := o.TrendStart.Format(time.DateOnly); got != today && got != time.Now().UTC().Format(time.DateOnly) {
		t.Errorf("trend start %s, want the day the findings tables were made", got)
	}
}

// A question answered "not affected" by mistake can be taken back: it is listed with who answered, and asking it again puts it back in
// Needs your input. An "affected" answer is not taken back here (it made a finding).
func TestModelAPI_ANotAffectedAnswerCanBeTakenBack(t *testing.T) {
	e := modelEnv(t)
	in := conform[oas.FindingsGetFindingsInputOK](t, e, "GET", "/findings/input", "viewer", "")
	before := in.Total
	if code, b := e.call("POST", "/findings/questions/q-1/answer", "operator", `{"answer":"not_affected","note":"not on this build"}`); code != 200 {
		t.Fatalf("answer: %d %v", code, b)
	}
	if in := conform[oas.FindingsGetFindingsInputOK](t, e, "GET", "/findings/input", "viewer", ""); in.Total != before-1 {
		t.Fatalf("queue after the answer %d, want %d", in.Total, before-1)
	}
	ans := conform[oas.FindingsGetFindingsAnsweredOK](t, e, "GET", "/findings/answered", "viewer", "")
	if ans.Total != 1 || ans.Items[0].ID != "q-1" || ans.Items[0].By == "" || ans.Items[0].Device.Name != "nas01" {
		t.Fatalf("answered %+v", ans)
	}
	if code, b := e.call("POST", "/findings/questions/q-1/unanswer", "viewer", ""); code != 403 {
		t.Errorf("a viewer took back an answer: %d %v", code, b)
	}
	if code, b := e.call("POST", "/findings/questions/q-1/unanswer", "operator", ""); code != 200 || b["id"] != "q-1" {
		t.Fatalf("take back: %d %v", code, b)
	}
	if in := conform[oas.FindingsGetFindingsInputOK](t, e, "GET", "/findings/input", "viewer", ""); in.Total != before {
		t.Errorf("queue after taking it back %d, want %d", in.Total, before)
	}
	if ans := conform[oas.FindingsGetFindingsAnsweredOK](t, e, "GET", "/findings/answered", "viewer", ""); ans.Total != 0 {
		t.Errorf("answered after taking it back: %+v", ans)
	}
	if code, b := e.call("POST", "/findings/questions/q-1/unanswer", "operator", ""); code != 409 || errCode(b) != "not_answered" {
		t.Errorf("taking back an open question: %d %v", code, b)
	}
	if code, b := e.call("POST", "/findings/questions/q-none/unanswer", "operator", ""); code != 404 {
		t.Errorf("unknown question: %d %v", code, b)
	}
}

// A finding Vedette closes because the distribution's fixed package already carries the fix says so: the proof's reason is the
// closing note, so the handled line reads "the match was corrected: Ubuntu 26.04 fixed … in linux 7.0.0-43.43, and this device has
// 7.0.0-43.43" instead of a bare "the match was corrected". A closure no proof explains keeps no note.
func TestReconcile_ADistroProofSaysWhyItClosed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	sw := Software{ID: "s-1", Display: "App", Vendor: "Acme", Product: "App", Version: "1.0", Source: "nmap", SeenAt: t0}
	a := Asset{ID: "a-1", Name: "host-1", Software: []Software{sw}}
	m := versionMatch(sw)
	e.matchPass(t, a, MatchResult{New: []Match{m}})
	proof := Match{CVE: m.CVE, SoftwareID: sw.ID, Evidence: Evidence{CheckedAt: t0, Summary: "Not affected: Ubuntu 26.04 fixed " + m.CVE +
		" in linux 7.0.0-43.43, and this device has 7.0.0-43.43 (Ubuntu security notices). Vedette closed this by itself and reopens it if a later match says the device is affected."}}
	e.matchPass(t, a, MatchResult{NotAffected: []Match{proof}})
	f := e.only(t)
	want := "Ubuntu 26.04 fixed " + m.CVE + " in linux 7.0.0-43.43, and this device has 7.0.0-43.43 (Ubuntu security notices)."
	if f.State != StateHandled || f.ResolvedBy != SystemUser || f.Note != want {
		t.Fatalf("closed %+v, want Vedette's close with the note %q", f, want)
	}
	if got := proofReason(ViaVersionMoved, proof); got != "" {
		t.Errorf("a version move took a proof's note: %q", got)
	}
}

// Two software lines of one product with one CVE each close with their own line's proof: the closing note of one line never says
// the other line's package release. The matcher hands the proof of every line, and the reconcile keys them by CVE and line.
func TestReconcile_EachLineClosesWithItsOwnProof(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	pkg := func(id, full string) Software {
		return Software{ID: id, Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", KevKeys: []string{"openbsd|openssh"},
			Source: "agent", Packaged: true, PkgVersion: full, PkgSource: "openssh"}
	}
	v := Vuln{CVE: "CVE-2026-10001", Vendor: "OpenBSD", Product: "OpenSSH",
		Affected: []Affected{{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "10.6p2"}}},
		Distro:   []DistroFix{{Distro: "ubuntu", Release: "24.04", Package: "openssh", Status: "fixed", Fixed: "1:9.6p1-3ubuntu13.5"}}}
	r := MatchAsset(Asset{ID: "a", Name: "web-01", OS: "Ubuntu 24.04.1 LTS", Software: []Software{pkg("s-a", "1:9.6p1-3ubuntu13.5"), pkg("s-b", "1:9.6p1-3ubuntu13.14")}},
		[]Vuln{v}, map[string]bool{v.CVE: true}, now)
	if len(r.NotAffected) != 1 || len(r.NotAffected[0].each) != 2 {
		t.Fatalf("not affected %+v, want one proof per line", r.NotAffected)
	}
	for _, p := range r.NotAffected[0].each {
		want := map[string]string{"s-a": "this device has 1:9.6p1-3ubuntu13.5 ", "s-b": "this device has 1:9.6p1-3ubuntu13.14 "}[p.SoftwareID]
		if want == "" || !strings.Contains(p.Evidence.Summary, want) {
			t.Errorf("proof of %s: %q, want it to say %q", p.SoftwareID, p.Evidence.Summary, want)
		}
	}

	e := newEnv(t)
	swA := Software{ID: "s-a", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", Source: "agent", SeenAt: t0}
	swB := Software{ID: "s-b", Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", Source: "agent", SeenAt: t0}
	a := Asset{ID: "a-1", Name: "host-1", Software: []Software{swA, swB}}
	e.matchPass(t, a, MatchResult{New: []Match{versionMatch(swA), versionMatch(swB)}})
	proof := func(id, has string) Match {
		return Match{CVE: "CVE-2026-1001", SoftwareID: id, Evidence: Evidence{CheckedAt: t0, Summary: "Not affected: Ubuntu 24.04 fixed CVE-2026-1001 in openssh 1:9.6p1-3ubuntu13.5, and this device has " +
			has + " (Ubuntu security data). Vedette closed this by itself and reopens it if a later match says the device is affected."}}
	}
	pa, pb := proof("s-a", "1:9.6p1-3ubuntu13.5"), proof("s-b", "1:9.6p1-3ubuntu13.14")
	carried := pa
	carried.each = []Match{pa, pb}
	e.matchPass(t, a, MatchResult{NotAffected: []Match{carried}})
	fs, err := e.svc.Findings(t.Context(), "a-1")
	if err != nil || len(fs) != 2 {
		t.Fatalf("findings %+v %v", fs, err)
	}
	for _, f := range fs {
		want := map[string]string{"s-a": "and this device has 1:9.6p1-3ubuntu13.5 (", "s-b": "and this device has 1:9.6p1-3ubuntu13.14 ("}[f.SoftwareID]
		if f.State != StateHandled || !strings.Contains(f.Note, want) {
			t.Errorf("%s: state %s, note %q, want its own line's %q", f.SoftwareID, f.State, f.Note, want)
		}
	}
}
