package feeds

import (
	"strings"
	"testing"
	"time"
)

// POST-1, D-144: feeds keeps a record of every new_kev it announced, so a subscriber that missed the event (module
// off, process down) can catch up. The baseline pull (D-78) and custom feeds announce nothing; paging is by (At, CVE).
func TestContract_POST1_NewKEVSinceListsWhatWasAnnounced(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("cisa-kev")
	e.mirror("cisa-kev", o.url("/kev.json"))
	kev := testFile(t, "kev.json")
	o.body("/kev.json", `"v1"`, kev)
	if c, b := e.fetch("cisa-kev"); c != 200 {
		t.Fatalf("%d %v", c, b)
	}
	st := e.svc.st
	zero := time.Time{}
	if got, err := st.NewKEVSince(t.Context(), zero, "", 10); err != nil || len(got) != 0 {
		t.Fatalf("after the baseline pull: %v %v (D-78: it announces nothing)", got, err)
	}

	entry := func(cve string) string {
		return `{"cveID":"` + cve + `","vendorProject":"Acme","product":"Box","vulnerabilityName":"n","dateAdded":"2026-11-04","shortDescription":"d","requiredAction":"a","dueDate":"2026-11-25","knownRansomwareCampaignUse":"Unknown","notes":""},`
	}
	o.body("/kev.json", `"v2"`, strings.Replace(kev, `"vulnerabilities": [`, `"vulnerabilities": [`+entry("CVE-2026-10099")+entry("CVE-2026-10098"), 1))
	e.setNow(e.clock().Add(time.Hour))
	pulled := e.clock()
	if c, b := e.fetch("cisa-kev"); c != 200 {
		t.Fatalf("%d %v", c, b)
	}
	got, err := st.NewKEVSince(t.Context(), zero, "", 10)
	if err != nil || len(got) != 2 || got[0].CVE != "CVE-2026-10098" || got[1].CVE != "CVE-2026-10099" {
		t.Fatalf("announced: %+v %v", got, err)
	}
	if !got[0].At.Equal(pulled) || got[0].Vendor != "Acme" || got[0].Product != "Box" || got[0].DateAdded != "2026-11-04" || got[0].HasTemplate {
		t.Errorf("entry: %+v (announced at %v)", got[0], pulled)
	}

	// one at a time, from the last one handled
	page, err := st.NewKEVSince(t.Context(), zero, "", 1)
	if err != nil || len(page) != 1 || page[0].CVE != "CVE-2026-10098" {
		t.Fatalf("first page: %+v %v", page, err)
	}
	page, err = st.NewKEVSince(t.Context(), page[0].At, page[0].CVE, 1)
	if err != nil || len(page) != 1 || page[0].CVE != "CVE-2026-10099" {
		t.Fatalf("second page: %+v %v", page, err)
	}
	if page, err = st.NewKEVSince(t.Context(), page[0].At, page[0].CVE, 1); err != nil || len(page) != 0 {
		t.Fatalf("after the last: %+v %v", page, err)
	}

	// the same catalog again announces nothing new; a custom feed's CVE is never announced
	e.setNow(e.clock().Add(time.Hour))
	e.fetch("cisa-kev")
	addCustom(t, e.db, "custom-1", "Partner CVEs", KindVulnerabilities)
	applyV(t, e.db, e.clock(), "custom-1", []Vuln{vuln("CVE-2026-30001", "Partner", "Thing", "2026-11-01")}, false)
	if got, _ = st.NewKEVSince(t.Context(), zero, "", 10); len(got) != 2 {
		t.Errorf("announced after a repeat and a custom feed: %+v", got)
	}

	for _, n := range []int{0, -1, MaxNewKEVPage + 1} {
		if _, err := st.NewKEVSince(t.Context(), zero, "", n); err == nil {
			t.Errorf("limit %d accepted", n)
		}
	}
}
