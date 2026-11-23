package feeds

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// The signals of the four sample CVEs, read through ReadUrgencyFacts after real pulls of the frozen fixtures (the Metasploit, Exploit-DB
// and PoC-in-GitHub indexes, Rapid7's blog, and CISA's list with the Synology entry of 18 Nov 2026), are the qualifying signals of
// findings' sample fixture (modules/findings/testdata/urgency-samples.json), which findings rates into their layers. A decoder that
// reads another day or source breaks this test, not only the decoder's own.
func TestUrgencyFacts_TheFourSampleCVEsFromTheFrozenFixtures(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.setNow(time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC))
	e.only(metasploitFeedID, exploitDBFeedID, pocGitHubFeedID, rapid7FeedID, "cisa-kev")
	for _, f := range []struct{ id, path, file string }{
		{metasploitFeedID, "/msf.json", "metasploit.json.gz"},
		{exploitDBFeedID, "/edb.csv", "exploitdb.csv.gz"},
		{pocGitHubFeedID, "/poc.tar.gz", "poc-in-github.tar.gz"},
	} {
		b := fixtureBytes(t, f.file)
		if f.id != pocGitHubFeedID {
			b = gunzipBytes(t, b)
		}
		o.body(f.path, `"`+f.id+`"`, string(b))
		e.mirror(f.id, o.url(f.path))
	}
	o.body("/rapid7.xml", `"r7"`, string(textFixture(t, "rapid7.xml.gz")))
	e.mirror(rapid7FeedID, o.url("/rapid7.xml"))
	o.body("/kev.json", `"kev"`, `{"title":"CISA Catalog of Known Exploited Vulnerabilities","catalogVersion":"2026.11.18","dateReleased":"2026-11-18T14:00:00.000Z","count":1,
"vulnerabilities":[{"cveID":"CVE-2024-10441","vendorProject":"Synology","product":"DiskStation Manager","vulnerabilityName":"Synology DiskStation Manager Improper Encoding or Escaping of Output Vulnerability",
"dateAdded":"2026-11-18","shortDescription":"Synology DiskStation Manager contains an improper encoding or escaping of output vulnerability.","requiredAction":"Apply mitigations per vendor instructions.",
"dueDate":"2026-12-09","knownRansomwareCampaignUse":"Unknown","notes":"https://example.com/advisory/synology","cwes":["CWE-116"]}]}`)
	e.mirror("cisa-kev", o.url("/kev.json"))
	for _, id := range []string{metasploitFeedID, exploitDBFeedID, pocGitHubFeedID, rapid7FeedID, "cisa-kev"} {
		if err := e.svc.Fetch(t.Context(), id); err != nil {
			t.Fatal(err)
		}
		if st := e.feed(id); st.Status != "ok" {
			t.Fatalf("%s: %+v %q", id, st, deref(st.Error))
		}
	}

	b, err := os.ReadFile("../findings/testdata/urgency-samples.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Samples []struct {
			CVE     string `json:"cve"`
			Signals []struct {
				Kind      string    `json:"kind"`
				Source    string    `json:"source"`
				FirstSeen time.Time `json:"first_seen"`
				Qualifies bool      `json:"qualifies"`
			} `json:"signals"`
		} `json:"samples"`
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	var cves []string
	for _, s := range fx.Samples {
		cves = append(cves, s.CVE)
	}
	facts, err := ReadUrgencyFacts(t.Context(), e.db.Reader(), cves)
	if err != nil {
		t.Fatal(err)
	}
	key := func(kind, source string, day time.Time) string {
		return kind + " " + source + " " + day.UTC().Format(time.DateOnly)
	}
	for _, s := range fx.Samples {
		var want, got []string
		for _, g := range s.Signals {
			if g.Qualifies {
				want = append(want, key(g.Kind, g.Source, g.FirstSeen))
			}
		}
		for _, g := range facts[s.CVE].Signals {
			if g.Qualifies {
				got = append(got, key(g.Kind, g.Source, g.FirstSeen))
			}
		}
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s: the decoders give %s, the sample fixture holds %s", s.CVE, strings.Join(got, "; "), strings.Join(want, "; "))
		}
	}
}
