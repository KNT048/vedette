package feeds

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// checkClaims is what must hold for any claim a vendor decoder returns: a CVE id within the bounds of feeds_signal and a date.
func checkClaims(t *testing.T, claims []vendorClaim) {
	t.Helper()
	for _, c := range claims {
		if len(c.CVE) > 20 || !cveRE.MatchString(c.CVE) || c.Date.IsZero() {
			t.Fatalf("claim %+v", c)
		}
	}
}

func FuzzParseMSRCExploited(f *testing.F) {
	f.Add([]byte(msrcList(msrcRow("CVE-2026-0001", "2026-11-10T08:00:00-08:00"))))
	f.Add([]byte(`{"@odata.nextLink":"https://example.com/x","value":[{"cveNumber":"ADV1","exploited":"Yes"},{"cveNumber":1}]}`))
	f.Add([]byte(`{"value":[{"cveNumber":"CVE-2026-1","releaseDate":"2026-01-01T00:00:00Z","exploited":"Yes","revisions":[{"revisionDate":"x"}]}]} {}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		pg, err := parseMSRCExploited(bytes.NewReader(data))
		if err == nil {
			checkClaims(t, pg.Claims)
		}
	})
}

func FuzzParseCSAF(f *testing.F) {
	f.Add([]byte(ciscoDoc("cisco-sa-a", "2026-01-01T00:00:00Z", "The PSIRT is aware of attempted exploitation of CVE-2026-0001. Not CVE-2026-0002.", []string{`{"date":"2026-01-02T00:00:00Z","summary":"exploited CVE-2026-0001"}`}, "CVE-2026-0001", "CVE-2026-0002")))
	f.Add([]byte(fortiDoc("FG-IR-26-1", "2026-01-01T00:00:00", [2]string{"CVE-2026-0001", "<p>This is being exploited in the wild.</p>"})))
	f.Add([]byte(`{"document":{"tracking":{"id":"x","initial_release_date":"2026-01-01"}},"vulnerabilities":[{"cve":"cve-1-1","threats":[{"category":"exploit_status","details":"Exploited:Yes"}]}]}`))
	for _, doc := range slowShapes(1) { // the shapes that once cost minutes: many CVEs claimed again and again, revisions naming many CVEs
		f.Add([]byte(doc))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := parseCSAF(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, claims := range []func(context.Context, csafDoc, *claimWork) ([]vendorClaim, int, error){ciscoClaims, fortinetClaims} {
			cs, _, err := claims(t.Context(), d, nil)
			if err != nil {
				t.Fatal(err)
			}
			checkClaims(t, cs)
		}
	})
}

func FuzzParseAdvisoryFeeds(f *testing.F) {
	f.Add([]byte(ciscoFeed([2]string{"cisco-sa-a-12345678", "2026-11-20 16:00:00.0"})))
	f.Add([]byte(fortiFeed([2]string{"FG-IR-26-100", "https://filestore.fortinet.com/fortiguard/psirt/csaf_a.json"})))
	f.Add([]byte(`<rss><channel><item><link>a/b</link><guid>../x</guid></item></channel></rss>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, parse := range []func(*bytes.Reader) ([]csafRef, Stats, error){
			func(r *bytes.Reader) ([]csafRef, Stats, error) { return parseCiscoFeed(r) },
			func(r *bytes.Reader) ([]csafRef, Stats, error) { return parseFortiGuardFeed(r) },
		} {
			refs, _, err := parse(bytes.NewReader(data))
			if err != nil {
				continue
			}
			for _, r := range refs {
				// every document is asked of the feed's own host at a checked path: no way up, no query, no other host
				if !strings.HasPrefix(r.Path, "/") || strings.Contains(r.Path, "..") || strings.ContainsAny(r.Path, "?#\\ ") || r.ID == "" {
					t.Fatalf("ref %+v", r)
				}
			}
		}
	})
}

func FuzzClaimForms(f *testing.F) {
	f.Add("The Cisco PSIRT is aware of attempted exploitation of CVE-2026-0001, but not aware of malicious use of CVE-2026-0002.", "CVE-2026-0001")
	f.Add("<p>Fortinet has observed this to be exploited in the wild&nbsp;.</p>", "CVE-2026-0003")
	f.Add(strings.Repeat("These vulnerabilities are exploited in the wild. ", 500), "CVE-2026-0004")
	f.Fuzz(func(t *testing.T, text, scope string) {
		for _, forms := range [][]claimForm{ciscoForms, fortinetForms} {
			r := newClaimReader(forms, csafMaxClaimText, nil)
			if err := r.read(t.Context(), text, []string{scope}, map[string]bool{scope: true}); err != nil {
				t.Fatal(err)
			}
			if got := r.result(); len(got) > 1 || (len(got) == 1 && got[0] != scope) {
				t.Fatalf("%q claims %v outside its scope", text, got)
			}
		}
	})
}
