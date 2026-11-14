package feeds

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

var vcNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// vcEntryJSON is one entry as VulnCheck writes it (cve is an array).
func vcEntryJSON(cve, vendor, product, added, cisa string) string {
	c := ""
	if cisa != "" {
		c = fmt.Sprintf(`,"cisa_date_added":%q`, cisa)
	}
	return fmt.Sprintf(`{"vendorProject":%q,"product":%q,"shortDescription":"d","vulnerabilityName":"%s flaw","required_action":"Apply updates.","knownRansomwareCampaignUse":"Unknown","cve":[%q],"vulncheck_reported_exploitation":[{"url":"https://example.org/%s","date_added":"2026-10-30T00:00:00.000Z"},{"url":"http://plain.example/x","date_added":"2026-10-31T00:00:00.000Z"}],"date_added":%q%s}`,
		vendor, product, product, cve, cve, added+"T00:00:00.000Z", c)
}

func vcPage(totalPages int, entries ...string) string {
	return fmt.Sprintf(`{"_benchmark":0.01,"_meta":{"timestamp":"2026-11-05T12:00:00Z","index":"vulncheck-kev","limit":100,"total_pages":%d,"page":1},"data":[%s]}`, totalPages, strings.Join(entries, ","))
}

// D-557: only recent entries CISA does not list become vulncheck-kev entries; a bad entry is rejected and counted.
func TestParseVulnCheckPage(t *testing.T) {
	t.Parallel()
	res, err := ParseVulnCheckPage([]byte(vcPage(3,
		vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", ""),
		vcEntryJSON("CVE-2026-1002", "Acme", "Router", "2026-10-30", "2026-11-01"), // CISA lists it
		vcEntryJSON("CVE-2024-1003", "Acme", "Old", "2024-01-30", ""),              // older than the window
		vcEntryJSON("not-a-cve", "Acme", "Bad", "2026-10-30", ""),
		`{"cve":["CVE-2026-1004"],"vendorProject":"Acme","product":"P","date_added":"yesterday"}`,
		`{"cve":["CVE-2026-1005"],"vendorProject":7,"product":"P"}`,
		`{"cve":["CVE-2026-1006"],"vendorProject":"Acme\u0000x","product":"P","date_added":"2026-10-30T00:00:00Z"}`,
	)), vcNow)
	if err != nil || res.TotalPages != 3 || res.FirstCVE != "CVE-2026-1001" || len(res.Vulns) != 1 || res.Accepted != 3 || res.Rejected != 4 {
		t.Fatalf("%+v %v", res, err)
	}
	v := res.Vulns[0]
	if v.CVE != "CVE-2026-1001" || v.DateAdded != "2026-10-30" || !slices.Equal(v.Links, []string{"https://example.org/CVE-2026-1001"}) || // the http link is dropped
		!strings.HasPrefix(v.RequiredAction, vulnCheckAction+" First reported exploited 2026-10-30. Apply updates.") {
		t.Errorf("vuln = %+v", v)
	}
	for name, body := range map[string]string{
		"html": `<html>sign in</html>`, "no data": `{"_meta":{}}`, "data not a list": `{"data":{"x":1}}`,
		"too large": `{"data":[` + strings.Repeat(" ", MaxBodyBytes) + `]}`,
	} {
		if _, err := ParseVulnCheckPage([]byte(body), vcNow); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a page claiming more than twice the page size is cut: the rest is not trusted
	many := make([]string, vulnCheckPage*2+50)
	for i := range many {
		many[i] = vcEntryJSON(fmt.Sprintf("CVE-2026-%05d", 2000+i), "Acme", "P", "2026-10-30", "")
	}
	if res, err := ParseVulnCheckPage([]byte(vcPage(1, many...)), vcNow); err != nil || len(res.Vulns) != vulnCheckPage*2 || !res.Truncated {
		t.Errorf("oversize: %d %v %v", len(res.Vulns), res.Truncated, err)
	}
}

func TestVulnCheckPageURL(t *testing.T) {
	t.Parallel()
	u, err := VulnCheckPageURL("https://api.vulncheck.com/v3/index/vulncheck-kev", 2)
	if err != nil || u != "https://api.vulncheck.com/v3/index/vulncheck-kev?limit=100&page=2" {
		t.Fatalf("%q %v", u, err)
	}
	for _, bad := range []string{"https://api.vulncheck.com/v3?token=abc", "http://example.com/x", "https://u:p@example.com/x"} {
		if _, err := VulnCheckPageURL(bad, 1); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// D-557: OFF means no request; the key is stored sealed and shown as its last four characters; the feed sends it only as
// the bearer header; its CVEs become exploited entries next to CISA's (CISA wins), get CVE.org ranges, and everything
// goes when the key is removed.
func TestContract_VulnCheckKEV_BYOK(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only() // every feed off; VulnCheck KEV stays off until a key is saved
	e.mirror("vulncheck-kev", o.url("/vc"))
	const key = "vckey-ABCDEF123456"
	applyV(t, e.db, epoch0, "cisa-kev", []Vuln{vuln("CVE-2026-1002", "Acme", "Router", "2026-11-01")}, false)
	o.serve("/vc", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(vcPage(2, vcEntryJSON("CVE-2026-1003", "Initech", "Portal", "2026-11-02", ""))))
			return
		}
		_, _ = w.Write([]byte(vcPage(2,
			vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", ""),
			vcEntryJSON("CVE-2026-1002", "Acme", "Router", "2026-10-30", "2026-11-01"))))
	})

	// off, and no key: no request, and it cannot be turned on
	if c, b := e.put("vulncheck-kev", `{"enabled":true}`); c != 400 || code(b) != "invalid_auth" {
		t.Fatalf("on without a key: %d %v", c, b)
	}
	if c, _ := e.fetch("vulncheck-kev"); c == 200 || len(o.all()) != 0 {
		t.Fatalf("fetched while off: %d, %d requests", c, len(o.all()))
	}
	if c, b := e.put("vulncheck-kev", `{"api_key":"short"}`); c != 400 || code(b) != "invalid_auth" {
		t.Fatalf("short key: %d %v", c, b)
	}
	if c, b := e.put("ipsum", `{"api_key":"`+key+`"}`); c != 400 {
		t.Fatalf("a key on another feed: %d %v", c, b)
	}

	// saving the key turns it on
	c, b := e.put("vulncheck-kev", `{"api_key":"`+key+`"}`)
	if c != 200 || at(b, "enabled") != true || at(b, "auth", "type") != "bearer" || at(b, "auth", "secret_last4") != "3456" || strings.Contains(fmt.Sprint(b), "ABCDEF") {
		t.Fatalf("save key: %d %v", c, b)
	}
	if _, list := e.get("/feeds/sources"); strings.Contains(fmt.Sprint(list), "ABCDEF") {
		t.Fatal("the key is in the feed list")
	}
	var plain int
	_ = e.db.Reader().QueryRowContext(t.Context(), `SELECT count(*) FROM feeds_source WHERE id = 'vulncheck-kev' AND secret_id IS NOT NULL AND (url || coalesce(error, '') || coalesce(secret_last4, '')) NOT LIKE '%ABCDEF%'`).Scan(&plain)
	if plain != 1 {
		t.Fatal("the key is not held by core/secrets or leaks into the row")
	}
	c, b = e.fetch("vulncheck-kev")
	if c != 200 || at(b, "status") != "ok" || at(b, "records") != 2.0 {
		t.Fatalf("fetch: %d %v", c, b)
	}
	for _, h := range o.all() {
		if strings.Contains(h.query, "ABCDEF") || strings.Contains(h.query, "token") {
			t.Fatalf("the key is in the address: %s", h.query)
		}
	}
	if strings.Contains(e.auditText(), "ABCDEF") {
		t.Fatal("the key is in the audit log")
	}
	rows, err := e.svc.st.KevVulns(t.Context())
	owners := map[string]string{}
	for _, r := range rows {
		owners[r.CVE] = r.SourceID
	}
	if err != nil || len(owners) != 3 || owners["CVE-2026-1001"] != "vulncheck-kev" || owners["CVE-2026-1003"] != "vulncheck-kev" || owners["CVE-2026-1002"] != "cisa-kev" {
		t.Fatalf("owners = %v %v", owners, err)
	}
	if base := e.pub.named(EventSyncBaseline); len(base) != 1 || base[0] != (SyncBaselineEvent{Source: "vulncheck-kev", Count: 2}) {
		t.Errorf("first fill: %v", base)
	}
	if keys, err := e.svc.st.KevCVEsByKeys(t.Context(), []string{"acme|gateway"}); err != nil || !slices.Equal(keys, []string{"CVE-2026-1001"}) {
		t.Errorf("matching by product: %v %v", keys, err)
	}
	// its CVEs are among those CVE.org is asked for ranges (NVD has none)
	todo, err := e.svc.st.cveOrgTodo(t.Context(), vcNow, 10)
	if err != nil || len(todo) != 3 {
		t.Errorf("CVE.org todo: %v %v", todo, err)
	}

	// a new entry later is news, not baseline
	e.setNow(e.clock().Add(7 * time.Hour))
	o.serve("/vc", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(vcPage(1, vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", ""), vcEntryJSON("CVE-2026-1009", "Acme", "Gateway", "2026-11-05", ""))))
	})
	if c, _ := e.fetch("vulncheck-kev"); c != 200 {
		t.Fatal(c)
	}
	if news := e.pub.named(EventNewKEV); len(news) != 1 || news[0].(NewKEVEvent).CVE != "CVE-2026-1009" {
		t.Errorf("new_kev: %v", news)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_vuln WHERE source_id = 'vulncheck-kev'`); n != 2 { // 1003 is no longer listed
		t.Errorf("%d rows", n)
	}

	// a refused key is the customer's to fix; the text never has the key
	e.setNow(e.clock().Add(7 * time.Hour))
	o.serve("/vc", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	e.fetch("vulncheck-kev")
	if f := e.feed("vulncheck-kev"); f.Status != "error" || f.Error == nil || !strings.Contains(*f.Error, "did not accept the API key") || strings.Contains(*f.Error, "ABCDEF") {
		t.Fatalf("feed = %+v", f)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_vuln WHERE source_id = 'vulncheck-kev'`); n != 2 {
		t.Errorf("a refused pull changed the data: %d rows", n)
	}

	// removing the key: off, data gone, key gone; the CISA entry stays
	c, b = e.put("vulncheck-kev", `{"api_key":""}`)
	if c != 200 || at(b, "enabled") != false || at(b, "auth", "type") != "none" || at(b, "auth", "secret_last4") != nil || at(b, "status") != "never" {
		t.Fatalf("remove key: %d %v", c, b)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_vuln WHERE source_id = 'vulncheck-kev'`); n != 0 {
		t.Errorf("%d rows left", n)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_vuln WHERE source_id = 'cisa-kev'`); n != 1 {
		t.Errorf("CISA rows: %d", n)
	}
	if n := count(t, e.db, `SELECT count(*) FROM core_secret WHERE purpose = 'feeds_source.secret'`); n != 0 {
		t.Errorf("%d secrets left", n)
	}
}
