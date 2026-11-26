package feeds

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strconv"
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

// vcPage is one page of the list in the shape of VulnCheck's cursor paging (fake data): total is the entries of the whole list
// (_meta.total_documents, 0 leaves it out), next the cursor of the next page ("" on the last page).
func vcPage(total int, next string, entries ...string) string {
	meta := `"timestamp":"2026-11-05T12:00:00Z","index":"vulncheck-kev","limit":100,"sort":"_timestamp","order":"desc"`
	if total > 0 {
		meta += fmt.Sprintf(`,"total_documents":%d,"total_pages":%d,"max_pages":6`, total, (total+99)/100)
	}
	if next != "" {
		meta += fmt.Sprintf(`,"next_cursor":%q`, next)
	}
	return fmt.Sprintf(`{"_benchmark":0.01,"_meta":{%s},"data":[%s]}`, meta, strings.Join(entries, ","))
}

// Only recent entries CISA does not list become vulncheck-kev entries; a bad entry is rejected and counted.
func TestParseVulnCheckPage(t *testing.T) {
	t.Parallel()
	res, err := ParseVulnCheckPage([]byte(vcPage(250, "c2",
		vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", ""),
		vcEntryJSON("CVE-2026-1002", "Acme", "Router", "2026-10-30", "2026-11-01"), // CISA lists it
		vcEntryJSON("CVE-2024-1003", "Acme", "Old", "2024-01-30", ""),              // older than the window
		vcEntryJSON("not-a-cve", "Acme", "Bad", "2026-10-30", ""),
		`{"cve":["CVE-2026-1004"],"vendorProject":"Acme","product":"P","date_added":"yesterday"}`,
		`{"cve":["CVE-2026-1005"],"vendorProject":7,"product":"P"}`,
		`{"cve":["CVE-2026-1006"],"vendorProject":"Acme\u0000x","product":"P","date_added":"2026-10-30T00:00:00Z"}`,
	)), vcNow, nil)
	if err != nil || res.Total != 250 || res.NextCursor != "c2" || res.Entries != 7 || res.FirstCVE != "CVE-2026-1001" || len(res.Vulns) != 1 || res.Accepted != 3 || res.Rejected != 4 {
		t.Fatalf("%+v %v", res, err)
	}
	v := res.Vulns[0]
	if v.CVE != "CVE-2026-1001" || v.DateAdded != "2026-10-30" || !slices.Equal(v.Links, []string{"https://example.org/CVE-2026-1001"}) || // the http link is dropped
		!strings.HasPrefix(v.RequiredAction, vulnCheckAction+" First reported exploited 2026-10-30. Apply updates.") {
		t.Errorf("vuln = %+v", v)
	}
	for name, body := range map[string]string{
		"html": `<html>sign in</html>`, "no data": `{"_meta":{}}`, "data not a list": `{"data":{"x":1}}`,
		"too large":           `{"data":[` + strings.Repeat(" ", MaxBodyBytes) + `]}`,
		"cursor with a space": `{"_meta":{"next_cursor":"a b"},"data":[]}`,
		"cursor too long":     `{"_meta":{"next_cursor":"` + strings.Repeat("a", vulnCheckMaxCur+1) + `"},"data":[]}`,
	} {
		if _, err := ParseVulnCheckPage([]byte(body), vcNow, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a page claiming more than twice the page size is cut: the rest is not trusted
	many := make([]string, vulnCheckPage*2+50)
	for i := range many {
		many[i] = vcEntryJSON(fmt.Sprintf("CVE-2026-%05d", 2000+i), "Acme", "P", "2026-10-30", "")
	}
	if res, err := ParseVulnCheckPage([]byte(vcPage(len(many), "", many...)), vcNow, nil); err != nil || len(res.Vulns) != vulnCheckPage*2 || !res.Truncated {
		t.Errorf("oversize: %d %v %v", len(res.Vulns), res.Truncated, err)
	}
}

func TestVulnCheckPageURL(t *testing.T) {
	t.Parallel()
	const base = "https://api.vulncheck.com/v3/index/vulncheck-kev"
	u, err := VulnCheckPageURL(base, "")
	if err != nil || u != base+"?limit=100&start_cursor=true" {
		t.Fatalf("first page: %q %v", u, err)
	}
	if u, err = VulnCheckPageURL(base, "c2/+="); err != nil || u != base+"?cursor=c2%2F%2B%3D&limit=100" {
		t.Fatalf("next page: %q %v", u, err)
	}
	for _, bad := range []string{"https://api.vulncheck.com/v3?token=abc", "http://example.com/x", "https://u:p@example.com/x"} {
		if _, err := VulnCheckPageURL(bad, ""); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// VulnCheck's warnings reach the customer as plain text: a list or one text, control characters dropped, at most 200 characters.
func TestVulnCheckPage_Warnings(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		`"warnings":["Results limited by plan.","Second."]`: "Results limited by plan; Second",
		`"warnings":"One text"`:                             "One text",
		`"warnings":{"x":1}`:                                "",
		`"warnings":["bad\u0007"]`:                          "",
		`"warnings":["` + strings.Repeat("w", 300) + `"]`:   strings.Repeat("w", 200),
	} {
		res, err := ParseVulnCheckPage([]byte(`{"_meta":{"truncated":true,`+raw+`},"data":[]}`), vcNow, nil)
		if err != nil || res.Warning != want || !res.Short {
			t.Errorf("%s: %q %v %v", raw, res.Warning, res.Short, err)
		}
	}
}

// OFF means no request; the key is stored sealed and shown as its last four characters; the feed sends it only as
// the bearer header; its CVEs become exploited entries next to CISA's (CISA wins), get CVE.org ranges, and everything
// goes when the key is removed.
func TestContract_VulnCheckKEV_BYOK(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only()                                // every feed off; VulnCheck KEV stays off until a key is saved
	e.setURL("vulncheck-kev", o.url("/vc")) // no mirror through the API (L3): the test points the address itself
	if c, b := e.put("vulncheck-kev", `{"url":"https://example.net/vc"}`); c != 400 || code(b) != "invalid_url" {
		t.Fatalf("an address for the key to follow: %d %v", c, b)
	}
	const key = "vckey-ABCDEF123456"
	applyV(t, e.db, epoch0, "cisa-kev", []Vuln{vuln("CVE-2026-1002", "Acme", "Router", "2026-11-01")}, false)
	o.serve("/vc", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("cursor") == "c2" {
			_, _ = w.Write([]byte(vcPage(3, "", vcEntryJSON("CVE-2026-1003", "Initech", "Portal", "2026-11-02", ""))))
			return
		}
		_, _ = w.Write([]byte(vcPage(3, "c2",
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
		if strings.Contains(h.query, "ABCDEF") || strings.Contains(h.query, "token") || strings.Contains(h.query, "page=") {
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
	// its CVEs are among those whose CVE record is asked for by ID (a public list names them)
	todo, err := e.svc.st.recordDue(t.Context(), vcNow, 10)
	if err != nil || len(todo) != 3 {
		t.Errorf("CVE records due: %v %v", todo, err)
	}

	// a new entry later is news, not baseline
	e.setNow(e.clock().Add(7 * time.Hour))
	o.serve("/vc", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(vcPage(2, "", vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", ""), vcEntryJSON("CVE-2026-1009", "Acme", "Gateway", "2026-11-05", ""))))
	})
	if c, _ := e.fetch("vulncheck-kev"); c != 200 {
		t.Fatal(c)
	}
	if news := e.pub.named(EventNewKEV); len(news) != 1 || news[0].(NewKEVEvent).CVE != "CVE-2026-1009" {
		t.Errorf("new_kev: %v", news)
	}
	// the announcement is recorded with the entry, so a subscriber that missed the event catches up; the first fill is not
	if got, err := e.svc.st.NewKEVSince(t.Context(), time.Time{}, "", 10); err != nil || len(got) != 1 || got[0].CVE != "CVE-2026-1009" ||
		got[0].Vendor != "Acme" || got[0].Product != "Gateway" || !got[0].At.Equal(e.clock()) {
		t.Errorf("announced: %+v %v", got, err)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_kev WHERE list = 'vulncheck'`); n != 2 { // 1003 is no longer listed
		t.Errorf("%d rows", n)
	}

	// a refused key is the customer's to fix; the text never has the key
	e.setNow(e.clock().Add(7 * time.Hour))
	o.serve("/vc", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	e.fetch("vulncheck-kev")
	if f := e.feed("vulncheck-kev"); f.Status != "error" || f.Error == nil || !strings.Contains(*f.Error, "did not accept the API key") || strings.Contains(*f.Error, "ABCDEF") {
		t.Fatalf("feed = %+v", f)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_kev WHERE list = 'vulncheck'`); n != 2 {
		t.Errorf("a refused pull changed the data: %d rows", n)
	}

	// removing the key: off, data gone, key gone; the CISA entry stays
	c, b = e.put("vulncheck-kev", `{"api_key":""}`)
	if c != 200 || at(b, "enabled") != false || at(b, "auth", "type") != "none" || at(b, "auth", "secret_last4") != nil || at(b, "status") != "never" {
		t.Fatalf("remove key: %d %v", c, b)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_kev WHERE list = 'vulncheck'`); n != 0 {
		t.Errorf("%d rows left", n)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_kev WHERE list = 'cisa'`); n != 1 {
		t.Errorf("CISA rows: %d", n)
	}
	if n := count(t, e.db, `SELECT count(*) FROM core_secret WHERE purpose = 'feeds_source.secret'`); n != 0 {
		t.Errorf("%d secrets left", n)
	}

	// saving a key again is a first fill again: quiet, however many entries come back (review L2)
	before := len(e.pub.named(EventNewKEV))
	e.setNow(e.clock().Add(time.Hour))
	o.serve("/vc", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(vcPage(1, "", vcEntryJSON("CVE-2026-1001", "Acme", "Gateway", "2026-10-30", ""))))
	})
	if c, _ := e.put("vulncheck-kev", `{"api_key":"`+key+`"}`); c != 200 {
		t.Fatal(c)
	}
	if c, _ := e.fetch("vulncheck-kev"); c != 200 || len(e.pub.named(EventNewKEV)) != before || len(e.pub.named(EventSyncBaseline)) != 2 {
		t.Errorf("a key saved again alerted: new_kev %d -> %d, baselines %d", before, len(e.pub.named(EventNewKEV)), len(e.pub.named(EventSyncBaseline)))
	}
}

func (e *env) setURL(id, url string) {
	e.t.Helper()
	write(e.t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.t.Context(), `UPDATE feeds_source SET url = ? WHERE id = ?`, url, id)
		return err
	})
}

// Review M1: a list that is not provably complete fails the pull and the rows loaded before stay. Each case is the shape of an
// answer (fake data) and the reason the customer reads.
func TestVulnCheckPull_FailsClosedWhenTheListIsNotComplete(t *testing.T) {
	t.Parallel()
	entry := func(n int) string {
		return vcEntryJSON(fmt.Sprintf("CVE-2026-%05d", 10000+n), "Acme", "Gateway", "2026-10-30", "")
	}
	// n is the page asked for: 1 without a cursor, else the number in the cursor "c<n>"
	for name, tc := range map[string]struct {
		serve func(n int) string
		why   string
	}{
		"no entry count": {func(int) string { return `{"data":[` + entry(1) + `]}` }, "did not say how many entries"},
		"goes on and on": {func(n int) string { return vcPage(999_999, fmt.Sprintf("c%d", n+1), entry(n)) }, "goes on past 50,000 entries"},
		"same cursor":    {func(int) string { return vcPage(300, "c2", entry(1)) }, "the same page came back twice"},
		"cursor ignored": {func(n int) string { return vcPage(300, fmt.Sprintf("c%d", n+1), entry(1)) }, "the same page came back twice"},
		"an empty page": {func(n int) string {
			if n == 2 {
				return vcPage(300, "c3")
			}
			return vcPage(300, fmt.Sprintf("c%d", n+1), entry(n))
		}, "a page was empty"},
		"stopped short": {func(n int) string {
			if n == 2 {
				return `{"_meta":{"total_documents":300,"truncated":true,"warnings":["Results limited by plan."]},"data":[` + entry(2) + `]}`
			}
			return vcPage(300, "c2", entry(1))
		}, "VulnCheck stopped after 2 of its 300 entries; it said: Results limited by plan"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, o := pullEnv(t)
			e.only()
			e.setURL("vulncheck-kev", o.url("/vc"))
			if c, b := e.put("vulncheck-kev", `{"api_key":"vckey-ABCDEF123456"}`); c != 200 {
				t.Fatalf("%d %v", c, b)
			}
			applyV(t, e.db, epoch0, "vulncheck-kev", []Vuln{vuln("CVE-2026-1099", "Acme", "Old", "2026-10-01")}, false)
			o.serve("/vc", func(w http.ResponseWriter, r *http.Request) {
				n := 1
				if c := r.URL.Query().Get("cursor"); c != "" {
					n, _ = strconv.Atoi(strings.TrimPrefix(c, "c"))
				}
				_, _ = w.Write([]byte(tc.serve(n)))
			})
			e.fetch("vulncheck-kev")
			f := e.feed("vulncheck-kev")
			if f.Status != "error" || f.Error == nil || !strings.Contains(*f.Error, "could not be read completely") || !strings.Contains(*f.Error, tc.why) {
				t.Fatalf("feed = %+v", f)
			}
			if n := count(t, e.db, `SELECT count(*) FROM feeds_kev WHERE list = 'vulncheck' AND cve = 'CVE-2026-1099'`); n != 1 {
				t.Fatal("the rows loaded before were deleted")
			}
		})
	}
}

// The list outgrew the page count Vedette accepted: with 6,136 entries VulnCheck answers "total_pages": 62 (and "max_pages": 6)
// by page number. The pull reads it by cursor instead, every entry to the last, whatever the page count. The server below
// answers in the shape VulnCheck uses (fake entries): by page number with total_pages, by cursor with total_documents and an
// opaque base64 next_cursor (the last entry read), and no next_cursor on the last page.
func TestVulnCheckPull_ReadsAListOfMoreThanSixtyPages(t *testing.T) {
	t.Parallel()
	const total = 6136
	entries := make([]string, total)
	for i := range entries {
		added := "2024-01-30" // older than the window: read, counted, not kept
		if i%100 == 0 {
			added = "2026-10-30"
		}
		entries[i] = vcEntryJSON(fmt.Sprintf("CVE-2026-%05d", 90000-i), "Acme", "Gateway", added, "")
	}
	cur := func(i int) string {
		return base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "CVE-2026-%05d", 90000-i))
	}
	e, o := pullEnv(t)
	e.only()
	e.setURL("vulncheck-kev", o.url("/vc"))
	if c, b := e.put("vulncheck-kev", `{"api_key":"vckey-ABCDEF123456"}`); c != 200 {
		t.Fatalf("%d %v", c, b)
	}
	o.serve("/vc", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if p := q.Get("page"); p != "" { // page numbers: what VulnCheck says the list is by page
			n, _ := strconv.Atoi(p)
			from := min((n-1)*100, total)
			_, _ = fmt.Fprintf(w, `{"_benchmark":0.1,"_meta":{"timestamp":"2026-11-05T12:00:00Z","index":"vulncheck-kev","limit":100,"total_documents":%d,"sort":"_id","order":"desc","page":%d,"total_pages":62,"max_pages":6,"first_item":%d,"last_item":%d},"data":[%s]}`,
				total, n, from+1, min(from+100, total), strings.Join(entries[from:min(from+100, total)], ","))
			return
		}
		from := 0
		if c := q.Get("cursor"); c != "" {
			for from < total && cur(from) != c {
				from++
			}
			from++
		} else if q.Get("start_cursor") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		to := min(from+100, total)
		next := ""
		if to < total {
			next = fmt.Sprintf(`,"next_cursor":%q`, cur(to-1))
		}
		_, _ = fmt.Fprintf(w, `{"_benchmark":0.1,"_meta":{"timestamp":"2026-11-05T12:00:00Z","index":"vulncheck-kev","limit":100,"total_documents":%d,"sort":"_id","order":"desc"%s},"data":[%s]}`,
			total, next, strings.Join(entries[from:to], ","))
	})
	if c, b := e.fetch("vulncheck-kev"); c != 200 || at(b, "status") != "ok" || at(b, "records") != 62.0 {
		t.Fatalf("fetch: %d %v", c, b)
	}
	if hits := o.all(); len(hits) != 62 {
		t.Errorf("%d requests, want 62 pages of 100", len(hits))
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_kev WHERE list = 'vulncheck'`); n != 62 {
		t.Errorf("%d rows, want every recent entry of all 62 pages", n)
	}
}

// A refused key, a rate limit and a plan without the list each say what happened, and none of them changes the rows.
func TestVulnCheckPull_SaysWhyVulnCheckRefused(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		code       int
		retryAfter string
		why        string
	}{
		"key refused":       {http.StatusUnauthorized, "", "did not accept the API key"},
		"key forbidden":     {http.StatusForbidden, "", "did not accept the API key"},
		"rate limit":        {http.StatusTooManyRequests, "", "limiting the requests of this API key (HTTP 429, too many requests). Vedette keeps the list it had and tries again later."},
		"rate limit, wait":  {http.StatusTooManyRequests, "1500", "tries again later; VulnCheck asked to wait 25 minutes."},
		"plan without list": {http.StatusPaymentRequired, "", "plan of this API key does not include the VulnCheck KEV list (HTTP 402)"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, o := pullEnv(t)
			e.only()
			e.setURL("vulncheck-kev", o.url("/vc"))
			if c, b := e.put("vulncheck-kev", `{"api_key":"vckey-ABCDEF123456"}`); c != 200 {
				t.Fatalf("%d %v", c, b)
			}
			applyV(t, e.db, epoch0, "vulncheck-kev", []Vuln{vuln("CVE-2026-1099", "Acme", "Old", "2026-10-01")}, false)
			o.serve("/vc", func(w http.ResponseWriter, _ *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(`{"error":true,"errors":["refused"]}`))
			})
			e.fetch("vulncheck-kev")
			f := e.feed("vulncheck-kev")
			if f.Status != "error" || f.Error == nil || !strings.Contains(*f.Error, tc.why) || strings.Contains(*f.Error, "ABCDEF") {
				t.Fatalf("feed = %+v", f)
			}
			if n := count(t, e.db, `SELECT count(*) FROM feeds_kev WHERE list = 'vulncheck' AND cve = 'CVE-2026-1099'`); n != 1 {
				t.Fatal("the rows loaded before were deleted")
			}
		})
	}
}

// Review M2, L1, L2, L4: a held entry stays past 180 days while VulnCheck lists it; VulnCheck takes a custom feed's CVE but
// never CISA's; CISA takes VulnCheck's over (announced as KEV); an entry with several CVEs gives each its row. (A key saved
// again is a quiet first fill: TestContract_VulnCheckKEV_BYOK.)
func TestVulnCheckEntries_OwnershipAndWindow(t *testing.T) {
	t.Parallel()
	old := vcEntryJSON("CVE-2025-2001", "Acme", "Gateway", "2025-01-30", "")
	res, err := ParseVulnCheckPage([]byte(vcPage(1, "", old)), vcNow, nil)
	if err != nil || len(res.Vulns) != 0 {
		t.Fatalf("old, not held: %v %v", res.Vulns, err)
	}
	if res, err = ParseVulnCheckPage([]byte(vcPage(1, "", old)), vcNow, map[string]bool{"CVE-2025-2001": true}); err != nil || len(res.Vulns) != 1 {
		t.Fatalf("old, held: %v %v", res.Vulns, err)
	}
	multi := strings.Replace(vcEntryJSON("CVE-2026-3001", "Acme", "Gateway", "2026-10-30", ""), `["CVE-2026-3001"]`, `["CVE-2026-3001","cve-2026-3002","junk","CVE-2026-3001"]`, 1)
	if res, err = ParseVulnCheckPage([]byte(vcPage(1, "", multi)), vcNow, nil); err != nil || len(res.Vulns) != 2 || res.Vulns[1].CVE != "CVE-2026-3002" || res.Accepted != 1 {
		t.Fatalf("several CVEs: %+v %v", res, err)
	}

	db := newEnv(t).db
	// another feed's CVE is taken over by VulnCheck, a CISA one is not
	applyV(t, db, epoch0, "nuclei-templates", []Vuln{vuln("CVE-2026-4001", "Acme", "A", "2026-11-01")}, false)
	applyV(t, db, epoch0, "cisa-kev", []Vuln{vuln("CVE-2026-4002", "Acme", "B", "2026-11-01")}, false)
	fresh, _ := applyV(t, db, epoch0, "vulncheck-kev", []Vuln{vuln("CVE-2026-4001", "Acme", "A", "2026-11-01"), vuln("CVE-2026-4002", "Acme", "B", "2026-11-01")}, false)
	owner := func(c string) string {
		var s string
		_ = db.Reader().QueryRowContext(t.Context(), `SELECT k.source_id FROM feeds_kev k WHERE k.cve = ? ORDER BY CASE k.list WHEN 'cisa' THEN 0 WHEN 'vulncheck' THEN 1 ELSE 2 END LIMIT 1`, c).Scan(&s)
		return s
	}
	if owner("CVE-2026-4001") != "vulncheck-kev" || owner("CVE-2026-4002") != "cisa-kev" || len(fresh) != 1 {
		t.Fatalf("owners %s %s, fresh %d", owner("CVE-2026-4001"), owner("CVE-2026-4002"), len(fresh))
	}
	// CISA takes VulnCheck's row over: its first sighting as KEV
	if fresh, _ = applyV(t, db, epoch0, "cisa-kev", []Vuln{vuln("CVE-2026-4001", "Acme", "A", "2026-11-02")}, false); len(fresh) != 1 || owner("CVE-2026-4001") != "cisa-kev" {
		t.Fatalf("CISA take-over: %v %s", fresh, owner("CVE-2026-4001"))
	}
}
