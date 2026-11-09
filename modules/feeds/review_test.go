package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Tests of the independent review of WP-20 (feat/feeds-module): each was written red first.

func vulnFeedBody(name, u string) string {
	return `{"name":"` + name + `","kind":"vulnerabilities","url":"` + u + `","enabled":true,"interval_hours":24,
"auth":{"type":"none","header_name":null,"username":null},
"parser":{"format":"csv","records_path":"","delimiter":",","has_header":true,"fields":{"cve":{"source":"cve","regex":"","trim":true,"lowercase":false,"date_format":"auto"},
"vendor":{"source":"vendor","regex":"","trim":true,"lowercase":false,"date_format":"auto"},"date":{"source":"date","regex":"","trim":true,"lowercase":false,"date_format":"auto"}}}}`
}

func (e *env) addVulnFeed(name, u string) string {
	e.t.Helper()
	c, b, raw := e.do("POST", "/feeds/custom", "admin", vulnFeedBody(name, u))
	if c != 201 {
		e.t.Fatalf("%d %s", c, raw)
	}
	return at(b, "id").(string)
}

func TestContract_POST1_CustomFeedIsNotKEV(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("cisa-kev", "first-epss")
	e.mirror("cisa-kev", o.url("/kev.json"))
	e.mirror("first-epss", o.url("/epss"))
	maxIDs := 0
	epssOrigin(o, &maxIDs)
	kev := testFile(t, "kev.json")
	o.body("/kev.json", `"v1"`, kev)
	o.serve("/v.csv", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("cve,vendor,date\nCVE-2026-20001,Acme,2026-11-04\nCVE-2026-10099,Partner,2026-11-04\n"))
	})
	vid := e.addVulnFeed("Partner CVEs", o.url("/v.csv"))
	e.fetch(vid)
	if n := len(e.pub.named(EventNewKEV)) + len(e.pub.named(EventVulnUpdated)); n != 0 {
		t.Fatalf("a custom feed published %d KEV events: %v", n, e.pub.events)
	}
	// EPSS is asked only about CVEs of the CISA list
	e.fetch("cisa-kev")
	e.fetch("first-epss")
	for _, h := range o.all() {
		if h.path == "/epss" && (strings.Contains(h.query, "CVE-2026-20001") || strings.Contains(h.query, "CVE-2026-10099")) {
			t.Errorf("a CVE that only a custom feed lists was sent to api.first.org: %s", h.query)
		}
	}
	// the weekly sentences are about the CISA list only
	_, w := e.get("/feeds/weekly")
	for i := 0; at(w, "items", i) != nil; i++ {
		if at(w, "items", i, "cve") == "CVE-2026-20001" {
			t.Errorf("a custom feed's CVE is described as added to the CISA list: %v", at(w, "items", i, "text"))
		}
	}
	// CISA lists the CVE a custom feed had first: that is its first sighting as KEV
	o.body("/kev.json", `"v2"`, strings.Replace(kev, `"vulnerabilities": [`, `"vulnerabilities": [{"cveID":"CVE-2026-10099","vendorProject":"Acme","product":"Box","vulnerabilityName":"n","dateAdded":"2026-11-04","shortDescription":"d","requiredAction":"a","dueDate":"2026-11-25","knownRansomwareCampaignUse":"Unknown","notes":""},`, 1))
	before := len(e.pub.named(EventNewKEV))
	e.setNow(e.clock().Add(time.Hour))
	e.fetch("cisa-kev")
	news := e.pub.named(EventNewKEV)
	if len(news) != before+1 || news[len(news)-1].(NewKEVEvent).CVE != "CVE-2026-10099" {
		t.Errorf("take-over by cisa-kev: %v", news)
	}
	pairs, _ := e.svc.st.KevPairs(t.Context())
	for _, p := range pairs {
		if p.Vendor == "Partner" || p.Vendor == "Unknown" {
			t.Errorf("a custom feed's product is in the KEV pairs: %v", p)
		}
	}
}

func TestContract_INV14_HaveNotRelevantHaveCreatesOneDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.loadKEV()
	id := "synology%7Cdiskstation%20manager"
	for _, a := range []string{"have", "not_relevant", "have"} {
		if c, _, raw := e.do("POST", "/feeds/weekly/"+id, "operator", `{"answer":"`+a+`"}`); c != 200 {
			t.Fatalf("%s: %d %s", a, c, raw)
		}
	}
	if len(e.inv.added) != 1 {
		t.Errorf("have, not_relevant, have created %d devices, want exactly one per product", len(e.inv.added))
	}
}

func TestContract_INV14_HaveWhileInventoryWasOffAddsTheDeviceLater(t *testing.T) {
	t.Parallel()
	e, _ := pullEnv(t)
	e.only()
	e.loadKEV()
	e.gate.Set("inventory", false)
	id := "synology%7Cdiskstation%20manager"
	if c, _, raw := e.do("POST", "/feeds/weekly/"+id, "operator", `{"answer":"have"}`); c != 200 {
		t.Fatal(c, raw)
	}
	if err := e.svc.RunPull(t.Context()); err != nil || len(e.inv.added) != 0 {
		t.Fatalf("inventory off: %v, %d devices", err, len(e.inv.added))
	}
	e.gate.Set("inventory", true)
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(e.inv.added) != 1 || e.inv.added[0].Key != "synology|diskstation manager" {
		t.Fatalf("after the inventory came back: %+v", e.inv.added)
	}
	// from now on nothing adds it again, whatever is answered
	for _, a := range []string{"not_relevant", "have"} {
		e.do("POST", "/feeds/weekly/"+id, "operator", `{"answer":"`+a+`"}`)
	}
	_ = e.svc.RunPull(t.Context())
	if len(e.inv.added) != 1 {
		t.Errorf("%d devices", len(e.inv.added))
	}
}

func TestContract_INV3_LongVendorOrProductIsRejectedAtIngest(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only()
	o.serve("/v.csv", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("cve,vendor,date\nCVE-2026-20001," + strings.Repeat("A", 600) + ",2026-11-04\nCVE-2026-20002,Acme,2026-11-04\n"))
	})
	vid := e.addVulnFeed("Partner CVEs", o.url("/v.csv"))
	_, f := e.fetch(vid)
	if at(f, "status") != "ok" || at(f, "records") != 1.0 || !strings.Contains(at(f, "error").(string), "1 of 2 rows were rejected") {
		t.Errorf("feed: %v", f)
	}
	if _, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-20001"); found {
		t.Error("a row with a 600 character vendor was stored")
	}
	// the weekly answer of any stored product works
	e.loadKEV()
	_, w := e.get("/feeds/weekly")
	pid := at(w, "items", 0, "id").(string)
	if c, _, raw := e.do("POST", "/feeds/weekly/"+url.PathEscape(pid), "operator", `{"answer":"not_relevant"}`); c != 200 {
		t.Errorf("%d %s", c, raw)
	}
	// a feed whose only row is too long fails as a whole and keeps what it had
	o.serve("/v.csv", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("cve,vendor\nCVE-2026-20001," + strings.Repeat("A", 600) + "\n"))
	})
	e.setNow(e.clock().Add(time.Hour))
	if _, f = e.fetch(vid); at(f, "status") != "error" || !strings.Contains(at(f, "error").(string), "All 1 rows were rejected") || rowsOf(t, e.db, "feeds_vuln") != 4 {
		t.Errorf("all rejected: %v, %d rows", f, rowsOf(t, e.db, "feeds_vuln"))
	}
}

// blockedPull starts a fetch of a custom IOC feed that waits at the origin until release is closed.
func blockedPull(t *testing.T, e *env, o *origin) (id string, release chan struct{}, res chan int) {
	t.Helper()
	started := make(chan struct{})
	release, res = make(chan struct{}), make(chan int, 1)
	o.serve("/old.csv", func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.Header().Set("ETag", `"old"`)
		_, _ = w.Write([]byte("dst_ip\n185.220.101.47\n"))
	})
	body := strings.Replace(customBody, `https://threat-share.example.net/c2.csv`, o.url("/old.csv"), 1)
	_, b, _ := e.do("POST", "/feeds/custom", "admin", body)
	id = at(b, "id").(string)
	go func() { c, _ := e.fetch(id); res <- c }()
	<-started
	return id, release, res
}

func TestContract_INV8_EditDuringPullDropsTheStaleResult(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only()
	id, release, res := blockedPull(t, e, o)
	put := strings.Replace(customBody, `https://threat-share.example.net/c2.csv`, o.url("/new.csv"), 1)
	if c, _, raw := e.do("PUT", "/feeds/custom/"+id, "admin", put); c != 200 {
		t.Fatalf("put %d %s", c, raw)
	}
	close(release)
	if c := <-res; c != 200 {
		t.Errorf("manual fetch: %d", c)
	}
	f := e.feed(id)
	if (f.ETag != nil && *f.ETag == `"old"`) || rowsOf(t, e.db, "feeds_ioc") != 0 || rowsOf(t, e.db, "feeds_fetch_log") != 0 {
		t.Errorf("the pull of the old address wrote under the new one: etag=%v iocs=%d logs=%d", f.ETag, rowsOf(t, e.db, "feeds_ioc"), rowsOf(t, e.db, "feeds_fetch_log"))
	}
}

func TestContract_INV8_DeleteDuringPullIs404(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only()
	id, release, res := blockedPull(t, e, o)
	if c, _, _ := e.do("DELETE", "/feeds/custom/"+id, "admin", ""); c != 204 {
		t.Fatal(c)
	}
	close(release)
	if c := <-res; c != 404 {
		t.Errorf("manual fetch of a feed deleted meanwhile: HTTP %d, want 404", c)
	}
	if rowsOf(t, e.db, "feeds_ioc") != 0 || rowsOf(t, e.db, "feeds_fetch_log") != 0 {
		t.Error("a deleted feed's pull left data")
	}
}

func TestContract_INV8_DisableDuringPullWritesNothing(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only()
	id, release, res := blockedPull(t, e, o)
	if c, b := e.put(id, `{"enabled":false}`); c != 200 {
		t.Fatal(c, b)
	}
	close(release)
	<-res
	if rowsOf(t, e.db, "feeds_ioc") != 0 || e.feed(id).Status != "never" {
		t.Errorf("a pull of a feed switched off meanwhile stored data: %d iocs, %s", rowsOf(t, e.db, "feeds_ioc"), e.feed(id).Status)
	}
}

func TestContract_INV8_KindChangeDuringPullDropsTheStaleResult(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only()
	id, release, res := blockedPull(t, e, o)
	body := strings.Replace(strings.Replace(customBody, `https://threat-share.example.net/c2.csv`, o.url("/old.csv"), 1), `"kind":"ioc"`, `"kind":"vulnerabilities"`, 1)
	body = strings.Replace(body, `"indicator":{"source":"dst_ip"`, `"cve":{"source":"dst_ip"`, 1)
	if c, _, raw := e.do("PUT", "/feeds/custom/"+id, "admin", body); c != 200 {
		t.Fatalf("%d %s", c, raw)
	}
	close(release)
	<-res
	if rowsOf(t, e.db, "feeds_ioc") != 0 {
		t.Error("IOC rows of the old kind were stored after the kind changed")
	}
}

func TestContract_INV8_DatabaseFailureLeavesATraceAndBacksOff(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only()
	o.serve("/c2.csv", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("dst_ip\n185.220.101.47\n")) })
	body := strings.Replace(customBody, `https://threat-share.example.net/c2.csv`, o.url("/c2.csv"), 1)
	_, b, _ := e.do("POST", "/feeds/custom", "admin", body)
	id := at(b, "id").(string)
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `CREATE TRIGGER feeds_test_break BEFORE INSERT ON feeds_ioc BEGIN SELECT RAISE(ABORT, 'disk full'); END`)
		return err
	})
	c, f := e.fetch(id)
	if c != 200 || at(f, "status") != "error" || at(f, "error") != "The result could not be stored. Check the disk space and the box logs." {
		t.Fatalf("%d %v", c, f)
	}
	hits := o.count("/c2.csv")
	// back-off: the job does not hit the source again at once
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/c2.csv") != hits {
		t.Errorf("RunPull right after a failure: %v, %d more requests", err, o.count("/c2.csv")-hits)
	}
	if e.feed(id).Failures != 1 || len(e.pub.named(EventFetchFailed)) != 1 {
		t.Errorf("failures %d, events %v", e.feed(id).Failures, e.pub.named(EventFetchFailed))
	}
}

func TestReenablingAFeedResetsItsBackOff(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("cisa-kev")
	e.mirror("cisa-kev", o.url("/kev.json"))
	o.serve("/kev.json", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	for range 3 {
		e.setNow(e.clock().Add(time.Hour))
		e.fetch("cisa-kev")
	}
	if e.feed("cisa-kev").Failures != 3 {
		t.Fatalf("failures %d", e.feed("cisa-kev").Failures)
	}
	e.put("cisa-kev", `{"enabled":false}`)
	e.put("cisa-kev", `{"enabled":true}`)
	if f := e.feed("cisa-kev"); f.Failures != 0 {
		t.Errorf("failures after re-enabling: %d", f.Failures)
	}
	before := o.count("/kev.json")
	_ = e.svc.RunPull(t.Context())
	if o.count("/kev.json") != before+1 {
		t.Error("a re-enabled feed waits for its old back-off")
	}
}

func TestStatusOfABoxThatNeverPulledDoesNotLookFresh(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, b := e.get("/feeds/status")
	g, err := time.Parse(time.RFC3339, at(b, "generated_at").(string))
	if err != nil || e.clock().Sub(g) < 365*24*time.Hour {
		t.Errorf("generated_at %v on a box that never pulled", at(b, "generated_at"))
	}
}

func TestContract_INV10_InventoryErrorDegradesToNull(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.loadKEV()
	e.inv.matchErr = errors.New("inventory is broken")
	c, b := e.get("/feeds/hot?window=7d")
	if c != 200 || at(b, "rows", 0, "you_have") != nil || len(at(b, "rows", 0, "matched_assets").([]any)) != 0 {
		t.Errorf("hot: %d %v", c, at(b, "rows", 0))
	}
	c, d := e.get("/feeds/cve/CVE-2026-10001")
	if c != 200 || d["matched"] != nil {
		t.Errorf("cve: %d %v", c, d["matched"])
	}
}

func TestParseTestEmptySampleMeansNoRecords(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	parser := `{"format":"lines","records_path":"","delimiter":",","has_header":true,"fields":{"indicator":{"source":"","regex":"","trim":true,"lowercase":false,"date_format":"auto"}}}`
	c, b, raw := e.do("POST", "/feeds/parse-test", "admin", `{"kind":"ioc","parser":`+parser+`,"sample":""}`)
	if c != 200 || at(b, "sample") != "" || at(b, "accepted") != 0.0 || at(b, "rejected") != 0.0 || len(at(b, "records").([]any)) != 0 || at(b, "sample_label") != "Plain list of addresses" {
		t.Errorf("%d %s", c, raw)
	}
}

func TestFeedLockIsContextAwareAndPruned(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only()
	id, release, res := blockedPull(t, e, o)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.svc.Fetch(ctx, id) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("waiting for the lock: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("a pull waiting for another pull of the same feed ignores its context")
	}
	close(release)
	<-res
	e.svc.mu.Lock()
	n := len(e.svc.locks)
	e.svc.mu.Unlock()
	if n != 0 {
		t.Errorf("%d feed locks kept after the pulls finished", n)
	}
}

func TestVulnerabilityDatesInTheFutureAreClamped(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only()
	o.serve("/v.csv", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("cve,vendor,date\nCVE-2026-20001,Acme,2099-01-01\n"))
	})
	e.fetch(e.addVulnFeed("Partner CVEs", o.url("/v.csv")))
	v, _, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-20001")
	if v.DateAdded != "2026-11-05" {
		t.Errorf("date_added %s, want today", v.DateAdded)
	}
}

func TestWeeklyAndSearchAnswerFromSQLNotFromAFullScan(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var vs []Vuln
	for i := range 300 { // 100 products, three CVEs each, dates spread over 300 days
		d := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -i)
		vs = append(vs, vuln(fmt.Sprintf("CVE-2025-%04d", 2000+i), "Vendor"+fmt.Sprint(i%100), "Product"+fmt.Sprint(i%100), d.Format("2006-01-02")))
	}
	applyV(t, e.db, e.clock(), "cisa-kev", vs, false)
	_, w := e.get("/feeds/weekly")
	if at(w, "items", 7, "cve") == nil || at(w, "items", 8) != nil {
		t.Fatalf("weekly: %v", w)
	}
	for i := 0; i < 8; i++ { // newest CVE of each of the 8 newest products
		if want := fmt.Sprintf("CVE-2025-%04d", 2000+i); at(w, "items", i, "cve") != want {
			t.Errorf("item %d: %v, want %s", i, at(w, "items", i, "cve"), want)
		}
	}
	_, s := e.get("/feeds/search?q=product42")
	if len(at(s, "vulns").([]any)) != 3 || at(s, "vulns", 0, "cve") != "CVE-2025-2042" {
		t.Errorf("search: %v", s)
	}
	e.loadKEV()
	_, s = e.get("/feeds/search?q=synology%20nas") // the recognised name, not in vendor, product or name
	if len(at(s, "vulns").([]any)) != 1 {
		t.Errorf("search by the recognised name: %v", s)
	}
}
