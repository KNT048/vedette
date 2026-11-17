package feeds

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// #946 review r1: the CISA list never freezes on a bad catalog, never shrinks, and the watch survives a wrong clock and a person's
// "Fetch now". The env's clock is 5 Nov 2026, 12:00 UTC.

// kevDoc is a KEV catalog with n valid entries (CVE-2026-3xxxx from base). version and released are raw JSON values ("" leaves the
// field out), so a test can send a number or nothing.
func kevDoc(version, released string, n, base int) string {
	var b strings.Builder
	b.WriteString(`{"title": "CISA Catalog of Known Exploited Vulnerabilities"`)
	if version != "" {
		b.WriteString(`, "catalogVersion": ` + version)
	}
	if released != "" {
		b.WriteString(`, "dateReleased": ` + released)
	}
	b.WriteString(`, "vulnerabilities": [`)
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"cveID": "CVE-2026-%d", "vendorProject": "Acme", "product": "Router %d", "vulnerabilityName": "Acme Router Flaw",
"dateAdded": "2026-11-01", "shortDescription": "A flaw.", "requiredAction": "Patch.", "dueDate": "2026-11-22",
"knownRansomwareCampaignUse": "Unknown", "notes": ""}`, 30000+base+i, i)
	}
	b.WriteString(`]}`)
	return b.String()
}

func (e *env) catalog() (version string, records int) {
	e.t.Helper()
	f := e.feed("cisa-kev")
	if f.Records != nil {
		records = *f.Records
	}
	return orEmpty(f.CatalogVersion), records
}

// High: a catalogVersion years ahead (a typo) is not plausible; it never freezes the list, and the next good copy replaces it.
func TestG13r1_AFutureVersionTypoHealsAtTheNextGoodCopy(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusServiceUnavailable) })
	o.body(primaryPath, `"p1"`, kevDoc(`"2062.11.17"`, `"2026-11-04T10:00:00Z"`, 20, 0))
	if _, b := e.fetch("cisa-kev"); at(b, "status") != "ok" {
		t.Fatalf("first pull: %v", b)
	}
	if v, _ := e.catalog(); v != "2062.11.17" {
		t.Fatalf("held %q", v)
	}
	o.body(primaryPath, `"p2"`, kevDoc(`"2026.11.05"`, `"2026-11-05T10:00:00Z"`, 21, 0))
	e.setNow(e.clock().Add(time.Hour))
	if _, b := e.fetch("cisa-kev"); at(b, "status") != "ok" || at(b, "answered_by") != AnsweredCISA {
		t.Fatalf("the next good copy: %v %v", at(b, "status"), at(b, "error"))
	}
	if v, n := e.catalog(); v != "2026.11.05" || n != 21 {
		t.Errorf("the typo was not healed: %q %d", v, n)
	}
	if _, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-30020"); !found {
		t.Error("the new entry was not stored")
	}
	// a copy that sends the typo now is judged by its dateReleased: an older release is not news
	o.body(mirrorPath, `"m1"`, kevDoc(`"2099.01.01"`, `"2026-11-04T09:00:00Z"`, 21, 0))
	e.setNow(e.clock().Add(time.Hour))
	e.fetch("cisa-kev")
	if v, _ := e.catalog(); v != "2026.11.05" {
		t.Errorf("a future version won: %q", v)
	}
}

// High: KEV only grows. A copy with a newer version but fewer than 95 % of the entries held is refused with a note; both cut is a
// failed check (so the alert of D-629 can fire), never a freeze with a green status.
func TestG13r1_ACutCopyWithANewerVersionIsRefused(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.body(primaryPath, `"p1"`, kevDoc(`"2026.11.04"`, `"2026-11-04T10:00:00Z"`, 20, 0))
	o.body(mirrorPath, `"m1"`, kevDoc(`"2026.11.04"`, `"2026-11-04T10:00:00Z"`, 20, 0))
	e.fetch("cisa-kev")
	o.body(primaryPath, `"p2"`, kevDoc(`"2026.11.05"`, `"2026-11-05T10:00:00Z"`, 10, 100))
	e.setNow(e.clock().Add(time.Hour))
	_, b := e.fetch("cisa-kev")
	msg, _ := at(b, "error").(string)
	if at(b, "status") != "ok" || !strings.HasPrefix(msg, "cisa.gov sent a list of 10 entries, fewer than 95% of the 20 on this box, so it was not used") {
		t.Fatalf("cut copy: %v %q", at(b, "status"), msg)
	}
	if v, n := e.catalog(); v != "2026.11.04" || n != 20 {
		t.Errorf("the cut list was taken: %q %d", v, n)
	}
	if _, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-30100"); found {
		t.Error("an entry of the cut list was stored")
	}
	// the same cut body again (a 304) is still refused; the GitHub copy cut too: a failed check
	o.body(mirrorPath, `"m2"`, kevDoc(`"2026.11.05"`, `"2026-11-05T10:00:00Z"`, 10, 100))
	e.setNow(e.clock().Add(time.Hour))
	if _, b := e.fetch("cisa-kev"); at(b, "status") != "error" || !strings.Contains(at(b, "error").(string), "CISA's GitHub copy sent a list of 10 entries") {
		t.Errorf("both cut: %v %v", at(b, "status"), at(b, "error"))
	}
}

// Medium: a schema change. A catalogVersion that cannot be read falls back to dateReleased; a copy with neither is refused with a
// note (never a freeze) and is still asked conditionally.
func TestG13r1_SchemaChangeFallsBackToDateReleasedAndNeitherIsRefused(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusServiceUnavailable) })
	o.body(primaryPath, `"p1"`, kevDoc(`"2026.11.04"`, `"2026-11-04T10:00:00Z"`, 20, 0))
	e.fetch("cisa-kev")
	o.body(primaryPath, `"p2"`, kevDoc(`2026110501`, `"2026-11-05T10:00:00Z"`, 21, 0)) // a number now
	e.setNow(e.clock().Add(time.Hour))
	if _, b := e.fetch("cisa-kev"); at(b, "status") != "ok" {
		t.Fatalf("numeric version: %v", b)
	}
	if _, n := e.catalog(); n != 21 {
		t.Errorf("the release with a numeric version was not taken: %d entries", n)
	}
	o.body(primaryPath, `"p3"`, kevDoc("", "", 22, 0)) // neither field
	e.setNow(e.clock().Add(time.Hour))
	if _, b := e.fetch("cisa-kev"); at(b, "status") != "error" || !strings.Contains(at(b, "error").(string), "cisa.gov sent a list with no readable version or release date") {
		t.Errorf("no version, no date: %v %v", at(b, "status"), at(b, "error"))
	}
	if _, n := e.catalog(); n != 21 {
		t.Errorf("a list without version or date was taken: %d", n)
	}
	e.setNow(e.clock().Add(time.Hour))
	e.fetch("cisa-kev")
	var asks []string
	for _, h := range o.all() {
		if h.path == primaryPath {
			asks = append(asks, h.header.Get("If-None-Match"))
		}
	}
	if len(asks) != 4 || asks[3] != `"p3"` {
		t.Errorf("cisa.gov asked with %q: the refused copy is still asked conditionally", asks)
	}
}

// Low: of two equal catalogs cisa.gov's is kept; the same catalog with more entries than a partial copy held replaces it.
func TestG13r1_SameCatalogPrefersCISAAndMoreEntries(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.body(mirrorPath, `"m1"`, kevDoc(`"2026.11.04"`, `"2026-11-04T10:00:00Z"`, 20, 0))
	e.fetch("cisa-kev")
	o.body(primaryPath, `"p1"`, kevDoc(`"2026.11.04"`, `"2026-11-04T10:00:00Z"`, 20, 0))
	e.setNow(e.clock().Add(time.Hour))
	if _, b := e.fetch("cisa-kev"); at(b, "answered_by") != AnsweredCISA {
		t.Errorf("the same catalog: newest from %v", at(b, "answered_by"))
	}
	// the GitHub copy has the same version with more entries (cisa.gov's was partial): taken
	o.body(mirrorPath, `"m2"`, kevDoc(`"2026.11.04"`, `"2026-11-04T10:00:00Z"`, 21, 0))
	e.setNow(e.clock().Add(time.Hour))
	if _, b := e.fetch("cisa-kev"); at(b, "answered_by") != AnsweredMirror {
		t.Errorf("more entries: newest from %v", at(b, "answered_by"))
	}
	if _, n := e.catalog(); n != 21 {
		t.Errorf("entries %d", n)
	}
}

// High: turning the list off and on forgets the held version and every validator; the next check reads both copies in full.
// Low: a new address starts a new count of failures.
func TestG13r1_OffAndOnForgetsTheHeldVersionAndANewAddressItsFailures(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.body(primaryPath, `"p1"`, kevDoc(`"2062.11.17"`, `"2026-11-04T10:00:00Z"`, 20, 0))
	o.body(mirrorPath, `"m1"`, kevDoc(`"2062.11.17"`, `"2026-11-04T10:00:00Z"`, 20, 0))
	e.fetch("cisa-kev")
	e.put("cisa-kev", `{"enabled":false}`)
	e.put("cisa-kev", `{"enabled":true}`)
	f := e.feed("cisa-kev")
	copies, held, err := e.svc.st.kevCopies(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if f.CatalogVersion != nil || f.ETag != nil || f.MirrorETag != nil || copies.CISA.Read || !held.IsZero() {
		t.Errorf("after off and on: version %v etag %v mirror etag %v copies %+v released %v", f.CatalogVersion, f.ETag, f.MirrorETag, copies, held)
	}
	e.setNow(e.clock().Add(time.Hour))
	e.fetch("cisa-kev")
	for _, h := range o.all()[2:] {
		if h.header.Get("If-None-Match") != "" {
			t.Errorf("%s asked with %q after off and on", h.path, h.header.Get("If-None-Match"))
		}
	}

	o.serve("/own.json", func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
	e.mirror("cisa-kev", o.url("/own.json"))
	e.fetch("cisa-kev")
	e.fetch("cisa-kev")
	if e.feed("cisa-kev").Failures != 2 {
		t.Fatalf("failures at the own address: %d", e.feed("cisa-kev").Failures)
	}
	e.put("cisa-kev", fmt.Sprintf(`{"url":%q}`, o.url(primaryPath)))
	if n := e.feed("cisa-kev").Failures; n != 0 {
		t.Errorf("a new address kept %d failures", n)
	}
}

// Medium: a last good pull in the future (the clock was ahead, then corrected) is not trusted: while both copies fail there is one
// alert and no "up to date again" until a check really works.
func TestContract_D629_AFutureLastSuccessNeverFlaps(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	a := &alerts{}
	e.svc.Alert = a.send
	o.body(primaryPath, `"p1"`, testFile(t, "kev.json"))
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	e.tick(e.svc, 0)
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET last_success = '2026-11-06T20:00:00.000Z', last_fetch = '2026-11-06T20:00:00.000Z' WHERE id = 'cisa-kev'`)
		return err
	})
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
	for range 6 {
		e.tick(e.svc, time.Hour)
	}
	got := a.list()
	if len(got) != 1 || !strings.HasPrefix(got[0], "feeds-kev-stale-") {
		t.Fatalf("both failing with a future last good pull: %v", got)
	}
	o.body(mirrorPath, `"m2"`, testFile(t, "kev.json"))
	e.tick(e.svc, time.Hour)
	if got := a.list(); len(got) != 2 || !strings.HasPrefix(got[1], "feeds-kev-fresh-") {
		t.Errorf("after the copy came back: %v", got)
	}
}

// Low: a person's "Fetch now" does not count toward the two checks in a row.
func TestContract_D629_FetchNowDoesNotCount(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	a := &alerts{}
	e.svc.Alert = a.send
	o.body(primaryPath, `"p1"`, testFile(t, "kev.json"))
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	e.tick(e.svc, 0)
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
	e.setNow(e.clock().Add(30 * time.Minute))
	e.fetch("cisa-kev")
	e.setNow(e.clock().Add(31 * time.Minute))
	e.fetch("cisa-kev")
	e.tick(e.svc, time.Minute) // inside the back-off: the job does not pull
	if got := a.list(); len(got) != 0 {
		t.Fatalf("two clicks of Fetch now alerted: %v", got)
	}
	w, err := e.svc.st.kevWatch(t.Context())
	if err != nil || w.FailedChecks != 0 {
		t.Errorf("checks counted: %d %v", w.FailedChecks, err)
	}
}

// Low: a box upgraded from before migration 0016 (answered_by the GitHub copy, both validators, no copies, no release date) reads both
// copies in full once, with no flood of "new" entries.
func TestG13r1_AnUpgradedBoxReadsBothCopiesOnceWithoutNews(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.body(primaryPath, `"p1"`, testFile(t, "kev.json"))
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	e.fetch("cisa-kev")
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET kev_copies = NULL, catalog_released = NULL, answered_by = 'CISA GitHub mirror',
etag = '"old"', mirror_etag = '"m1"' WHERE id = 'cisa-kev'`)
		return err
	})
	before := len(e.pub.named(EventNewKEV))
	e.setNow(e.clock().Add(time.Hour))
	c, b := e.fetch("cisa-kev")
	if c != 200 || at(b, "status") != "ok" || at(b, "answered_by") != AnsweredCISA {
		t.Fatalf("after the upgrade: %d %v %v", c, at(b, "status"), at(b, "answered_by"))
	}
	for _, h := range o.all()[2:] {
		if h.header.Get("If-None-Match") != "" {
			t.Errorf("%s asked conditionally before its version was known: %q", h.path, h.header.Get("If-None-Match"))
		}
	}
	if n := len(e.pub.named(EventNewKEV)); n != before {
		t.Errorf("%d new_kev events after the upgrade", n-before)
	}
}
