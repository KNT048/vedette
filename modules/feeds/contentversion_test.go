package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"io/fs"
	"maps"
	"net/http"
	"slices"
	"testing"
	"testing/fstest"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/core/winrel"
	"github.com/knt048/vedette/modules/core"
)

// INV-32: how each built-in feed reads its source, which decides how new code reads its stored data again. A new feed must be put in
// one of these classes (and given a content version), so the reload after an update is decided for it, not left to its interval.
func TestContentVersion_EveryFeedHasAReloadPath(t *testing.T) {
	t.Parallel()
	conditional := []string{"abusech-feodo", alpineOSVFeedID, "cisa-kev", debianTrackerFeedID, epssAllFeedID, "et-open", "hagezi-tif", "ipsum",
		"nuclei-templates", "tor-exit", ubuntuOSVFeedID, ubuntuVEXFeedID} // whole file, ETag/Last-Modified: a 304 kept the old parse
	plain := []string{"first-epss", vulnCheckFeedID, winRelFeedID} // whole source, no validators: read again only after the interval
	incremental := []string{cveOrgFeedID, nvdFeedID, recentFeedID} // only what changed at the source: never the old records
	got := map[string]string{}
	for _, b := range BuiltinSources() {
		if contentVersions[b.Decoder] < 1 {
			t.Errorf("%s: decoder %s has no content version", b.ID, b.Decoder)
		}
		got[b.ID] = "whole"
		if contentResets[b.Decoder] != nil {
			got[b.ID] = "incremental"
		}
	}
	want := map[string]string{}
	for _, id := range slices.Concat(conditional, plain) {
		want[id] = "whole"
	}
	for _, id := range incremental {
		want[id] = "incremental"
	}
	if !maps.Equal(got, want) {
		t.Fatalf("reload class of the built-in feeds:\n got %v\nwant %v", got, want)
	}
	if contentVersions[DecoderParser] < 1 { // custom feeds
		t.Error("the custom feeds' parser has no content version")
	}
}

func setVersion(t *testing.T, e *env, id string, v int) {
	t.Helper()
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET content_version = ? WHERE id = ?`, v, id)
		return err
	})
}

// fv is the feed row with its stored content version.
func (e *env) fv(id string) sourceRow {
	e.t.Helper()
	r, err := e.svc.st.withVersion(e.t.Context(), e.feed(id))
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func lastHit(o *origin, path string) hit {
	var h hit
	for _, x := range o.all() {
		if x.path == path {
			h = x
		}
	}
	return h
}

// A feed that reads a whole file with validators: after an update that changes its content version it is read at the next check, not
// after its interval, and without If-None-Match (a 304 would keep the old parse). The back-off after failures and the switch hold.
func TestContentVersion_WholeFileFeedIsReadAgainAtOnce(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("et-open")
	e.mirror("et-open", o.url("/et.txt"))
	o.body("/et.txt", `"e1"`, "185.220.101.47\n45.148.10.95\n")
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/et.txt") != 1 {
		t.Fatalf("first pull: %d requests, %v", o.count("/et.txt"), err)
	}
	if f := e.fv("et-open"); f.Status != "ok" || f.ContentVersion != contentVersions[DecoderParser] || f.reload() {
		t.Fatalf("after the first pull: %+v", f)
	}
	e.setNow(e.clock().Add(time.Hour))
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/et.txt") != 1 {
		t.Fatalf("within its interval: %d requests, %v", o.count("/et.txt"), err)
	}

	setVersion(t, e, "et-open", 0) // the box runs code that stores or parses this feed differently
	e.setNow(e.clock().Add(PullEvery))
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/et.txt") != 2 {
		t.Fatalf("after the update: %d requests, %v", o.count("/et.txt"), err)
	}
	if h := lastHit(o, "/et.txt"); h.header.Get("If-None-Match") != "" || h.header.Get("If-Modified-Since") != "" {
		t.Fatalf("the reload was conditional: %v", h.header)
	}
	if f := e.fv("et-open"); f.Status != "ok" || f.reload() {
		t.Fatalf("after the reload: %+v", f)
	}
	e.setNow(e.clock().Add(PullEvery))
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/et.txt") != 2 {
		t.Fatalf("read again once only: %d requests, %v", o.count("/et.txt"), err)
	}

	// a reload that fails keeps the old version and waits out the back-off
	setVersion(t, e, "et-open", 0)
	o.serve("/et.txt", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "busy", http.StatusServiceUnavailable) })
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/et.txt") != 3 {
		t.Fatalf("failing reload: %d requests, %v", o.count("/et.txt"), err)
	}
	if f := e.fv("et-open"); f.Status != "error" || !f.reload() {
		t.Fatalf("after a failed reload: %+v", f)
	}
	failed := e.clock()
	e.setNow(failed.Add(BackoffBase - time.Minute))
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/et.txt") != 3 {
		t.Fatalf("within the back-off: %d requests, %v", o.count("/et.txt"), err)
	}
	o.body("/et.txt", `"e1"`, "185.220.101.47\n45.148.10.95\n")
	e.setNow(failed.Add(BackoffBase))
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/et.txt") != 4 || e.fv("et-open").reload() {
		t.Fatalf("after the back-off: %d requests, %v, %+v", o.count("/et.txt"), err, e.fv("et-open"))
	}
	if h := lastHit(o, "/et.txt"); h.header.Get("If-None-Match") != "" {
		t.Fatalf("the reload after a failure was conditional: %v", h.header)
	}

	// a feed that is off is not contacted; it is read again when it is turned on
	setVersion(t, e, "et-open", 0)
	if c, b := e.put("et-open", `{"enabled":false}`); c != 200 {
		t.Fatalf("turn off: %d %v", c, b)
	}
	e.setNow(e.clock().Add(PullEvery))
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/et.txt") != 4 || !e.fv("et-open").reload() {
		t.Fatalf("off: %d requests, %v", o.count("/et.txt"), err)
	}
	if c, b := e.put("et-open", `{"enabled":true}`); c != 200 {
		t.Fatalf("turn on: %d %v", c, b)
	}
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/et.txt") != 5 || e.fv("et-open").reload() {
		t.Fatalf("on again: %d requests, %v", o.count("/et.txt"), err)
	}
}

// The CISA list: both copies are read in full, and the catalog the box holds is taken again (parsed by the new code) though it is
// the same; it announces nothing new.
func TestContentVersion_CISAListReadsBothCopiesInFull(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.body(primaryPath, `"p1"`, testFile(t, "kev.json"))
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	if err := e.svc.RunPull(t.Context()); err != nil || e.fv("cisa-kev").reload() {
		t.Fatalf("first pull: %v %+v", err, e.fv("cisa-kev"))
	}
	e.setNow(e.clock().Add(time.Hour))
	if err := e.svc.RunPull(t.Context()); err != nil || lastHit(o, primaryPath).header.Get("If-None-Match") != `"p1"` {
		t.Fatalf("hourly check: conditional, %v", err)
	}
	execSQL(t, e.db, `UPDATE feeds_vuln SET description = 'parsed by older code' WHERE source_id = 'cisa-kev'`)
	setVersion(t, e, "cisa-kev", 0)
	e.setNow(e.clock().Add(PullEvery))
	if err := e.svc.RunPull(t.Context()); err != nil || o.count(primaryPath) != 3 || o.count(mirrorPath) != 3 {
		t.Fatalf("after the update: %v, cisa.gov %d, GitHub copy %d", err, o.count(primaryPath), o.count(mirrorPath))
	}
	for _, p := range []string{primaryPath, mirrorPath} {
		if h := lastHit(o, p); h.header.Get("If-None-Match") != "" {
			t.Fatalf("%s asked conditionally: %v", p, h.header)
		}
	}
	if f := e.fv("cisa-kev"); f.Status != "ok" || f.reload() {
		t.Fatalf("after the reload: %+v", f)
	}
	if v, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10001"); !found || v.Description == "parsed by older code" {
		t.Fatalf("the held catalog was not taken again: %+v", v)
	}
	if n := len(e.pub.named(EventNewKEV)); n != 0 {
		t.Fatalf("the same catalog announced %d new CVEs", n)
	}
}

// Windows releases (version 2: the monthly updates): a box whose updates table is still empty (its last pull ran before the table
// existed) reads the pages at the next check; the first fill of the table makes findings match the Windows CVEs again as a baseline,
// and moves the plan's stamp. A page that fails stores what was read but keeps the old version: the next try waits a back-off, then
// reads the pages again until every page is in.
func TestContentVersion_WindowsReleasesReadAgainAndMatchedAgain(t *testing.T) {
	t.Cleanup(func() { winrel.Learn(nil); winrel.LearnUpdates(nil) })
	e, o := pullEnv(t)
	e.setNow(day(t, "2026-11-17").Add(12 * time.Hour))
	e.only(winRelFeedID)
	e.setURL(winRelFeedID, o.url("/rh/windows11-release-information"))
	o.body("/rh/windows11-release-information", `"a"`, testFile(t, "winrel/windows11-release-information.html"))
	o.body("/rh/"+winRelServerPage, `"b"`, testFile(t, "winrel/windows-server-release-info.html"))
	o.body("/rh/"+winRel10Page, `"c"`, testFile(t, "winrel/release-information.html"))
	write(t, e.db, func(tx *sql.Tx) error {
		_, _, err := applyAffected(t.Context(), tx, map[string][]AffectedRow{"CVE-2026-21001": {{CPE: "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*", EndExcl: "10.0.26100.32230"}}}, false, epoch0)
		return err
	})
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/rh/windows11-release-information") != 1 || e.fv(winRelFeedID).reload() {
		t.Fatalf("first pull: %v, %+v", err, e.fv(winRelFeedID))
	}
	pages := func() [3]int {
		return [3]int{o.count("/rh/windows11-release-information"), o.count("/rh/" + winRelServerPage), o.count("/rh/" + winRel10Page)}
	}
	var got []RangesUpdatedEvent
	e.svc.Events = publishFunc(func(ev events.Event) {
		if r, ok := ev.Data.(RangesUpdatedEvent); ok {
			got = append(got, r)
		}
	})
	stamp, err := e.svc.st.TierStamp(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	// a box from before the updates table: no rows, version 1; at the reload the Windows 10 page fails
	execSQL(t, e.db, `DELETE FROM feeds_winrel_update`)
	winrel.LearnUpdates(nil)
	setVersion(t, e, winRelFeedID, 1)
	o.serve("/rh/"+winRel10Page, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "busy", http.StatusServiceUnavailable) })
	e.setNow(e.clock().Add(time.Hour))
	if err := e.svc.RunPull(t.Context()); err != nil || pages() != [3]int{2, 2, 2} {
		t.Fatalf("after the update: %v, pages %v", err, pages())
	}
	if f := e.fv(winRelFeedID); f.Status != "ok" || f.ContentVersion != 1 {
		t.Fatalf("a reload with a page missing recorded the version: %+v", f)
	}
	if us := winrel.Updates(26100, true); len(us) == 0 || us[len(us)-1].Rev != 33822 {
		t.Fatalf("Server 2025 updates after the reload: %+v", us)
	}
	if len(got) != 1 || !slices.Contains(got[0].CVEs, "CVE-2026-21001") || !got[0].First {
		t.Fatalf("findings was not asked to match the Windows CVEs again, as a baseline: %+v", got)
	}
	if now, err := e.svc.st.TierStamp(t.Context()); err != nil || now == stamp {
		t.Fatalf("the plan's stamp did not move: %q %v", now, err)
	}
	// the next try waits the back-off of one short reload, then reads the pages again
	got = nil
	short := e.clock()
	e.setNow(short.Add(BackoffBase - time.Minute))
	if err := e.svc.RunPull(t.Context()); err != nil || pages() != [3]int{2, 2, 2} {
		t.Fatalf("within the back-off: %v, pages %v", err, pages())
	}
	e.setNow(short.Add(BackoffBase))
	if err := e.svc.RunPull(t.Context()); err != nil || pages() != [3]int{3, 3, 3} || e.fv(winRelFeedID).ContentVersion != 1 {
		t.Fatalf("second try, the page still fails: %v, pages %v, %+v", err, pages(), e.fv(winRelFeedID))
	}
	e.setNow(short.Add(BackoffBase + 2*BackoffBase - time.Minute)) // two short reloads: 10 minutes
	if err := e.svc.RunPull(t.Context()); err != nil || pages() != [3]int{3, 3, 3} {
		t.Fatalf("within the second back-off: %v, pages %v", err, pages())
	}
	o.body("/rh/"+winRel10Page, `"c"`, testFile(t, "winrel/release-information.html"))
	e.setNow(short.Add(3 * BackoffBase))
	if err := e.svc.RunPull(t.Context()); err != nil || pages() != [3]int{4, 4, 4} {
		t.Fatalf("third try: %v, pages %v", err, pages())
	}
	if f := e.fv(winRelFeedID); f.Status != "ok" || f.ContentVersion != 2 {
		t.Fatalf("every page read: %+v", f)
	}
	if len(got) != 1 || got[0].First { // the Windows 10 rows are news to a table that has rows
		t.Fatalf("Windows 10 updates: %+v", got)
	}
	// the same pages again a day later: nothing changed, nothing matched again
	got = nil
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.RunPull(t.Context()); err != nil || len(got) != 0 || pages() != [3]int{5, 5, 5} {
		t.Fatalf("an unchanged pull: %v, %+v, pages %v", err, got, pages())
	}
}

// A reload of the CISA list never takes a shorter copy of the catalog it holds: the GitHub copy has the same version with one entry
// fewer while cisa.gov fails, so nothing is stored, the version stays (nothing was parsed into the table) and no CVE is dropped. The
// next try, after the back-off, reads cisa.gov's full list: the version is recorded and nothing is announced as new.
func TestContentVersion_CISAReloadNeverTakesAShorterCopy(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	full := testFile(t, "kev.json")
	o.body(primaryPath, `"p1"`, full)
	o.body(mirrorPath, `"m1"`, full)
	if err := e.svc.RunPull(t.Context()); err != nil || e.fv("cisa-kev").reload() {
		t.Fatalf("first pull: %v %+v", err, e.fv("cisa-kev"))
	}
	held := rowsOf(t, e.db, "feeds_vuln")
	var doc map[string]any
	if err := json.Unmarshal([]byte(full), &doc); err != nil {
		t.Fatal(err)
	}
	vs, _ := doc["vulnerabilities"].([]any)
	doc["vulnerabilities"] = slices.DeleteFunc(vs, func(v any) bool { return at(v, "cveID") == "CVE-2026-10003" }) // same catalogVersion and dateReleased
	shorter, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	o.body(mirrorPath, `"m2"`, string(shorter))
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "busy", http.StatusServiceUnavailable) })
	setVersion(t, e, "cisa-kev", 0)
	e.setNow(e.clock().Add(PullEvery))
	if err := e.svc.RunPull(t.Context()); err != nil || o.count(mirrorPath) != 2 {
		t.Fatalf("reload: %v, GitHub copy asked %d times", err, o.count(mirrorPath))
	}
	if n := rowsOf(t, e.db, "feeds_vuln"); n != held {
		t.Fatalf("a shorter copy was taken: %d rows, held %d", n, held)
	}
	if _, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10003"); !found {
		t.Fatal("the reload dropped CVE-2026-10003")
	}
	if f := e.fv("cisa-kev"); f.Status != "ok" || !f.reload() {
		t.Fatalf("the version was recorded though nothing was parsed into the table: %+v", f)
	}
	o.body(primaryPath, `"p1"`, full)
	e.setNow(e.clock().Add(BackoffBase - time.Minute))
	if err := e.svc.RunPull(t.Context()); err != nil || o.count(mirrorPath) != 2 {
		t.Fatalf("within the back-off: %v, %d", err, o.count(mirrorPath))
	}
	e.setNow(e.clock().Add(time.Minute))
	if err := e.svc.RunPull(t.Context()); err != nil || o.count(mirrorPath) != 3 || e.fv("cisa-kev").reload() {
		t.Fatalf("after the back-off: %v, %d, %+v", err, o.count(mirrorPath), e.fv("cisa-kev"))
	}
	if n := len(e.pub.named(EventNewKEV)); n != 0 {
		t.Fatalf("%d CVEs announced as new", n)
	}
}

// The incremental feeds start their own full reload, in one transaction with the new version: nvd-kev its full pull, nvd-recent its
// 12-month fill (the cursor goes), cve-org every record due again. A feed that is off waits until it is turned on.
func TestContentVersion_IncrementalFeedsStartTheirOwnReload(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	write(t, e.db, func(tx *sql.Tx) error {
		now := e.clock()
		if err := saveRecentCursor(ctx, tx, recentCursor{URL: "https://services.nvd.nist.gov/rest/json/cves/2.0", Mode: modeDone, From: now, To: now, Until: now}); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO feeds_cveorg_checked (cve, checked_at) VALUES ('CVE-2024-3400', ?)`, store.FormatTS(now))
		return err
	})
	for _, id := range []string{nvdFeedID, recentFeedID, cveOrgFeedID} { // pulled before, by older code
		execSQL(t, e.db, `UPDATE feeds_source SET last_fetch = '2026-11-05T11:00:00.000Z', last_success = '2026-11-05T11:00:00.000Z', status = 'ok' WHERE id = '`+id+`'`)
		setVersion(t, e, id, 0)
	}
	if c, b := e.put(recentFeedID, `{"enabled":false}`); c != 200 {
		t.Fatalf("turn off: %d %v", c, b)
	}
	rows := func() []sourceRow {
		r, err := e.svc.st.sources(ctx)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := e.svc.st.contentVersionsStored(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for i := range r {
			r[i].ContentVersion = stored[r[i].ID]
		}
		return r
	}
	started, err := e.svc.startReloads(ctx, rows())
	if err != nil || !maps.Equal(started, map[string]bool{nvdFeedID: true, cveOrgFeedID: true}) {
		t.Fatalf("started %v, %v", started, err)
	}
	if full, err := e.svc.st.fullDue(ctx, nvdFeedID); err != nil || !full {
		t.Fatalf("nvd-kev full pull due: %v %v", full, err)
	}
	var checked string
	if err := e.db.Reader().QueryRowContext(ctx, `SELECT checked_at FROM feeds_cveorg_checked`).Scan(&checked); err != nil || checked != "1970-01-01T00:00:00.000Z" {
		t.Fatalf("cve-org stamp %q %v", checked, err)
	}
	if c, err := e.svc.st.recentCursor(ctx); err != nil || c == nil || e.fv(recentFeedID).ContentVersion != 0 {
		t.Fatalf("nvd-recent is off: its cursor and version stay: %+v %v", c, err)
	}
	if e.fv(nvdFeedID).reload() || e.fv(cveOrgFeedID).reload() {
		t.Fatal("the version was not recorded with the reload")
	}
	if c, b := e.put(recentFeedID, `{"enabled":true}`); c != 200 {
		t.Fatalf("turn on: %d %v", c, b)
	}
	started, err = e.svc.startReloads(ctx, rows())
	if err != nil || !maps.Equal(started, map[string]bool{recentFeedID: true}) {
		t.Fatalf("turned on: started %v, %v", started, err)
	}
	if c, err := e.svc.st.recentCursor(ctx); err != nil || c != nil || e.fv(recentFeedID).reload() {
		t.Fatalf("nvd-recent cursor after the reload started: %+v %v", c, err)
	}
	if started, err = e.svc.startReloads(ctx, rows()); err != nil || len(started) != 0 {
		t.Fatalf("started twice: %v %v", started, err)
	}
}

// cve-org's reload is due at the next check, not an hour later: every record is read again.
func TestContentVersion_CVEOrgReadsEveryRecordAgainAtOnce(t *testing.T) {
	t.Parallel()
	e, o, _ := cveOrgEnv(t)
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := len(o.all())
	if first == 0 {
		t.Fatal("no record read")
	}
	e.setNow(e.clock().Add(PullEvery))
	if err := e.svc.RunPull(t.Context()); err != nil || len(o.all()) != first {
		t.Fatalf("within the interval: %d requests, %v", len(o.all())-first, err)
	}
	setVersion(t, e, cveOrgFeedID, 0)
	e.setNow(e.clock().Add(PullEvery))
	if err := e.svc.RunPull(t.Context()); err != nil || len(o.all()) != 2*first {
		t.Fatalf("after the update: %d requests, want %d, %v", len(o.all())-first, first, err)
	}
	if e.fv(cveOrgFeedID).reload() {
		t.Fatal("version not recorded")
	}
}

// Alpine's privacy rule holds through a reload: no Alpine device, no request; the first device that states Alpine Linux gets the
// whole file read by the new code.
func TestContentVersion_AlpineIsNotFetchedWithoutADevice(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(alpineOSVFeedID)
	e.mirror(alpineOSVFeedID, o.url("/Alpine/all.zip"))
	o.body("/Alpine/all.zip", `"z1"`, string(alpineRecords(t)))
	e.loadKEV()
	applyV(t, e.db, e.clock(), "cisa-kev", []Vuln{vuln("CVE-2026-123158", "OpenBSD", "OpenSSH", "2026-11-06")}, false)
	inv := &distroInv{got: map[string]map[string]bool{DistroAlpine: {}}}
	e.svc.Inventory = inv
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/Alpine/all.zip") != 1 || e.fv(alpineOSVFeedID).reload() {
		t.Fatalf("filled: %v, %d requests", err, o.count("/Alpine/all.zip"))
	}
	inv.got = map[string]map[string]bool{DistroUbuntu: {"openssh": true}} // the Alpine device left
	setVersion(t, e, alpineOSVFeedID, 0)
	for range 2 {
		e.setNow(e.clock().Add(PullEvery))
		if err := e.svc.RunPull(t.Context()); err != nil || o.count("/Alpine/all.zip") != 1 {
			t.Fatalf("no Alpine device: %v, %d requests", err, o.count("/Alpine/all.zip"))
		}
	}
	inv.got = map[string]map[string]bool{DistroAlpine: {}}
	e.setNow(e.clock().Add(PullEvery))
	if err := e.svc.RunPull(t.Context()); err != nil || o.count("/Alpine/all.zip") != 2 || e.fv(alpineOSVFeedID).reload() {
		t.Fatalf("an Alpine device again: %v, %d requests, %+v", err, o.count("/Alpine/all.zip"), e.fv(alpineOSVFeedID))
	}
	if h := lastHit(o, "/Alpine/all.zip"); h.header.Get("If-None-Match") != "" {
		t.Fatalf("the reload was conditional: %v", h.header)
	}
}

// Migration 0021 on a box that ran 0001..0020: every feed is at version 1, so only the Windows releases feed (version 2) is read again.
func TestMigration0021ContentVersion(t *testing.T) {
	t.Parallel()
	before := fstest.MapFS{}
	entries, err := fs.ReadDir(Migrations, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() >= "0021" {
			continue
		}
		b, err := fs.ReadFile(Migrations, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		before[e.Name()] = &fstest.MapFile{Data: b}
	}
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "feeds", FS: before})
	s := &Store{db: db}
	if err := s.SeedBuiltins(context.Background(), epoch0); err != nil {
		t.Fatal(err)
	}
	addCustom(t, db, "cf-v", "Partner advisories", KindVulnerabilities)
	if err := store.Migrate(t.Context(), db, "feeds", Migrations); err != nil {
		t.Fatal(err)
	}
	rows, err := s.sources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	stored, err := s.contentVersionsStored(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var again []string
	for _, r := range rows {
		r.ContentVersion = stored[r.ID]
		if r.ContentVersion != 1 {
			t.Errorf("%s: version %d", r.ID, r.ContentVersion)
		}
		if r.reload() {
			again = append(again, r.ID)
		}
	}
	if !slices.Equal(again, []string{winRelFeedID}) {
		t.Fatalf("read again after the update: %v", again)
	}
}
