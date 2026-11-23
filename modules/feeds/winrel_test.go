package feeds

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/winrel"
)

// The trimmed real pages (fetched 2026-11-17) give Windows 11 26H2 (26300) on 24H2's line, its first public build 26300.9457 of
// 2026-09-29, 26H1 (28000) on a line of its own, and the server releases; the hotpatch calendar under the same heading is not a history.
func TestParseWinRelPages(t *testing.T) {
	client, err := parseWinRelPage([]byte(testFile(t, "winrel/windows11-release-information.html")), false)
	if err != nil {
		t.Fatal(err)
	}
	server, err := parseWinRelPage([]byte(testFile(t, "winrel/windows-server-release-info.html")), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(client) != 4 || client[0].name != "Version 26H2" || client[0].build != 26300 || len(client[0].updates) != 6 {
		t.Fatalf("client histories: %+v", client)
	}
	if u := client[0].updates[0]; u.update != "2026-11 B" || u.rev != 9974 || u.kb != "KB5132061" || u.date != time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC) {
		t.Errorf("26H2's November update: %+v", u)
	}
	if len(server) != 4 || server[0].name != "Windows Server 2025" || !server[0].server {
		t.Fatalf("server histories: %+v", server)
	}
	got := map[string]winrel.Release{}
	for _, r := range winRelReleases(append(client, server...), day(t, "2026-11-17")) {
		got[r.Product] = r
	}
	want := map[string]winrel.Release{
		"windows_11_26h2":     {Build: 26300, Product: "windows_11_26h2", Display: "Windows 11 26H2", Line: 26100, GA: day(t, "2026-09-29"), GARev: 9457},
		"windows_11_26h1":     {Build: 28000, Product: "windows_11_26h1", Display: "Windows 11 26H1", Line: 28000, GA: day(t, "2026-02-10"), GARev: 1575}, // review r1 L4: not the media's 28000.1
		"windows_11_25h2":     {Build: 26200, Product: "windows_11_25h2", Display: "Windows 11 25H2", Line: 26100, GA: day(t, "2025-09-30"), GARev: 6584},
		"windows_server_2025": {Build: 26100, Product: "windows_server_2025", Display: "Windows Server 2025", Server: true, Line: 26100, GA: day(t, "2024-11-01"), GARev: 1742},
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: got %+v, want %+v", p, got[p], w)
		}
	}
	if len(got) != 6 { // 26H2, 26H1, 25H2, 24H2; Server 2025, 2022 (2019 and 2016 are older than any name the feed derives: the table's)
		t.Errorf("releases: %v", got)
	}
	// the table keeps its own 25H2 and Server 2025; 26H2 and 26H1 are learned
	t.Cleanup(func() { winrel.Learn(nil) })
	var rels []winrel.Release
	for _, r := range got {
		rels = append(rels, r)
	}
	if n := winrel.Learn(rels); n != 2 {
		t.Errorf("learned %d", n)
	}
}

// Review r1 M2 of #951: a release whose general availability is after the pull is not one; the address of the feed cannot be changed
// (Microsoft has no mirror of these pages).
func TestWinRel_FutureGAAndPinnedAddress(t *testing.T) {
	row := func(upd, day, build, kb string) string {
		return "<tr><td>x</td><td>" + upd + "</td><td>" + day + "</td><td>" + build + "</td><td>" + kb + "</td></tr>"
	}
	page := `<strong>Version 27H2 (OS build 26400)</strong><table id="historyTable_0"><tbody>` + row("2027-11 B", "2027-11-09", "26400.9999", "KB5000001") +
		`</tbody></table><strong>Version 26H2 (OS build 26300)</strong><table id="historyTable_1"><tbody>` + row("2026-11 B", "2026-11-10", "26300.9974", "KB5132061") + `</tbody></table>`
	hs, err := parseWinRelPage([]byte(page), false)
	if err != nil || len(hs) != 2 {
		t.Fatalf("%+v %v", hs, err)
	}
	rels := winRelReleases(hs, day(t, "2026-11-17"))
	if len(rels) != 1 || rels[0].Build != 26300 {
		t.Errorf("releases: %+v", rels)
	}
	e := newEnv(t)
	if c, b := e.put(winRelFeedID, `{"url":"https://example.net/windows11-release-information"}`); c != 400 || code(b) != "invalid_url" {
		t.Errorf("another address: %d %v", c, b)
	}
	if c, b := e.put(winRelFeedID, `{"url":""}`); c != 200 { // back to the default: allowed
		t.Errorf("the default address: %d %v", c, b)
	}
}

// Untrusted input: a row of another build, a bad date or KB, an over-long name and a page without the tables are not read.
func TestParseWinRelPage_Hostile(t *testing.T) {
	row := func(upd, day, build, kb string) string {
		return "<tr><td>x</td><td>" + upd + "</td><td>" + day + "</td><td>" + build + "</td><td>" + kb + "</td></tr>"
	}
	page := `<strong>Version 27H2 (OS build 26400)</strong><table id="historyTable_0"><tbody>` +
		row("2027-11 B", "2027-11-09", "26300.9999", "KB5000001") + // another build
		row("2027-11 B", "2027-13-09", "26400.9999", "KB5000001") + // no such day
		row("2027-11 B", "2027-11-09", "26400.9999", "KB5<script>") +
		row("<b>2027-10 B</b>", "2027-10-12", "26400.9000", "<a href=x>KB5000002</a>") + // markup around values is read as text
		`</tbody></table><strong>` + strings.Repeat("A", 200) + ` (OS build 26500)</strong><table id="historyTable_1"><tr>` + row("", "2027-01-01", "26500.1", "") + `</tr></table>`
	hs, err := parseWinRelPage([]byte(page), false)
	if err != nil || len(hs) != 1 || len(hs[0].updates) != 1 || hs[0].updates[0].kb != "KB5000002" || hs[0].updates[0].rev != 9000 {
		t.Fatalf("%+v %v", hs, err)
	}
	if _, err := parseWinRelPage([]byte(`<html><table id="historyTable_0"></table></html>`), false); err == nil {
		t.Error("a page without release tables is read")
	}
}

// A pull stores the releases and hands them to core/winrel; a later page Vedette cannot read fails the pull and keeps them (INV-3).
func TestWinRelPull(t *testing.T) {
	t.Cleanup(func() { winrel.Learn(nil); winrel.LearnUpdates(nil) })
	e, o := pullEnv(t)
	e.only(winRelFeedID)
	e.setURL(winRelFeedID, o.url("/rh/windows11-release-information")) // no mirror through the API (review r1 M2)
	o.body("/rh/windows11-release-information", `"a"`, testFile(t, "winrel/windows11-release-information.html"))
	o.body("/rh/"+winRelServerPage, `"b"`, "<html>moved</html>") // review r1 L5: the server page is optional
	o.body("/rh/"+winRel10Page, `"w"`, "<html>moved</html>")     // and the Windows 10 page
	if err := e.svc.Fetch(t.Context(), winRelFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e.feed(winRelFeedID); f.Status != "ok" || f.Records == nil || *f.Records != 4 { // 26H2, 26H1, 25H2, 24H2: no server page
		t.Fatalf("feed %+v", f)
	}
	if r, ok := winrel.ByBuild(26300, false); !ok || r.Product != "windows_11_26h2" || r.Line != 26100 {
		t.Fatalf("26300 after the pull: %+v %v", r, ok)
	}
	// review r1 L1: every good pull learns, also one that changed nothing (memory lost, the table kept)
	winrel.Learn(nil)
	o.body("/rh/"+winRelServerPage, `"b2"`, "<html>moved</html>")
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), winRelFeedID); err != nil {
		t.Fatal(err)
	}
	if _, ok := winrel.ByBuild(26300, false); !ok {
		t.Fatal("a pull that changed nothing did not learn")
	}
	n := rowsOf(t, e.db, "feeds_winrel")
	o.body("/rh/windows11-release-information", `"c"`, "<html>moved</html>")
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), winRelFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e.feed(winRelFeedID); f.Status != "error" || rowsOf(t, e.db, "feeds_winrel") != n {
		t.Fatalf("feed %+v, %d rows", f, rowsOf(t, e.db, "feeds_winrel"))
	}
	if _, ok := winrel.ByBuild(26300, false); !ok {
		t.Fatal("a failed pull forgot 26H2")
	}
}

// newestUpdates is the newest monthly update of each release (build, server 0/1) among us.
func newestUpdates(us []winrel.Update) map[[2]int]winrel.Update {
	out := map[[2]int]winrel.Update{}
	for _, u := range us {
		k := [2]int{u.Build, boolInt(u.Server)}
		if o, ok := out[k]; !ok || u.Rev > o.Rev {
			out[k] = u
		}
	}
	return out
}

// The monthly security updates ("YYYY-MM B") of every history table of the three pages (trimmed real pages, 2026-11-17), each by the
// build its rows name: also a table with a paragraph between its heading and it (Windows 10 22H2 and 21H2), the client LTSC/LTSB
// editions of the Windows 10 page and the releases whose heading the release list does not read. Never a preview, an out-of-band
// update (26100.33828 of 2026-11-13), a first build or a hotpatch calendar.
func TestParseWinRelUpdates(t *testing.T) {
	var all []winrel.Update
	for _, p := range []struct {
		file   string
		server bool
	}{{"winrel/windows11-release-information.html", false}, {"winrel/windows-server-release-info.html", true}, {"winrel/release-information.html", false}} {
		all = append(all, parseWinRelUpdates([]byte(testFile(t, p.file)), p.server, day(t, "2026-11-17"))...)
	}
	type want struct {
		rev int
		kb  string
	}
	wants := map[[2]int]want{
		{26100, 1}: {33822, "KB5131080"}, {20348, 1}: {5870, "KB5131090"}, {17763, 1}: {9487, "KB5131085"}, {14393, 1}: {9688, "KB5131291"},
		{26100, 0}: {9974, "KB5132061"}, {26200, 0}: {9974, "KB5132061"}, {26300, 0}: {9974, "KB5132061"}, {28000, 0}: {3501, "KB5132059"},
		{19045, 0}: {7846, "KB5131096"}, {19044, 0}: {7846, "KB5131096"}, {17763, 0}: {9487, "KB5131085"},
	}
	got := newestUpdates(all)
	if len(got) != len(wants) {
		t.Errorf("releases: %v", got)
	}
	for k, w := range wants {
		if u := got[k]; u.Rev != w.rev || u.KB != w.kb || u.Day != day(t, "2026-11-10") {
			t.Errorf("%v: got %+v, want %+v", k, u, w)
		}
	}
	var hot []winrel.Update
	for _, u := range all {
		if u.Hotpatch {
			hot = append(hot, u)
			continue
		}
		if u.Rev == 33828 || u.Rev == 7850 || u.Rev == 1742 || u.Day.Before(day(t, "2026-01-01")) {
			t.Errorf("not a monthly security update: %+v", u)
		}
	}
	// the hotpatch calendars give their hotpatches only (not the baselines, not a month with no build yet)
	wantHot := []winrel.Update{
		{Build: 26300, Rev: 9911, KB: "KB5132043", Day: day(t, "2026-11-10"), Hotpatch: true},
		{Build: 26100, Server: true, Rev: 33730, KB: "KB5131077", Day: day(t, "2026-11-10"), Hotpatch: true},
	}
	if len(hot) != len(wantHot) || hot[0] != wantHot[0] || hot[1] != wantHot[1] {
		t.Errorf("hotpatches: %+v", hot)
	}
	// untrusted input: a revision 0, a build of letters, a bad KB, an out-of-band row, a date after the pull and a date outside the
	// label's month are not read
	row := func(upd, d, build, kb string) string {
		return "<tr><td>x</td><td>" + upd + "</td><td>" + d + "</td><td>" + build + "</td><td>" + kb + "</td></tr>"
	}
	page := `<table id="historyTable_0"><tbody>` + row("2026-11 B", "2026-11-10", "26100.0", "KB5000001") + row("2026-11 B", "2026-11-10", "26a00.5", "KB5000001") +
		row("2026-11 B", "2026-11-10", "26100.5", "KB5<b>") + row("2026-11 OOB", "2026-11-13", "26100.6", "KB5000002") + row("2026-11 B", "2026-11-10", "26100.7", "") +
		row("2027-11 B", "2027-11-10", "26100.8", "KB5000003") + row("2026-10 B", "2026-11-10", "26100.9", "KB5000004") + `</tbody></table>`
	hp := func(upd, typ, d, build, kb string) string {
		return "<tr><td>November</td><td>" + upd + "</td><td>" + typ + "</td><td>" + d + "</td><td>" + build + "</td><td>" + kb + "</td></tr>"
	}
	page += `<table id="HotpatchCalendar_WindowsServer2025_2026"><tbody>` + hp("2026.11 B", "Baseline (Restart)", "2026-11-10", "26100.10", "KB5000005") +
		hp("2026.11 B", "Hotpatch", "2026-12-10", "26100.11", "KB5000006") + hp("2026.12 B", "Hotpatch", "2026-12-08", "26100.12", "KB5000007") +
		hp("2026.11 B", "Hotpatch", "", "", "") +
		// a pasted regular build: the history's B (26100.7), and builds of its out-of-band and preview rows (26100.6, 26100.13)
		hp("2026.11 B", "Hotpatch", "2026-11-10", "26100.7", "KB5000008") + hp("2026.11 B", "Hotpatch", "2026-11-10", "26100.6", "KB5000009") +
		hp("2026.11 B", "Hotpatch", "2026-11-10", "26100.13", "KB5000010") + `</tbody></table>`
	page += `<table id="historyTable_1"><tbody>` + row("2026-10 D", "2026-10-28", "26100.13", "KB5000011") + `</tbody></table>`
	if us := parseWinRelUpdates([]byte(page), true, day(t, "2026-11-17")); len(us) != 1 || us[0].Rev != 7 || us[0].KB != "" || !us[0].Server {
		t.Errorf("hostile rows: %+v", us)
	}
}

// A pull stores the monthly updates of every page it read and hands them to core/winrel; a page that fails keeps the stored updates
// of its releases, and a pull that fails keeps them all.
func TestWinRelPull_MonthlyUpdates(t *testing.T) {
	t.Cleanup(func() { winrel.Learn(nil); winrel.LearnUpdates(nil) })
	e, o := pullEnv(t)
	e.setNow(day(t, "2026-11-17").Add(12 * time.Hour)) // the day the fixture pages were read: their newest rows are not in the future
	e.only(winRelFeedID)
	e.setURL(winRelFeedID, o.url("/rh/windows11-release-information"))
	o.body("/rh/windows11-release-information", `"a"`, testFile(t, "winrel/windows11-release-information.html"))
	o.body("/rh/"+winRelServerPage, `"b"`, testFile(t, "winrel/windows-server-release-info.html"))
	o.body("/rh/"+winRel10Page, `"c"`, testFile(t, "winrel/release-information.html"))
	newest := func(build int, server bool) int {
		us := winrel.Updates(build, server)
		if len(us) == 0 {
			return 0
		}
		return us[len(us)-1].Rev
	}
	if err := e.svc.Fetch(t.Context(), winRelFeedID); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		build  int
		server bool
		rev    int
	}{{26100, true, 33822}, {26100, false, 9974}, {26200, false, 9974}, {19045, false, 7846}, {17763, false, 9487}, {17763, true, 9487}} {
		if got := newest(c.build, c.server); got != c.rev {
			t.Errorf("%d server=%v: newest %d, want %d", c.build, c.server, got, c.rev)
		}
	}
	n := rowsOf(t, e.db, "feeds_winrel_update")
	if n == 0 {
		t.Fatal("no update stored")
	}
	// a hotpatch is stored and learned as one: a device on it is current to its month's update
	if b, _, ok := winrel.Baseline(26100, true, 33730); !ok || b.Rev != 33822 || newest(26100, true) != 33822 {
		t.Errorf("Server 2025 hotpatch of November: %+v %v", b, ok)
	}
	// the server and Windows 10 pages fail: their releases keep their stored updates
	o.body("/rh/"+winRelServerPage, `"b2"`, "<html>moved</html>")
	o.body("/rh/"+winRel10Page, `"c2"`, "<html>moved</html>")
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), winRelFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e.feed(winRelFeedID); f.Status != "ok" || rowsOf(t, e.db, "feeds_winrel_update") != n || newest(26100, true) != 33822 || newest(19045, false) != 7846 {
		t.Fatalf("feed %+v, %d rows, Server 2025 %d, Windows 10 22H2 %d", f, rowsOf(t, e.db, "feeds_winrel_update"), newest(26100, true), newest(19045, false))
	}
	// the Windows 11 page fails: the pull fails and every update is kept
	o.body("/rh/windows11-release-information", `"a2"`, "<html>moved</html>")
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), winRelFeedID); err != nil {
		t.Fatal(err)
	}
	if f := e.feed(winRelFeedID); f.Status != "error" || rowsOf(t, e.db, "feeds_winrel_update") != n || newest(26200, false) != 9974 {
		t.Fatalf("feed %+v, %d rows", f, rowsOf(t, e.db, "feeds_winrel_update"))
	}
	// a restart reads them back
	winrel.LearnUpdates(nil)
	if err := e.svc.LearnWindowsReleases(t.Context()); err != nil || newest(26100, true) != 33822 {
		t.Fatalf("after a restart: %v, Server 2025 %d", err, newest(26100, true))
	}
}

func day(t *testing.T, s string) time.Time {
	t.Helper()
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// A read of the Windows releases cut short by the end of its context (the box stopping while a pull or the first request runs) is
// not an error in the log; the same read failing with the context alive is.
func TestLearnWindowsReleases_StopIsNotAnError(t *testing.T) {
	t.Cleanup(func() { winrel.Learn(nil); winrel.LearnUpdates(nil) })
	e := newEnv(t)
	var buf bytes.Buffer
	e.svc.Log = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	levels := func() []string {
		var out []string
		for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
			var r struct{ Level, Msg string }
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatalf("log line %q: %v", line, err)
			}
			out = append(out, r.Level+" "+r.Msg)
		}
		buf.Reset()
		return out
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	e.svc.learnWindowsReleases(ctx)
	if got := levels(); !slices.Equal(got, []string{"DEBUG reading the Windows releases failed"}) {
		t.Fatalf("after a stop the log has %q, want one debug line", got)
	}

	if err := e.db.Close(); err != nil {
		t.Fatal(err)
	}
	e.svc.learnWindowsReleases(t.Context())
	if got := levels(); !slices.Equal(got, []string{"ERROR reading the Windows releases failed"}) {
		t.Fatalf("with the database gone the log has %q, want one error line", got)
	}
}
