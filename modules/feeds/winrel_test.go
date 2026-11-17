package feeds

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/winrel"
)

// D-603: the trimmed real pages (fetched 2026-11-17) give Windows 11 26H2 (26300) on 24H2's line, its first public build 26300.9457 of
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
	t.Cleanup(func() { winrel.Learn(nil) })
	e, o := pullEnv(t)
	e.only(winRelFeedID)
	e.setURL(winRelFeedID, o.url("/rh/windows11-release-information")) // no mirror through the API (review r1 M2)
	o.body("/rh/windows11-release-information", `"a"`, testFile(t, "winrel/windows11-release-information.html"))
	o.body("/rh/"+winRelServerPage, `"b"`, "<html>moved</html>") // review r1 L5: the server page is optional
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

func day(t *testing.T, s string) time.Time {
	t.Helper()
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
