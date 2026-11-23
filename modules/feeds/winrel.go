package feeds

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"html"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/winrel"
)

// The Windows releases Microsoft lists. core/winrel holds a hand table of Windows 10, 11 and Server releases; a release
// newer than it (Windows 11 26H2, build 26300, out 2026-09-29) left every Windows CVE of such a PC "could not be checked" until a code
// change. The feed windows-releases reads Microsoft's Windows release information pages on the box once a day: for each release its
// OS build and the history of its updates (date, build with revision, KB). From those a release gets its NVD name (Windows 11
// "Version 26H2" is windows_11_26h2, "Windows Server 2028" windows_server_2028, the names NVD gives every release since 2021), its
// general availability and first public build (the history's earliest row, as core/winrel's table takes it) and its line: a client release
// whose update of a month is the same KB at the same revision as a release of the table's (KB5132061 is 26300.9974, 26200.9974 and
// 26100.9974) is on that release's line, so NVD's rows of 24H2 and 25H2 decide for 26H2 with the device's revision (findings).
// The releases go to core/winrel (Learn), which keeps the table's own facts first. The page is untrusted input: every value is checked
// and bounded, and a page without the tables Vedette reads is a failed pull that keeps the last good list.

const winRelFeedID = "windows-releases"

// winRelServerPage is the page of Windows Server releases, next to the feed's address (the Windows 11 page).
const winRelServerPage = "windows-server-release-info"

// winRel10Page is the page of Windows 10 releases, next to the feed's address: read only for its monthly updates (Windows 10 22H2
// with Extended Security Updates, the LTSC/LTSB editions 2015, 2016, 2019 and 2021), never for releases (core/winrel's table has them
// all, and its "Version 22H2" is not Windows 11's).
const winRel10Page = "release-information"

// winRelMaxBytes bounds each page (the Windows 11 page is about 140 kB, the server page 170 kB, November 2026).
const winRelMaxBytes = 2 << 20

var (
	// a release's history table: its heading ("Version 26H2 (OS build 26300)", "Windows Server 2025 (OS build 26100)") then the table
	// Microsoft gives the id historyTable_N (the hotpatch calendars under the same headings have other ids)
	winRelTableRE = regexp.MustCompile(`(?s)<strong>([^<]{3,80}?) \(OS build ([0-9]{5})\)</strong>\s*(?:</summary>\s*)?<table[^>]*\bid="historyTable_[0-9]{1,3}"[^>]*>(.*?)</table>`)
	winRelRowRE   = regexp.MustCompile(`(?s)<tr[^>]*>(.*?)</tr>`)
	winRelCellRE  = regexp.MustCompile(`(?s)<td[^>]*>(.*?)</td>`)
	winRelTagRE   = regexp.MustCompile(`<[^>]*>`)
	winRelBuildRE = regexp.MustCompile(`^([0-9]{5})\.([0-9]{1,6})$`)
	winRelKBRE    = regexp.MustCompile(`^KB[0-9]{6,8}$`)
	winRelUpdRE   = regexp.MustCompile(`^(?:20[0-9]{2}-[01][0-9] (?:[A-E]|OOB))?$`)
	winRelClient  = regexp.MustCompile(`^Version ([0-9]{2}H[12])$`)
	winRelServer  = regexp.MustCompile(`^Windows Server (20[2-9][0-9])$`)
	// every history table of a page, whatever stands between its heading and it (a paragraph on the enablement package, "- End of
	// updates"): its rows name their own build, so the monthly updates need no heading
	winRelAnyTableRE = regexp.MustCompile(`(?s)<table[^>]*\bid="historyTable_[0-9]{1,3}"[^>]*>(.*?)</table>`)
	winRelMonthlyRE  = regexp.MustCompile(`^20[0-9]{2}-[01][0-9] B$`)
	// a hotpatch calendar ("Calendar year 2026" of Windows Server 2025, Windows 11 24H2): Month, Update type ("2026.11 B"), Type
	// ("Hotpatch", "Baseline (Restart)"), Availability date, Build, KB
	winRelHotpatchTableRE = regexp.MustCompile(`(?s)<table[^>]*\bid="HotpatchCalendar_[A-Za-z0-9_]{1,60}"[^>]*>(.*?)</table>`)
	winRelHotpatchRE      = regexp.MustCompile(`^20[0-9]{2}\.[01][0-9] B$`)
)

// winRelUpdate is one row of a release's history.
type winRelUpdate struct {
	update string // "2026-11 B"; "" for the release's first build
	date   time.Time
	rev    int
	kb     string // "KB5132061"; "" when the row has none
}

// winRelHistory is one release's history table.
type winRelHistory struct {
	name    string // "Version 26H2", "Windows Server 2025"
	build   int
	server  bool
	updates []winRelUpdate
}

// parseWinRelPage reads the history tables of one of Microsoft's release information pages. A row whose build is not of the heading's
// build, or whose date, revision, update type or KB is not of the expected shape, is skipped; a page with no release is an error.
func parseWinRelPage(body []byte, server bool) ([]winRelHistory, error) {
	var out []winRelHistory
	for _, m := range winRelTableRE.FindAllSubmatch(body, 64) {
		h := winRelHistory{name: winRelText(m[1]), server: server}
		h.build, _ = strconv.Atoi(string(m[2]))
		for _, row := range winRelRowRE.FindAllSubmatch(m[3], 2000) {
			cells := winRelCellRE.FindAllSubmatch(row[1], 8)
			if len(cells) != 5 {
				continue // the heading row (th) or another shape
			}
			upd, day, build, kb := winRelText(cells[1][1]), winRelText(cells[2][1]), winRelText(cells[3][1]), winRelText(cells[4][1])
			bm := winRelBuildRE.FindStringSubmatch(build)
			d, err := time.Parse(time.DateOnly, day)
			if bm == nil || bm[1] != string(m[2]) || err != nil || d.Year() < 2015 || !winRelUpdRE.MatchString(upd) || kb != "" && !winRelKBRE.MatchString(kb) {
				continue
			}
			rev, _ := strconv.Atoi(bm[2])
			h.updates = append(h.updates, winRelUpdate{update: upd, date: d, rev: rev, kb: kb})
		}
		if len(h.updates) > 0 {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil, fail(ErrBadSample, "Microsoft's release information page has none of the release tables Vedette reads (its layout may have changed); the list on the box was kept.")
	}
	return out, nil
}

// parseWinRelUpdates reads the monthly security updates ("2026-11 B") of every history table of one of Microsoft's release
// information pages, of the kind of the page (server or client), each by the build its row names. The previews (C, D), out-of-band
// and first builds are left out: the target of a Windows release's update is the month's security update everyone is offered. It reads
// the hotpatches of the page's hotpatch calendars too (Type "Hotpatch"; the calendars' baselines are the history's B rows): a device on
// one is current to its month (core/winrel.Baseline). A hotpatch at a build the page's update history lists (a first build, a B, a
// preview, an out-of-band update) is a pasted regular build, not a hotpatch, and is left out. A row whose values are not of the expected shape is skipped, and so is one dated
// after now or outside the month its label names (a mistyped date would stay "newest" for a year); a page with none gives none.
func parseWinRelUpdates(body []byte, server bool, now time.Time) []winrel.Update {
	var out []winrel.Update
	read := func(label, day, build, kb string, hotpatch bool) {
		bm := winRelBuildRE.FindStringSubmatch(build)
		d, err := time.Parse(time.DateOnly, day)
		if bm == nil || err != nil || d.Year() < 2015 || kb != "" && !winRelKBRE.MatchString(kb) || d.After(now) ||
			d.Format("2006-01") != strings.Replace(label[:7], ".", "-", 1) {
			return
		}
		b, _ := strconv.Atoi(bm[1])
		rev, _ := strconv.Atoi(bm[2])
		if b < 10240 || rev < 1 {
			return
		}
		out = append(out, winrel.Update{Build: b, Server: server, Rev: rev, KB: kb, Day: d, Hotpatch: hotpatch})
	}
	regular := map[string]bool{} // every build of the update histories ("26100.33674")
	for _, m := range winRelAnyTableRE.FindAllSubmatch(body, 64) {
		for _, row := range winRelRowRE.FindAllSubmatch(m[1], 2000) {
			cells := winRelCellRE.FindAllSubmatch(row[1], 8)
			if len(cells) != 5 {
				continue
			}
			regular[winRelText(cells[3][1])] = true
			if upd := winRelText(cells[1][1]); winRelMonthlyRE.MatchString(upd) {
				read(upd, winRelText(cells[2][1]), winRelText(cells[3][1]), winRelText(cells[4][1]), false)
			}
		}
	}
	for _, m := range winRelHotpatchTableRE.FindAllSubmatch(body, 64) {
		for _, row := range winRelRowRE.FindAllSubmatch(m[1], 100) {
			cells := winRelCellRE.FindAllSubmatch(row[1], 8)
			if len(cells) != 6 {
				continue
			}
			if upd := winRelText(cells[1][1]); winRelHotpatchRE.MatchString(upd) && winRelText(cells[2][1]) == "Hotpatch" && !regular[winRelText(cells[4][1])] {
				read(upd, winRelText(cells[3][1]), winRelText(cells[4][1]), winRelText(cells[5][1]), true)
			}
		}
	}
	return out
}

func winRelText(b []byte) string {
	return strings.Join(strings.Fields(html.UnescapeString(winRelTagRE.ReplaceAllString(string(b), " "))), " ")
}

// winRelReleases derives the releases of the histories of both pages: the ones whose heading has a shape NVD names, with their
// line. Releases the hand table has are derived too (their KBs tie a new release to their line); core/winrel.Learn drops them. A
// shared update ties a release to the line of the other release as core/winrel knows it now: the table's, or one learned by an earlier
// pull. So a release whose updates match only another new release of the same pull, and none of the table's, is on a line of its own
// until the next pull, when that other release is known (review r1 L6 of #951; today 24H2, a table release, shares every 26100-line
// update). A release whose general availability is after now is not one (review r1 M2: a date the page cannot have yet).
func winRelReleases(hs []winRelHistory, now time.Time) []winrel.Release {
	type key struct {
		kb  string
		rev int
	}
	byKB := map[key][]int{} // the client builds whose history has this update
	for _, h := range hs {
		if h.server {
			continue
		}
		for _, u := range h.updates {
			if u.kb != "" {
				byKB[key{u.kb, u.rev}] = append(byKB[key{u.kb, u.rev}], h.build)
			}
		}
	}
	var out []winrel.Release
	for _, h := range hs {
		r := winrel.Release{Build: h.build, Server: h.server, Line: h.build}
		if m := winRelServer.FindStringSubmatch(h.name); h.server && m != nil {
			r.Product, r.Display = "windows_server_"+m[1], "Windows Server "+m[1]
		} else if m := winRelClient.FindStringSubmatch(h.name); !h.server && m != nil {
			r.Product, r.Display = "windows_11_"+strings.ToLower(m[1]), "Windows 11 "+m[1]
		} else {
			continue // a release NVD names some other way ("Windows Server, version 23H2"): the hand table's
		}
		byDay := func(a, b winRelUpdate) int { // 26H2's 26300.9457 and 26300.9550 both came on 2026-09-29
			return cmp.Or(a.date.Compare(b.date), cmp.Compare(a.rev, b.rev))
		}
		r.GA = slices.MinFunc(h.updates, byDay).date
		if r.GA.After(now) {
			continue
		}
		// the first public build: the earliest row with a KB or a revision of 100 or more (core/winrel's own rule). 26H1's first row is
		// the media's 28000.1, below every update Windows Update offers; a Canary build 28000.x is not 26H1 (review r1 L4 of #951)
		var public []winRelUpdate
		for _, u := range h.updates {
			if u.kb != "" || u.rev >= 100 {
				public = append(public, u)
			}
		}
		if len(public) > 0 {
			r.GARev = slices.MinFunc(public, byDay).rev
		}
		if !h.server {
			for _, u := range h.updates {
				for _, b := range byKB[key{u.kb, u.rev}] {
					if b == h.build {
						continue
					}
					l := b
					if t, ok := winrel.ByBuild(b, false); ok {
						l = t.Line
					}
					r.Line = min(r.Line, l)
				}
			}
		}
		out = append(out, r)
	}
	return out
}

// buildWinRel fetches the feed's address (the Windows 11 page, required), the server page and the Windows 10 page next to it. The
// server page is optional (review r1 L5 of #951): every Windows Server release it lists today is in core/winrel's table, so a failure
// of it is logged and the client releases are still learned. The Windows 10 page is optional too and gives monthly updates only. A page
// that fails keeps the stored updates of its releases (applyWinRel replaces only the releases a pull read).
func (s *Service) buildWinRel(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	dir := src.URL[:strings.LastIndex(src.URL, "/")+1]
	var hs []winRelHistory
	var ups []winrel.Update
	for i, u := range []string{src.URL, dir + winRelServerPage, dir + winRel10Page} {
		resp, err := s.get(ctx, Request{URL: u, MaxBytes: winRelMaxBytes})
		var h []winRelHistory
		if err == nil && i < 2 {
			h, err = parseWinRelPage(resp.Body, i == 1)
		}
		if err == nil && i == 2 && len(winRelAnyTableRE.FindIndex(resp.Body)) == 0 {
			err = fail(ErrBadSample, "Microsoft's Windows 10 release information page has none of the tables Vedette reads (its layout may have changed).")
		}
		if err != nil && i == 0 {
			return p, err
		}
		if err != nil {
			s.Log.WarnContext(ctx, "a Windows release page could not be read; the Windows 11 releases are still learned and its stored updates kept", "url", u, "error", err)
			continue
		}
		p.out.Bytes += len(resp.Body)
		hs = append(hs, h...)
		ups = append(ups, parseWinRelUpdates(resp.Body, i == 1, s.now())...)
	}
	rels := winRelReleases(hs, s.now())
	if !slices.ContainsFunc(rels, func(r winrel.Release) bool { return !r.Server }) {
		return p, fail(ErrBadSample, "Microsoft's release information page lists no Windows 11 release Vedette can read (its layout may have changed); the list on the box was kept.")
	}
	p.out.OK, p.out.Records, p.out.Accepted = true, len(rels), len(rels)
	p.winRel, p.winRelUpd, p.hasWinRel = rels, ups, true
	return p, nil
}

// applyWinRel replaces the stored releases (feeds_winrel) and the stored monthly updates of every release the pull read
// (feeds_winrel_update); when the releases or the updates changed, it returns the CVEs NVD lists Windows rows for, for findings to
// match again (EventRangesUpdated): an update moves the build a hotpatched device is compared at (core/winrel.Baseline) and the target
// and KB of the fix. The plan's target builds follow at its next plan pass (TierStamp has this feed). first: the pull filled an empty
// table of updates (the first pull, or the first after the update that added the table): the matches it changes are a baseline, not
// news (EventRangesUpdated.First).
func applyWinRel(ctx context.Context, tx *sql.Tx, rels []winrel.Release, ups []winrel.Update) (changedCVEs []string, first bool, err error) {
	updsBefore, err := winRelUpdateRows(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	read := map[[2]int]bool{}
	for _, u := range ups {
		k := [2]int{u.Build, boolInt(u.Server)}
		if !read[k] {
			read[k] = true
			if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_winrel_update WHERE build = ? AND server = ?`, k[0], k[1]); err != nil {
				return nil, false, fmt.Errorf("feeds: clear windows updates: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_winrel_update (build, server, rev, kb, day, hotpatch) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
			u.Build, k[1], u.Rev, u.KB, u.Day.Format(time.DateOnly), boolInt(u.Hotpatch)); err != nil {
			return nil, false, fmt.Errorf("feeds: store windows update: %w", err)
		}
	}
	before, err := winRelRows(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_winrel`); err != nil {
		return nil, false, fmt.Errorf("feeds: clear windows releases: %w", err)
	}
	for _, r := range rels {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_winrel (build, server, product, display, line, ga, ga_rev) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT DO NOTHING`, r.Build, boolInt(r.Server), r.Product, r.Display, r.Line, r.GA.Format(time.DateOnly), r.GARev); err != nil {
			return nil, false, fmt.Errorf("feeds: store windows release: %w", err)
		}
	}
	after, err := winRelRows(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	updsAfter, err := winRelUpdateRows(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	if slices.Equal(before, after) && slices.Equal(updsBefore, updsAfter) {
		return nil, false, nil
	}
	first = len(updsBefore) == 0 && len(updsAfter) > 0
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT r.cve FROM feeds_cve_range r WHERE r.vendor = 'microsoft' AND r.product GLOB 'windows*' AND r.part = 'o'
AND r.cve IN (SELECT cve FROM feeds_kev WHERE source_id IN ('cisa-kev', 'vulncheck-kev')) ORDER BY r.cve`)
	if err != nil {
		return nil, false, fmt.Errorf("feeds: windows cves: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, false, fmt.Errorf("feeds: windows cves: %w", err)
		}
		changedCVEs = append(changedCVEs, c)
	}
	return changedCVEs, first, rows.Err()
}

type winRelQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// winRelRows reads the stored releases, ordered.
func winRelRows(ctx context.Context, q winRelQuerier) ([]winrel.Release, error) {
	rows, err := q.QueryContext(ctx, `SELECT build, server, product, display, line, ga, ga_rev FROM feeds_winrel ORDER BY server, build`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read windows releases: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []winrel.Release
	for rows.Next() {
		var r winrel.Release
		var server int
		var ga string
		if err := rows.Scan(&r.Build, &server, &r.Product, &r.Display, &r.Line, &ga, &r.GARev); err != nil {
			return nil, fmt.Errorf("feeds: read windows releases: %w", err)
		}
		r.Server = server == 1
		if r.GA, err = time.Parse(time.DateOnly, ga); err != nil {
			continue // the CHECK keeps the shape; a date that does not parse is no release
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// winRelUpdateRows reads the stored monthly updates.
func winRelUpdateRows(ctx context.Context, q winRelQuerier) ([]winrel.Update, error) {
	rows, err := q.QueryContext(ctx, `SELECT build, server, rev, kb, day, hotpatch FROM feeds_winrel_update ORDER BY build, server, rev`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read windows updates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []winrel.Update
	for rows.Next() {
		var u winrel.Update
		var server, hotpatch int
		var d string
		if err := rows.Scan(&u.Build, &server, &u.Rev, &u.KB, &d, &hotpatch); err != nil {
			return nil, fmt.Errorf("feeds: read windows updates: %w", err)
		}
		u.Server, u.Hotpatch = server == 1, hotpatch == 1
		if u.Day, err = time.Parse(time.DateOnly, d); err != nil {
			continue
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// LearnWindowsReleases hands the stored releases and monthly updates to core/winrel: when the service is built (cmd/vedette, before
// any match or agent report needs them), when it is first ready, and after every good pull. With the feed off the stored lists stay in
// use (the last good copy); they are never deleted by turning the feed off, only replaced by a good pull.
func (s *Service) LearnWindowsReleases(ctx context.Context) error {
	rels, err := winRelRows(ctx, s.DB.Reader())
	if err != nil {
		return err
	}
	ups, err := winRelUpdateRows(ctx, s.DB.Reader())
	if err != nil {
		return err
	}
	winrel.Learn(rels)
	winrel.LearnUpdates(ups)
	return nil
}

// learnWindowsReleases is LearnWindowsReleases for the callers that go on without the list: a failure is logged, and a read cut short
// because the caller's context ended (shutdown, the module turned off) is not a failure.
func (s *Service) learnWindowsReleases(ctx context.Context) {
	if err := s.LearnWindowsReleases(ctx); err != nil {
		s.Log.Log(ctx, failLevel(ctx), "reading the Windows releases failed", "error", err)
	}
}
