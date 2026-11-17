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

// D-603: the Windows releases Microsoft lists. core/winrel holds a hand table of Windows 10, 11 and Server releases (D-546); a release
// newer than it (Windows 11 26H2, build 26300, out 2026-09-29) left every Windows CVE of such a PC "could not be checked" until a code
// change. The feed windows-releases reads Microsoft's Windows release information pages on the box once a day: for each release its
// OS build and the history of its updates (date, build with revision, KB). From those a release gets its NVD name (Windows 11
// "Version 26H2" is windows_11_26h2, "Windows Server 2028" windows_server_2028, the names NVD gives every release since 2021), its
// general availability and first public build (the history's earliest row, as core/winrel's table takes it) and its line: a client release
// whose update of a month is the same KB at the same revision as a release of the table's (KB5132061 is 26300.9974, 26200.9974 and
// 26100.9974) is on that release's line, so NVD's rows of 24H2 and 25H2 decide for 26H2 with the device's revision (findings, D-546).
// The releases go to core/winrel (Learn), which keeps the table's own facts first. The page is untrusted input: every value is checked
// and bounded, and a page without the tables Vedette reads is a failed pull that keeps the last good list.

const winRelFeedID = "windows-releases"

// winRelServerPage is the page of Windows Server releases, next to the feed's address (the Windows 11 page).
const winRelServerPage = "windows-server-release-info"

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

func winRelText(b []byte) string {
	return strings.Join(strings.Fields(html.UnescapeString(winRelTagRE.ReplaceAllString(string(b), " "))), " ")
}

// winRelReleases derives the releases of the histories of both pages (D-603): the ones whose heading has a shape NVD names, with their
// line. Releases the hand table has are derived too (their KBs tie a new release to their line); core/winrel.Learn drops them.
func winRelReleases(hs []winRelHistory) []winrel.Release {
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
		first := slices.MinFunc(h.updates, func(a, b winRelUpdate) int { // 26H2's 26300.9457 and 26300.9550 both came on 2026-09-29
			return cmp.Or(a.date.Compare(b.date), cmp.Compare(a.rev, b.rev))
		})
		r.GA, r.GARev = first.date, first.rev // the first row of the history: the build at general availability (core/winrel's own rule)
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

// buildWinRel fetches both pages from the feed's address (the Windows 11 page) and the server page next to it.
func (s *Service) buildWinRel(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	serverURL := src.URL[:strings.LastIndex(src.URL, "/")+1] + winRelServerPage
	var hs []winRelHistory
	for i, u := range []string{src.URL, serverURL} {
		resp, err := s.get(ctx, Request{URL: u, MaxBytes: winRelMaxBytes})
		if err != nil {
			return p, err
		}
		h, err := parseWinRelPage(resp.Body, i == 1)
		if err != nil {
			return p, err
		}
		p.out.Bytes += len(resp.Body)
		hs = append(hs, h...)
	}
	rels := winRelReleases(hs)
	if !slices.ContainsFunc(rels, func(r winrel.Release) bool { return !r.Server }) || !slices.ContainsFunc(rels, func(r winrel.Release) bool { return r.Server }) {
		return p, fail(ErrBadSample, "Microsoft's release information pages list no Windows 11 or no Windows Server release Vedette can read (their layout may have changed); the list on the box was kept.")
	}
	p.out.OK, p.out.Records, p.out.Accepted = true, len(rels), len(rels)
	p.winRel, p.hasWinRel = rels, true
	return p, nil
}

// applyWinRel replaces the stored releases (feeds_winrel) and says whether they changed; the CVEs NVD lists Windows rows for are
// returned when they did, for findings to match again (EventRangesUpdated).
func applyWinRel(ctx context.Context, tx *sql.Tx, rels []winrel.Release) (changedCVEs []string, changed bool, err error) {
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
	if slices.Equal(before, after) {
		return nil, false, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT cve FROM feeds_affected WHERE cpe GLOB 'cpe:2.3:o:microsoft:windows*' ORDER BY cve`)
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
	return changedCVEs, true, rows.Err()
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

// LearnWindowsReleases hands the stored releases to core/winrel (D-603): when the service is built (cmd/vedette, before any match
// or agent report needs them), when it is first ready, and after a pull that changed them. With the feed off the
// stored list stays in use (the last good copy); it is never deleted by turning the feed off, only replaced by a good pull.
func (s *Service) LearnWindowsReleases(ctx context.Context) error {
	rels, err := winRelRows(ctx, s.DB.Reader())
	if err != nil {
		return err
	}
	winrel.Learn(rels)
	return nil
}
