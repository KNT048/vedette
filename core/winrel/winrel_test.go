package winrel

import (
	"strings"
	"testing"
	"time"
)

// One release per build and kind, one per NVD name, every line the first build of a client release of the table, and a
// server release never on a client line.
func TestReleasesTable(t *testing.T) {
	seen, names := map[[2]int]bool{}, map[string]bool{}
	for _, r := range releases {
		kind := 0
		if r.Server {
			kind = 1
		}
		if seen[[2]int{r.Build, kind}] || names[r.Product] {
			t.Errorf("%+v: twice", r)
		}
		seen[[2]int{r.Build, kind}], names[r.Product] = true, true
		if !strings.HasPrefix(r.Product, "windows_") || r.Product != strings.ToLower(r.Product) || r.Build < 10240 || r.Build > 99999 || r.GA.IsZero() {
			t.Errorf("%+v", r)
		}
		first, ok := ByBuild(r.Line, r.Server)
		if !ok || first.Line != r.Line || r.Server && r.Line != r.Build {
			t.Errorf("%s: line %d", r.Product, r.Line)
		}
		if got, ok := ByProduct(r.Product); !ok || got != r {
			t.Errorf("ByProduct(%s): %+v", r.Product, got)
		}
	}
	if r, ok := ByBuild(26200, false); !ok || r.Product != "windows_11_25h2" || r.Line != 26100 {
		t.Errorf("25H2: %+v", r)
	}
	if r, _ := ByBuild(26100, false); r.GARev != 1742 || r.LastFreeRev != 0 {
		t.Errorf("24H2 revisions: %+v", r)
	}
	if r, _ := ByBuild(19045, false); r.LastFreeRev <= r.GARev {
		t.Errorf("10 22H2 revisions: %+v", r)
	}
	if r, ok := ByBuild(26100, true); !ok || r.Product != "windows_server_2025" || r.Line != 26100 {
		t.Errorf("Server 2025: %+v", r)
	}
	if _, ok := ByBuild(20348, false); ok {
		t.Error("20348 is a server build only")
	}
}

// A release Microsoft's release information lists and the table does not is answered after the table's; the table's facts win,
// and a release with a bad name, line or kind is dropped.
func TestLearn(t *testing.T) {
	t.Cleanup(func() { Learn(nil) })
	h2 := Release{Build: 26300, Product: "windows_11_26h2", Display: "Windows 11 26H2", Line: 26100, GA: day("2026-09-29"), GARev: 9457, Ended: true, LastFreeRev: 5}
	h1 := Release{Build: 28000, Product: "windows_11_26h1", Display: "Windows 11 26H1", Line: 28000, GA: day("2026-02-10"), GARev: 1}
	n := Learn([]Release{
		h2, h1,
		{Build: 26200, Product: "windows_11_25h2", Display: "x", Line: 26200, GA: day("2025-09-30")},                       // the table's: kept as the table says
		{Build: 26400, Product: "windows_11_25h2", Display: "x", Line: 26400, GA: day("2027-09-30")},                       // the table's name
		{Build: 26500, Product: "windows_11_27h2", Display: "x", Line: 22621, GA: day("2027-09-30")},                       // the first build of a line of the table: kept
		{Build: 26600, Product: "windows_11_28h2", Display: "x", Line: 26200, GA: day("2028-09-30")},                       // 26200 is not a line's first build
		{Build: 26700, Product: "windows_server_2028", Display: "Windows Server 2028", Line: 26100, GA: day("2028-01-01")}, // a server on a client line
		{Build: 26800, Product: "windows_xp", Display: "x", Line: 26800, GA: day("2028-01-01")},
		{Build: 26900, Product: "windows_11_29h2", Display: "x", Line: 26900},                        // no GA
		{Build: 26300, Product: "windows_11_30h2", Display: "x", Line: 26300, GA: day("2030-01-01")}, // the build again
	})
	if n != 3 { // 26H2, 26H1 and 27H2
		t.Fatalf("kept %d: %+v", n, learnedReleases())
	}
	if r, ok := ByBuild(26300, false); !ok || r.Product != "windows_11_26h2" || r.Line != 26100 || r.Ended || r.LastFreeRev != 0 {
		t.Errorf("26H2: %+v %v", r, ok)
	}
	if r, ok := ByProduct("windows_11_26h1"); !ok || r.Build != 28000 || r.Line != 28000 {
		t.Errorf("26H1: %+v %v", r, ok)
	}
	if r, _ := ByBuild(26200, false); r.Display != "Windows 11 25H2" || r.Line != 26100 {
		t.Errorf("25H2 changed: %+v", r)
	}
	if _, ok := ByBuild(26300, true); ok {
		t.Error("26300 is a client build only")
	}
	if got := len(Releases()); got != len(releases)+3 {
		t.Errorf("Releases: %d", got)
	}
	Learn(nil)
	if _, ok := ByBuild(26300, false); ok {
		t.Error("Learn(nil) keeps 26H2")
	}
}

// LearnUpdates keeps the valid updates once per release and revision, oldest first, server and client apart; each call replaces the last.
func TestLearnUpdates(t *testing.T) {
	t.Cleanup(func() { LearnUpdates(nil) })
	d := func(s string) time.Time { return day(s) }
	n := LearnUpdates([]Update{
		{Build: 26100, Server: true, Rev: 33822, KB: "KB5131080", Day: d("2026-11-10")},
		{Build: 26100, Server: true, Rev: 33650, KB: "KB5126646", Day: d("2026-10-13")},
		{Build: 26100, Server: true, Rev: 33822, KB: "KB5131080", Day: d("2026-11-10")}, // twice
		{Build: 26100, Rev: 9974, KB: "KB5132061", Day: d("2026-11-10")},
		{Build: 9600, Rev: 1, Day: d("2026-11-10")},                       // not Windows 10 or later
		{Build: 26100, Rev: 0, Day: d("2026-11-10")},                      // no revision
		{Build: 26100, Rev: 9000, KB: "KB<script>", Day: d("2026-11-10")}, // bad KB
		{Build: 26100, Rev: 9001}, // no day
	})
	if n != 3 {
		t.Errorf("kept %d", n)
	}
	if us := Updates(26100, true); len(us) != 2 || us[0].Rev != 33650 || us[1].Rev != 33822 {
		t.Errorf("Server 2025: %+v", us)
	}
	if us := Updates(26100, false); len(us) != 1 || us[0].Rev != 9974 {
		t.Errorf("24H2: %+v", us)
	}
	LearnUpdates(nil)
	if us := Updates(26100, true); us != nil {
		t.Errorf("after forgetting: %+v", us)
	}
}

// A hotpatch revision is current to the monthly update of its month (Baseline); it is never one of Updates.
func TestBaseline(t *testing.T) {
	t.Cleanup(func() { LearnUpdates(nil) })
	LearnUpdates([]Update{
		{Build: 26100, Server: true, Rev: 33650, Day: day("2026-10-13")},
		{Build: 26100, Server: true, Rev: 33822, KB: "KB5131080", Day: day("2026-11-10")},
		{Build: 26100, Server: true, Rev: 33730, KB: "KB5131077", Day: day("2026-11-10"), Hotpatch: true},
		{Build: 26100, Server: true, Rev: 33900, Day: day("2026-12-08"), Hotpatch: true}, // its month's update is not known yet
	})
	if us := Updates(26100, true); len(us) != 2 || us[1].Rev != 33822 {
		t.Errorf("monthly: %+v", us)
	}
	if b, h, ok := Baseline(26100, true, 33730); !ok || b.Rev != 33822 || b.KB != "KB5131080" || h.KB != "KB5131077" {
		t.Errorf("November hotpatch: %+v %+v %v", b, h, ok)
	}
	for _, c := range []struct {
		rev    int
		server bool
	}{{33650, true}, {33900, true}, {33730, false}, {12345, true}} {
		if b, _, ok := Baseline(26100, c.server, c.rev); ok {
			t.Errorf("%+v: %+v", c, b)
		}
	}
}

// A hotpatch row whose build is wrong in value maps nothing: below or at the previous month's update, at or above its own month's,
// in a month with no update before it, or at a monthly update's revision (dropped whatever the order the rows come in).
func TestBaseline_HostileRows(t *testing.T) {
	t.Cleanup(func() { LearnUpdates(nil) })
	hot := func(rev int, d string) Update {
		return Update{Build: 26100, Server: true, Rev: rev, Day: day(d), Hotpatch: true}
	}
	LearnUpdates([]Update{
		hot(33650, "2026-11-10"), // October's update pasted as November's hotpatch, given before the monthly rows
		{Build: 26100, Server: true, Rev: 33650, Day: day("2026-10-13")},
		{Build: 26100, Server: true, Rev: 33822, Day: day("2026-11-10")},
		hot(33600, "2026-11-10"), // below October's update
		hot(33830, "2026-11-10"), // above November's
		hot(33500, "2026-10-13"), // October: no update before it is known
	})
	if us := Updates(26100, true); len(us) != 2 || us[0].Rev != 33650 {
		t.Fatalf("monthly: %+v", us)
	}
	for _, rev := range []int{33650, 33600, 33830, 33500} {
		if b, h, ok := Baseline(26100, true, rev); ok {
			t.Errorf("%d mapped to %+v (hotpatch %+v)", rev, b, h)
		}
	}
}
