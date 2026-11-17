package findings

import (
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/winrel"
)

// learn26 gives core/winrel the releases the feed windows-releases derives from Microsoft's pages of 2026-11-17 (feeds' winrel_test
// reads them from the trimmed real pages): 26H2 on 24H2's line, 26H1 on its own. Not parallel: Learn is global, and the D-602 tests
// read build 26300 as one the box has not learned.
func learn26(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { winrel.Learn(nil) })
	if n := winrel.Learn([]winrel.Release{
		{Build: 26300, Product: "windows_11_26h2", Display: "Windows 11 26H2", Line: 26100, GA: winDay("2026-09-29"), GARev: 9457},
		{Build: 28000, Product: "windows_11_26h1", Display: "Windows 11 26H1", Line: 28000, GA: winDay("2026-02-10"), GARev: 1575},
	}); n != 2 {
		t.Fatalf("learned %d", n)
	}
}

// D-603 (N100 DESKTOP-55UKKFV, Windows 11 Pro 10.0.26300.9974): once the box learned 26H2 from Microsoft's list, its Windows entries
// are decided by build. NVD's rows of 24H2 and 25H2 decide with the device's revision (one line, one monthly update), and its own
// rows once NVD names windows_11_26h2.
func TestMatchAsset_D603_LearnedRelease(t *testing.T) {
	learn26(t)
	// CVE-2025-62215 (November 2025): 24H2 and 25H2 fixed in 7092; 26H2 shipped after, at 9457
	w, m := oneMatch(t, winPC(26300, false, "9974", "x64"), cve62215, true)
	wantMatch(t, "26H2 on the 24H2 line", w, m, "notaffected", "", "")
	// a November 2026 entry NVD lists for 26H2 itself (the N100's feeds_affected has windows_11_26h2 < 10.0.26300.9711)
	nov := nvdWindows("CVE-2026-96951", "2026-10-20",
		nvdRow{"windows_11_24h2", "*", "x64", "10.0.26100.9711"}, nvdRow{"windows_11_25h2", "*", "x64", "10.0.26200.9711"},
		nvdRow{"windows_11_26h2", "*", "x64", "10.0.26300.9711"}, nvdRow{"windows_11_26h1", "*", "x64", "10.0.28000.3231"})
	w, m = oneMatch(t, winPC(26300, false, "9550", "x64"), nov, false)
	wantMatch(t, "26H2 below the fix", w, m, "new", BasisVersion, SeverityHigh, "before 10.0.26300.9711")
	w, m = oneMatch(t, winPC(26300, false, "9974", "x64"), nov, true)
	wantMatch(t, "26H2 patched", w, m, "notaffected", "", "")
	if f := FixedInFor(winPC(26300, false, "9550", "x64"), nov); f == nil || f.Kind != "fixed" || f.Fixed != "10.0.26300.9711" {
		t.Errorf("fixed_in: %+v", f)
	}
	// 26H1 is a line of its own: its own row decides; 24H2's never do
	w, m = oneMatch(t, winPC(28000, false, "3000", "x64"), nov, false)
	wantMatch(t, "26H1 below the fix", w, m, "new", BasisVersion, SeverityHigh, "before 10.0.28000.3231")
	// a family row NVD writes with the version (windows_11:26h2) names the learned release
	if l, ok := winListedOf(mustCPE(t, "cpe:2.3:o:microsoft:windows_11:26h2:*:*:*:*:*:*:*")); !ok || l.build != 26300 || l.family != "" {
		t.Errorf("windows_11:26h2: %+v", l)
	}
}

// Review r1 M1 of #951: a learned release never closes on "only older releases are listed": Vedette does not know when Microsoft stops
// servicing it, and a list that leaves it out may mean it is no longer fixed. 26H1 (28000) is above the whole 26100 line by build.
func TestMatchAsset_D603_LearnedReleaseNeverClosesOnOlderReleases(t *testing.T) {
	learn26(t)
	named := nvdWindows("CVE-2026-96951", "2026-10-20", nvdRow{"windows_11_26h1", "*", "x64", "10.0.28000.3231"}) // NVD names 26H1 somewhere
	// CVE-2025-62215 lists only the 26100 line and older; CISA listed it a year before winNow (settled) and 90 days before 26H1's GA (shipped)
	w, m := oneMatch(t, winPC(28000, false, "3501", "x64"), cve62215, true, named)
	wantMatch(t, "26H1, only older releases listed", w, m, "nameonly", "", "", "Vedette learned Windows 11 26H1 from Microsoft's release list")
}

// Review r1 L4 of #951, D-602: a build below a learned release's first public build (a Dev Channel 26300 before 9457, a Canary 28000.1)
// is an Insider build: not checked, neither by its own rows nor by its siblings'.
func TestMatchAsset_D603_BelowFirstPublicBuildIsNotChecked(t *testing.T) {
	learn26(t)
	nov := nvdWindows("CVE-2026-96951", "2026-10-20",
		nvdRow{"windows_11_24h2", "*", "x64", "10.0.26100.9711"}, nvdRow{"windows_11_26h2", "*", "x64", "10.0.26300.9711"},
		nvdRow{"windows_11_26h1", "*", "x64", "10.0.28000.3231"})
	for _, c := range []struct {
		build int
		rev   string
		v     Vuln
	}{{26300, "9000", nov}, {26300, "9000", cve62215}, {28000, "1", nov}} {
		w, m := oneMatch(t, winPC(c.build, false, c.rev, "x64"), c.v, false)
		wantMatch(t, fmt.Sprintf("%d.%s %s", c.build, c.rev, c.v.CVE), w, m, "nameonly", "", "", "an Insider or preview build")
	}
}

// Review r1 L3 of #951: 26H1 is newer by build than 25H2 but on another line, not its successor: no "check that 25H2 is still
// supported" note; still not checked.
func TestMatchAsset_D603_OtherLineIsNoSuccessor(t *testing.T) {
	learn26(t)
	v := nvdWindows("CVE-2026-90001", "2026-10-20", nvdRow{"windows_11_23h2", "*", "x64", "10.0.22631.7652"}, nvdRow{"windows_11_26h1", "*", "x64", "10.0.28000.3231"})
	w, m := oneMatch(t, winPC(26200, false, "9711", "x64"), v, false)
	if w != "nameonly" || strings.Contains(m.Evidence.Summary, "still supported") {
		t.Errorf("%s %q", w, m.Evidence.Summary)
	}
}

// D-603: a build neither the table nor Microsoft's list has (a Canary Insider build below the newest release) stays "could not be
// checked", and says it is not a release Vedette knows: Microsoft publishes no fixed builds for Insider builds.
func TestMatchAsset_D603_InsiderBuildStaysUnchecked(t *testing.T) {
	learn26(t)
	a := desktop55()
	a.OS = "Microsoft Windows 11 Pro 10.0.27950.1000"
	a.Software[0].Product, a.Software[0].Version = "Windows (build 27950)", "10.0.27950.1000"
	v := cve62215
	v.NVDAnswered = true
	res := MatchAsset(a, []Vuln{v}, nil, winNow)
	if len(res.New) != 0 || len(res.NameOnly) != 1 || len(res.Unchecked) != 1 || res.Unchecked[0].Reason != UncheckedNotComparable {
		t.Fatalf("%+v", res)
	}
	if s := res.NameOnly[0].Evidence.Summary; !strings.Contains(s, "Windows build 27950 is not a Windows release Vedette knows (an Insider or other pre-release build") {
		t.Errorf("%q", s)
	}
}
