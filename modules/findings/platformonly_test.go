package findings

import (
	"testing"
)

// NVD's CPE configurations separate the affected product (vulnerable: true) from the environment it runs on (vulnerable: false, the
// "running on" operating system of an AND configuration). An operating system that a CVE names only as such an environment is not the
// affected product: an exploited list that files the CVE under the operating system's name does not make the operating system's own
// row affected, and the box says so instead of "the record names other products". An exploited CVE still waits for a person.
func TestPlatformOnly_OperatingSystemNamedOnlyAsTheEnvironment(t *testing.T) {
	t.Parallel()
	const (
		appCPE = "cpe:2.3:a:example:font_viewer:*:*:*:*:*:*:*:*"
		osCPE  = "cpe:2.3:o:example:example_os_7:7.2.100:*:*:*:*:*:x64:*"
	)
	viewer := Affected{CPE: appCPE, Range: VersionRange{EndExcl: "3.1"}, Platforms: []string{"example:example_os_5", "example:example_os_6"}}
	osRow := Software{ID: "s-os", Display: "Example OS 7", Vendor: "Example", Product: "Example OS 7", Version: "7.2.100", CPE: osCPE,
		Source: "agent", KevKeys: []string{"example|example os"}}
	appRow := func(ver string) Software {
		return Software{ID: "s-viewer", Display: "Example Font Viewer", Vendor: "Example", Product: "Font Viewer", Version: ver, Source: "agent"}
	}
	asset := func(s Software) Asset {
		return Asset{ID: "pc", Name: "pc-01", OS: "Example OS 7", Software: []Software{s}}
	}

	t.Run("exploited, the operating system row", func(t *testing.T) {
		t.Parallel()
		v := uncVuln("CVE-2026-90901", "Example", "Example OS", uncNew, viewer)
		res := MatchAsset(asset(osRow), []Vuln{v}, nil, uncNow)
		if len(res.New) != 0 {
			t.Fatalf("an operating system named only as the environment got a finding: %+v", res.New)
		}
		if len(res.Unchecked) != 1 || res.Unchecked[0].undecided == nil || res.Unchecked[0].undecided.Reason != UndecidedPlatformOnly {
			t.Fatalf("unchecked %+v, want one row with reason %s", res.Unchecked, UndecidedPlatformOnly)
		}
		if got := res.Unchecked[0].undecided.Ranges; len(got) != 1 {
			t.Errorf("the rows that name the operating system as the environment: %v, want the one application row", got)
		}
		q := Question{Kind: QuestionNoRangeData, Detail: QuestionDetail{Version: "7.2.100", Undecided: res.Unchecked[0].undecided}}
		if got := PossibleCause(PossibleItem{Question: q, CVE: v.CVE, Exploited: true, State: PossibleOpen}, ReadState{Ready: true}); got != CauseNeedsPerson {
			t.Errorf("cause %q, want %q: an exploited CVE is closed by a person only", got, CauseNeedsPerson)
		}
	})

	t.Run("on no exploited list, the operating system row", func(t *testing.T) {
		t.Parallel()
		v := uncVuln("CVE-2026-90902", "", "", uncNew, viewer)
		res := MatchAsset(asset(osRow), []Vuln{v}, nil, uncNow)
		if len(res.New)+len(res.Existing)+len(res.Unchecked) != 0 {
			t.Fatalf("not affected expected: new %+v, unchecked %+v", res.New, res.Unchecked)
		}
	})

	t.Run("the application row is decided by its range", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			ver  string
			want int
		}{{"3.0.2", 1}, {"3.1", 0}} {
			v := uncVuln("CVE-2026-90903", "Example", "Font Viewer", uncNew, viewer)
			res := MatchAsset(asset(appRow(tc.ver)), []Vuln{v}, nil, uncNow)
			if len(res.New) != tc.want || len(res.Unchecked) != 0 {
				t.Errorf("Font Viewer %s: new %+v, unchecked %+v, want %d findings", tc.ver, res.New, res.Unchecked, tc.want)
			}
		}
	})

	t.Run("not the environment-only shape: the record keeps its old label", func(t *testing.T) {
		t.Parallel()
		for name, aff := range map[string][]Affected{
			"no running-on condition":         {{CPE: appCPE, Range: VersionRange{EndExcl: "3.1"}}},
			"another vendor's system":         {{CPE: appCPE, Range: VersionRange{EndExcl: "3.1"}, Platforms: []string{"other:other_os"}}},
			"an operating system is affected": {viewer, {CPE: "cpe:2.3:o:example:example_os_6:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "6.9"}}},
			"a row without a part":            {viewer, {CPE: "cpe:2.3:*:example:font_service:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "2.0"}}},
		} {
			v := uncVuln("CVE-2026-90904", "Example", "Example OS", uncNew, aff...)
			res := MatchAsset(asset(osRow), []Vuln{v}, nil, uncNow)
			if len(res.Unchecked) != 1 || res.Unchecked[0].undecided == nil || res.Unchecked[0].undecided.Reason == UndecidedPlatformOnly {
				t.Errorf("%s: unchecked %+v, want one row not labelled %s", name, res.Unchecked, UndecidedPlatformOnly)
			}
		}
	})
}
