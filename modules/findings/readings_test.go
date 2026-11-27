package findings

import (
	"strings"
	"testing"
)

// Every reading of a record: a CVE is decided when each reading the record supports gives the same verdict for the installed version,
// and stays a question when they disagree. Synthetic products: the rule reads the shape of the rows, never the product.
func TestEveryReading_DecidesOnlyWhenAllAgree(t *testing.T) {
	t.Parallel()
	const (
		decided = "not affected"
		asked   = "question"
		found   = "finding"
	)
	outcome := func(res MatchResult) string {
		switch {
		case len(res.New) > 0 && res.New[0].Basis == BasisVersion:
			return found
		case len(res.New) > 0 || len(res.Unchecked) > 0 || len(res.NameOnly) > 0:
			return asked
		}
		return decided
	}

	// A product whose rows state only fixed releases, per build (channel) the rows pin and the box cannot tell for the line. Unscoped
	// fixes (from the first version on) below which the version lies are affected under every reading, and the rows already decide that
	// (decide, pinnedInside); a fix scoped to a release line says the line got a fix, not that older lines carried the flaw, so the
	// readings disagree and the CVE stays possible.
	t.Run("fixed releases only", func(t *testing.T) {
		t.Parallel()
		const mailer = "cpe:2.3:a:example:mailer:*:*:*:*:"
		row := func(channel, start, end string) Affected {
			return Affected{CPE: mailer + channel + ":*:*:*", Range: VersionRange{StartIncl: start, EndExcl: end}}
		}
		for _, tc := range []struct {
			name, ver string
			aff       []Affected
			want      string
		}{
			{"lower than the unscoped fix of every channel", "30.5.0", []Affected{row("-", "", "52.0"), row("extended", "", "45.9.0")}, found},
			{"one unscoped fix, no channel", "115.9", []Affected{{CPE: "cpe:2.3:a:example:mailer:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "152"}}}, found},
			// "unaffected 140.12 through 140.*" and "unaffected 152 and later": the line's fix says the line got one, not that older lines
			// carried the flaw (it may have come in at 140.0), so the readings disagree
			{"a fix scoped to a later line", "115.9", []Affected{row("-", "", "152"), row("extended", "140.0", "140.12")}, asked},
			{"lower than every fix, three lines", "30.5.0", []Affected{row("-", "", "57.0"), row("extended", "45.0", "45.17.0"), row("extended", "53.0", "53.4.0")}, asked},
			{"past the fix of one channel", "46.0.1", []Affected{row("-", "", "52.0"), row("extended", "45.0", "45.9.0")}, asked},
			{"a row with a lower bound of its own", "30.5.0", []Affected{row("-", "", "52.0"), row("extended", "45.2.0", "45.9.0")}, asked},
			{"the plain row starts inside the line", "30.5.0", []Affected{row("-", "30.2", "52.0"), row("extended", "45.0", "45.9.0")}, asked},
			{"every row starts at its own line", "30.5.0", []Affected{row("-", "52.0", "52.3"), row("extended", "45.0", "45.9.0")}, asked},
			{"one pinned channel alone", "30.5.0", []Affected{row("extended", "", "52.0")}, asked},
			{"a system pin", "30.5.0", []Affected{{CPE: "cpe:2.3:a:example:mailer:*:*:*:*:*:linux:*:*", Range: VersionRange{EndExcl: "52.0"}},
				{CPE: "cpe:2.3:a:example:mailer:*:*:*:*:*:macos:*:*", Range: VersionRange{EndExcl: "52.0"}}}, asked},
			{"an inclusive end", "30.5.0", []Affected{row("-", "", "52.0"), {CPE: mailer + "extended:*:*:*", Range: VersionRange{StartIncl: "45.0", EndIncl: "45.9.0"}}}, asked},
		} {
			s := Software{ID: "m", Display: "Example Mailer", Vendor: "Example", Product: "Mailer", Version: tc.ver, Source: "agent"}
			res := MatchAsset(Asset{ID: "pc", Name: "pc-01", Software: []Software{s}}, []Vuln{{CVE: "CVE-2099-7101", NVDAnswered: true, Published: uncNew, Affected: tc.aff}}, nil, uncNow)
			got := outcome(res)
			if got == decided {
				got = asked // a CVE these rows do not decide is never proved unaffected by this rule
			}
			if got != tc.want {
				t.Errorf("%s (%s): %s, want %s (new %+v, unchecked %+v)", tc.name, tc.ver, got, tc.want, res.New, res.Unchecked)
			}
		}
	})

	// A list a third party wrote, which may name only the release trains it tested.
	t.Run("fix of a release train", func(t *testing.T) {
		t.Parallel()
		const agent = "cpe:2.3:*:example:relay_agent:*:*:*:*:*:*:*:*"
		fixed := func(start, end string) Affected {
			return Affected{CPE: agent, Range: VersionRange{StartIncl: start, EndExcl: end}}
		}
		through := Affected{CPE: agent, Range: VersionRange{StartIncl: "2.1.0", EndIncl: "4.8.0"}}
		besideNVD := func() []Affected {
			return []Affected{{CPE: "cpe:2.3:a:example:relay_server:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "2.1.0", EndExcl: "4.8.0"}},
				{CPE: agent, Range: VersionRange{StartIncl: "2.1.0", EndExcl: "4.8.0"}, AffectedOnly: true}}
		}
		for _, tc := range []struct {
			name, ver string
			aff       []Affected
			partial   bool // a CVE.org list with no NVD rows
			exploited bool
			want      string
		}{
			{"at the fix of a row from another train", "4.8.0", []Affected{fixed("2.1.0", "4.8.0")}, true, false, decided},
			{"past the fix on the fix's train", "4.8.3", []Affected{fixed("2.1.0", "4.8.0")}, true, false, decided},
			{"inside the row", "4.7.9", []Affected{fixed("2.1.0", "4.8.0")}, true, false, found},
			{"on a later train than the fix", "4.9.1", []Affected{fixed("2.1.0", "4.8.0")}, true, false, asked},
			{"past an inclusive end: no fix stated", "4.8.3", []Affected{through}, true, false, asked},
			{"a later row of the train starts above the version", "4.8.2", []Affected{fixed("2.1.0", "4.8.0"), fixed("4.8.5", "4.8.9")}, true, false, asked},
			// a release of the train after the fix is listed affected: the fix did not hold, and no later fix is stated
			{"a row after the fix, through a release below the version", "4.8.6", []Affected{fixed("2.1.0", "4.8.0"),
				{CPE: agent, Range: VersionRange{StartIncl: "4.8.2", EndIncl: "4.8.4"}}}, true, false, asked},
			{"an exact release after the fix", "4.8.6", []Affected{fixed("2.1.0", "4.8.0"),
				{CPE: "cpe:2.3:a:example:relay_agent:4.8.2:*:*:*:*:*:*:*"}}, true, false, asked},
			{"a row from an older train through a release after the fix", "4.8.6", []Affected{fixed("2.1.0", "4.8.0"),
				{CPE: agent, Range: VersionRange{StartIncl: "3.0.0", EndIncl: "4.8.4"}}}, true, false, asked},
			{"exploited: only a person closes it", "4.8.0", []Affected{fixed("2.1.0", "4.8.0")}, true, true, asked},
			{"a record row beside NVD rows of another product, at its fix", "4.8.0", besideNVD(), false, false, decided},
			{"a record row beside NVD rows of another product, later train", "4.9.0", besideNVD(), false, false, asked},
			// the catalogue keeps only the rows that name a product some device has: the record's row alone, still marked as read beside NVD's
			{"the record's row alone, read beside NVD's", "4.8.0", besideNVD()[1:], true, false, decided},
		} {
			v := Vuln{CVE: "CVE-2099-7201", NVDAnswered: true, Published: uncNew, Affected: tc.aff}
			s := Software{ID: "r", Display: "Example Relay Agent", Vendor: "Example", Product: "Relay Agent", Version: tc.ver, Source: "agent"}
			if tc.partial {
				v.RangesFrom = RangesCVEOrgPartial
			}
			if tc.exploited {
				v = uncVuln(v.CVE, "Example", "Relay Agent", uncNew, tc.aff...)
				v.RangesFrom = RangesCVEOrgPartial
				s.KevKeys = []string{"example|relayagent"}
			}
			res := MatchAsset(Asset{ID: "pc", Name: "pc-01", OS: "Windows 11", Software: []Software{s}}, []Vuln{v}, nil, uncNow)
			if got := outcome(res); got != tc.want {
				t.Errorf("%s (%s): %s, want %s (new %+v, unchecked %+v)", tc.name, tc.ver, got, tc.want, res.New, res.Unchecked)
			}
			if tc.want != decided {
				continue
			}
			have := MatchAsset(Asset{ID: "pc", Name: "pc-01", OS: "Windows 11", Software: []Software{s}}, []Vuln{v}, map[string]bool{v.CVE: true}, uncNow)
			if len(have.NotAffected) != 1 || !strings.Contains(have.NotAffected[0].Evidence.Summary, "decided under every reading") {
				t.Errorf("%s: an open finding is not closed with the readings named: %+v", tc.name, have.NotAffected)
			}
		}
	})
}
