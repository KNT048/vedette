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

	// An extended-support build of a line older than every line the CVE's ESR rows list. The build attributes are the box's
	// derivation (installAttrs), set here for a product of no install rule.
	t.Run("unlisted older line", func(t *testing.T) {
		t.Parallel()
		const mailer = "cpe:2.3:a:example:mailer:*:*:*:*:"
		row := func(edition, start, end string) Affected {
			return Affected{CPE: mailer + edition + ":*:*:*", Range: VersionRange{StartIncl: start, EndExcl: end}}
		}
		for _, tc := range []struct {
			name string
			aff  []Affected
			want string
		}{
			{"the plain row holds the version and the line's first release", []Affected{row("-", "", "52.0"), row("esr", "45.0", "45.9.0")}, found},
			{"the plain row starts after the line's first release", []Affected{row("-", "32.0", "52.0"), row("esr", "45.0", "45.9.0")}, asked},
			{"the plain row ends below the version", []Affected{row("-", "", "30.3.0"), row("esr", "45.0", "45.9.0")}, asked},
			{"a listed ESR line is older than the line", []Affected{row("-", "", "52.0"), row("esr", "24.0", "24.9.0"), row("esr", "45.0", "45.9.0")}, asked},
		} {
			s := Software{ID: "m", Display: "Example Mailer", Vendor: "Example", Product: "Mailer", Version: "30.5.0", Source: "agent"}
			a := Asset{ID: "pc", Name: "pc-01", Software: []Software{s}}
			in := newSWInfo(s, "")
			in.install = installAttrs{edition: mozillaESR, esrLine: 30, editionWhy: "its numbering says so"}
			v := Vuln{CVE: "CVE-2099-7101", NVDAnswered: true, Published: uncNew, Affected: tc.aff}
			m, out := judgeRanges(a, s, in, v, nil, uncNow)
			got := asked
			if out == outMatch && m.Basis == BasisVersion {
				got = found
			}
			if got != tc.want {
				t.Errorf("%s: %s (%v, %q), want %s", tc.name, got, out, m.Evidence.Summary, tc.want)
			}
			if got == found && !strings.Contains(m.Evidence.Summary, "decided under every reading") {
				t.Errorf("%s: the evidence does not name the readings: %q", tc.name, m.Evidence.Summary)
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

// The same rule through the whole match, on a product whose install rule derives the build: an ESR build of an end-of-life line.
func TestEveryReading_EndOfLifeESRLine(t *testing.T) {
	t.Parallel()
	ff := func(edition, start, end string) Affected {
		return Affected{CPE: "cpe:2.3:a:mozilla:firefox:*:*:*:*:" + edition + ":*:*:*", Range: VersionRange{StartIncl: start, EndExcl: end}}
	}
	a := Asset{ID: "pc", Name: "pc-01", Software: []Software{{ID: "f", Display: "Mozilla Firefox ESR (x64 en-US)", Vendor: "Mozilla",
		Product: "Firefox", Version: "102.15.0", Source: "agent"}}}
	for _, tc := range []struct {
		name string
		aff  []Affected
		want int // findings
	}{
		{"older than every listed ESR line, inside the plain row", []Affected{ff("-", "", "152.0"), ff("esr", "140.0", "140.12.0")}, 1},
		{"older than every listed ESR line, the plain row starts inside the line", []Affected{ff("-", "102.5", "152.0"), ff("esr", "140.0", "140.12.0")}, 0},
	} {
		res := MatchAsset(a, []Vuln{{CVE: "CVE-2099-7301", NVDAnswered: true, Published: uncNew, Affected: tc.aff}}, nil, uncNow)
		if len(res.New) != tc.want || tc.want == 1 && res.New[0].Basis != BasisVersion {
			t.Errorf("%s: new %+v, unchecked %+v, want %d version finding", tc.name, res.New, res.Unchecked, tc.want)
		}
		if tc.want == 0 && len(res.Unchecked) != 1 {
			t.Errorf("%s: no question: %+v", tc.name, res)
		}
	}
}
