package findings

import "testing"

// OpenSSL is decided by its ranges on every branch. NVD writes the 0.9.8, 1.0.x and 1.1.1 branches in OpenSSL's letter notation, which
// runs past "z" ("0.9.8za", "1.0.2zd", "1.1.1zk"), beside the numeric 3.x ranges. The rows below are NVD's for real CVEs, cut to the
// OpenSSL rows (their CVE records add no readable range). Every one decides a 3.5.0 install: outside every range is not affected,
// with proof, and inside one is affected.
func TestDecide_OpenSSLLetterBranches(t *testing.T) {
	t.Parallel()
	const ossl = "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
	rng := func(start, end string) Affected {
		return Affected{CPE: ossl, Range: VersionRange{StartIncl: start, EndExcl: end}}
	}
	exact := func(v string) Affected { return Affected{CPE: "cpe:2.3:a:openssl:openssl:" + v + ":*:*:*:*:*:*:*"} }
	cves := map[string][]Affected{
		"CVE-2014-0195": {rng("0.9.8", "0.9.8za"), rng("1.0.0", "1.0.0m"), rng("1.0.1", "1.0.1h")},
		"CVE-2014-0224": {{CPE: ossl, Range: VersionRange{EndExcl: "0.9.8za"}}, rng("1.0.0", "1.0.0m"), rng("1.0.1", "1.0.1h")},
		"CVE-2015-0204": {{CPE: ossl, Range: VersionRange{EndIncl: "0.9.8zc"}}, exact("1.0.0a"), exact("1.0.0o"), exact("1.0.1"), exact("1.0.1j")},
		"CVE-2022-0778": {rng("1.0.2", "1.0.2zd"), rng("1.1.0", "1.1.1n"), rng("3.0.0", "3.0.2")},
		"CVE-2022-1292": {rng("1.0.2", "1.0.2ze"), rng("1.1.1", "1.1.1o"), rng("3.0.0", "3.0.3")},
	}
	row := func(ver string, keyed bool) Software {
		s := Software{ID: "s-openssl", Display: "OpenSSL " + ver + " Light (64-bit)", Vendor: "OpenSSL", Product: "OpenSSL", Version: ver, Source: "agent"}
		if keyed {
			s.KevKeys = []string{"openssl|openssl"}
		}
		return s
	}
	for _, tc := range []struct {
		cve, ver string
		want     Tri
	}{
		{"CVE-2014-0195", "3.5.0", No},
		{"CVE-2014-0224", "3.5.0", No},
		{"CVE-2015-0204", "3.5.0", No},
		{"CVE-2022-0778", "3.5.0", No},
		{"CVE-2022-1292", "3.5.0", No},
		{"CVE-2022-0778", "3.0.1", Yes},
		{"CVE-2022-0778", "1.0.2zc", Yes},
		{"CVE-2022-1292", "1.0.2ze", No},
		{"CVE-2014-0224", "0.9.8zb", No},
		{"CVE-2014-0224", "0.9.8y", Yes},
	} {
		v := uncVuln(tc.cve, "OpenSSL", "OpenSSL", uncNew, cves[tc.cve]...)
		got, _, _, proof := decide(newSWInfo(row(tc.ver, true), ""), v, keyIDs(v))
		if got != tc.want || got == No && proof != proofRange {
			t.Errorf("%s on %s: %v (proof %d), want %v", tc.cve, tc.ver, got, proof, tc.want)
		}
	}

	// As the device page reads them, on a row CISA's key reaches and on one only NVD's list names: no finding and no question.
	var vulns []Vuln
	for cve, aff := range cves {
		vulns = append(vulns, uncVuln(cve, "OpenSSL", "OpenSSL", uncNew, aff...))
	}
	for _, keyed := range []bool{true, false} {
		a := Asset{ID: "pc", Name: "pc-01", OS: "Windows 11", Software: []Software{row("3.5.0", keyed)}}
		if res := MatchAsset(a, vulns, nil, uncNow); len(res.New) != 0 || len(res.Unchecked) != 0 {
			t.Errorf("OpenSSL 3.5.0 (keyed %v): new %d, unchecked %+v", keyed, len(res.New), res.Unchecked)
		}
	}
}

// A CVE whose list names several release branches is decided by the rows that compare with the version. A row inside one release
// branch that is not the version's, in a notation that does not compare ("0.4.3-ac3", "0.7.2" with a pinned update), cannot hold the
// version whatever its suffix means: it is set aside and the rows that compare decide (VLC 3.0.20 and CVE-2012-1775, which NVD lists
// up to 2.0.0 and at many exact releases). Only when no row decides does the CVE stay a question.
func TestDecide_RowOfAnotherBranchDoesNotBlockTheDecision(t *testing.T) {
	t.Parallel()
	const vlc = "cpe:2.3:a:videolan:vlc_media_player:*:*:*:*:*:*:*:*"
	at := func(v string) Affected {
		return Affected{CPE: "cpe:2.3:a:videolan:vlc_media_player:" + v + ":*:*:*:*:*:*"}
	}
	upTo := Affected{CPE: vlc, Range: VersionRange{EndIncl: "2.0.0"}}
	ac3 := at("0.4.3-ac3:*")
	test2 := at("0.7.2:test2")
	row := func(ver string) Software {
		return Software{ID: "s-vlc", Display: "VLC media player", Vendor: "VideoLAN", Product: "VLC media player", Version: ver, Source: "agent",
			CPE: vlc, KevKeys: []string{"videolan|vlc media player"}}
	}
	for _, tc := range []struct {
		name, ver string
		aff       []Affected
		want      Tri
		proof     proofKind
	}{
		{"rows of other branches beside a range that decides", "3.0.20", []Affected{upTo, ac3, test2}, No, proofRange},
		{"inside the range that decides", "1.1.0", []Affected{upTo, ac3}, Yes, proofNone},
		// Nothing but rows of another branch: no row decides, so the CVE is not proved either way.
		{"only rows of another branch", "3.0.20", []Affected{ac3}, Unknown, proofNone},
		// The version is of the row's branch: its suffix decides, which this comparison does not read.
		{"a version of the row's branch", "0.4.3", []Affected{ac3, {CPE: vlc, Range: VersionRange{StartIncl: "2.0.0", EndExcl: "2.0.5"}}}, Unknown, proofNone},
		// A row with no start is no branch: "up to 0.4.3-ac3" spans every older release.
		{"a range with no start", "3.0.20", []Affected{{CPE: vlc, Range: VersionRange{EndIncl: "0.4.3-ac3"}}}, Unknown, proofNone},
	} {
		v := uncVuln("CVE-2026-80131", "VideoLAN", "VLC media player", uncNew, tc.aff...)
		got, _, _, proof := decide(newSWInfo(row(tc.ver), ""), v, keyIDs(v))
		if got != tc.want || proof != tc.proof {
			t.Errorf("%s: %v (proof %d), want %v (proof %d)", tc.name, got, proof, tc.want, tc.proof)
		}
	}
}

// A row in another notation than the version is not a row of another branch: Office "2016" against build "16.0.4266" still cannot be
// compared, and is not set aside.
func TestDecide_OtherNotationIsNotAnotherBranch(t *testing.T) {
	t.Parallel()
	const office = "cpe:2.3:a:microsoft:office:2016:*:*:*:*:*:*:*"
	s := Software{ID: "s-office", Display: "Microsoft Office", Vendor: "Microsoft", Product: "Office", Version: "16.0.4266.1001", Source: "agent",
		CPE: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*", KevKeys: []string{"microsoft|office"}}
	v := uncVuln("CVE-2026-80133", "Microsoft", "Office", uncNew, Affected{CPE: office},
		Affected{CPE: "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "17.0.0", EndExcl: "17.0.5"}})
	if got, _, _, _ := decide(newSWInfo(s, ""), v, keyIDs(v)); got == No {
		t.Fatalf("an exact row in another notation was set aside: %v", got)
	}
}

// A placeholder version ("0", "0.0.0") is no version at all, so it is of no release branch: an exact row it does not compare with may
// be the release installed. The row is not set aside, even beside a row that rules itself out, and the line still asks for its version.
func TestDecide_PlaceholderVersionIsOfNoBranch(t *testing.T) {
	t.Parallel()
	v := uncVuln("CVE-2026-80134", "Example", "Example App", uncNew,
		Affected{CPE: "cpe:2.3:a:example:example_app:1.5.2:*:*:*:*:*:*:*"},
		Affected{CPE: "cpe:2.3:a:example:example_app:*:*:*:*:*:macos:*:*", Range: VersionRange{EndExcl: "2.0.0"}})
	for _, ver := range []string{"0", "0.0.0"} {
		s := Software{ID: "s-app", Display: "Example App", Vendor: "Example", Product: "Example App", Version: ver, Source: "agent",
			CPE: "cpe:2.3:a:example:example_app:*:*:*:*:*:windows:*:*", KevKeys: []string{"example|example app"}}
		if got, _, _, _ := decide(newSWInfo(s, ""), v, keyIDs(v)); got != Unknown {
			t.Errorf("version %q: %v, want Unknown (the exact row may be the release installed)", ver, got)
		}
		a := Asset{ID: "pc", Name: "pc-01", OS: "Windows 11", Software: []Software{s}}
		if res := MatchAsset(a, []Vuln{v}, nil, uncNow); len(res.NeedVersion) != 1 {
			t.Errorf("version %q: need version %+v, unchecked %+v, want one item asking for the version", ver, res.NeedVersion, res.Unchecked)
		}
	}
}
