package findings

import (
	"slices"
	"strings"
	"testing"
)

// The Juniper EX4200-48T of customer walk 1 (W1-32) as the N100 box n23 stored it: found over LLDP only, no IP, no
// software row, OS "JUNOS 15.1R7.9", model "EX4200-48T". testdata/kev-nvd-junos-n23.json holds the box's 8 Juniper CISA
// entries with their NVD rows. The expected sets were checked by hand against those rows (D-510):
//   - CVE-2023-36844, -36845, -36847: "junos:*" before 20.4, named "EX Series" (and SRX): 15.1 is inside.
//   - CVE-2025-21590: "junos:*" before 21.2, no series named: inside.
//   - CVE-2020-1631: exact rows, "junos:15.1:r7" among them: 15.1R7.9 is build 9 of 15.1R7, inside.
//   - CVE-2023-36846: before 20.4, but CISA names "SRX Series" only: not on an EX.
//   - CVE-2023-36851: rows from 21.2 on only, SRX: outside. CVE-2015-7755: ScreenOS, another product.
func walk1EX4200() Asset {
	return Asset{ID: "a-bjehktolua77qnpyk2vc6lbune", Name: "Juniper Networks EX4200-48T", OS: "JUNOS 15.1R7.9", StatedOS: "JUNOS 15.1R7.9", Model: "EX4200-48T"}
}

func matchedCVEs(ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.CVE)
	}
	slices.Sort(out)
	return out
}

func TestJunos_EX4200FromLLDPGetsItsExploitedCVEsByVersion(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-junos-n23.json")
	r := MatchAsset(walk1EX4200(), vulns, nil, t0)
	want := []string{"CVE-2020-1631", "CVE-2023-36844", "CVE-2023-36845", "CVE-2023-36847", "CVE-2025-21590"}
	if got := matchedCVEs(r.New); !slices.Equal(got, want) {
		t.Fatalf("EX4200 on JUNOS 15.1R7.9: got %v, want %v", got, want)
	}
	for _, m := range r.New {
		if m.Basis != BasisVersion || m.SoftwareDisplay != "Juniper Junos OS" || m.SoftwareID != osSoftwareID(walk1EX4200().ID) {
			t.Errorf("%s: %+v", m.CVE, m)
		}
		s := m.Evidence.Summary
		if !strings.Contains(s, "runs Juniper Junos OS 15.1R7.9. Its version is inside the range affected by "+m.CVE) || strings.Contains(s, "SRX") || strings.Contains(s, "not checked") {
			t.Errorf("%s: %q", m.CVE, s)
		}
	}
	if len(r.NeedVersion) != 0 {
		t.Errorf("the version is known: %+v", r.NeedVersion)
	}
	// EPSS 0.9 (CVE-2023-36845 on the box) makes it critical; CVE-2025-21590 (EPSS 0.017) stays high.
	for _, m := range r.New {
		if m.CVE == "CVE-2023-36845" && m.Severity != SeverityCritical || m.CVE == "CVE-2025-21590" && m.Severity != SeverityHigh {
			t.Errorf("%s severity %s", m.CVE, m.Severity)
		}
	}
	if !strings.Contains(r.New[slices.IndexFunc(r.New, func(m Match) bool { return m.CVE == "CVE-2020-1631" })].Evidence.Summary, "(version 15.1R7)") {
		t.Errorf("CVE-2020-1631 names the NVD row it is inside: %+v", r.New)
	}
}

// D-510: the series filter needs a model. The same switch without one keeps today's behaviour (the SRX-only
// CVE-2023-36846 is listed, its range contains 15.1); an SRX gets the SRX ones and not the EX-only ones.
func TestJunos_SeriesNamedByCISAFollowsTheModel(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-junos-n23.json")
	for _, tc := range []struct {
		model, os string
		want      []string
	}{
		{"", "JUNOS 15.1R7.9", []string{"CVE-2020-1631", "CVE-2023-36844", "CVE-2023-36845", "CVE-2023-36846", "CVE-2023-36847", "CVE-2025-21590"}},
		{"SRX345", "Junos OS 21.4R3-S4", []string{"CVE-2023-36845", "CVE-2023-36846", "CVE-2023-36851", "CVE-2025-21590"}},
		{"vSRX", "JUNOS 15.1X49-D90.3", []string{"CVE-2020-1631", "CVE-2023-36845", "CVE-2023-36846", "CVE-2025-21590"}},
		{"MX204", "JUNOS 20.4R3-S9", []string{"CVE-2025-21590"}},
		{"ex2300-24t", "JUNOS 18.2R3.4", []string{"CVE-2020-1631", "CVE-2023-36844", "CVE-2023-36845", "CVE-2023-36847", "CVE-2025-21590"}},
	} {
		a := walk1EX4200()
		a.Model, a.OS, a.StatedOS = tc.model, tc.os, tc.os
		if got := matchedCVEs(MatchAsset(a, vulns, nil, t0).New); !slices.Equal(got, tc.want) {
			t.Errorf("%q on %q: got %v, want %v", tc.model, tc.os, got, tc.want)
		}
	}
}

// The forms a Junos version comes in, against the real rows of CVE-2020-1631 (exact rows: 12.3, 12.3x48:d10…d100,
// 15.1:r7, 15.1x49:d10…d90, … up to 20.1:r1) and CVE-2023-36845 (before 20.4, plus 20.4:r1 … 22.4:r2, 23.2:r1).
func TestJunos_VersionForms(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-junos-n23.json")
	byCVE := map[string]Vuln{}
	for _, v := range vulns {
		byCVE[v.CVE] = v
	}
	for _, tc := range []struct {
		ver, cve string
		want     Tri
		proof    proofKind
	}{
		{"15.1R7.9", "CVE-2020-1631", Yes, proofNone},  // build 9 of 15.1R7
		{"15.1R7-S5", "CVE-2020-1631", Yes, proofNone}, // listed
		{"15.1R7", "CVE-2020-1631", Yes, proofNone},
		// Review H1 of #703: NVD's gaps. Updates between listed ones of the release are affected; before the first listed
		// one, not known; after the last (15.1R7-S6, S7: Juniper's fix is S7), no finding but never "proved not affected".
		{"12.3R12-S10", "CVE-2020-1631", Yes, proofNone},   // between S8 and S11
		{"15.1R4-S3", "CVE-2020-1631", Yes, proofNone},     // between R4 and R4-S7
		{"17.3R3-S5", "CVE-2020-1631", Yes, proofNone},     // between R3-S4 and R3-S7
		{"17.3R1.10", "CVE-2020-1631", Unknown, proofNone}, // 17.3R1-S1 is the first listed 17.3
		{"15.1R7-S6", "CVE-2020-1631", No, proofNone},
		{"15.1R7-S7", "CVE-2020-1631", No, proofNone},
		{"21.3R1", "CVE-2025-21590", Unknown, proofNone}, // a release NVD skips, between 21.2 and 21.4
		{"22.1R3-S2", "CVE-2025-21590", Unknown, proofNone},
		{"21.4R3-S5", "CVE-2020-1631", No, proofRange}, // after every release NVD lists (up to 20.1): proved
		{"20.4R3-S9", "CVE-2020-1631", No, proofRange},
		{"23.4R1", "CVE-2023-36845", No, proofRange},
		{"15.1R7.9", "CVE-2023-36851", No, proofNone},     // before every listed release (21.2 on): no proof
		{"12.3X48-D100", "CVE-2020-1631", Yes, proofNone}, // X train, listed as 12.3x48:d100
		{"12.3X48-D105", "CVE-2020-1631", No, proofNone},  // after the last listed D100
		{"15.1X49-D90", "CVE-2020-1631", Yes, proofNone},
		{"15.1R7.9", "CVE-2023-36845", Yes, proofNone},     // before 20.4
		{"12.3X48-D105", "CVE-2023-36845", Yes, proofNone}, // 12.3 is before 20.4
		{"20.4R3-S8", "CVE-2023-36845", Yes, proofNone},
		{"20.4R3-S9", "CVE-2023-36845", No, proofNone}, // the fix, after the last listed 20.4R3-S8
		{"21.4R3-S4.18", "CVE-2023-36845", Yes, proofNone},
		{"21.4R3-S5", "CVE-2023-36845", No, proofNone}, // the fix of 21.4
		{"22.4R2-S1", "CVE-2023-36845", No, proofNone},
		{"20.4R3-EVO", "CVE-2023-36845", Unknown, proofNone}, // Junos OS Evolved is not read the Junos way
		// Round 2, HIGH-1: Juniper fixes per maintenance branch. NVD lists 22.3 up to R2-S1, then R3: the fixed R2-S2 is
		// after the last listed update of its own branch (R2), not "between 22.3R1 and 22.3R3".
		{"22.3R2-S2", "CVE-2023-36844", No, proofNone},
		// JSA11021's fixed builds of CVE-2020-1631, each after the last listed update of its branch.
		{"18.4R1-S7", "CVE-2020-1631", No, proofNone},
		{"18.4R2-S5", "CVE-2020-1631", No, proofNone},
		{"18.3R2-S4", "CVE-2020-1631", No, proofNone},
		{"18.3R1-S7", "CVE-2020-1631", No, proofNone},
		{"18.2R2-S7", "CVE-2020-1631", No, proofNone},
		{"17.4R1-S8", "CVE-2020-1631", No, proofNone},
	} {
		in := newSWInfo(Software{Vendor: "Juniper", Product: "Junos OS", Version: tc.ver}, "")
		got, _, _, proof := decide(in, byCVE[tc.cve], false)
		if got != tc.want || proof != tc.proof {
			t.Errorf("%s %s: %v proof %d, want %v proof %d", tc.ver, tc.cve, got, proof, tc.want, tc.proof)
		}
	}
}

// The stated OS strings that give a Junos row, and those that do not (nmap's names are guesses, D-501).
func TestJunos_DeviceOSForms(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ os, ver string }{
		{"JUNOS 15.1R7.9", "15.1R7.9"},
		{"Junos OS 21.4R3-S5", "21.4R3-S5"},
		{"JUNOS 12.3R12.4", "12.3R12.4"},
		{"junos 12.3X48-D105", "12.3X48-D105"},
		{"Juniper Junos OS 12.1 - 15.1", ""},
		{"Juniper JUNOS 10.4R1.9 (EX4200 switch)", ""}, // review M2 of #703
		{"Juniper Junos 12.1X44-D10.4", ""},
		{"Junos OS Evolved 22.4R3-EVO", ""},
		{"JUNOS 22.4R3-EVO", ""},
		{"Cisco IOS 15.2(4)M3", ""},
		{"", ""},
	} {
		sws := deviceSoftware(Asset{ID: "a", StatedOS: tc.os})
		got := ""
		if len(sws) == 1 {
			got = sws[0].Version
		}
		if got != tc.ver {
			t.Errorf("%q: version %q, want %q", tc.os, got, tc.ver)
		}
	}
	// nmap's guess won the OS field: the OS the device itself stated still decides; the folded OS alone gives nothing.
	if sws := deviceSoftware(Asset{ID: "a", OS: "Juniper JUNOS 10.4R1.9 (EX4200 switch)", StatedOS: "JUNOS 15.1R7.9"}); len(sws) != 1 || sws[0].Version != "15.1R7.9" {
		t.Fatalf("%+v", sws)
	}
	if sws := deviceSoftware(Asset{ID: "a", OS: "JUNOS 15.1R7.9"}); len(sws) != 0 {
		t.Fatalf("only the device's own statement gives a row: %+v", sws)
	}
	// A row a person (or a scan) recorded for Junos with a version wins: the OS gives no second row.
	a := Asset{ID: "a", StatedOS: "JUNOS 15.1R7.9", Software: []Software{{ID: "s", Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS", Version: "15.1R7", KevKeys: []string{"Juniper|Junos OS"}}}}
	if sws := deviceSoftware(a); len(sws) != 1 || sws[0].ID != "s" {
		t.Fatalf("%+v", sws)
	}
}

// D-510 on the box: the EX4200 already has an open finding of the SRX-only CVE-2023-36846 (the earlier install made it
// as a product match). The match creates the five EX findings, leaves that one open for a person with the reason in its
// history, and never closes it (a model is not a proof about the version, and D-506 is about "Multiple Products" only).
func TestJunos_OpenSRXOnlyFindingOnAnEXStaysOpenWithTheReason(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-junos-n23.json")
	dev := walk1EX4200()
	e := newEnv(t)
	e.inv.match = map[string]Asset{dev.ID: dev}
	e.inv.assets = map[string]AssetView{dev.ID: {ID: dev.ID, IP: NoIP, Kind: "switch", Display: "switch"}}
	e.feeds.vulns = vulns
	noModel := dev
	noModel.Model = ""
	openProductFindings(t, e, noModel, vulns, []string{"CVE-2023-36846"})
	for pass := range 2 {
		res, err := e.svc.UpsertFromMatch(t.Context(), dev, vulns)
		if err != nil || len(res.Created) != 5*(1-pass) || res.Closed+res.Retired != 0 {
			t.Fatalf("pass %d: %+v %v", pass, res, err)
		}
	}
	f, err := loadByPair(t.Context(), e.db.Reader(), dev.ID, "CVE-2023-36846")
	if err != nil {
		t.Fatal(err)
	}
	const want = "CISA lists CVE-2023-36846 for Juniper SRX Series only; this device's model is EX4200-48T. Check the vendor advisory and close it if it does not apply."
	var notes []string
	for _, h := range f.History {
		if h.Action == "no_longer_matches" {
			notes = append(notes, h.Note)
		}
	}
	if f.Status != StatusSuspected || !slices.Equal(notes, []string{want}) {
		t.Fatalf("status %s, notes %q", f.Status, notes)
	}
}

// Review M3 of #703: a person picked "Juniper Junos OS" in the catalog and left the version empty. The version the switch
// states decides (the five findings), not "add the version"; a row with other keys stays.
func TestJunos_RecordedRowWithoutVersionGivesWayToTheStatedOne(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-junos-n23.json")
	a := walk1EX4200()
	a.Software = []Software{
		{ID: "s-manual", Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS", KevKeys: []string{"juniper|junos os"}},
		{ID: "s-other", Display: "Juniper ScreenOS", Vendor: "Juniper", Product: "ScreenOS", Version: "6.3.0r17", KevKeys: []string{"juniper|screenos"}},
	}
	r := MatchAsset(a, vulns, nil, t0)
	if got := matchedCVEs(r.New); !slices.Equal(got, []string{"CVE-2015-7755", "CVE-2020-1631", "CVE-2023-36844", "CVE-2023-36845", "CVE-2023-36847", "CVE-2025-21590"}) || len(r.NeedVersion) != 0 {
		t.Fatalf("new %v, need %+v", got, r.NeedVersion)
	}
}

// Review M1 of #703: CISA's names list series in several forms; a device is ruled out only when its own series is in
// none of them.
func TestJunos_SeriesListForms(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, model string
		out         bool
	}{
		{"Juniper Junos OS SRX and EX Series PHP External Variable Modification Vulnerability", "SRX300", false},
		{"Juniper Junos OS SRX and EX Series PHP External Variable Modification Vulnerability", "SRX4600", false},
		{"Juniper Junos OS SRX and EX Series PHP External Variable Modification Vulnerability", "vSRX", false},
		{"Juniper Junos OS EX and SRX Series Missing Authentication", "EX4200-48T", false},
		{"Juniper Junos OS EX and SRX Series Missing Authentication", "EX-4300", false},
		{"Juniper Junos OS EX and SRX Series Missing Authentication", "EX9208", false},
		{"Juniper Junos OS MX Series and EX9200 Series Denial of Service", "EX9208", false},
		{"Juniper Junos OS MX Series and EX9200 Series Denial of Service", "SRX345", true},
		{"Juniper Junos OS SRX Series Missing Authentication for Critical Function Vulnerability", "EX4200-48T", true},
		{"Juniper Junos OS SRX Series Missing Authentication for Critical Function Vulnerability", "", false},
		{"Juniper Junos OS Path Traversal Vulnerability", "EX4200-48T", false},
	} {
		if _, out := otherSeries(tc.model, Vuln{Vendor: "Juniper", Product: "Junos OS", Name: tc.name}); out != tc.out {
			t.Errorf("%q on %q: out %v, want %v", tc.name, tc.model, out, tc.out)
		}
	}
}

// Review L1 of #703: a Junos row NVD writes in a form the scheme cannot read is Unknown, never a No; a row of another
// release type ("15.1:f", "15.1:a1") is not 15.1R7.
func TestJunos_UnreadableRows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		cpe  string
		want Tri
	}{
		{"cpe:2.3:o:juniper:junos:15.1r7:*:*:*:*:*:*:*", Unknown},
		{"cpe:2.3:o:juniper:junos:15.1:r7.9:*:*:*:*:*:*", Unknown},
		{"cpe:2.3:o:juniper:junos:15.1:r7-s1.2:*:*:*:*:*:*", Unknown},
		{"cpe:2.3:o:juniper:junos:15.1:r:*:*:*:*:*:*", Unknown},
		{"cpe:2.3:o:juniper:junos:15.1:f:*:*:*:*:*:*", No},
		{"cpe:2.3:o:juniper:junos:15.1:a1:*:*:*:*:*:*", No},
		{"cpe:2.3:o:juniper:junos:15.1:r7:*:*:*:*:*:*", Yes},
	} {
		c, err := ParseCPE(tc.cpe)
		if err != nil {
			t.Fatal(err)
		}
		if got, _, ok := junosEval(c, VersionRange{}, "15.1R7.9"); !ok || got != tc.want {
			t.Errorf("%s: %v, want %v", tc.cpe, got, tc.want)
		}
	}
}

// Review L2 of #703: the Junos proof rule is for Junos rows only. Another product's version that only reads like Junos
// ("15.1F6") and is ruled out by a row pinned to another platform is no proof: the generic rule cannot read the version.
func TestJunos_ProofRuleIsForJunosRowsOnly(t *testing.T) {
	t.Parallel()
	v := Vuln{CVE: "CVE-2026-0001", Vendor: "Acme", Product: "Router OS", Affected: []Affected{
		{CPE: "cpe:2.3:o:acme:router_os:*:*:*:*:*:*:arm64:*", Range: VersionRange{EndExcl: "20.1"}},
	}}
	in := newSWInfo(Software{Vendor: "Acme", Product: "Router OS", Version: "15.1F6", CPE: "cpe:2.3:o:acme:router_os:15.1f6:*:*:*:*:*:x86:*"}, "")
	if got, _, _, proof := decide(in, v, false); got != No || proof != proofNone {
		t.Errorf("Acme 15.1F6 on x86: %v proof %d", got, proof)
	}
}

// Round 2 of #703 (MEDIUM-1, LOW-1): what NVD lists besides the readable rows of the device's branch. A row of the device's
// release that junosRow does not read ("15.1:-", "15.1:f", "15.1:a1") is never a proof; a range's end release counts as
// listed ("before 21.2" with no 21.2 rows proves nothing on 21.2R1; "before 15.1" and 16.1 rows leave 15.1 out: Unknown).
// A branch NVD skips inside a listed release is Unknown.
func TestJunos_WhatNVDListsBesidesTheBranch(t *testing.T) {
	t.Parallel()
	row := func(rel, upd string) string { return "cpe:2.3:o:juniper:junos:" + rel + ":" + upd + ":*:*:*:*:*:*" }
	all := "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*"
	for _, tc := range []struct {
		name, ver string
		aff       []Affected
		want      Tri
		proof     proofKind
	}{
		{"15.1:- only", "15.1R7", []Affected{{CPE: row("12.3", "r1")}, {CPE: row("15.1", "-")}}, Unknown, proofNone},
		{"15.1:f only", "15.1R7", []Affected{{CPE: row("12.3", "r1")}, {CPE: row("15.1", "f")}}, No, proofNone},
		{"15.1:a1 only", "15.1R7", []Affected{{CPE: row("12.3", "r1")}, {CPE: row("15.1", "a1")}}, No, proofNone},
		{"before 21.2 only, on 21.2", "21.2R1", []Affected{{CPE: all, Range: VersionRange{EndExcl: "21.2"}}}, No, proofNone},
		{"before 21.2 only, after it", "22.1R1", []Affected{{CPE: all, Range: VersionRange{EndExcl: "21.2"}}}, No, proofRange},
		{"before 15.1 and 16.1 rows, on 15.1", "15.1R5", []Affected{{CPE: all, Range: VersionRange{EndExcl: "15.1"}}, {CPE: row("16.1", "r1")}}, Unknown, proofNone},
		{"before 15.1 and 16.1 rows, on 15.2", "15.2R1", []Affected{{CPE: all, Range: VersionRange{EndExcl: "15.1"}}, {CPE: row("16.1", "r1")}}, Unknown, proofNone},
		{"a branch NVD skips", "15.1R6-S3", []Affected{{CPE: row("15.1", "r5")}, {CPE: row("15.1", "r7-s5")}}, Unknown, proofNone},
		{"after every listed branch", "15.1R8", []Affected{{CPE: row("15.1", "r5")}, {CPE: row("15.1", "r7-s5")}}, No, proofNone},
	} {
		v := Vuln{CVE: "CVE-2099-0001", Vendor: "Juniper", Product: "Junos OS", Affected: tc.aff}
		in := newSWInfo(Software{Vendor: "Juniper", Product: "Junos OS", Version: tc.ver}, "")
		if got, _, _, proof := decide(in, v, false); got != tc.want || proof != tc.proof {
			t.Errorf("%s (%s): %v proof %d, want %v proof %d", tc.name, tc.ver, got, proof, tc.want, tc.proof)
		}
	}
}

// Round 2 of #703 (LOW-2): a recorded Junos row wins only with a full Junos version; "15.1" or "JUNOS 15.1R7.9" typed by a
// person gives way to the version the switch states.
func TestJunos_RecordedRowWinsOnlyWithAJunosVersion(t *testing.T) {
	t.Parallel()
	vulns := loadGolden(t, "testdata/kev-nvd-junos-n23.json")
	for _, ver := range []string{"15.1", "JUNOS 15.1R7.9", "12.1"} {
		a := walk1EX4200()
		a.Software = []Software{{ID: "s-manual", Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS", Version: ver, KevKeys: []string{"juniper|junos os"}}}
		if sws := deviceSoftware(a); len(sws) != 1 || sws[0].ID != osSoftwareID(a.ID) || sws[0].Version != "15.1R7.9" {
			t.Errorf("recorded %q: %+v", ver, sws)
		}
		r := MatchAsset(a, vulns, nil, t0)
		if got := matchedCVEs(r.New); !slices.Equal(got, []string{"CVE-2020-1631", "CVE-2023-36844", "CVE-2023-36845", "CVE-2023-36847", "CVE-2025-21590"}) {
			t.Errorf("recorded %q: %v", ver, got)
		}
	}
}
