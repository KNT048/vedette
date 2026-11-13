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
	return Asset{ID: "a-bjehktolua77qnpyk2vc6lbune", Name: "Juniper Networks EX4200-48T", OS: "JUNOS 15.1R7.9", Model: "EX4200-48T"}
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
		a.Model, a.OS = tc.model, tc.os
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
	}{
		{"15.1R7.9", "CVE-2020-1631", Yes},     // build 9 of 15.1R7
		{"15.1R7-S5", "CVE-2020-1631", Yes},    // listed
		{"15.1R7-S7", "CVE-2020-1631", No},     // the fix
		{"12.3X48-D100", "CVE-2020-1631", Yes}, // X train, listed as 12.3x48:d100
		{"12.3X48-D105", "CVE-2020-1631", No},  // not listed
		{"15.1X49-D90", "CVE-2020-1631", Yes},
		{"15.1R7", "CVE-2020-1631", Yes},
		{"21.4R3-S5", "CVE-2020-1631", No}, // a release NVD does not list
		{"20.4R3-S9", "CVE-2020-1631", No},
		{"15.1R7.9", "CVE-2023-36845", Yes},     // before 20.4
		{"12.3X48-D105", "CVE-2023-36845", Yes}, // 12.3 is before 20.4
		{"20.4R3-S9", "CVE-2023-36845", No},     // 20.4R3-S9 is the fix
		{"20.4R3-S8", "CVE-2023-36845", Yes},
		{"21.4R3-S5", "CVE-2023-36845", No}, // the fix of 21.4
		{"21.4R3-S4.18", "CVE-2023-36845", Yes},
		{"22.4R2-S1", "CVE-2023-36845", No},
		{"23.4R1", "CVE-2023-36845", No},
		{"20.4R3-EVO", "CVE-2023-36845", Unknown}, // Junos OS Evolved is not read the Junos way
	} {
		in := newSWInfo(Software{Vendor: "Juniper", Product: "Junos OS", Version: tc.ver}, "")
		got, _, _, _ := decide(in, byCVE[tc.cve], false)
		if got != tc.want {
			t.Errorf("%s %s: %v, want %v", tc.ver, tc.cve, got, tc.want)
		}
	}
}

// The OS strings that give a Junos row, and those that do not (nmap's guess names a generation, D-501).
func TestJunos_DeviceOSForms(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ os, ver string }{
		{"JUNOS 15.1R7.9", "15.1R7.9"},
		{"Junos OS 21.4R3-S5", "21.4R3-S5"},
		{"JUNOS 12.3R12.4", "12.3R12.4"},
		{"junos 12.3X48-D105", "12.3X48-D105"},
		{"Juniper Networks, Inc. ex4200-48t Ethernet Switch, kernel JUNOS 15.1R7.9, Build date: 2019-08-30", "15.1R7.9"},
		{"Juniper Junos OS 12.1 - 15.1", ""},
		{"Junos OS Evolved 22.4R3-EVO", ""},
		{"JUNOS 22.4R3-EVO", ""},
		{"Cisco IOS 15.2(4)M3", ""},
		{"", ""},
	} {
		sws := deviceSoftware(Asset{ID: "a", OS: tc.os})
		got := ""
		if len(sws) == 1 {
			got = sws[0].Version
		}
		if got != tc.ver {
			t.Errorf("%q: version %q, want %q", tc.os, got, tc.ver)
		}
	}
	// A row a person (or a scan) recorded for Junos wins: the OS gives no second row.
	a := Asset{ID: "a", OS: "JUNOS 15.1R7.9", Software: []Software{{ID: "s", Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS", Version: "15.1R7", KevKeys: []string{"Juniper|Junos OS"}}}}
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
