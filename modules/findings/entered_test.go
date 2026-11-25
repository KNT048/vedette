package findings

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/productid"
)

// The version a person typed or corrected is their word: a match on it is confirmed by that person when it is made, never queued
// in Needs your input for the same person to confirm, and the history names them. It is judged again at every match like the
// device's own report (a correction of the ranges closes it, the person's Not affected on the finding page stays), and its
// confirmation is not one Undo can take back (the next match would confirm it again).
func TestMatch_EnteredVersionIsThePersonsWord(t *testing.T) {
	t.Parallel()
	const admin = "admin@example.test"
	e := newEnv(t)
	e.feeds.vulns = []Vuln{qnapRanged}
	a := nas("6.1.1")
	a.Software[0].Source, a.Software[0].SetBy = "manual", admin
	e.inv.mu.Lock()
	e.inv.match[a.ID] = a
	e.inv.mu.Unlock()
	if _, err := e.svc.UpsertFromMatch(t.Context(), a, e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	f := e.only(t)
	if f.Basis != DetectStatement || f.Verified != VerifiedPerson {
		t.Fatalf("basis %s verified %s, want statement confirmed by the person", f.Basis, f.Verified)
	}
	evs, err := e.svc.Events(t.Context(), f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.IndexFunc(evs, func(ev Event) bool { return ev.Kind == EvConfirmed }); i < 0 || evs[i].Actor != SystemUser || evs[i].Detail.By != admin ||
		!strings.Contains(evs[i].Detail.Note, "6.1.1") {
		t.Errorf("history %+v: want Vedette's confirmation on %s's word naming the version", evs, admin)
	}
	if v := verificationOf(f, evs); v.By == nil || *v.By != admin || !v.Entered {
		t.Errorf("verification %+v: the finding page names the person whose entered version confirmed it", v)
	}
	if acts := e.auditActions(); slices.Contains(acts, "findings.confirm") {
		t.Errorf("audit %v: Vedette's confirmation is no action of the person", acts)
	}
	in, err := e.svc.Input(t.Context(), "", "", Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(in.Items, func(it InputItemJS) bool { return it.Kind == "unconfirmed" }) {
		t.Errorf("queue %+v: a finding on the person's own version asks them to confirm it", in.Items)
	}
	if rec, err := e.svc.Get(t.Context(), f.ID); err != nil || rec.Basis != BasisVersion {
		t.Errorf("older read model basis %q (%v), want version (no Undo of a confirmation nobody pressed)", rec.Basis, err)
	}
	if _, err := e.svc.Unverify(t.Context(), f.ID, admin); !errors.Is(err, ErrNotConfirmedByHand) {
		t.Errorf("unverify: %v, want refused", err)
	}
	// NVD corrects its range: the person's version is outside it now, and the finding closes as a correction of the match
	e.advance(time.Hour)
	fixed := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.0"}})
	e.feeds.vulns = []Vuln{fixed}
	if _, err := e.svc.UpsertFromMatch(t.Context(), a, e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	if f := e.only(t); f.State != StateHandled || f.Via != ViaDataCorrected {
		t.Errorf("after the range correction: %s via %s, want handled via data_corrected", f.State, f.Via)
	}
}

// A line a person entered without a known author (no SetBy), or a banner, stays suspected: only a person's own word confirms.
func TestMatch_EnteredVersionWithoutAPersonStaysSuspected(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ source, by string }{{"manual", ""}, {"nmap", ""}} {
		e := newEnv(t)
		e.feeds.vulns = []Vuln{qnapRanged}
		a := nas("6.1.1")
		a.Software[0].Source, a.Software[0].SetBy = tc.source, tc.by
		if _, err := e.svc.UpsertFromMatch(t.Context(), a, e.feeds.vulns); err != nil {
			t.Fatal(err)
		}
		if f := e.only(t); f.Verified != VerifiedNo {
			t.Errorf("%s: verified %s, want no", tc.source, f.Verified)
		}
	}
}

// NVD's NA ("-") in an edition is the plain edition, one of the alternatives (CVE-2026-4718's real rows): a version inside the range of
// every edition NVD lists is affected whichever edition the device runs; inside some only, it stays a question; inside none, nothing.
// #906 holds: a row that states its edition is judged by it, NA never covers an edition left unstated by itself, and a plain edition
// NVD lists alone proves nothing about the others.
func TestMatchAsset_PlainEditionIsOneOfTheAlternatives(t *testing.T) {
	t.Parallel()
	tb := func(edition, end string) Affected {
		return Affected{CPE: "cpe:2.3:a:mozilla:thunderbird:*:*:*:*:" + edition + ":*:*:*", Range: VersionRange{EndExcl: end}}
	}
	cve := Vuln{CVE: "CVE-2026-4718", NVDAnswered: true, Published: uncNew, Affected: []Affected{
		{CPE: "cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*", Range: VersionRange{EndExcl: "140.9.0"}},
		{CPE: "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "149.0"}},
		tb("esr", "140.9.0"), tb("-", "149.0")}}
	row := func(ver, cpe string) Asset {
		return Asset{ID: "pc", Name: "pc", Software: []Software{{ID: "s", Display: "Mozilla Thunderbird", Vendor: "Mozilla", Product: "Thunderbird",
			Version: ver, CPE: cpe, Source: "agent"}}}
	}
	for _, tc := range []struct {
		name string
		a    Asset
		v    Vuln
		want string // "finding", "question", "none"
	}{
		{"115.9.0, inside the ESR and the plain range", row("115.9.0", ""), cve, "finding"},
		{"145.0, inside the plain range only", row("145.0", ""), cve, "question"},
		{"150.0, inside none", row("150.0", ""), cve, "none"},
		{"145.0 stating ESR", row("145.0", "cpe:2.3:a:mozilla:thunderbird:145.0:*:*:*:esr:*:*:*"), cve, "none"},
		{"115.9.0 stating ESR", row("115.9.0", "cpe:2.3:a:mozilla:thunderbird:115.9.0:*:*:*:esr:*:*:*"), cve, "finding"},
		{"plain edition listed alone", row("115.9.0", ""), Vuln{CVE: "CVE-2099-0201", NVDAnswered: true, Published: uncNew,
			Affected: []Affected{tb("-", "149.0")}}, "question"},
	} {
		r := MatchAsset(tc.a, []Vuln{tc.v}, nil, t0)
		got := "none"
		switch {
		case len(r.New) == 1 && r.New[0].Basis == BasisVersion:
			got = "finding"
		case len(r.New) != 0:
			got = "product finding"
		case len(r.Unchecked) == 1:
			got = "question"
		}
		if got != tc.want {
			t.Errorf("%s: %s, want %s (%+v)", tc.name, got, tc.want, r)
		}
		if got == "finding" && tc.a.Software[0].CPE == "" && !strings.Contains(r.New[0].Evidence.Summary, "for esr or plain only") {
			t.Errorf("%s: evidence %q does not name the editions", tc.name, r.New[0].Evidence.Summary)
		}
	}
	// Jenkins: NVD's "-" (weekly) before 2.442 and LTS before 2.426.3; 2.430 is past the LTS fix, so the edition decides
	jenkins := Vuln{CVE: "CVE-2024-23897", Vendor: "Jenkins", Product: "Jenkins Command Line Interface (CLI)", NVDAnswered: true, Published: uncNew, DateAdded: uncNew,
		Affected: []Affected{{CPE: "cpe:2.3:a:jenkins:jenkins:*:*:*:*:-:*:*:*", Range: VersionRange{EndExcl: "2.442"}},
			{CPE: "cpe:2.3:a:jenkins:jenkins:*:*:*:*:lts:*:*:*", Range: VersionRange{EndExcl: "2.426.3"}}}}
	for ver, want := range map[string]int{"2.430": 0, "2.400": 1} {
		a := Asset{ID: "ci", Name: "ci", Software: []Software{{ID: "j", Display: "Jenkins", Vendor: "Jenkins", Product: "Jenkins", Version: ver, Source: "agent",
			KevKeys: []string{productid.Key(jenkins.Vendor, jenkins.Product)}}}}
		if r := MatchAsset(a, []Vuln{jenkins}, nil, t0); len(r.New) != want || want == 0 && len(r.Unchecked)+len(r.NameOnly) == 0 {
			t.Errorf("Jenkins %s: %+v, want %d version finding(s), else a question", ver, r, want)
		}
	}
}

// NVD's exact list is an enumeration: a row of a release line it does not list, newer than or between the listed lines, is no
// candidate, so it is never asked (Junos 25.4R1 for CVE-2026-21913, listed at 24.4 and 25.2 releases only; Java 8 Update 491 for
// CVE-2025-21587, listed at 8u441 and at Java 11, 17 and 21). A line older than every listed one stays a question (Junos 15.1R7.9:
// end-of-life lines are often not evaluated; the vendor's own record decides it when it says so), and so does a row of a listed line
// when nothing decides it (an older update than the listed one: Oracle's "8u77 and earlier") and a listed release (it is never taken
// off as "not listed").
func TestUnchecked_OtherReleaseLinesAreNotListed(t *testing.T) {
	t.Parallel()
	junosRows := func(rels ...string) []Affected {
		var out []Affected
		for _, r := range rels {
			out = append(out, Affected{CPE: "cpe:2.3:o:juniper:junos:" + r + ":*:*:*:*:*:*"})
		}
		return out
	}
	junos := Vuln{CVE: "CVE-2026-21913", NVDAnswered: true, Published: uncNew,
		Affected: junosRows("24.4:-", "24.4:r1", "24.4:r1-s2", "24.4:r1-s3", "25.2:-", "25.2:r1", "25.2:r1-s1", "25.2:r2")}
	java := Vuln{CVE: "CVE-2025-21587", NVDAnswered: true, Published: uncNew, Affected: []Affected{
		{CPE: "cpe:2.3:a:oracle:jre:1.8.0:update441:*:*:-:*:*:*"}, {CPE: "cpe:2.3:a:oracle:jre:11.0.26:*:*:*:*:*:*:*"},
		{CPE: "cpe:2.3:a:oracle:jre:17.0.14:*:*:*:*:*:*:*"}, {CPE: "cpe:2.3:a:oracle:jre:21.0.6:*:*:*:*:*:*:*"}, {CPE: "cpe:2.3:a:oracle:jre:24:*:*:*:*:*:*:*"}}}
	junosRow := func(ver string) Asset {
		return Asset{ID: "sw", Name: "sw", Model: "EX4200-48T", Software: []Software{{ID: "s", Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS",
			Version: ver, Source: "manual", SetBy: "admin@example.test", KevKeys: []string{"juniper|junos os"}}}}
	}
	javaRow := func(ver string) Asset {
		return Asset{ID: "pc", Name: "pc", Software: []Software{{ID: "s", Display: "Java 8 Update", Vendor: "Oracle", Product: "Java SE", Version: ver,
			Source: "agent", KevKeys: []string{"oracle|java se"}}}}
	}
	for _, tc := range []struct {
		name string
		a    Asset
		v    Vuln
		want string // "none", "question", or "kept" (a finding or a question: not taken off)
	}{
		{"Junos 15.1R7.9 (older than every listed line)", junosRow("15.1R7.9"), junos, "question"},
		{"Junos 25.4R1 (newer than every listed line)", junosRow("25.4R1"), junos, "none"},
		{"Junos 24.4R1-S2 (listed)", junosRow("24.4R1-S2"), junos, "kept"},
		{"Java 8u491", javaRow("8.0.4910.10"), java, "none"},
		{"Java 8u401 (an older update of the listed line)", javaRow("8.0.4010.7"), java, "question"},
		{"Java 17.0.14 (listed)", javaRow("17.0.14"), java, "kept"},
	} {
		r := MatchAsset(tc.a, []Vuln{tc.v}, nil, t0)
		got := "none"
		switch {
		case len(r.New) == 1:
			got = "finding"
		case len(r.Unchecked) == 1:
			got = "question"
		}
		if got != tc.want && (tc.want != "kept" || got == "none") {
			t.Errorf("%s: %s, want %s (%+v)", tc.name, got, tc.want, r)
		}
	}
}

// A release line older than every line an exact NVD list names is still asked: vendors often do not evaluate end-of-life lines
// (Juniper's advisories say so; Oracle lists supported releases only), so their absence from the list is no statement about them.
// Only a line newer than or between the listed lines is no candidate.
func TestUnchecked_OlderLineThanEveryListedStaysAsked(t *testing.T) {
	t.Parallel()
	junosRows := func(rels ...string) []Affected {
		var out []Affected
		for _, r := range rels {
			out = append(out, Affected{CPE: "cpe:2.3:o:juniper:junos:" + r + ":*:*:*:*:*:*"})
		}
		return out
	}
	exploited := Vuln{CVE: "CVE-2099-0301", Vendor: "Juniper", Product: "Junos OS", NVDAnswered: true, Published: uncNew, DateAdded: uncNew,
		Affected: junosRows("21.2:r1", "21.2:r3-s7", "21.4:r1", "21.4:r3-s6", "22.2:r1", "22.2:r3-s3")}
	plain := exploited
	plain.CVE, plain.Vendor, plain.Product, plain.DateAdded = "CVE-2099-0302", "", "", time.Time{}
	java := Vuln{CVE: "CVE-2099-0303", NVDAnswered: true, Published: uncNew, Affected: []Affected{
		{CPE: "cpe:2.3:a:oracle:jre:1.8.0:update441:*:*:-:*:*:*"}, {CPE: "cpe:2.3:a:oracle:jre:11.0.26:*:*:*:*:*:*:*"}}}
	junosRow := func(ver string) Asset {
		return Asset{ID: "sw", Name: "sw", Software: []Software{{ID: "s", Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS",
			Version: ver, Source: "agent", KevKeys: []string{"juniper|junos os"}}}}
	}
	javaRow := func(ver string) Asset {
		return Asset{ID: "pc", Name: "pc", Software: []Software{{ID: "s", Display: "Java 7 Update 401", Vendor: "Oracle", Product: "Java SE",
			Version: ver, Source: "agent", KevKeys: []string{"oracle|java se"}}}}
	}
	for _, tc := range []struct {
		name  string
		a     Asset
		v     Vuln
		asked bool
	}{
		{"exploited, Junos 15.1R7.9 (older than every listed line)", junosRow("15.1R7.9"), exploited, true},
		{"Junos 15.1R7.9 (older than every listed line)", junosRow("15.1R7.9"), plain, true},
		{"Java 7u401 (older than every listed line)", javaRow("7.0.4010.10"), java, true},
		{"Junos 21.3R3 (between listed lines)", junosRow("21.3R3"), plain, false},
		{"Junos 23.4R1 (newer than every listed line)", junosRow("23.4R1"), plain, false},
	} {
		r := MatchAsset(tc.a, []Vuln{tc.v}, nil, t0)
		if asked := len(r.Unchecked) > 0; asked != tc.asked || len(r.New) != 0 {
			t.Errorf("%s: asked %v, want %v (%+v)", tc.name, asked, tc.asked, r)
		}
	}
}

// A person's own Confirm stays as on a finding of any other basis: it holds at every match (a correction of the ranges does not take
// it back) and Undo takes it back, also on a finding that rests on a version a person entered, and also when that version's author
// is known only after the Confirm (a finding confirmed by hand before entries were confirmed by themselves). Only Vedette's
// confirmation on the entered version is judged again at every match.
func TestMatch_OwnConfirmOnEnteredVersionHolds(t *testing.T) {
	t.Parallel()
	for _, laterBy := range []string{"", "admin@example.test"} {
		e := newEnv(t)
		e.feeds.vulns = []Vuln{qnapRanged}
		a := nas("6.1.1")
		a.Software[0].Source = "manual"
		e.inv.mu.Lock()
		e.inv.match[a.ID] = a
		e.inv.mu.Unlock()
		if _, err := e.svc.UpsertFromMatch(t.Context(), a, e.feeds.vulns); err != nil {
			t.Fatal(err)
		}
		f := e.only(t)
		if _, err := e.svc.Verify(t.Context(), f.ID, "logged in, the affected build runs", "anna@example.com"); err != nil {
			t.Fatal(err)
		}
		a.Software[0].SetBy = laterBy
		e.advance(time.Hour)
		if _, err := e.svc.UpsertFromMatch(t.Context(), a, e.feeds.vulns); err != nil {
			t.Fatal(err)
		}
		if f := e.only(t); f.Verified != VerifiedPerson {
			t.Errorf("author %q: after the next match verified %s, want the person's own Confirm to hold", laterBy, f.Verified)
		}
		if evs, err := e.svc.Events(t.Context(), f.ID); err != nil {
			t.Fatal(err)
		} else if v := verificationOf(e.only(t), evs); v.By == nil || *v.By != "anna@example.com" || v.Entered {
			t.Errorf("author %q: verification %+v, want confirmed by the person who pressed Confirm", laterBy, v)
		}
		if rec, err := e.svc.Get(t.Context(), f.ID); err != nil || rec.Basis != BasisPerson {
			t.Errorf("author %q: older read model basis %q (%v), want person (the Undo button)", laterBy, rec.Basis, err)
		}
		e.advance(time.Hour)
		fixed := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.0"}})
		if _, err := e.svc.UpsertFromMatch(t.Context(), a, []Vuln{fixed}); err != nil {
			t.Fatal(err)
		}
		if f := e.only(t); f.State != StateOpen || f.Verified != VerifiedPerson {
			t.Errorf("author %q: after a range correction %s verified %s, want open and still confirmed by the person", laterBy, f.State, f.Verified)
		}
		if _, err := e.svc.Unverify(t.Context(), f.ID, "anna@example.com"); err != nil {
			t.Errorf("author %q: undo of the person's own Confirm: %v", laterBy, err)
		}
	}
}

// The vendor's record decides "not affected" from what it states, never "affected" (CVE-2026-21913's real record: Juniper's entry
// for EX4000 models, defaultStatus unaffected, unaffected from 0 before 24.4R1, affected 24.4 before 24.4R2 and 25.2 before
// 25.2R1-S2). A version inside a range the vendor states unaffected is not affected whatever the model; a version outside every
// model-limited range, in a train one of them ends in, is not affected; a version inside a model-limited range is not decided by
// it (Vedette does not know the model), and a version inside an affected range of every device stays affected.
func TestMatchAsset_VendorStatementsSayOnlyNotAffected(t *testing.T) {
	t.Parallel()
	p, ok := productid.ResolveStored("Juniper", "Junos OS", "Juniper Junos OS", "")
	if !ok {
		t.Fatal("Junos OS is not in the product catalogue")
	}
	statements := func(unaffected [][3]string, models [][3]string) []SchemedRange {
		var out []SchemedRange
		for _, r := range schemedRows(t, "juniper-junos", p.Key, unaffected...) {
			r.Unaffected = true
			out = append(out, r)
		}
		for _, r := range schemedRows(t, "juniper-junos", p.Key, models...) {
			r.ModelOnly = true
			out = append(out, r)
		}
		return out
	}
	var nvd []Affected
	for _, r := range []string{"24.4:-", "24.4:r1", "24.4:r1-s2", "24.4:r1-s3", "25.2:-", "25.2:r1", "25.2:r1-s1", "25.2:r2"} {
		nvd = append(nvd, Affected{CPE: "cpe:2.3:o:juniper:junos:" + r + ":*:*:*:*:*:*"})
	}
	record := Vuln{CVE: "CVE-2026-21913", NVDAnswered: true, Published: uncNew, Affected: nvd,
		Schemed: statements([][3]string{{"", "24.4R1", ""}}, [][3]string{{"24.4", "24.4R2", ""}, {"25.2", "25.2R1-S2", ""}})}
	everyDevice := record
	everyDevice.CVE = "CVE-2099-0401"
	everyDevice.Schemed = append(schemedRows(t, "juniper-junos", p.Key, [3]string{"", "21.2R3-S6", ""}), record.Schemed...)
	modelsOnly := Vuln{CVE: "CVE-2099-0402", Vendor: "Juniper", Product: "Junos OS", NVDAnswered: true, Published: uncNew, DateAdded: uncNew,
		Schemed: statements(nil, [][3]string{{"24.4", "24.4R2", ""}})}
	row := func(ver string) Asset {
		return Asset{ID: "sw", Name: "sw", Model: "EX4200-48T", Software: []Software{{ID: "s", Display: "Juniper Junos OS", Vendor: "Juniper", Product: "Junos OS",
			Version: ver, Source: "manual", SetBy: "admin@example.test", KevKeys: []string{"juniper|junos os"}}}}
	}
	for _, tc := range []struct {
		name string
		ver  string
		v    Vuln
		want string // "none", "finding" (a version finding), "kept" (a finding or a question: the vendor's rows do not decide)
	}{
		{"15.1R7.9, inside the range the vendor states unaffected", "15.1R7.9", record, "none"},
		{"24.4R2, past the model-limited range of its train", "24.4R2", record, "none"},
		{"24.4R1-S2, inside a model-limited range (NVD lists it)", "24.4R1-S2", record, "kept"},
		{"15.1R7.9, inside an affected range of every device too", "15.1R7.9", everyDevice, "finding"},
		{"24.4R1, inside a model-limited range only", "24.4R1", modelsOnly, "kept"},
	} {
		r := MatchAsset(row(tc.ver), []Vuln{tc.v}, nil, t0)
		got := "none"
		switch {
		case len(r.New) == 1 && r.New[0].Basis == BasisVersion:
			got = "finding"
		case len(r.New)+len(r.Unchecked)+len(r.NameOnly)+len(r.NotComparable) > 0:
			got = "kept"
		}
		if got != tc.want {
			t.Errorf("%s: %s, want %s (%+v)", tc.name, got, tc.want, r)
		}
	}
}
