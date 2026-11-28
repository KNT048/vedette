package findings

import (
	"strings"
	"testing"
	"time"
)

// The distribution's stated status decides a package it built, from one table of status tokens, for a made-up universe package
// (quillpad) of Ubuntu 24.04 that Ubuntu tracks only in its Ubuntu Pro pocket (esm-apps): "not affected" closes, "under investigation"
// keeps the pair undecided with the triage named, "affected" opens a finding whose fix can only come through Ubuntu Pro. A stated
// triage or "not affected" outranks an OSV record without a fixed event.
func quillpad() (Asset, Vuln) {
	a := Asset{ID: "a", Name: "web-01", OS: "Ubuntu 24.04.3 LTS", Software: []Software{{ID: "s-quill", Display: "Quillpad", Vendor: "Acme", Product: "Quillpad",
		Version: "2.4.1", Source: "agent", Packaged: true, PkgVersion: "2.4.1-3ubuntu0.2", PkgSource: "quillpad", KevKeys: []string{"acme|quillpad"}}}}
	v := Vuln{CVE: "CVE-2026-71101", NVDAnswered: true, Origin: RangeNVD, DistroOn: map[string]bool{"ubuntu": true},
		Affected: []Affected{{CPE: "cpe:2.3:a:acme:quillpad:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "2.5"}}}}
	return a, v
}

func quillRow(status string, pro bool) DistroFix {
	return DistroFix{Distro: "ubuntu", Release: "24.04", Package: "quillpad", Status: status, Pro: pro}
}

var distroNow = time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

func TestDistroStatus_ProPocketNotAffectedCloses(t *testing.T) {
	t.Parallel()
	a, v := quillpad()
	v.Distro = []DistroFix{quillRow("not_affected", true)}
	r := MatchAsset(a, []Vuln{v}, map[string]bool{v.CVE: true}, distroNow)
	if len(r.New)+len(r.Existing) != 0 || len(r.NotAffected) != 1 ||
		!strings.Contains(r.NotAffected[0].Evidence.Summary, "Ubuntu says its quillpad package of Ubuntu 24.04 is not affected by CVE-2026-71101") {
		t.Fatalf("a pocket's not affected: %+v", r)
	}
	// the strict rule stays: a build without Ubuntu's own mark is not closed by a word that compares no version
	a.Software[0].PkgVersion = "2.4.1-3"
	if r := MatchAsset(a, []Vuln{v}, map[string]bool{v.CVE: true}, distroNow); len(r.NotAffected) != 0 {
		t.Fatalf("closed a build Ubuntu's mark does not prove: %+v", r.NotAffected)
	}
}

func TestDistroStatus_ProPocketTriageStaysUndecidedWithItsReason(t *testing.T) {
	t.Parallel()
	a, v := quillpad()
	v.Distro = []DistroFix{quillRow(distroTriage, true)}
	for _, listed := range []bool{false, true} {
		if listed {
			v.Vendor, v.Product = "Acme", "Quillpad"
		}
		r := MatchAsset(a, []Vuln{v}, nil, distroNow)
		if len(r.NotAffected) != 0 || len(r.New) != 0 && (!listed || !r.New[0].upstream) {
			t.Fatalf("listed %v: a triage decided: %+v", listed, r)
		}
		if c := distroSilence(swInfoOn(a.Software[0], a), v); c != DistroTriaging {
			t.Fatalf("listed %v: cause %q, want %q", listed, c, DistroTriaging)
		}
	}
}

func TestDistroStatus_ProPocketAffectedOpensWithAProOnlyFix(t *testing.T) {
	t.Parallel()
	a, v := quillpad()
	v.Vendor, v.Product = "Acme", "Quillpad" // "affected, no fix yet" raises a finding of an exploited CVE only
	v.Distro = []DistroFix{quillRow("open", true)}
	r := MatchAsset(a, []Vuln{v}, nil, distroNow)
	if len(r.New) != 1 {
		t.Fatalf("a pocket's affected: %+v", r)
	}
	if s := r.New[0].Evidence.Summary; !strings.Contains(s, "Ubuntu lists its quillpad package of Ubuntu 24.04 as affected by CVE-2026-71101 in Ubuntu Pro (ESM), with no fixed release yet") ||
		!strings.Contains(s, "comes through Ubuntu Pro (ESM) only") {
		t.Fatalf("evidence %q", s)
	}
	fx := FixOf(a, a.Software[0], v)
	if fx.Kind != FixNoneYet || fx.Chan() != ChannelUbuntuPro {
		t.Fatalf("fix %+v", fx)
	}
	text := View{Finding: Finding{Basis: DetectPackage, Fix: fx}}.FixText()
	if !strings.Contains(text, "Ubuntu Pro") || strings.Contains(text, "watch for the distribution's update") {
		t.Fatalf("fix text %q", text)
	}
	// a public release's "affected" (no pocket) keeps the ordinary words
	v.Distro = []DistroFix{quillRow("open", false)}
	if fx := FixOf(a, a.Software[0], v); fx.Kind != FixNoneYet || fx.Chan() != ChannelPublic {
		t.Fatalf("public fix %+v", fx)
	}
}

func TestDistroStatus_StatedVEXStatusOutranksAnOSVRecordWithoutAFix(t *testing.T) {
	t.Parallel()
	a, v := quillpad()
	v.Vendor, v.Product = "Acme", "Quillpad"
	osvOpen := quillRow("open", false) // an OSV record of the release with no fixed event
	// VEX says under investigation: Ubuntu has no word that decides yet. An exploited CVE whose upstream range covers the version is the
	// suspected finding of a package the distribution has not answered for (awaitingDistro), never the distribution's confirmed
	// "affected", and it names the triage
	v.Distro = []DistroFix{osvOpen, quillRow(distroTriage, false)}
	if r := MatchAsset(a, []Vuln{v}, nil, distroNow); len(r.New) != 1 || !r.New[0].upstream || r.New[0].Evidence.Agent ||
		!strings.Contains(r.New[0].Evidence.Summary, "Ubuntu states that it is still triaging CVE-2026-71101 for this package") {
		t.Fatalf("OSV's missing fix outranked VEX's triage: %+v", r.New)
	}
	v.Affected[0].Range.EndExcl = "2.4" // the upstream range does not cover it: no finding at all
	if r := MatchAsset(a, []Vuln{v}, nil, distroNow); len(r.New) != 0 {
		t.Fatalf("a triage raised a finding outside the upstream range: %+v", r.New)
	}
	v.Affected[0].Range.EndExcl = "2.5"
	if c := distroSilence(swInfoOn(a.Software[0], a), v); c != DistroTriaging {
		t.Fatalf("cause %q", c)
	}
	// VEX says not affected: closed
	v.Distro = []DistroFix{osvOpen, quillRow("not_affected", false)}
	if r := MatchAsset(a, []Vuln{v}, map[string]bool{v.CVE: true}, distroNow); len(r.New) != 0 || len(r.NotAffected) != 1 {
		t.Fatalf("OSV's missing fix outranked VEX's not affected: %+v", r)
	}
	// VEX says affected, or says nothing: OSV's word stands, a finding
	for _, rows := range [][]DistroFix{{osvOpen, quillRow("open", false)}, {osvOpen}} {
		v.Distro = rows
		if r := MatchAsset(a, []Vuln{v}, nil, distroNow); len(r.New) != 1 {
			t.Fatalf("%+v: %+v", rows, r)
		}
	}
	// a fixed release still outranks a triage: the version comparison decides
	v.Distro = []DistroFix{quillRow(distroTriage, false), {Distro: "ubuntu", Release: "24.04", Package: "quillpad", Status: "fixed", Fixed: "2.4.1-3ubuntu0.2"}}
	if r := MatchAsset(a, []Vuln{v}, map[string]bool{v.CVE: true}, distroNow); len(r.NotAffected) != 1 {
		t.Fatalf("a fixed release under a triage: %+v", r)
	}
}
