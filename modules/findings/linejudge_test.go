package findings

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// lineNow is the day the line tests match on; lineCVEDay the day the CVE was published.
var (
	lineNow    = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	lineCVEDay = time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
)

// nodeLineSupport is endoflife.date's support of the Node.js lines the cases read (cut to facts, 27 Nov 2026).
var nodeLineSupport = []LineSupport{
	{Source: "endoflife-date", Product: "node.js|node.js", Line: "20", Released: time.Date(2023, 4, 18, 0, 0, 0, 0, time.UTC), AssessedUntil: time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC)},
	{Source: "endoflife-date", Product: "node.js|node.js", Line: "22", Released: time.Date(2024, 4, 24, 0, 0, 0, 0, time.UTC), AssessedUntil: time.Date(2027, 4, 30, 0, 0, 0, 0, time.UTC)},
	{Source: "endoflife-date", Product: "node.js|node.js", Line: "26", Released: time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC)},
}

func nodeRow(version string) Software {
	return Software{ID: "node", Display: "Node.js", Vendor: "Node.js", Product: "Node.js", Version: version, Source: "agent"}
}

// The release-line verdict (M-13) over every verdict × what NVD says × a stale source × an exploited CVE. Only the vendor's explicit
// rows (affected, fixed, unaffected) and its fresh convention change the decision; a line the vendor no longer assesses, or whose
// status is hidden, gives the same answer as without the line source (the CVE record's own statement decides). An explicit "not
// affected" yields to an NVD row that names the line itself; the convention yields to any NVD row that covers the version.
func TestLineJudge_EveryVerdict(t *testing.T) {
	t.Parallel()
	const cve = "CVE-2026-105481"
	cover := LineCover{Source: "nodejs-security-wg", Product: "node.js|node.js", Ref: "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
		StatedAt: lineCVEDay, Absent: AbsentUnaffectedIfSupported}
	row := func(line, status, fixed string) LineRow {
		return LineRow{Source: cover.Source, Product: cover.Product, Line: line, Status: status, Fixed: fixed, Explicit: true}
	}
	verdicts := []struct {
		name    string
		version string
		rows    []LineRow
		want    lineVerdict
	}{
		{"affected", "22.19.0", []LineRow{row("22", "affected", "22.23.4"), row("26", "affected", "26.12.1")}, lineAffected},
		{"fixed", "22.24.0", []LineRow{row("22", "affected", "22.23.4")}, lineFixed},
		{"explicit unaffected", "22.19.0", []LineRow{row("22", "unaffected", "")}, lineUnaffected},
		{"convention unaffected", "22.19.0", []LineRow{row("26", "affected", "26.12.1")}, lineUnaffected},
		{"not assessed", "20.10.0", []LineRow{row("22", "affected", "22.23.4"), row("26", "affected", "26.12.1")}, lineNotAssessed},
		{"hidden", "22.19.0", []LineRow{row("22", "hidden", "")}, lineHidden},
		{"platform limited", "22.19.0", []LineRow{{Source: cover.Source, Product: cover.Product, Line: "22", Status: "affected", Fixed: "22.23.4", Explicit: true, Platforms: []string{"win32"}}}, lineNone},
	}
	nvd := []struct {
		name string
		rows []Affected
	}{
		{"no NVD rows", nil},
		{"NVD names the line", []Affected{{CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "22.0.0", EndExcl: "22.30.0"}}}},
		{"NVD passes through", []Affected{{CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "30.0.0"}}}},
		{"NVD lists another line", []Affected{{CPE: "cpe:2.3:a:nodejs:node.js:26.3.0:*:*:*:*:*:*:*"}}},
	}
	for _, vc := range verdicts {
		for _, nc := range nvd {
			for _, stale := range []bool{false, true} {
				for _, exploited := range []bool{false, true} {
					name := fmt.Sprintf("%s/%s/stale=%v/exploited=%v", vc.name, nc.name, stale, exploited)
					c := cover
					c.Stale = stale
					v := Vuln{CVE: cve, Published: lineCVEDay, Affected: nc.rows, NVDAnswered: true, Lines: vc.rows, LineCovers: []LineCover{c}, LineSupport: nodeLineSupport}
					if exploited {
						v.Vendor, v.Product, v.Source = "Node.js", "Node.js", "cisa-kev"
					}
					base := v
					base.Lines, base.LineCovers, base.LineSupport = nil, nil, nil
					a := Asset{ID: "dev", Name: "dev.example.com", Software: []Software{nodeRow(vc.version)}}
					s := a.Software[0]
					in := swInfoOn(s, a)
					run := func(v Vuln) outcome {
						var key []identity
						if exploited {
							key = keyIDs(v)
						}
						_, out := matchOne(a, s, in, v, exploited, key, true, lineNow)
						return out
					}
					got, without := run(v), run(base)
					lr := lineJudge(a, s, in, v)
					want := without // the verdicts that decide nothing, and the decisions an NVD row overrides
					wantVerdict := vc.want
					switch vc.want {
					case lineAffected:
						want = outMatch
					case lineFixed, lineUnaffected:
						overridden := nc.name == "NVD names the line" || vc.name == "convention unaffected" && (nc.name == "NVD passes through" || stale)
						if overridden {
							wantVerdict = lineNone
						} else {
							want = outNotAffected
						}
					}
					if lr.verdict != wantVerdict {
						t.Errorf("%s: verdict %d, want %d", name, lr.verdict, wantVerdict)
					}
					if got != want {
						t.Errorf("%s: outcome %v, want %v (without the line source: %v)", name, got, want, without)
					}
				}
			}
		}
	}
}

// A finding a vendor's line statement decided names the vendor, its fix of the line, and the line source as the origin of its range;
// a CVE the vendor's convention rules out says why in the closing sentence.
func TestLineJudge_EvidenceFixAndOrigin(t *testing.T) {
	t.Parallel()
	cover := LineCover{Source: "nodejs-security-wg", Product: "node.js|node.js", Ref: "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
		StatedAt: lineCVEDay, Absent: AbsentUnaffectedIfSupported}
	v := Vuln{CVE: "CVE-2026-105481", Published: lineCVEDay, NVDAnswered: true, LineCovers: []LineCover{cover}, LineSupport: nodeLineSupport,
		Lines: []LineRow{{Source: cover.Source, Product: cover.Product, Line: "22", Status: "affected", Fixed: "22.23.4", Explicit: true}}}
	a := Asset{ID: "dev", Name: "dev.example.com", Software: []Software{nodeRow("22.19.0")}}
	res := MatchAsset(a, []Vuln{v}, nil, lineNow)
	if len(res.New) != 1 {
		t.Fatalf("matches = %+v", res)
	}
	if s := res.New[0].Evidence.Summary; !strings.Contains(s, "Node.js security team fixed CVE-2026-105481 in 22.23.4 for release line 22") {
		t.Errorf("evidence = %q", s)
	}
	if f := FixOf(a, a.Software[0], v); f.Kind != FixUpdate || f.Version != "22.23.4" {
		t.Errorf("fix = %+v", f)
	}
	d := Detection{SoftwareID: "node", Basis: DetectDeviceVersion}
	resolve(&d, a, map[string]line{"node": {sw: a.Software[0]}}, v)
	if d.RangeOrigin != RangeVendorLine {
		t.Errorf("range origin = %q", d.RangeOrigin)
	}
	v.Lines[0].Line = "26"
	have := map[string]bool{v.CVE: true}
	res = MatchAsset(a, []Vuln{v}, have, lineNow)
	if len(res.NotAffected) != 1 || !strings.Contains(res.NotAffected[0].Evidence.Summary, "a line it supported then and does not list is not affected") {
		t.Errorf("not affected = %+v", res.NotAffected)
	}
}

// An NVD row that covers the version and names the device's release line keeps the finding even when another NVD row that only passes
// through the line (and ends later) covers it too: the vendor's "fixed" on the line yields to the row naming the line, whichever row
// explains the finding best.
func TestLineJudge_NVDNamesLineBesideAPassingRow(t *testing.T) {
	t.Parallel()
	cover := LineCover{Source: "nodejs-security-wg", Product: "node.js|node.js", StatedAt: lineCVEDay, Absent: AbsentUnaffectedIfSupported}
	v := Vuln{CVE: "CVE-2026-105481", Published: lineCVEDay, NVDAnswered: true, LineCovers: []LineCover{cover}, LineSupport: nodeLineSupport,
		Lines: []LineRow{{Source: cover.Source, Product: cover.Product, Line: "22", Status: "affected", Fixed: "22.23.4", Explicit: true}},
		Affected: []Affected{
			{CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "20.0.0", EndExcl: "30.0.0"}},  // passes through line 22
			{CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "22.0.0", EndExcl: "22.30.0"}}, // names line 22
		}}
	a := Asset{ID: "dev", Name: "dev.example.com", Software: []Software{nodeRow("22.24.0")}}
	s := a.Software[0]
	in := swInfoOn(s, a)
	if lr := lineJudge(a, s, in, v); lr.decides() {
		t.Errorf("verdict %d decides, want none: an NVD row names line 22 and covers 22.24.0", lr.verdict)
	}
	if res := MatchAsset(a, []Vuln{v}, nil, lineNow); len(res.New) != 1 {
		t.Errorf("matches = %+v, want the finding NVD's row on line 22 states", res)
	}
}
