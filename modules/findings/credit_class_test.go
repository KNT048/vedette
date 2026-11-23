package findings

import (
	"database/sql"
	"fmt"
	"testing"
	"time"
)

// The ways a source can read the software line of a finding: the five sources of a reading.
var creditSources = []struct {
	name string
	sw   Software
}{
	{"agent", Software{Source: "agent", Version: "1.0"}},
	{"snmp", Software{Source: SourceSNMP, Version: "1.0"}},
	{"banner", Software{Source: "nmap", Version: "1.0"}},
	{"person's entry", Software{Source: "manual", Version: "1.0"}},
	{"distribution package", Software{Source: "agent", Version: "1.0", Packaged: true, PkgVersion: "1.0-1ubuntu1", PkgSource: "app"}},
}

// The ways a flaw goes away, and the handling each must give whatever read the version.
var creditWays = []struct {
	name string
	want string // resolution/via
}{
	{"upgrade", "patched/version_moved"},
	{"removal", "patched/software_removed"},
	{"distribution fix", "patched/distro_fixed"},
	{"range correction", "not_relevant/data_corrected"},
}

// matchPass writes one match result for device a, as UpsertFromMatch does after MatchAsset.
func (e *env) matchPass(t *testing.T, a Asset, m MatchResult) {
	t.Helper()
	vulns := []Vuln{{CVE: "CVE-2026-1001"}}
	if err := e.svc.write(t.Context(), func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		existing, err := findingsOf(t.Context(), tx, a.ID)
		if err != nil {
			return err
		}
		_, err = e.svc.applyMatch(t.Context(), tx, a, vulns, cveSet(vulns), m, m, existing, now, emit)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// versionMatch is the match of CVE-2026-1001 on line sw as MatchAsset gives it: the reading it compared.
func versionMatch(sw Software) Match {
	return Match{CVE: "CVE-2026-1001", SoftwareID: sw.ID, SoftwareDisplay: sw.Display, Basis: BasisVersion,
		Evidence: Evidence{Summary: "inside the range", Read: readingOf(sw, newSWInfo(sw, ""))}}
}

// The patch credit class test: every source of a reading × every way a flaw goes away gives the handling of the way, never one that depends on
// the source. Patch credit (patched, with who and how) for an upgrade, a removal and a distribution's fix; "Vedette corrected its
// match" for a range correction. Before this model only an agent's or SNMP's upgrade was credited (2 of the 20).
func TestCredit_EverySourceAndEveryWayAFlawGoesAway(t *testing.T) {
	t.Parallel()
	credited := 0
	for _, src := range creditSources {
		for _, way := range creditWays {
			t.Run(src.name+" × "+way.name, func(t *testing.T) {
				e := newEnv(t)
				sw := src.sw
				sw.ID, sw.Display, sw.Vendor, sw.Product, sw.SeenAt = "s-1", "App", "Acme", "App", t0.Add(-time.Hour)
				a := Asset{ID: "a-1", Name: "host-1", Software: []Software{sw}}
				e.matchPass(t, a, MatchResult{New: []Match{versionMatch(sw)}})
				e.advance(time.Hour)
				var m MatchResult
				switch way.name {
				case "upgrade":
					a.Software[0].Version, a.Software[0].SeenAt = "2.0", t0.Add(time.Hour)
					if sw.Packaged {
						a.Software[0].PkgVersion = "2.0-1ubuntu1"
					}
				case "removal":
					a.Software = nil
				case "distribution fix":
					m.NotAffected = []Match{{CVE: "CVE-2026-1001", SoftwareID: "s-1", pkgFixed: true}}
				}
				e.matchPass(t, a, m)
				fs, err := e.svc.Findings(t.Context(), "a-1")
				if err != nil || len(fs) != 1 {
					t.Fatalf("%v %v", fs, err)
				}
				f := fs[0]
				if got := string(f.Resolution) + "/" + string(f.Via); got != way.want || f.ResolvedBy != SystemUser || f.Detected {
					t.Fatalf("handled %s by %s (detected %v), want %s by Vedette", got, f.ResolvedBy, f.Detected, way.want)
				}
				if way.name == "upgrade" {
					from, to := "1.0", "2.0"
					if sw.Packaged {
						from, to = "1.0-1ubuntu1", "2.0-1ubuntu1"
					}
					if f.FromVersion != from || f.ToVersion != to {
						t.Fatalf("credit line %s → %s, want %s → %s", f.FromVersion, f.ToVersion, from, to)
					}
				}
				if f.Resolution == ResolutionPatched {
					credited++
				}
			})
		}
	}
	if want := len(creditSources) * 3; credited != want {
		t.Errorf("%d of %d cases credited, want %d", credited, len(creditSources)*len(creditWays), want)
	}
	t.Logf("credited %d of %d (source × way)", credited, len(creditSources)*len(creditWays))
}

// A person who corrects the version a source read (a wrong reading, not an update) earns no credit: nothing changed on the device.
func TestCredit_APersonsCorrectionIsNoUpdate(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	sw := Software{ID: "s-1", Display: "App", Vendor: "Acme", Product: "App", Version: "1.0", Source: "nmap", SeenAt: t0}
	a := Asset{ID: "a-1", Name: "host-1", Software: []Software{sw}}
	e.matchPass(t, a, MatchResult{New: []Match{versionMatch(sw)}})
	a.Software[0].Source, a.Software[0].ReportedSource, a.Software[0].Version = "manual", "nmap", "2.0" // a person's entry over the banner
	e.matchPass(t, a, MatchResult{})
	fs, _ := e.svc.Findings(t.Context(), "a-1")
	if len(fs) != 1 || fs[0].Resolution != ResolutionNotRelevant || fs[0].Via != ViaDataCorrected {
		t.Fatalf("%+v", fs)
	}
}

// A person who said the software is not installed handles its findings as not relevant, under their own name.
func TestCredit_NotInstalledIsThePersonsWord(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	sw := Software{ID: "s-1", Display: "App", Vendor: "Acme", Product: "App", Version: "1.0", Source: "nmap", SeenAt: t0}
	a := Asset{ID: "a-1", Name: "host-1", Software: []Software{sw}}
	e.matchPass(t, a, MatchResult{New: []Match{versionMatch(sw)}})
	sw.MarkedBy = "anna@example.com"
	a.Software, a.NotInstalled = nil, []Software{sw}
	e.matchPass(t, a, MatchResult{})
	fs, _ := e.svc.Findings(t.Context(), "a-1")
	if len(fs) != 1 || fs[0].Resolution != ResolutionNotRelevant || fs[0].Via != ViaNotInstalled || fs[0].ResolvedBy != "anna@example.com" {
		t.Fatalf("%+v", fs)
	}
}

// A CVE on two software lines of one device (Java 8 beside Java 21) is two findings: updating one line credits that one finding and
// leaves the other open, through the matcher itself.
func TestCredit_TwoLinesOfOneCVEAreTwoFindings(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	vuln := qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.2"}})
	dev := func(v1, v2 string) Asset {
		a := nas(v1)
		second := a.Software[0]
		second.ID, second.Version = "s-2", v2
		a.Software = append(a.Software, second)
		for i := range a.Software {
			a.Software[i].Source, a.Software[i].SeenAt = "agent", e.clock.Add(-time.Minute)
		}
		return a
	}
	res, err := e.svc.UpsertFromMatch(t.Context(), dev("6.1.1", "6.0.5"), []Vuln{vuln})
	if err != nil || len(res.Created) != 2 {
		t.Fatalf("one finding per line: %+v %v", res, err)
	}
	e.advance(time.Hour)
	if _, err := e.svc.UpsertFromMatch(t.Context(), dev("6.2.0", "6.0.5"), []Vuln{vuln}); err != nil { // the first line is updated
		t.Fatal(err)
	}
	fs, err := e.svc.Findings(t.Context(), "a-1")
	if err != nil || len(fs) != 2 {
		t.Fatalf("%+v %v", fs, err)
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.SoftwareID] = fmt.Sprintf("%s %s %s %s→%s", f.State, f.Resolution, f.Via, f.FromVersion, f.ToVersion)
	}
	if got["s-1"] != "handled patched version_moved 6.1.1→6.2.0" || got["s-2"] != "open   →" {
		t.Fatalf("lines: %q", got)
	}
	// handling the CVE on the other line acts on that finding only
	var open string
	for _, f := range fs {
		if f.SoftwareID == "s-2" {
			open = f.ID
		}
	}
	if n, _, err := e.svc.Handle(t.Context(), []string{open}, ResolutionAccepted, "replaced next month", dayOf(t0).AddDate(0, 1, 0), "anna@example.com"); err != nil || n != 1 {
		t.Fatalf("handle: %d %v", n, err)
	}
	if e.count(`SELECT count(*) FROM fnd_finding WHERE state = 'open'`) != 0 || e.count(`SELECT count(*) FROM fnd_finding WHERE resolution = 'accepted'`) != 1 {
		t.Fatal("handling one line touched the other")
	}
}

// A person who changes the version of a line that is only their own entry updated the device and said so: the finding is patched
// (version_moved, credit) and handled by that person, never "by Vedette". Setting the version back opens it again, and the reopen line
// names the person who set it back.
func TestCredit_APersonsOwnEntryMovedIsTheirs(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	const who = "qa@example.com"
	sw := Software{ID: "s-1", Display: "nginx", Vendor: "F5", Product: "nginx", Version: "1.30.5", Source: "manual", SetBy: who, SeenAt: t0}
	a := Asset{ID: "a-1", Name: "web-01", Software: []Software{sw}}
	e.matchPass(t, a, MatchResult{New: []Match{versionMatch(sw)}})
	e.advance(time.Hour)
	a.Software[0].Version = "1.30.6"
	e.matchPass(t, a, MatchResult{})
	fs, _ := e.svc.Findings(t.Context(), "a-1")
	if len(fs) != 1 {
		t.Fatalf("%+v", fs)
	}
	f := fs[0]
	if f.Resolution != ResolutionPatched || f.Via != ViaVersionMoved || f.ResolvedBy != who || f.FromVersion != "1.30.5" || f.ToVersion != "1.30.6" {
		t.Fatalf("handled %s/%s by %q (%s → %s), want patched/version_moved by %s", f.Resolution, f.Via, f.ResolvedBy, f.FromVersion, f.ToVersion, who)
	}
	if got := handledSentence(f); got != "Patched by qa@example.com: version changed 1.30.5 → 1.30.6." {
		t.Errorf("closing sentence %q", got)
	}
	e.advance(time.Hour)
	a.Software[0].Version = "1.30.5"
	e.matchPass(t, a, MatchResult{Existing: []Match{versionMatch(a.Software[0])}})
	v, err := e.svc.View(t.Context(), f.ID)
	if err != nil {
		t.Fatal(err)
	}
	js := v.JSON()
	if js.Status != "update_recommended" || js.Reopened == nil || js.Reopened.Why != WhyDetectedAgain || js.Reopened.By == nil || *js.Reopened.By != who {
		t.Fatalf("after the version was set back: status %s, reopened %+v; want open with the person who set it back", js.Status, js.Reopened)
	}
}

// A source's reading that moves past the range is still Vedette's patch credit, and the reopen line of a source's reading names nobody.
func TestCredit_ASourcesMoveIsVedettes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	sw := Software{ID: "s-1", Display: "nginx", Vendor: "F5", Product: "nginx", Version: "1.30.5", Source: "agent", SeenAt: t0}
	a := Asset{ID: "a-1", Name: "web-01", Software: []Software{sw}}
	e.matchPass(t, a, MatchResult{New: []Match{versionMatch(sw)}})
	e.advance(time.Hour)
	a.Software[0].Version, a.Software[0].SeenAt = "1.30.6", t0.Add(time.Hour)
	e.matchPass(t, a, MatchResult{})
	fs, _ := e.svc.Findings(t.Context(), "a-1")
	if len(fs) != 1 || fs[0].ResolvedBy != SystemUser || fs[0].Via != ViaVersionMoved {
		t.Fatalf("%+v", fs)
	}
	e.advance(time.Hour)
	a.Software[0].Version, a.Software[0].SeenAt = "1.30.5", t0.Add(2*time.Hour)
	e.matchPass(t, a, MatchResult{Existing: []Match{versionMatch(a.Software[0])}})
	v, err := e.svc.View(t.Context(), fs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if r := v.JSON().Reopened; r == nil || r.Why != WhyDetectedAgain || r.By != nil {
		t.Fatalf("reopened %+v, want detected_again by nobody", r)
	}
}
