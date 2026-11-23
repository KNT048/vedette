package findings

import (
	"testing"
	"time"
)

// scanDevice is the QNAP of the service tests read by source src at version v, read at the env's clock.
func (e *env) scanDevice(v, src string) Asset {
	a := nas(v)
	a.Software[0].Source, a.Software[0].SeenAt = src, *e.clock
	e.inv.mu.Lock()
	e.inv.match[a.ID] = a
	e.inv.mu.Unlock()
	return a
}

func (e *env) only(t *testing.T) Finding {
	t.Helper()
	fs, err := e.svc.Findings(t.Context(), "a-1")
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %+v %v", fs, err)
	}
	return fs[0]
}

var qnapRanged = qnapVuln(Affected{CPE: qnapCPE, Range: VersionRange{StartIncl: "6.0", EndExcl: "6.1.2"}})

// A safe check's confirmation is evidence of the version it saw: when the device's own newer reading moves past the affected range,
// the finding is patched by Vedette with the versions, like any other.
func TestScanProof_AConfirmedFindingIsCreditedWhenTheVersionMoves(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.feeds.vulns = []Vuln{qnapRanged}
	if res, err := e.svc.UpsertFromMatch(t.Context(), e.scanDevice("6.1.1", "agent"), e.feeds.vulns); err != nil || len(res.Created) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	e.advance(time.Hour)
	if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", qnapRanged.CVE, scanEv("t1")); err != nil {
		t.Fatal(err)
	}
	if f := e.only(t); f.Verified != VerifiedScan || f.SoftwareID != "s-1" || f.MatchedVersion != "6.1.1" {
		t.Fatalf("after the check: %+v", f)
	}
	e.advance(time.Hour)
	if _, err := e.svc.UpsertFromMatch(t.Context(), e.scanDevice("6.2.0", "agent"), e.feeds.vulns); err != nil {
		t.Fatal(err)
	}
	f := e.only(t)
	if f.State != StateHandled || f.Resolution != ResolutionPatched || f.Via != ViaVersionMoved || f.FromVersion != "6.1.1" || f.ToVersion != "6.2.0" || f.ResolvedBy != SystemUser {
		t.Fatalf("after the update: %+v", f)
	}
}

// A safe check is about the line the CVE is on: with two lines of the product, it confirms the one the matcher reads the entry on,
// not every line; on a device with a line but no finding yet, the finding it makes is on that line.
func TestScanProof_TheCheckConfirmsOneLine(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.feeds.vulns = []Vuln{qnapRanged}
	a := e.scanDevice("6.1.1", "agent")
	second := a.Software[0]
	second.ID, second.Version = "s-2", "6.0.5"
	a.Software = append(a.Software, second)
	e.inv.mu.Lock()
	e.inv.match["a-1"] = a
	e.inv.mu.Unlock()
	if res, err := e.svc.UpsertFromMatch(t.Context(), a, e.feeds.vulns); err != nil || len(res.Created) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", qnapRanged.CVE, scanEv("t1")); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE verified = 'scan'`); n != 1 {
		t.Fatalf("%d lines confirmed by one check", n)
	}

	o := newEnv(t)
	o.feeds.vulns = []Vuln{qnapRanged}
	o.scanDevice("6.2.0", "nmap") // outside the range: no finding
	if _, err := o.svc.ConfirmFromScan(t.Context(), "a-1", qnapRanged.CVE, scanEv("t1")); err != nil {
		t.Fatal(err)
	}
	if f := o.only(t); f.SoftwareID != "s-1" || f.Basis != DetectScan || f.MatchedVersion != "6.2.0" {
		t.Fatalf("the check's finding: %+v", f)
	}
}

// A distribution's package fix (same upstream, a new revision) credits a finding a safe check confirmed, whether or not a match pass
// ran between the check and the fix: the package release is compared whenever the line has one.
func TestScanProof_APackageFixAfterTheCheck(t *testing.T) {
	t.Parallel()
	for _, between := range []bool{false, true} {
		e := newEnv(t)
		sw := Software{ID: "s-1", Display: "App", Vendor: "Acme", Product: "App", Source: "agent", Version: "1.0", Packaged: true,
			PkgVersion: "1.0-1ubuntu1", PkgSource: "app", SeenAt: t0}
		a := Asset{ID: "a-1", Name: "host-1", Software: []Software{sw}}
		e.inv.mu.Lock()
		e.inv.match["a-1"] = a
		e.inv.mu.Unlock()
		e.feeds.vulns = []Vuln{{CVE: "CVE-2026-1001"}}
		e.matchPass(t, a, MatchResult{New: []Match{versionMatch(sw)}})
		e.advance(time.Hour)
		if _, err := e.svc.ConfirmFromScan(t.Context(), "a-1", "CVE-2026-1001", scanEv("t1")); err != nil {
			t.Fatal(err)
		}
		if between {
			e.advance(time.Hour)
			e.matchPass(t, a, MatchResult{Existing: []Match{versionMatch(sw)}})
		}
		e.advance(time.Hour)
		a.Software[0].PkgVersion, a.Software[0].SeenAt = "1.0-1ubuntu2", *e.clock
		e.matchPass(t, a, MatchResult{NotAffected: []Match{{CVE: "CVE-2026-1001", SoftwareID: "s-1", pkgFixed: true}}})
		f := e.only(t)
		if f.State != StateHandled || f.Via != ViaVersionMoved || f.FromVersion != "1.0-1ubuntu1" || f.ToVersion != "1.0-1ubuntu2" {
			t.Errorf("a match pass between: %v: %+v", between, f)
		}
	}
}
