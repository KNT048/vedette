package findings

import (
	"testing"
	"time"
)

// catalogueOnly is a CVE on no exploited list: only the catalogue holds it, with NVD's ranges.
func catalogueOnly(cve, cpe, start, end string) Vuln {
	return Vuln{CVE: cve, NVDAnswered: true, Origin: RangeNVD, Affected: []Affected{{CPE: cpe, Range: VersionRange{StartIncl: start, EndExcl: end}}}}
}

func fortigate() Asset {
	const version = "7.2.5"
	return Asset{ID: "a-1", Name: "fw01", Software: []Software{{ID: "sw-fos", Display: "FortiOS", Vendor: "Fortinet", Product: "FortiOS",
		Version: version, CPE: "cpe:2.3:o:fortinet:fortios:" + version + ":*:*:*:*:*:*:*", Source: "snmp", KevKeys: []string{"fortinet|fortios"}}}}
}

// A CVE on no exploited list that the device's version is inside a bounded range of is a finding like any other (a range with no end
// says something only for an entry CISA's key reaches), with the fix the one resolver reads
// and the origin of the ranges it compared; the pass that follows writes nothing.
func TestMatchPass_EveryCatalogueCVEIsAFindingWithItsFix(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.inv.match = map[string]Asset{"a-1": fortigate()}
	rec := catalogueOnly("CVE-2026-100001", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.2.0", "7.2.9")
	cna := Vuln{CVE: "CVE-2026-100002", NVDAnswered: true, Origin: RangeCNA, RangesFrom: RangesCVEOrg,
		Affected: []Affected{{CPE: "cpe:2.3:*:fortinet:fortios:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "7.2.0", EndExcl: "7.2.11"}}}}
	open := catalogueOnly("CVE-2026-100003", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.0.0", "")
	open.Vendor, open.Product = "Fortinet", "FortiOS" // an exploited-list entry: CISA's key reaches the row by its name
	out := catalogueOnly("CVE-2026-100004", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.4.0", "7.4.3")
	e.feeds.vulns = []Vuln{rec, cna, open, out}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	fs, err := e.svc.Findings(t.Context(), "a-1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Finding{}
	for _, f := range fs {
		got[f.CVE] = f
	}
	want := map[string]struct {
		origin string
		fix    Fix
	}{
		"CVE-2026-100001": {RangeNVD, Fix{Kind: FixUpdate, Version: "7.2.9"}},
		"CVE-2026-100002": {RangeCNA, Fix{Kind: FixUpdate, Version: "7.2.11"}},
		"CVE-2026-100003": {RangeNVD, Fix{Kind: FixNoneYet}},
	}
	if len(got) != len(want) {
		t.Fatalf("findings %v, want %v", keysOf(got), want)
	}
	for cve, w := range want {
		f := got[cve]
		if !f.Detected || f.RangeOrigin != w.origin || f.Fix != w.fix || f.FixKey != FixKey("fortinet|fortios", w.fix) {
			t.Errorf("%s: detected %v origin %q fix %+v key %q, want origin %q fix %+v", cve, f.Detected, f.RangeOrigin, f.Fix, f.FixKey, w.origin, w.fix)
		}
	}
	rows := e.count(`SELECT count(*) FROM fnd_finding_event`)
	stamp := e.count(`SELECT count(*) FROM fnd_finding WHERE updated_at = (SELECT max(updated_at) FROM fnd_finding)`)
	e.advance(ReconcileEvery)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_event`); n != rows {
		t.Errorf("a pass that changes nothing appended %d events", n-rows)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE updated_at = (SELECT max(updated_at) FROM fnd_finding)`); n != stamp || e.count(`SELECT count(*) FROM fnd_finding WHERE updated_at > '`+t0.Format(tsLayout)+`'`) != 0 {
		t.Error("a pass that changes nothing rewrote rows")
	}
	e.advance(lastSeenStep)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE last_seen > '` + t0.Format(tsLayout) + `'`); n != len(want) {
		t.Errorf("after a day, last seen moved on %d findings, want %d", n, len(want))
	}
}

// The software line goes from the device: the pass still compares the CVEs of its findings (they are pinned), so the finding goes
// away as patched, even when no device runs the product any more.
func TestMatchPass_APinnedCVEIsJudgedWhenTheProductIsGone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.inv.match = map[string]Asset{"a-1": fortigate()}
	e.feeds.vulns = []Vuln{catalogueOnly("CVE-2026-100001", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.2.0", "7.2.9")}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	pinned, err := e.svc.pinnedCVEs(t.Context(), "")
	if err != nil || len(pinned) != 1 {
		t.Fatalf("pinned %v %v", pinned, err)
	}
	a := fortigate()
	a.Software = nil
	e.inv.match = map[string]Asset{"a-1": a}
	e.advance(ReconcileEvery)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	fs, err := e.svc.Findings(t.Context(), "a-1")
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %v %v", fs, err)
	}
	if f := fs[0]; f.Open() || f.Via != ViaSoftwareRemoved || f.Detected {
		t.Errorf("finding %+v, want handled via software_removed", f)
	}
}

// The scope asks the catalogue only for what the devices run, the device's own entries come from the vendors of its lines, and every
// exploited-list entry is read for every device (CISA's key reaches a row by its name).
func TestMatchPass_ScopeAndIndex(t *testing.T) {
	t.Parallel()
	a := fortigate()
	sc := NewMatchScope([]Asset{a}, nil)
	if !sc.Keep("fortinet", "fortios", false) || sc.Keep("apache", "http_server", false) {
		t.Errorf("scope keeps the wrong products")
	}
	kev := Vuln{CVE: "CVE-2024-0001", Vendor: "Apache", Product: "HTTP Server"}
	other := catalogueOnly("CVE-2026-100009", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.4.0", "2.4.60")
	own := catalogueOnly("CVE-2026-100001", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.2.0", "7.2.9")
	got := newMatchSet([]Vuln{kev, other, own}).forDevice(a)
	if len(got) != 2 || got[0].CVE != kev.CVE || got[1].CVE != own.CVE {
		t.Errorf("forDevice %v", vulnCVEs(got))
	}
}

func keysOf(m map[string]Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func vulnCVEs(vs []Vuln) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.CVE
	}
	return out
}

// A finding of a CVE on no exploited list is never announced and never rated exploited, whatever creates or changes it: the hourly
// pass, an inventory change (OnMatchChanged), a safe check, the device's own version confirming it, a person confirming it. A CVE on a
// list still is.
func TestMatchPass_ACVEOnNoListIsNeverAnnounced(t *testing.T) {
	t.Parallel()
	const quiet, loud = "CVE-2026-100001", "CVE-2026-100005"
	listed := catalogueOnly(loud, "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.2.0", "7.2.8")
	listed.Vendor, listed.Product = "Fortinet", "FortiOS"
	quietVuln := catalogueOnly(quiet, "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.2.0", "7.2.9")
	type path struct {
		name string
		run  func(e *env) error
	}
	agent := fortigate()
	agent.Software[0].Source = "agent" // the device's own reading confirms a version match
	stated := fortigate()
	stated.Software[0].Source = "manual" // a person's statement: not confirmed
	for _, p := range []path{
		{"reconcile", func(e *env) error { _, err := e.svc.Reconcile(e.t.Context()); return err }},
		{"inventory change", func(e *env) error { _, err := e.svc.OnMatchChanged(e.t.Context(), "a-1"); return err }},
		{"safe check", func(e *env) error {
			if _, err := e.svc.ConfirmFromScan(e.t.Context(), "a-1", quiet, Evidence{Summary: "hit", Template: "t", CheckedAt: t0}); err != nil {
				return err
			}
			_, err := e.svc.ConfirmFromScan(e.t.Context(), "a-1", loud, Evidence{Summary: "hit", Template: "t", CheckedAt: t0})
			return err
		}},
		{"device version", func(e *env) error {
			e.inv.match["a-1"] = stated
			if _, err := e.svc.OnMatchChanged(e.t.Context(), "a-1"); err != nil {
				return err
			}
			e.inv.match["a-1"] = agent
			e.advance(time.Hour)
			_, err := e.svc.OnMatchChanged(e.t.Context(), "a-1")
			return err
		}},
		{"a person", func(e *env) error {
			e.inv.match["a-1"] = stated
			if _, err := e.svc.OnMatchChanged(e.t.Context(), "a-1"); err != nil {
				return err
			}
			fs, err := e.svc.Findings(e.t.Context(), "a-1")
			if err != nil {
				return err
			}
			for _, f := range fs {
				if _, err := e.svc.Verify(e.t.Context(), f.ID, "Checked on the device's own console.", "it@example.com"); err != nil {
					return err
				}
			}
			return nil
		}},
	} {
		t.Run(p.name, func(t *testing.T) {
			e := newEnv(t)
			e.inv.match = map[string]Asset{"a-1": fortigate()}
			e.inv.assets["a-1"] = AssetView{ID: "a-1", Name: "fw01", IP: "192.0.2.1", Kind: "firewall"}
			e.feeds.vulns = []Vuln{quietVuln, listed}
			e.feeds.kev = map[string]KevInfo{loud: {Vendor: "Fortinet", Product: "FortiOS"}}
			if err := p.run(e); err != nil {
				t.Fatal(err)
			}
			fs, err := e.svc.Findings(t.Context(), "a-1")
			if err != nil {
				t.Fatal(err)
			}
			byCVE := map[string]Finding{}
			for _, f := range fs {
				byCVE[f.CVE] = f
			}
			if f, ok := byCVE[quiet]; !ok || f.Urgency != UrgencyUpdate {
				t.Errorf("the CVE on no list: %+v, want a finding at urgency %d", f, UrgencyUpdate)
			}
			if f, ok := byCVE[loud]; !ok || f.Urgency != UrgencyExploited {
				t.Errorf("the listed CVE: %+v, want a finding at urgency %d", f, UrgencyExploited)
			}
			loudSeen := false
			for _, ev := range e.pub.take() {
				id := ""
				switch x := ev.Payload.(type) {
				case CreatedEvent:
					id = x.FindingID
				case StatusChangedEvent:
					id = x.FindingID
				case UncheckedAddedEvent:
					for _, c := range x.CVEs {
						if c.CVE == quiet {
							t.Errorf("announced a question of the CVE on no list: %+v", x)
						}
					}
				}
				switch id {
				case byCVE[quiet].ID:
					t.Errorf("%s announced the CVE on no list: %+v", ev.Name, ev.Payload)
				case byCVE[loud].ID:
					loudSeen = true
				}
			}
			if !loudSeen {
				t.Error("the listed CVE was not announced")
			}
		})
	}
}
