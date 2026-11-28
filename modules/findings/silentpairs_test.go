package findings

import (
	"slices"
	"testing"
)

// silentCase is one (line, CVE) pair the matcher reaches without deciding it, and the possible question it must leave: the cause the
// lists show (PossibleCause) and the matcher's reason under it (coverDetail). unrelated: the record does not concern the line at all,
// so the pair is not related and nothing is asked.
type silentCase struct {
	name      string
	device    string
	sw        string
	vuln      Vuln
	cause     string
	detail    string
	unrelated bool
}

// Every pair the catalogue relates is decided or a possible question with a named cause: none is left undecided with nothing to show
// (a distribution's package its data has no word on, a version read from the network for a CVE on no exploited list, a line beside
// another line's finding, a package whose upstream ranges judge it and decide nothing). The pass only opens questions: none of these
// pairs is decided.
func TestCoverage_EveryRelatedPairIsDecidedOrAsked(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := *e.clock
	pkg := func(id, vendor, product, version, full, source string) Software {
		return Software{ID: id, Display: product, Vendor: vendor, Product: product, Version: version, Source: "agent", Packaged: true, PkgVersion: full, PkgSource: source}
	}
	ubuntu := Asset{ID: "u-1", Name: "app-01", OS: "Ubuntu 26.04.1 LTS", Software: []Software{
		pkg("s-wid", "Acmesoft", "Widget", "2.4.1", "2.4.1-1ubuntu0.2", "acme-widget"),
		pkg("s-ppa", "Acmesoft", "Gizmo", "3.2.0", "3.2.0-1+ubuntu26.04.1+ppa.example+1", "acme-gizmo"),
		pkg("s-norel", "Acmesoft", "Sprocket", "1.8", "", ""), // the agent gave no package release or source
		// one line read from two packages: the distribution decides one, and has no word on the other
		pkg("s-two", "Acmesoft", "Tool", "5.1", "5.1-2ubuntu0.4", "acme-tool"),
		pkg("s-two", "Acmesoft", "Tool", "5.1", "5.1-2ubuntu0.4", "acme-tool-extras"),
	}}
	rhel := Asset{ID: "r-2", Name: "db-02", OS: "Red Hat Enterprise Linux 9.4", Software: []Software{pkg("s-rwid", "Acmesoft", "Widget", "2.4.1", "2.4.1-3.el9", "acme-widget")}}
	alpine := Asset{ID: "a-3", Name: "gw-03", OS: "Alpine Linux 3.23.8", Software: []Software{pkg("s-abox", "Acmesoft", "Boxer", "1.37.0", "1.37.0-r30", "acme-boxer")}}
	desk := Asset{ID: "w-4", Name: "desk-04", OS: "Windows 11", Software: []Software{
		{ID: "s-ban", Display: "Acmesoft Gateway", Vendor: "Acmesoft", Product: "Gateway", Version: "3.1", Source: "nmap", CPE: "cpe:2.3:a:acmesoft:gateway:3.1:*:*:*:*:*:*:*"},
		{ID: "s-nov", Display: "Acmesoft Resolver", Vendor: "Acmesoft", Product: "Resolver", Source: "nmap", CPE: "cpe:2.3:a:acmesoft:resolver:*:*:*:*:*:*:*:*"},
		{ID: "s-run1", Display: "Acmesoft Runtime 5", Vendor: "Acmesoft", Product: "Runtime", Version: "5.0.3", Source: "agent", KevKeys: []string{"acmesoft|runtime"}},
		{ID: "s-run2", Display: "Acmesoft Runtime 4", Vendor: "Acmesoft", Product: "Runtime", Version: "4.2.0", Source: "agent", KevKeys: []string{"acmesoft|runtime"}},
		{ID: "s-edge", Display: "Microsoft Edge", Vendor: "Microsoft", Product: "Edge", Version: "158.0.4370.45", Source: "agent"},
	}}

	const widget, gizmo, sprocket, boxer = "cpe:2.3:a:acmesoft:widget:*:*:*:*:*:*:*:*", "cpe:2.3:a:acmesoft:gizmo:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:acmesoft:sprocket:*:*:*:*:*:*:*:*", "cpe:2.3:a:acmesoft:boxer:1.37.0:*:*:*:*:*:*:*"
	nvd := func(cve, cpe, end string, rows ...DistroFix) Vuln {
		v := Vuln{CVE: cve, NVDAnswered: true, Origin: RangeNVD, Published: now.AddDate(0, -2, 0), Distro: rows, DistroOn: map[string]bool{"ubuntu": true, "alpine": true}}
		af := Affected{CPE: cpe}
		if end != "" {
			af.Range = VersionRange{EndExcl: end}
		}
		v.Affected = []Affected{af}
		return v
	}
	row := func(release, pkg, status, fixed string) DistroFix {
		return DistroFix{Distro: "ubuntu", Release: release, Package: pkg, Status: status, Fixed: fixed}
	}
	olderRelease := nvd("CVE-2021-61003", widget, "2.0", row("20.04", "acme-widget", "fixed", "1.9-2ubuntu0.1"))
	olderRelease.Vendor, olderRelease.Product, olderRelease.Published = "Acmesoft", "Widget", now.AddDate(-5, 0, 0)
	runtime := nvd("CVE-2026-61012", "cpe:2.3:a:acmesoft:runtime:*:*:*:*:*:*:*:*", "")
	runtime.Affected = []Affected{{CPE: "cpe:2.3:a:acmesoft:runtime:5.0.3:*:*:*:*:*:*:*"}, {CPE: "cpe:2.3:a:acmesoft:runtime:4.2.5:*:*:*:*:*:*:*"}}
	runtime.Vendor, runtime.Product = "Acmesoft", "Runtime"
	legacy := nvd("CVE-2017-61020", "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*", "")
	legacy.Affected = append(legacy.Affected, Affected{CPE: "cpe:2.3:a:microsoft:internet_explorer:11:*:*:*:*:*:*:*"})
	legacy.Vendor, legacy.Product, legacy.Published = "Microsoft", "Internet Explorer", now.AddDate(-9, 0, 0)

	cases := []silentCase{
		{name: "the distribution has no row of the CVE", device: "u-1", sw: "s-wid", vuln: nvd("CVE-2026-61001", widget, "2.5"),
			cause: CauseDistroSilent, detail: DistroNotListed},
		{name: "the distribution lists another package only", device: "u-1", sw: "s-wid",
			vuln: nvd("CVE-2026-61002", widget, "2.5", row("26.04", "acme-widget-legacy", "fixed", "1.0-1ubuntu1")), cause: CauseDistroSilent, detail: DistroOtherPackages},
		{name: "an exploited CVE the distribution lists for an older release only", device: "u-1", sw: "s-wid", vuln: olderRelease,
			cause: CauseDistroSilent, detail: DistroOtherReleases},
		{name: "the distribution's row is about another build", device: "u-1", sw: "s-ppa",
			vuln: nvd("CVE-2026-61004", gizmo, "3.3", row("26.04", "acme-gizmo", "fixed", "3.2.0-1ubuntu1.1")), cause: CauseDistroSilent, detail: DistroOtherBuild},
		{name: "a package row with no release", device: "u-1", sw: "s-norel", vuln: nvd("CVE-2026-61005", sprocket, "1.9"),
			cause: CauseVersionNeeded, detail: UndecidedPackage},
		{name: "no data of the distribution", device: "r-2", sw: "s-rwid", vuln: nvd("CVE-2026-61006", widget, "2.5"),
			cause: CauseDistroSilent, detail: DistroNoData},
		{name: "a package its upstream ranges judge, listed at one release", device: "a-3", sw: "s-abox", vuln: nvd("CVE-2026-61013", boxer, ""),
			cause: CauseNeedsReading, detail: UndecidedExactOnly},
		{name: "a version read from the network, a CVE on no list", device: "w-4", sw: "s-ban",
			vuln: nvd("CVE-2026-61010", "cpe:2.3:a:acmesoft:gateway:*:*:*:*:*:*:*:*", "3.2"), cause: CauseVersionNeeded, detail: UndecidedNetworkVersion},
		{name: "no version, a CVE on no list", device: "w-4", sw: "s-nov",
			vuln: nvd("CVE-2026-61011", "cpe:2.3:a:acmesoft:resolver:*:*:*:*:*:*:*:*", "1.20"), cause: CauseVersionNeeded, detail: UndecidedNoVersion},
		{name: "a line beside another line's finding", device: "w-4", sw: "s-run2", vuln: runtime, cause: CauseNeedsReading, detail: UndecidedExactOnly},
		{name: "a legacy browser's record on the current browser", device: "w-4", sw: "s-edge", vuln: legacy, unrelated: true},
	}
	tool := nvd("CVE-2026-61014", "cpe:2.3:a:acmesoft:tool:*:*:*:*:*:*:*:*", "5.2", row("26.04", "acme-tool", "fixed", "5.1-2ubuntu0.3"))
	vulns := []Vuln{tool}
	for _, c := range cases {
		vulns = append(vulns, c.vuln)
	}
	devices := []Asset{ubuntu, rhel, alpine, desk}
	e.inv.assets = map[string]AssetView{}
	e.inv.match = map[string]Asset{}
	for _, a := range devices {
		e.inv.assets[a.ID] = AssetView{ID: a.ID, Hostname: ptr(a.Name), IP: "192.0.2.20", Kind: "server", Approved: true}
		e.inv.match[a.ID] = a
	}
	e.feeds.vulns = vulns
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	states := map[string]pairState{}
	questions := map[string]Question{}
	for _, a := range devices {
		rows, err := readDeviceRows(t.Context(), e.db.Reader(), a.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range rows.questions {
			for _, c := range append([]string{q.CVE}, q.Detail.CVEList...) {
				questions[a.ID+"/"+lineKey(c, q.SoftwareID)] = q
			}
		}
		in, err := e.svc.causeInputsOf(t.Context(), rows.questions, cveSet(vulns))
		if err != nil {
			t.Fatal(err)
		}
		read, _ := inWindow(vulns)
		st, _ := pairStates(newDevMatch(a, read, now), rows, in)
		for k, v := range st {
			states[a.ID+"/"+k] = v
		}
	}
	if st, ok := states["u-1/"+lineKey(tool.CVE, "s-two")]; !ok || st.by != RangeDistro || st.affected {
		t.Errorf("a line the distribution decided on one of its packages: %+v, want decided not affected by the distribution", st)
	}
	if q, ok := questions["u-1/"+lineKey(tool.CVE, "s-two")]; ok {
		t.Errorf("a line the distribution decided is asked about for its other package: %+v", q)
	}
	if st, ok := states["w-4/"+lineKey(runtime.CVE, "s-run1")]; !ok || !st.affected {
		t.Errorf("the line inside the range is not a finding: %+v", st)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := c.device + "/" + lineKey(c.vuln.CVE, c.sw)
			st, ok := states[key]
			if c.unrelated {
				if ok {
					t.Errorf("a record about another product line is related: %+v", st)
				}
				if q, ok := questions[key]; ok {
					t.Errorf("a record about another product line is asked: %+v", q)
				}
				return
			}
			if !ok {
				t.Fatal("the pair is not related")
			}
			if st.by != "" {
				t.Fatalf("decided by %q (affected %v): this pass only opens questions", st.by, st.affected)
			}
			if st.cause != c.cause || st.detail != c.detail {
				t.Errorf("cause %q detail %q, want %q %q", st.cause, st.detail, c.cause, c.detail)
			}
			q, ok := questions[key]
			if !ok {
				t.Fatal("no question asks about it")
			}
			if c.cause == CauseDistroSilent && q.CheckKey != "" {
				t.Errorf("a distribution's silence is checkable (the vendor's advisory does not speak for the distribution's build): %q", q.CheckKey)
			}
		})
	}
	for k, st := range states {
		if st.by == "" && st.detail == "" {
			t.Errorf("%s: undecided with no question (%q)", k, st.cause)
		}
	}
}

// A distribution's silence names its own cause, whatever the AI's reading stands at: nothing the vendor's page says decides the
// distribution's build.
func TestPossibleCause_DistributionSilence(t *testing.T) {
	t.Parallel()
	for _, r := range []string{DistroNotListed, DistroOtherPackages, DistroOtherReleases, DistroOtherBuild, DistroNoData} {
		q := Question{SoftwareID: "s-1", CVE: "CVE-2026-61001", Kind: QuestionNoRangeData, Detail: QuestionDetail{Version: "2.4.1",
			Undecided: &Undecided{Reason: r}}}
		for _, rs := range []ReadState{{}, {Ready: true, Auto: true}} {
			if got := PossibleCause(PossibleItem{Question: q, CVE: q.CVE, State: PossibleOpen}, rs); got != CauseDistroSilent {
				t.Errorf("%s with %+v: cause %q, want %q", r, rs, got, CauseDistroSilent)
			}
		}
		if !slices.Contains(UndecidedReasons, r) {
			t.Errorf("%s is not an undecided reason", r)
		}
	}
	if !slices.Contains(PossibleCauses, CauseDistroSilent) {
		t.Error("distro_silent is not a cause")
	}
}
