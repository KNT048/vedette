package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/content/nucleipack"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/pack"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// The deep-scan groups and exclusions as the adapters honour them, over the committed nuclei pack and the fakes of the other tests.

// modeAllGroups is a person's scan of the box's own IP with every group of the deep scan allowed.
var modeAllGroups = exposure.ScanMode{Full: true, Disruptive: true, DoS: true, Logins: true, Change: true, WebActive: true, OpenVAS: true}

// without is modeAllGroups with group g turned off by the target's settings (as narrow leaves it).
func without(g exposure.Groups) exposure.ScanMode {
	m := modeAllGroups
	m.Off = g
	switch g {
	case exposure.GroupDoS:
		m.DoS = false
	case exposure.GroupLogins:
		m.Logins = false
	case exposure.GroupChange:
		m.Change = false
	}
	return m
}

// The classifier held against the committed pack: every disruptive template is in exactly one group, the counts are the measured
// ones, and a check that can exhaust or crash a service is in the denial-of-service group whatever its tags (Billion Laughs has no
// dos tag). The deep set's templates whose names say denial of service are single GET reads of a version, so they stay deep.
func TestExposureGroups_TheClassifierHoldsAgainstThePack(t *testing.T) {
	t.Parallel()
	ix, err := nucleipack.Index()
	if err != nil {
		t.Fatal(err)
	}
	count := map[exposure.Groups]int{}
	for _, tp := range ix.Templates {
		g := templateGroup(tp)
		if (g != 0) != (tp.FullSet() == pack.SetDisruptive) {
			t.Fatalf("%s: group %d in set %q", tp.ID, g, tp.FullSet())
		}
		count[g]++
		if tp.FullSet() == pack.SetDeep && dosNameRE.MatchString(tp.Name) && !regexp.MustCompile(`^GET \S+( HTTP/1\.1)?$`).MatchString(tp.Request) {
			t.Errorf("deep template %s is named as a denial of service and sends %q", tp.ID, tp.Request)
		}
	}
	if g, ok := ix.Get("CVE-2019-11253"); !ok || slices.Contains(g.Tags, "dos") || templateGroup(g) != exposure.GroupDoS {
		t.Fatalf("Billion Laughs: %+v", g)
	}
	if count[exposure.GroupDoS] != 3 || count[exposure.GroupLogins] != 293 || count[exposure.GroupChange] != 1685 {
		t.Fatalf("groups: dos %d, logins %d, change %d (pack %s)", count[exposure.GroupDoS], count[exposure.GroupLogins], count[exposure.GroupChange], ix.Version)
	}
}

// Each disruptive group off: no template of it leaves core, the others still do; with every group on each group is sent (so the
// check is not empty). The step says the group was turned off.
func TestExposureGroups_NucleiSendsNoTemplateOfAGroupThatIsOff(t *testing.T) {
	t.Parallel()
	ix, err := nucleipack.Index()
	if err != nil {
		t.Fatal(err)
	}
	answer := func(r sensoractive.NucleiRequest) nucleiout.Outcome {
		var o nucleiout.Outcome
		for _, id := range r.Templates {
			o.Results = append(o.Results, nucleiout.Result{Template: id, Target: "8.8.8.8:18443", Matched: id == "wordpress-detect"})
		}
		return o
	}
	sent := func(m exposure.ScanMode) (map[exposure.Groups]int, []string) {
		f := &templatesFake{gateOK: true, answer: answer}
		a := f.scanner()
		a.mode = (&modes{list: []exposure.ScanMode{m}}).now
		st := fullTarget(true)
		st.Mode = m
		got, err := a.ScanTemplates(t.Context(), st, ownPublicIP, []exposure.TemplateJob{fullJobOf()})
		if err != nil {
			t.Fatal(err)
		}
		out := map[exposure.Groups]int{}
		for _, r := range f.reqs {
			for _, id := range r.Templates {
				tp, _ := ix.Get(id)
				out[templateGroup(tp)]++
			}
		}
		return out, got.NotChecked
	}
	all, _ := sent(modeAllGroups)
	for _, g := range []exposure.Groups{exposure.GroupDoS, exposure.GroupLogins, exposure.GroupChange} {
		if all[g] == 0 {
			t.Fatalf("every group on sends none of group %v: %v", g.Names(), all)
		}
		got, lines := sent(without(g))
		if got[g] != 0 {
			t.Errorf("%v off: %d of its templates were sent", g.Names(), got[g])
		}
		for _, other := range []exposure.Groups{exposure.GroupDoS, exposure.GroupLogins, exposure.GroupChange} {
			if other != g && got[other] == 0 {
				t.Errorf("%v off: none of %v was sent", g.Names(), other.Names())
			}
		}
		if !slices.ContainsFunc(lines, func(l string) bool {
			return strings.Contains(l, g.Names()[0]) && strings.Contains(l, exposure.NotBySettings)
		}) {
			t.Errorf("%v off: the lines %q", g.Names(), lines)
		}
	}
	// a group turned off while the run runs: the next chunk reads it (the run began with every group)
	f := &templatesFake{gateOK: true, answer: answer}
	a := f.scanner()
	a.mode = (&modes{list: []exposure.ScanMode{modeAllGroups, without(exposure.GroupLogins)}}).now
	if _, err := a.ScanTemplates(t.Context(), fullTarget(true), ownPublicIP, []exposure.TemplateJob{fullJobOf()}); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.reqs[1:] {
		for _, id := range r.Templates {
			if tp, _ := ix.Get(id); templateGroup(tp) == exposure.GroupLogins {
				t.Fatalf("a login template after the group was turned off: %s", id)
			}
		}
	}
}

// The paths to skip, by the first request of a template: under a prefix it is left out; a path built while it runs cannot be told
// and runs; a template outside http/ sends no web path.
func TestExposureGroups_TemplatePathAgainstThePathsToSkip(t *testing.T) {
	t.Parallel()
	tp := func(path, req string) pack.Template { return pack.Template{ID: "x", Path: path, Request: req} }
	skip := []string{"/admin", "/wp-admin/admin-ajax.php"}
	for _, c := range []struct {
		t    pack.Template
		want tplPathVerdict
	}{
		{tp("http/x.yaml", "GET {{BaseURL}}/admin/delete?id=1"), tplPathSkipped},
		{tp("http/x.yaml", "POST {{RootURL}}/admin"), tplPathSkipped},
		{tp("http/x.yaml", "GET /admin/users HTTP/1.1"), tplPathSkipped},
		{tp("http/x.yaml", "GET {{BaseURL}}/login"), tplPathRuns},
		{tp("http/x.yaml", "GET {{BaseURL}}"), tplPathRuns},
		{tp("http/x.yaml", "GET {{BaseURL}}/wp-admin/{{file}}"), tplPathUnknown},
		{tp("http/x.yaml", "GET {{BaseURL}}/ad{{x}}"), tplPathUnknown},
		{tp("http/x.yaml", "GET {{BaseURL}}{{paths}}"), tplPathUnknown},
		{tp("http/x.yaml", "GET {{Host}}:{{Port}}/admin"), tplPathUnknown},
		{tp("http/x.yaml", ""), tplPathUnknown},
		{tp("network/x.yaml", "GET {{BaseURL}}/admin"), tplPathRuns},
	} {
		if got := templatePathOf(c.t, skip); got != c.want {
			t.Errorf("%q: %v, want %v", c.t.Request, got, c.want)
		}
	}
	if got := templatePathOf(tp("http/x.yaml", "GET {{BaseURL}}/admin"), nil); got != tplPathRuns {
		t.Errorf("no paths to skip: %v", got)
	}
}

// nuclei with paths to skip: the templates under them are not sent, and the note names the ones it could not judge.
func TestExposureGroups_NucleiLeavesOutTheTemplatesOfASkippedPath(t *testing.T) {
	t.Parallel()
	ix, err := nucleipack.Index()
	if err != nil {
		t.Fatal(err)
	}
	f := &templatesFake{gateOK: true, answer: func(r sensoractive.NucleiRequest) nucleiout.Outcome {
		var o nucleiout.Outcome
		for _, id := range r.Templates {
			o.Results = append(o.Results, nucleiout.Result{Template: id, Target: "8.8.8.8:18443", Matched: id == "wordpress-detect"})
		}
		return o
	}}
	a := f.scanner()
	a.mode = (&modes{list: []exposure.ScanMode{modeAllGroups}}).now
	st := fullTarget(true)
	st.SkipPaths = []string{"/wp-"}
	got, err := a.ScanTemplates(t.Context(), st, ownPublicIP, []exposure.TemplateJob{fullJobOf()})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range f.reqs {
		for _, id := range r.Templates {
			n++
			if tp, _ := ix.Get(id); templatePathOf(tp, st.SkipPaths) == tplPathSkipped {
				t.Fatalf("%s was sent: %q", id, tp.Request)
			}
		}
	}
	if n == 0 || !slices.ContainsFunc(got.NotChecked, func(l string) bool { return strings.Contains(l, "could not filter") && strings.Contains(l, "/wp-") }) {
		t.Fatalf("%d sent, lines %q", n, got.NotChecked)
	}
}

// The ports to skip: nuclei gets no job on them.
func TestExposureGroups_NucleiGetsNoSkippedPort(t *testing.T) {
	t.Parallel()
	f := &templatesFake{gateOK: true, answer: func(sensoractive.NucleiRequest) nucleiout.Outcome { return nucleiout.Outcome{} }}
	a := f.scanner()
	a.mode = (&modes{list: []exposure.ScanMode{modeAllGroups}}).now
	st := fullTarget(true)
	st.SkipPorts = []int{18443}
	if _, err := a.ScanTemplates(t.Context(), st, ownPublicIP, []exposure.TemplateJob{fullJobOf("CVE-2018-13379")}); err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 0 {
		t.Fatalf("nuclei was sent %d runs to a skipped port", len(f.reqs))
	}
}

// nmap's disruptive scripts are split by group: the shape allows them while any disruptive group is on, the job carries the groups
// allowed, and a skipped port never goes.
func TestExposureGroups_NmapDisruptiveRunsTheGroupsAllowed(t *testing.T) {
	t.Parallel()
	if k := shapeOf(modeAllGroups); k != nmapargv.ExternalDisruptive {
		t.Fatalf("every group: %s", k.Name())
	}
	var sent [][]int
	var groups []nmapargv.Groups
	sc := exposureServiceScan{scanDisruptive: func(_ context.Context, _ netip.Addr, p []int, set sensoractive.Settings, _ sensoractive.OwnEgress) (sensoractive.External, error) {
		sent, groups = append(sent, p), append(groups, set.Groups)
		return sensoractive.External{}, nil
	}}
	for g, want := range map[exposure.Groups]nmapargv.Groups{
		exposure.GroupDoS:    nmapargv.GroupLogins | nmapargv.GroupChange,
		exposure.GroupLogins: nmapargv.GroupDoS | nmapargv.GroupChange,
		exposure.GroupChange: nmapargv.GroupDoS | nmapargv.GroupLogins,
	} {
		m := without(g)
		if k := shapeOf(m); k != nmapargv.ExternalDisruptive {
			t.Errorf("%v off: shape %s", g.Names(), k.Name())
		}
		groups = nil
		if _, err := sc.ScanDisruptive(t.Context(), exposure.ScanTarget{ID: "t1", Mode: m}, ownPublicIP, []int{22}); err != nil || len(groups) != 1 || groups[0] != want {
			t.Errorf("%v off: groups %v %v", g.Names(), groups, err)
		}
	}
	none := exposure.ScanMode{Full: true, WebActive: true, Off: exposure.GroupDoS | exposure.GroupLogins | exposure.GroupChange}
	var un *exposure.Unavailable
	if _, err := sc.ScanDisruptive(t.Context(), exposure.ScanTarget{ID: "t1", Mode: none}, ownPublicIP, []int{22}); !errors.As(err, &un) || shapeOf(none) != nmapargv.ExternalFull {
		t.Errorf("every disruptive group off: %v", err)
	}
	sent = nil
	if _, err := sc.ScanDisruptive(t.Context(), exposure.ScanTarget{ID: "t1", Mode: modeAllGroups, SkipPorts: []int{443}}, ownPublicIP, []int{22, 443}); err != nil || len(sent) != 1 || !slices.Equal(sent[0], []int{22}) {
		t.Fatalf("a skipped port: %v %v", sent, err)
	}
}

// ZAP's disruptive rules are asked for while either of their classes is allowed; the class that is off goes to the host as
// no_dos or no_change.
func TestExposureGroups_ZAPDisruptiveWithEitherClass(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		m                  exposure.ScanMode
		want, noDoS, noChg bool
	}{
		"every group":     {modeAllGroups, true, false, false},
		"dos off":         {without(exposure.GroupDoS), true, true, false},
		"data change off": {without(exposure.GroupChange), true, false, true},
		"logins off":      {without(exposure.GroupLogins), true, false, false},
	} {
		r := zapRun(t, api.StatusSucceeded, "", nil)
		r.Command = api.CmdZapActive
		r.Result, _ = json.Marshal(api.ZapActiveResult{ReportID: "0123456789abcdef0123456789abcdef", Size: 11})
		h := &fakeZapHost{run: r, report: []byte(`{"site":[]}`)}
		w := exposureWebScan{host: h, token: func(context.Context, string) (string, error) { return "0123456789abcdef", nil }}
		ipT := webIPTarget
		ipT.Mode, ipT.Grant = c.m, "0123456789abcdef0123456789abcdef"
		if _, err := w.Active(t.Context(), ipT, webIPPage); err != nil || len(h.active) != 1 || h.active[0].Disruptive != c.want {
			t.Errorf("%s: %+v %v", name, h.active, err)
			continue
		}
		st := h.active[0].Settings
		if (st != nil && st.NoDoS) != c.noDoS || (st != nil && st.NoChange) != c.noChg {
			t.Errorf("%s: settings %+v", name, st)
		}
	}
}

// The planner spends a port's room only on templates the mode and the paths to skip let leave: one of a group that is off, or
// under a path to skip, never takes a place another template could have had (the per-port cap and the progress bound count only
// sendable ones).
func TestExposureGroups_ThePlanSpendsItsRoomOnSendableTemplates(t *testing.T) {
	t.Parallel()
	ix, err := nucleipack.Index()
	if err != nil {
		t.Fatal(err)
	}
	products := pack.ProductTags(ix.Templates)
	p := fullPorts(ownPublicIP, []exposure.TemplateJob{fullJobOf("CVE-2018-13379")}, nil)[0]
	for name, f := range map[string]tplFilter{
		"logins off":             {m: without(exposure.GroupLogins)},
		"data change off":        {m: without(exposure.GroupChange)},
		"paths to skip":          {m: modeAllGroups, paths: []string{"/wp-", "/admin"}},
		"every disruptive group": {m: modeAllGroups},
	} {
		plan, capped := webPlan(ix, p, reachableTags(ix, products, p), f, 50)
		if len(plan) != 50 || capped == 0 {
			t.Errorf("%s: %d planned, %d capped", name, len(plan), capped)
		}
		for _, tp := range plan {
			if !f.runs(tp) {
				t.Errorf("%s: %s is planned but cannot be sent", name, tp.ID)
			}
		}
		if other := otherPlan(ix, fullPort{port: 22, service: "ssh", product: "OpenSSH"}, f); slices.ContainsFunc(other, func(tp pack.Template) bool { return !f.runs(tp) }) {
			t.Errorf("%s: a non-web plan holds a template that cannot be sent", name)
		}
	}
}
