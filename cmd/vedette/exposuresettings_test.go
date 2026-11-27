package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/surface"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// A target's deep-scan settings reach what each engine is handed: the nmap job's groups, ports to skip and speed, the host's ZAP
// settings, the surface scan's options and the nuclei job's rate. A group off is absent from what leaves core; every narrowing of
// exposure's ScanTarget is kept.

func TestExposureSettings_TheNmapJobsCarryTheSettings(t *testing.T) {
	t.Parallel()
	var got []sensoractive.Settings
	var kinds []nmapargv.Kind
	sc := exposureServiceScan{
		scan: func(_ context.Context, _ netip.Addr, k nmapargv.Kind, set sensoractive.Settings, _ sensoractive.OwnEgress) (sensoractive.External, error) {
			kinds, got = append(kinds, k), append(got, set)
			return sensoractive.External{}, nil
		},
		scanDisruptive: func(_ context.Context, _ netip.Addr, _ []int, set sensoractive.Settings, _ sensoractive.OwnEgress) (sensoractive.External, error) {
			kinds, got = append(kinds, nmapargv.ExternalDisruptive), append(got, set)
			return sensoractive.External{}, nil
		},
	}
	// the full sweep: the groups of the target's settings (a scheduled scan runs it too), the ports to skip, gentle
	full := exposure.ScanTarget{ID: "t1", Mode: exposure.ScanMode{Full: true}, Groups: exposure.GroupLogins | exposure.GroupChange | exposure.GroupWebActive,
		SkipPorts: []int{8080}, Gentle: true}
	if _, err := sc.ScanServices(t.Context(), full, ownPublicIP); err != nil {
		t.Fatal(err)
	}
	// the default scan: the ports to skip only
	if _, err := sc.ScanServices(t.Context(), exposure.ScanTarget{ID: "t1", SkipPorts: []int{22}}, ownPublicIP); err != nil {
		t.Fatal(err)
	}
	// the disruptive scripts with one group allowed: they run, with that group only (no longer every group or nothing)
	logins := exposure.ScanMode{Full: true, Disruptive: true, Logins: true, Off: exposure.GroupDoS | exposure.GroupChange}
	if _, err := sc.ScanDisruptive(t.Context(), exposure.ScanTarget{ID: "t1", Mode: logins, SkipPorts: []int{443}, Gentle: true}, ownPublicIP, []int{22, 443}); err != nil {
		t.Fatal(err)
	}
	want := []sensoractive.Settings{
		{Groups: nmapargv.GroupLogins | nmapargv.GroupChange, SkipPorts: []int{8080}, Gentle: true},
		{Groups: nmapargv.AllGroups, SkipPorts: []int{22}},
		{Groups: nmapargv.GroupLogins, SkipPorts: []int{443}, Gentle: true},
	}
	if !slices.Equal(kinds, []nmapargv.Kind{nmapargv.ExternalFull, nmapargv.External, nmapargv.ExternalDisruptive}) || len(got) != len(want) {
		t.Fatalf("kinds %v, settings %+v", kinds, got)
	}
	for i := range want {
		if got[i].Groups != want[i].Groups || !slices.Equal(got[i].SkipPorts, want[i].SkipPorts) || got[i].Gentle != want[i].Gentle {
			t.Errorf("job %d (%s): %+v, want %+v", i, kinds[i].Name(), got[i], want[i])
		}
	}
	if k := shapeOf(logins); k != nmapargv.ExternalDisruptive {
		t.Errorf("one disruptive group allowed: shape %s", k.Name())
	}
	// right before the disruptive job, the groups the target allows now
	g := ownGate{actor: "a", id: "t1", modeNow: func(context.Context, string, string) (exposure.ScanMode, error) {
		return exposure.ScanMode{Full: true, Disruptive: true, Change: true}, nil
	}}
	if now, err := g.GroupsNow(t.Context()); err != nil || now != nmapargv.GroupChange {
		t.Fatalf("GroupsNow %d %v", now, err)
	}
}

func TestExposureSettings_TheHostGetsTheZAPSettings(t *testing.T) {
	t.Parallel()
	ok := func() *fakeZapHost {
		r := zapRun(t, api.StatusSucceeded, "", nil)
		r.Command = api.CmdZapActive
		r.Result, _ = json.Marshal(api.ZapActiveResult{ReportID: "0123456789abcdef0123456789abcdef", Size: 11, SkippedRules: []int{30001, 40034}})
		return &fakeZapHost{run: r, report: []byte(`{"site":[]}`)}
	}
	if !(exposureWebScan{}).ExcludesPaths() {
		t.Fatal("the host leaves web paths out: the adapter must say so")
	}
	for name, c := range map[string]struct {
		m          exposure.ScanMode
		disruptive bool
		want       *api.ZapSettings
	}{
		"denial of service off": {without(exposure.GroupDoS), true, &api.ZapSettings{NoDoS: true, SkipPaths: []string{"/admin"}, Gentle: true}},
		"data change off":       {without(exposure.GroupChange), true, &api.ZapSettings{NoChange: true, SkipPaths: []string{"/admin"}, Gentle: true}},
		"both off":              {exposure.ScanMode{Full: true, Disruptive: true, Logins: true, WebActive: true}, false, &api.ZapSettings{SkipPaths: []string{"/admin"}, Gentle: true}},
	} {
		h := ok()
		w := exposureWebScan{host: h, token: func(context.Context, string) (string, error) { return "0123456789abcdef", nil }}
		ipT := webIPTarget
		ipT.Mode, ipT.Grant, ipT.SkipPaths, ipT.Gentle = c.m, "0123456789abcdef0123456789abcdef", []string{"/admin"}, true
		res, err := w.Active(t.Context(), ipT, webIPPage)
		if err != nil || len(h.active) != 1 {
			t.Fatalf("%s: %v", name, err)
		}
		a := h.active[0]
		if a.Disruptive != c.disruptive || a.Settings == nil || a.Settings.NoDoS != c.want.NoDoS || a.Settings.NoChange != c.want.NoChange ||
			!slices.Equal(a.Settings.SkipPaths, c.want.SkipPaths) || a.Settings.Gentle != c.want.Gentle {
			t.Errorf("%s: disruptive %v settings %+v", name, a.Disruptive, a.Settings)
		}
		if !slices.Equal(res.SkippedRules, []string{"30001", "40034"}) {
			t.Errorf("%s: skipped rules %v", name, res.SkippedRules)
		}
	}
	// the passive pass: the paths to skip; no settings at all for a target without any
	h := ok()
	h.run = zapRun(t, api.StatusSucceeded, "", &api.ZapBaselineResult{ReportID: "0123456789abcdef0123456789abcdef", Size: 11})
	w := exposureWebScan{host: h, token: func(context.Context, string) (string, error) { return "0123456789abcdef", nil }}
	ipT := webIPTarget
	ipT.SkipPaths = []string{"/delete"}
	if _, err := w.Baseline(t.Context(), ipT, webIPPage); err != nil || h.got.Settings == nil || !slices.Equal(h.got.Settings.SkipPaths, []string{"/delete"}) {
		t.Fatalf("baseline settings %+v %v", h.got.Settings, err)
	}
	if _, err := w.Baseline(t.Context(), webIPTarget, webIPPage); err != nil || h.got.Settings != nil {
		t.Fatalf("no settings: %+v %v", h.got.Settings, err)
	}
}

func TestExposureSettings_TheSurfaceScanSkipsPorts(t *testing.T) {
	t.Parallel()
	f := &fakeSurface{}
	r := &exposureRunner{on: func() bool { return true }, scan: f, scope: func(context.Context, string, netip.Addr) (bool, error) { return true, nil },
		log: slog.New(slog.DiscardHandler), running: map[*int]context.CancelCauseFunc{}}
	if _, err := r.Scan(t.Context(), exposure.ScanTarget{ID: "t1", Kind: exposure.KindIP, Value: "203.0.113.10", SkipPorts: []int{22}, Gentle: true}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.opts.SkipPorts, []int{22}) || !f.opts.Gentle {
		t.Fatalf("IP options %+v", f.opts)
	}
	f.opts = surface.Options{}
	if _, err := r.Scan(t.Context(), exposure.ScanTarget{ID: "t2", Kind: exposure.KindDomain, Value: "acme.example", SkipPorts: []int{80}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.opts.SkipPorts, []int{80}) {
		t.Fatalf("domain options %+v", f.opts)
	}
}

func TestExposureSettings_GentleNucleiJobs(t *testing.T) {
	t.Parallel()
	for _, gentle := range []bool{false, true} {
		f := &templatesFake{gateOK: true, answer: func(r sensoractive.NucleiRequest) nucleiout.Outcome {
			var o nucleiout.Outcome
			for _, id := range r.Templates {
				o.Results = append(o.Results, nucleiout.Result{Template: id, Target: "8.8.8.8:18443"})
			}
			return o
		}}
		a := f.scanner()
		a.mode = (&modes{list: []exposure.ScanMode{modeAllGroups}}).now
		st := fullTarget(true)
		st.Mode, st.Gentle = modeAllGroups, gentle
		if _, err := a.ScanTemplates(t.Context(), st, ownPublicIP, []exposure.TemplateJob{fullJobOf()}); err != nil {
			t.Fatal(err)
		}
		if len(f.reqs) == 0 {
			t.Fatal("no nuclei job")
		}
		want := map[bool]int{false: 20, true: 4}[gentle]
		for _, r := range f.reqs {
			if r.Rate != want {
				t.Fatalf("gentle %v: rate %d", gentle, r.Rate)
			}
		}
	}
}
