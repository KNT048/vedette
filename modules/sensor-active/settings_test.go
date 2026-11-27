package sensoractive_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// A target's deep-scan settings reach the nmap the worker runs: through the dispatcher, the job on the link and the worker's own
// build, the full sweep leaves out the scripts of a group that is off and names the ports to skip in --exclude-ports, the gentle
// speed is the job's rate, and the disruptive scripts are those of the groups allowed, narrowed again right before the job by what
// the target allows now. Every port to skip stays out of the External discovery and its -sV batches.

// groupFence is a deepFence that also says the disruptive groups the target allows now (sa.GroupGate).
type groupFence struct {
	deepFence
	groups nmapargv.Groups
	gerr   error
}

func (f *groupFence) GroupsNow(context.Context) (nmapargv.Groups, error) { return f.groups, f.gerr }

func scriptValue(argv []string) map[string]bool {
	out := map[string]bool{}
	if i := slices.Index(argv, "--script"); i >= 0 {
		for _, s := range strings.Split(argv[i+1], ",") {
			out[s] = true
		}
	}
	return out
}

func TestSettings_TheFullSweepTheWorkerRunsIsNarrowed(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		set  sa.DeepSettings
		rate int
	}{
		"denial of service off, a port skipped": {sa.DeepSettings{Groups: nmapargv.GroupLogins | nmapargv.GroupChange, SkipPorts: []int{8080}}, nmapargv.FullRate},
		"data change off, gentle":               {sa.DeepSettings{Groups: nmapargv.GroupDoS | nmapargv.GroupLogins, Gentle: true}, nmapargv.GentleRate},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := externalEnvWith(t, boxIP, "external_full.xml")
			own := &deepFence{ownFence: ownFence{ok: []netip.Addr{boxIP}}, now: nmapargv.ExternalFull}
			if _, err := e.svc.ScanExternalWith(e.ctx(), boxIP, nmapargv.ExternalFull, c.set, own); err != nil {
				t.Fatal(err)
			}
			want, err := nmapargv.BuildNarrow(nmapargv.ExternalFull, c.rate, nil, nmapargv.Narrow{Groups: c.set.Groups, SkipPorts: c.set.SkipPorts}, []netip.Addr{boxIP})
			if err != nil {
				t.Fatal(err)
			}
			calls := e.nm.calls(t)
			if len(calls) != 1 || !slices.Equal(calls[0], want) {
				t.Fatalf("nmap argv = %q\nwant %q", calls, want)
			}
			s := scriptValue(calls[0])
			if c.set.Groups&nmapargv.GroupDoS == 0 && s["http-slowloris-check"] {
				t.Error("denial of service off, but http-slowloris-check ran")
			}
			if c.set.Groups&nmapargv.GroupChange == 0 && s["http-shellshock"] {
				t.Error("data change off, but http-shellshock ran")
			}
			if r := e.str(`SELECT rate FROM sa_probe`); r != strconv.Itoa(c.rate) {
				t.Fatalf("probe row rate = %s", r)
			}
		})
	}
}

func TestSettings_TheDisruptiveScriptsAreThoseOfTheGroupsAllowedNow(t *testing.T) {
	t.Parallel()
	ports := []int{21, 22, 443, 49152} // the open ports of testdata/external_full.xml
	for name, c := range map[string]struct {
		set    sa.DeepSettings
		now    nmapargv.Groups
		want   nmapargv.Groups
		refuse bool
	}{
		"password guessing alone":            {sa.DeepSettings{Groups: nmapargv.GroupLogins}, nmapargv.AllGroups, nmapargv.GroupLogins, false},
		"a group turned off since the start": {sa.DeepSettings{Groups: nmapargv.GroupLogins | nmapargv.GroupChange}, nmapargv.GroupChange | nmapargv.GroupDoS, nmapargv.GroupChange, false},
		"every group turned off since":       {sa.DeepSettings{Groups: nmapargv.GroupLogins}, 0, 0, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := externalEnvWith(t, boxIP, "external_full.xml")
			own := &groupFence{deepFence: deepFence{ownFence: ownFence{ok: []netip.Addr{boxIP}}, now: nmapargv.ExternalDisruptive}, groups: c.now}
			_, err := e.svc.ScanDisruptiveWith(e.ctx(), boxIP, ports, c.set, own)
			if c.refuse {
				if !errors.Is(err, sa.ErrNotDisruptive) || len(e.nm.calls(t)) != 0 {
					t.Fatalf("err = %v, calls %q", err, e.nm.calls(t))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want, _ := nmapargv.BuildNarrow(nmapargv.ExternalDisruptive, nmapargv.FullRate, ports, nmapargv.Narrow{Groups: c.want}, []netip.Addr{boxIP})
			if calls := e.nm.calls(t); len(calls) != 1 || !slices.Equal(calls[0], want) {
				t.Fatalf("nmap argv = %q\nwant %q", calls, want)
			}
		})
	}
	// a port to skip never goes, whatever the caller handed over (the fake nmap answers for it anyway: that answer is not believed)
	e := externalEnvWith(t, boxIP, "external_full.xml")
	own := &groupFence{deepFence: deepFence{ownFence: ownFence{ok: []netip.Addr{boxIP}}, now: nmapargv.ExternalDisruptive}, groups: nmapargv.AllGroups}
	_, _ = e.svc.ScanDisruptiveWith(e.ctx(), boxIP, ports, sa.DeepSettings{Groups: nmapargv.AllGroups, SkipPorts: []int{22}}, own)
	if calls := e.nm.calls(t); len(calls) != 1 || calls[0][slices.Index(calls[0], "-p")+1] != "21,443,49152" {
		t.Fatalf("nmap argv = %q", calls)
	}
}

func TestSettings_TheExternalScanNeverNamesASkippedPort(t *testing.T) {
	t.Parallel()
	e := externalEnv(t, boxIP)
	skip := []int{3389, 8080} // ports of the fixed list that the fixtures do not answer on
	// the fake nmap prints the same answer for every batch, so some batches are not believed: only what was sent matters here
	_, _ = e.svc.ScanExternalWith(e.ctx(), boxIP, nmapargv.External, sa.DeepSettings{Groups: nmapargv.AllGroups, SkipPorts: skip}, &ownFence{ok: []netip.Addr{boxIP}})
	calls := e.nm.calls(t)
	if len(calls) < 2 {
		t.Fatalf("calls %q", calls)
	}
	if i := slices.Index(calls[0], "--exclude-ports"); i < 0 || calls[0][i+1] != "3389,8080" {
		t.Fatalf("discovery argv %q", calls[0])
	}
	for _, c := range calls[1:] {
		i := slices.Index(c, "-p")
		for _, p := range strings.Split(c[i+1], ",") {
			if p == "3389" || p == "8080" {
				t.Fatalf("a batch names a skipped port: %q", c)
			}
		}
	}
}

// The wide settings are the lines of before, and an older entry point is the wide one.
func TestSettings_WideIsTheLineOfBefore(t *testing.T) {
	t.Parallel()
	e := externalEnvWith(t, boxIP, "external_full.xml")
	own := &deepFence{ownFence: ownFence{ok: []netip.Addr{boxIP}}, now: nmapargv.ExternalFull}
	if _, err := e.svc.ScanExternalWith(e.ctx(), boxIP, nmapargv.ExternalFull, sa.WideSettings(), own); err != nil {
		t.Fatal(err)
	}
	want, _ := nmapargv.Build(nmapargv.ExternalFull, nmapargv.FullRate, []netip.Addr{boxIP})
	if calls := e.nm.calls(t); len(calls) != 1 || !slices.Equal(calls[0], want) {
		t.Fatalf("nmap argv = %q", calls)
	}
}

// A narrowed or gentle line goes only to a worker whose heartbeat says it takes the settings (nmap.narrow): an older worker gets
// nothing (ErrNarrowUnsupported), and the line of before still goes to it.
func TestSettings_ANarrowedLineNeedsAWorkerThatSaysSo(t *testing.T) {
	t.Parallel()
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 20 * time.Millisecond})
	if _, err := d.ActiveHeartbeat(t.Context(), &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true, Version: "7.95", Full: true}}); err != nil {
		t.Fatal(err)
	}
	for name, argv := range map[string][]string{
		"a group off":    must(nmapargv.BuildNarrow(nmapargv.ExternalFull, nmapargv.FullRate, nil, nmapargv.Narrow{Groups: nmapargv.GroupLogins | nmapargv.GroupChange}, []netip.Addr{boxIP})),
		"a port skipped": must(nmapargv.BuildNarrow(nmapargv.External, nmapargv.ExternalRate, nil, nmapargv.Narrow{Groups: nmapargv.AllGroups, SkipPorts: []int{22}}, []netip.Addr{boxIP})),
		"gentle":         must(nmapargv.BuildNarrow(nmapargv.ExternalFull, nmapargv.GentleRate, nil, nmapargv.Wide(), []netip.Addr{boxIP})),
	} {
		if _, err := d.Probe(t.Context(), argv); !errors.Is(err, sa.ErrNarrowUnsupported) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if rep, err := d.Jobs(t.Context(), 0, nil); err != nil || len(rep.Jobs) != 0 {
		t.Fatalf("jobs = %+v %v", rep.Jobs, err)
	}
}

func must(a []string, err error) []string {
	if err != nil {
		panic(err)
	}
	return a
}
