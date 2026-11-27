package main

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/exposure"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// A deep scan in two runs: the port scan of every TCP port (external_full_ports), then the full line on the open ports it found,
// each bounded by the step; a worker that does not run them (or a scan that is not deep) makes exposure run the one full run.
func TestExposureDeepScanRunsInTwoRuns(t *testing.T) {
	t.Parallel()
	type call struct {
		kind  nmapargv.Kind
		ports []int
		set   sensoractive.DeepSettings
		given time.Duration
	}
	var calls []call
	answer := sensoractive.External{Services: []sensoractive.ExternalService{{Port: 22}, {Port: 443}}, Ports: 65534, Refused: true}
	sc := exposureServiceScan{scanOn: func(ctx context.Context, _ netip.Addr, k nmapargv.Kind, ports []int, set sensoractive.DeepSettings, _ sensoractive.OwnEgress) (sensoractive.External, error) {
		d, _ := ctx.Deadline()
		calls = append(calls, call{k, slices.Clone(ports), set, time.Until(d)})
		return answer, nil
	}}
	target := exposure.ScanTarget{Mode: exposure.ScanMode{Full: true}, SkipPorts: []int{25}, Gentle: true}
	open, err := sc.ScanOpenPorts(t.Context(), target, ownPublicIP)
	if err != nil || !slices.Equal(open.Open, []int{22, 443}) || open.Ports != 65534 || !open.Refused {
		t.Fatalf("ScanOpenPorts = %+v %v", open, err)
	}
	if _, err := sc.ScanOpenServices(t.Context(), target, ownPublicIP, []int{22, 443}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0].kind != nmapargv.ExternalFullPorts || calls[0].ports != nil || calls[1].kind != nmapargv.ExternalFull || !slices.Equal(calls[1].ports, []int{22, 443}) {
		t.Fatalf("runs = %+v", calls)
	}
	for _, c := range calls {
		if !c.set.Gentle || !slices.Equal(c.set.SkipPorts, []int{25}) || c.given > exposure.FullServicesTimeout || c.given < exposure.FullServicesTimeout-time.Minute {
			t.Fatalf("run %s: settings %+v, bound %s", c.kind.Name(), c.set, c.given)
		}
	}
	for name, c := range map[string]struct {
		sc exposureServiceScan
		t  exposure.ScanTarget
	}{
		"a worker that runs one run": {exposureServiceScan{scanOn: func(context.Context, netip.Addr, nmapargv.Kind, []int, sensoractive.DeepSettings, sensoractive.OwnEgress) (sensoractive.External, error) {
			return sensoractive.External{}, sensoractive.ErrFullPortsUnsupported
		}}, target},
		"no two-run scanner":  {exposureServiceScan{}, target},
		"a scan not deep":     {sc, exposure.ScanTarget{}},
		"a domain's, no seam": {sc, exposure.ScanTarget{Mode: exposure.ScanMode{Full: true}, Domain: &exposure.DomainScope{}}},
	} {
		if _, err := c.sc.ScanOpenPorts(t.Context(), c.t, ownPublicIP); !errors.Is(err, exposure.ErrPortsFirstUnsupported) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// The bounds hold together: exposure's line names nmap's limits of the two runs, and the step has room for both, each with core's
	// fence (30 s), the worker's (25 s) and the pickup and the result (15 s), and a minute of waiting for the nmap slot.
	if exposure.FullPortsLimit != nmapargv.FullPortsHostTimeout || exposure.FullListLimit != nmapargv.FullListHostTimeout ||
		exposure.FullServicesTimeout < nmapargv.FullPortsHostTimeout+nmapargv.FullListHostTimeout+2*(70*time.Second)+time.Minute {
		t.Fatalf("exposure %s/%s/%s against nmap's %s + %s", exposure.FullServicesTimeout, exposure.FullPortsLimit, exposure.FullListLimit,
			nmapargv.FullPortsHostTimeout, nmapargv.FullListHostTimeout)
	}
}
