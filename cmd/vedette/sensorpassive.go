package main

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	sensorpassive "github.com/knt048/vedette/modules/sensor-passive"
)

var (
	sensorMu       sync.Mutex
	sensorServices = map[*store.DB]*sensorpassive.Service{}
)

// newSensorPassive returns the passive sensor service of d's database, building it on first use. The capture
// job and the HTTP handler must share one instance: the SPAN measurement lives in its memory.
// ponytail: keyed by database so serve and tests build one each; a field in deps would be cleaner once main.go
// may change (issue #33). No metadata consumer yet (the `logs` module, S-LOG-4): the default sink drops it.
func newSensorPassive(d deps) *sensorpassive.Service {
	sensorMu.Lock()
	defer sensorMu.Unlock()
	if s, ok := sensorServices[d.DB]; ok {
		return s
	}
	var sink observe.Sink // a nil *inventory.Service must stay a nil interface so New reports it
	if d.Inventory != nil {
		sink = d.Inventory
	}
	s, err := sensorpassive.New(sensorpassive.Config{DB: d.DB, Audit: d.Audit, Sink: sink, Host: netHost{}, Clock: d.Clock, Log: d.Log, Version: version})
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	sensorServices[d.DB] = s
	return s
}

// sensorPassiveJobs runs the capture loop while the module is on (SYS-5). Run blocks until the module is turned
// off; Every only matters when it fails early (a card that vanished): the scheduler starts it again.
func sensorPassiveJobs(d deps) []jobs.Job {
	svc := newSensorPassive(d)
	return []jobs.Job{{Module: "sensor-passive", Name: "capture", Every: 15 * time.Second, Run: svc.Run}}
}

// netHost is the stand-in for the host module (Box network, D-56): it lists the box's cards from the
// operating system and uses the default SPAN extraction with no exclusion filters. The host module replaces
// it with the admin's settings (deferred: .ai/deferred/feat-sensor-passive.md).
type netHost struct{}

func (netHost) Interfaces(context.Context) ([]sensorpassive.HostInterface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []sensorpassive.HostInterface
	for _, i := range all {
		if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) != 6 {
			continue
		}
		h := sensorpassive.HostInterface{Name: i.Name, MAC: i.HardwareAddr.String(), Link: i.Flags&net.FlagUp != 0 && i.Flags&net.FlagRunning != 0}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
					h.Addresses = append(h.Addresses, p.Addr())
				}
			}
		}
		out = append(out, h)
	}
	return out, nil
}

func (netHost) SpanOptions(context.Context) (sensorpassive.Extract, []sensorpassive.Filter, error) {
	return sensorpassive.Extract{DNS: true, TLSSNI: true, HTTPHost: true, Flows: true}, nil, nil
}
