package main

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/core"
	sensorpassive "github.com/knt048/vedette/modules/sensor-passive"
)

// newSensorPassive builds the passive sensor service once, in buildServices (deps.SensorPassive): the capture
// job and the HTTP handler must share it. No metadata consumer yet (the `logs` module, S-LOG-4): the default
// sink drops it.
func newSensorPassive(d deps) (*sensorpassive.Service, error) {
	var sink observe.Sink // a nil *inventory.Service must stay a nil interface so New reports it
	if d.Inventory != nil {
		sink = d.Inventory
	}
	return sensorpassive.New(sensorpassive.Config{DB: d.DB, Audit: d.Audit, Sink: sink, Host: netHost{box: d.Network}, Clock: d.Clock, Log: d.Log, Version: version})
}

// sensorPassiveJobs runs the capture loop while the module is on (SYS-5). Run blocks until the module is turned
// off; Every only matters when it fails early (a card that vanished): the scheduler starts it again.
func sensorPassiveJobs(d deps) []jobs.Job {
	return []jobs.Job{{Module: "sensor-passive", Name: "capture", Every: 15 * time.Second, Run: d.SensorPassive.Run}}
}

// netHost is the host module's answer to sensor-passive (Box network, D-56). The cards come from vedette-host
// (core runs in a container and cannot see them); the extraction switches and exclusion filters are the admin's
// settings of Settings, Box network. An install without a host reads the interfaces of the operating system it runs on.
type netHost struct{ box *core.NetworkHandlers }

func (n netHost) Interfaces(ctx context.Context) ([]sensorpassive.HostInterface, error) {
	cards, ok, err := n.box.Cards(ctx)
	if err != nil {
		return nil, err
	}
	if ok {
		out := make([]sensorpassive.HostInterface, 0, len(cards))
		for _, c := range cards {
			h := sensorpassive.HostInterface{Name: c.Name, MAC: c.MAC, Link: c.Link}
			for _, a := range c.Addresses {
				if a.Is4() {
					h.Addresses = append(h.Addresses, a)
				}
			}
			out = append(out, h)
		}
		return out, nil
	}
	return osInterfaces()
}

func osInterfaces() ([]sensorpassive.HostInterface, error) {
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

func (n netHost) SpanOptions(ctx context.Context) (sensorpassive.Extract, []sensorpassive.Filter, error) {
	s, err := n.box.SpanSettings(ctx)
	if err != nil {
		return sensorpassive.Extract{}, nil, err
	}
	x := sensorpassive.Extract{DNS: s.Extract.DNS, TLSSNI: s.Extract.TLSSNI, HTTPHost: s.Extract.HTTPHost, Flows: s.Extract.Flows}
	f := make([]sensorpassive.Filter, len(s.Filters))
	for i, v := range s.Filters {
		f[i] = sensorpassive.Filter{Type: v.Type, Value: v.Value}
	}
	return x, f, nil
}

// spanSensor is core.SpanSensor on the passive sensor: what the Box network page needs of it. svc is set once the
// sensor exists; before that, and while the module is off, nothing is measured.
type spanSensor struct {
	reg *modreg.Registry
	svc *sensorpassive.Service
}

func (s *spanSensor) SpanStats(ctx context.Context) (core.SpanMeasure, error) {
	if s.svc == nil || !s.reg.Enabled("sensor-passive") {
		return core.SpanMeasure{}, core.ErrNoSensor
	}
	m, err := s.svc.SpanStats(ctx)
	if err != nil {
		return core.SpanMeasure{}, err
	}
	return core.SpanMeasure{Verdict: m.Verdict, PPS: m.PPS, OtherMACs: m.OtherMACs, LastPacket: m.LastPacket}, nil
}

func (s *spanSensor) SetSpanPort(ctx context.Context, actor, iface string, span bool) error {
	if s.svc == nil {
		return core.ErrNoSensor
	}
	return s.svc.SetInterface(ctx, actor, sensorpassive.SensorID, iface, span)
}
