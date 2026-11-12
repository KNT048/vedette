package main

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/core"
	sensorpassive "github.com/knt048/vedette/modules/sensor-passive"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

// newSensorPassive builds the passive sensor service once, in buildServices (deps.SensorPassive): the sensor
// link (sensorBackend) and the HTTP handler must share it. No metadata consumer yet (the `logs` module, S-LOG-4): the default
// sink drops it.
func newSensorPassive(d deps) (*sensorpassive.Service, error) {
	var sink observe.Sink // a nil *inventory.Service must stay a nil interface so New reports it
	if d.Inventory != nil {
		sink = d.Inventory
	}
	cfg := sensorpassive.Config{DB: d.DB, Audit: d.Audit, Sink: sink, Host: netHost{box: d.Network}, Clock: d.Clock, Log: d.Log, Version: version}
	if d.Reg != nil { // SYS-5: asked again under the lock of a batch, after the listener let it in
		cfg.Enabled = func() bool { return d.Reg.Enabled("sensor-passive") }
	}
	if d.Inventory != nil { // the devices that exist do not count as new ones for the budget
		cfg.KnownMACs = d.Inventory.KnownMACs // uncapped (D-178)
	}
	return sensorpassive.New(cfg)
}

// There is no capture job in core (D-111, D-141): packets are read only by the `sensor` container, which reaches
// the Service through the sensor link (sensorBackend). The module has no jobs of its own here.

// netHost is the host module's answer to sensor-passive (Box network, D-56). The cards come from vedette-host
// (core runs in a container and cannot see them); the extraction switches and exclusion filters are the admin's
// settings of Settings, Box network. An install without a host reads the interfaces of the operating system it runs on.
// Interfaces only validates the card an admin picks (SetInterface, D-118): addresses are not shown from here.
type netHost struct{ box *core.NetworkHandlers }

func (n netHost) Interfaces(ctx context.Context) ([]capture.Interface, error) {
	cards, ok, err := n.box.Cards(ctx) // not HostCards: this one never fails for a host that does not answer
	if err != nil {
		return nil, err
	}
	if ok {
		return capInterfaces(cards), nil
	}
	return osInterfaces()
}

// HostCards is the list vedette-host reports. ok is false only when core runs without a host socket (container-only
// install, D-168, D-263): SetInterface then uses the cards of the sensor's heartbeat. A host that is configured but gives
// no list (down, socket absent, nothing cached yet) is an error: fail closed, the heartbeat never decides on an appliance (D-118).
func (n netHost) HostCards(ctx context.Context) ([]capture.Interface, bool, error) {
	cards, ok, err := n.box.Cards(ctx)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		if n.box.HasHost() {
			return nil, false, errors.New("vedette-host gave no list of cards; try again when it answers")
		}
		return nil, false, nil
	}
	return capInterfaces(cards), true, nil
}

// ManagementCard is where the sensor listens while no SPAN port is chosen (D-380); ok is false only without a host.
func (n netHost) ManagementCard(ctx context.Context) (string, bool) { return n.box.ManagementCard(ctx) }

func capInterfaces(cards []core.Card) []capture.Interface {
	out := make([]capture.Interface, 0, len(cards))
	for _, c := range cards {
		h := capture.Interface{Name: c.Name, MAC: c.MAC, Link: c.Link}
		for _, a := range c.Addresses {
			if a.Is4() {
				h.Addresses = append(h.Addresses, netip.PrefixFrom(a, 32)) // the host module reports addresses without a mask
			}
		}
		out = append(out, h)
	}
	return out
}

func osInterfaces() ([]capture.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []capture.Interface
	for _, i := range all {
		if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) != 6 {
			continue
		}
		h := capture.Interface{Name: i.Name, MAC: i.HardwareAddr.String(), Link: i.Flags&net.FlagUp != 0 && i.Flags&net.FlagRunning != 0}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
					h.Addresses = append(h.Addresses, p)
				}
			}
		}
		out = append(out, h)
	}
	return out, nil
}

func (n netHost) SpanOptions(ctx context.Context) (sensorlink.Extract, []sensorlink.Filter, error) {
	s, err := n.box.SpanSettings(ctx)
	if err != nil {
		return sensorlink.Extract{}, nil, err
	}
	x := sensorlink.Extract{DNS: s.Extract.DNS, SNI: s.Extract.TLSSNI, HTTP: s.Extract.HTTPHost, Flows: s.Extract.Flows}
	f := make([]sensorlink.Filter, len(s.Filters))
	for i, v := range s.Filters {
		f[i] = sensorlink.Filter{Type: v.Type, Value: v.Value}
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
