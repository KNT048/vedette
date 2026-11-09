package sensorpassive

// Limits on new devices (SYS-6): the source MAC of every frame is chosen by whoever is on the wire, and every new MAC
// the sensor reports becomes an unapproved device, an audit row and an event.

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

func strictCfg(book *deviceBook) engineConfig {
	return engineConfig{OwnMACs: own.OwnMACs, OwnIPs: own.OwnIPs, Devices: book}
}

func arpFrom(m pktgen.MAC, ip netip.Addr) []byte {
	return pktgen.ARP(pktgen.Bcast, 1, m, ip, pktgen.MAC{}, pktgen.RouterIP)
}

func macOf(a, b, c byte) pktgen.MAC { return pktgen.MAC{0x00, 0x16, 0x3e, a, b, c} }

func reportedDevices(obs []observe.Observation) map[string]bool {
	out := map[string]bool{}
	for _, o := range obs {
		out[o.AssetHint.MAC] = true
	}
	return out
}

// (a) A new MAC is reported only after two frames at least two seconds apart.
func TestNewMACNeedsTwoFramesTwoSecondsApart(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(strictCfg(newDeviceBook(defaultLimits)))
	frame := func(at time.Duration) {
		e.Handle(Packet{At: pktgen.T0.Add(at), Data: arpFrom(pktgen.PC, pktgen.PCIP)})
	}
	frame(0)
	frame(time.Second) // too soon
	frame(-time.Hour)  // a timestamp that goes back is not a second sighting
	if obs, _ := e.Drain(pktgen.T0, false); len(obs) != 0 {
		t.Fatalf("reported before the second frame: %+v", obs)
	}
	frame(2 * time.Second)
	obs, _ := e.Drain(pktgen.T0, false)
	if !reportedDevices(obs)[pktgen.PC.String()] {
		t.Fatalf("not reported after the second frame: %+v", obs)
	}
	if e.Counters()["new_macs_unconfirmed"] != 3 {
		t.Errorf("counters %v", e.Counters())
	}
}

// (a) One frame per random MAC, sustained for an hour, creates nothing.
func TestOneFramePerMACFloodCreatesNothing(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(strictCfg(newDeviceBook(defaultLimits)))
	devices := map[string]bool{}
	for minute := range 60 {
		at := pktgen.T0.Add(time.Duration(minute) * time.Minute)
		for i := range 100 {
			e.Handle(Packet{At: at.Add(time.Duration(i) * 100 * time.Millisecond), Data: arpFrom(macOf(byte(minute), byte(i>>8), byte(i)), netip.IPv4Unspecified())})
		}
		for m := range reportedDevices(first(e.Drain(at.Add(59*time.Second), false))) {
			devices[m] = true
		}
	}
	if len(devices) != 0 {
		t.Errorf("%d devices from MACs that each sent a single frame", len(devices))
	}
}

func first(obs []observe.Observation, _ []MetaItem) []observe.Observation { return obs }

// (b) The set of devices already reported belongs to the Service: a new Engine (settings change, capture reopened after
// an error) neither forgets them nor hands a flood a fresh budget. Known devices keep being reported during the flood.
func TestKnownDevicesAreStillReportedAfterARestartDuringAFlood(t *testing.T) {
	t.Parallel()
	book := newDeviceBook(defaultLimits)
	before, _ := newEngine(strictCfg(book))
	for _, at := range []time.Duration{0, 3 * time.Second} {
		before.Handle(Packet{At: pktgen.T0.Add(at), Data: arpFrom(pktgen.PC, pktgen.PCIP)})
	}
	if obs, _ := before.Drain(pktgen.T0, true); !reportedDevices(obs)[pktgen.PC.String()] {
		t.Fatal("the PC was not reported before the restart")
	}
	e, _ := newEngine(strictCfg(book)) // the same box after a settings change
	pcSeen, flooded := 0, map[string]bool{}
	for minute := range 10 {
		at := pktgen.T0.Add(time.Duration(minute+1) * time.Hour)
		for _, shift := range []time.Duration{0, 3 * time.Second} { // the flood: 200 MACs, two frames each, every hour
			for i := range 200 {
				e.Handle(Packet{At: at.Add(shift), Data: arpFrom(macOf(byte(minute), byte(i>>8), byte(i)), netip.AddrFrom4([4]byte{10, 9, byte(minute), byte(i)}))})
			}
		}
		e.Handle(Packet{At: at.Add(10 * time.Second), Data: arpFrom(pktgen.PC, pktgen.PCIP)})
		obs, _ := e.Drain(at.Add(11*time.Second), false)
		for m := range reportedDevices(obs) {
			if m == pktgen.PC.String() {
				pcSeen++
			} else {
				flooded[m] = true
			}
		}
	}
	if pcSeen != 10 { // once an hour (the repeat filter holds a sighting for 15 minutes), flood or not
		t.Errorf("the PC was reported %d times in 10 flooded hours, want 10", pcSeen)
	}
	if e.Counters()["new_macs_dropped"] == 0 {
		t.Errorf("the flood was not counted: %v", e.Counters())
	}
	if len(flooded) > maxNewMACsPerMinute*10 {
		t.Errorf("%d flood devices got through in 10 hours", len(flooded))
	}
}

// (c) At most maxNewMACsPerDay new devices a day; after that new MACs are only counted, known ones go on.
func TestDailyCeilingOfNewDevices(t *testing.T) {
	t.Parallel()
	book := newDeviceBook(bookLimits{PerMinute: 1 << 20, PerDay: maxNewMACsPerDay, ConfirmAfter: confirmAfter})
	e, _ := newEngine(strictCfg(book))
	const n = maxNewMACsPerDay + 100
	for _, shift := range []time.Duration{0, 3 * time.Second} {
		for i := range n {
			e.Handle(Packet{At: pktgen.T0.Add(time.Duration(i)*time.Second/10 + shift), Data: arpFrom(macOf(byte(i>>16), byte(i>>8), byte(i)), netip.IPv4Unspecified())})
		}
	}
	e.Handle(Packet{At: pktgen.T0.Add(time.Minute), Data: arpFrom(macOf(0, 0, 5), netip.MustParseAddr("10.1.1.1"))}) // device 5 is known
	obs, _ := e.Drain(pktgen.T0, true)
	seen := reportedDevices(obs)
	if len(seen) != maxNewMACsPerDay {
		t.Errorf("%d devices reported, want %d", len(seen), maxNewMACsPerDay)
	}
	if got := e.Counters()["new_macs_dropped"]; got != 100 {
		t.Errorf("new_macs_dropped = %d, want 100", got)
	}
	var again bool
	for _, o := range obs {
		again = again || (o.AssetHint.IP == netip.MustParseAddr("10.1.1.1"))
	}
	if !again {
		t.Error("a known device was refused after the ceiling")
	}
	// the next day the budget is back
	e.Handle(Packet{At: pktgen.T0.Add(25 * time.Hour), Data: arpFrom(macOf(0xee, 0, 1), netip.IPv4Unspecified())})
	e.Handle(Packet{At: pktgen.T0.Add(25*time.Hour + 3*time.Second), Data: arpFrom(macOf(0xee, 0, 1), netip.IPv4Unspecified())})
	if obs, _ := e.Drain(pktgen.T0.Add(26*time.Hour), true); !reportedDevices(obs)[macOf(0xee, 0, 1).String()] {
		t.Error("the day after, a new device was still refused")
	}
}

// The per-minute budget is a burst limit on top of the daily one.
func TestNewDevicesPerMinuteBudget(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(strictCfg(newDeviceBook(defaultLimits)))
	for _, shift := range []time.Duration{0, 3 * time.Second} {
		for i := range 300 {
			e.Handle(Packet{At: pktgen.T0.Add(shift), Data: arpFrom(macOf(1, byte(i>>8), byte(i)), netip.IPv4Unspecified())})
		}
	}
	if got := len(reportedDevices(first(e.Drain(pktgen.T0, true)))); got != maxNewMACsPerMinute {
		t.Errorf("%d devices in one minute, want %d", got, maxNewMACsPerMinute)
	}
}

// (b) A full book forgets the oldest device first; it does not clear everything.
func TestBookEvictsTheOldestFirst(t *testing.T) {
	t.Parallel()
	b := newDeviceBook(bookLimits{PerMinute: 1 << 30, PerDay: 1 << 30})
	m := func(i uint32) mac {
		var b mac
		binary.BigEndian.PutUint32(b[2:], i)
		return b
	}
	for i := range uint32(maxKnown + 3) {
		if b.admit(m(i), pktgen.T0) != admitNew {
			t.Fatalf("device %d was not new", i)
		}
	}
	if b.size() != maxKnown {
		t.Fatalf("the book holds %d devices, want %d", b.size(), maxKnown)
	}
	if b.admit(m(maxKnown+2), pktgen.T0) != admitKnown || b.admit(m(3), pktgen.T0) != admitKnown {
		t.Error("a recent device was forgotten")
	}
	// device 0 was evicted; seen again it is new (the eviction of 3 more devices makes room for it)
	if b.admit(m(0), pktgen.T0) != admitNew {
		t.Error("the oldest device was not the one forgotten")
	}
	if b.size() != maxKnown {
		t.Errorf("the book holds %d devices after a re-admission", b.size())
	}
}

// (a) MACs seen once do not pile up without limit.
func TestUnconfirmedMACsAreBounded(t *testing.T) {
	t.Parallel()
	b := newDeviceBook(defaultLimits)
	waits, refused := 0, 0
	for i := range maxUnconfirmed + 100 {
		switch b.admit(mac{0, 0, 0, byte(i >> 16), byte(i >> 8), byte(i)}, pktgen.T0) {
		case admitWait:
			waits++
		case admitRefused:
			refused++
		}
	}
	if waits != maxUnconfirmed || refused != 100 || len(b.first) != maxUnconfirmed {
		t.Errorf("waiting %d refused %d held %d", waits, refused, len(b.first))
	}
	// after the first sightings expire there is room again
	if b.admit(mac{9, 9, 9, 9, 9, 9}, pktgen.T0.Add(unconfirmedTTL+time.Second)) != admitWait {
		t.Error("expired first sightings were not dropped")
	}
}

// Low: a timestamp earlier than the start of the window does not reset the budget (a crafted recording with times that
// keep going back would lift the cap).
func TestBackwardTimestampsDoNotResetTheBudget(t *testing.T) {
	t.Parallel()
	e, _ := newEngine(engineConfig{OwnMACs: own.OwnMACs, Devices: newDeviceBook(bookLimits{PerMinute: maxNewMACsPerMinute, PerDay: maxNewMACsPerDay})})
	for i := range 600 {
		e.Handle(Packet{At: pktgen.T0.Add(time.Duration(600-i) * time.Millisecond), Data: arpFrom(macOf(1, byte(i>>8), byte(i)), netip.IPv4Unspecified())})
	}
	if got := len(reportedDevices(first(e.Drain(pktgen.T0, true)))); got > maxNewMACsPerMinute {
		t.Errorf("%d new MACs within 0.6 s of capture time", got)
	}
}
